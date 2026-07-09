/**
 * RFC 7523 §3 Client-Assertion Verification (private_key_jwt)
 *
 * Verifies the `client_assertion` JWT a headless agent presents to the token
 * endpoint for the client_credentials grant (#159/#160). EdDSA/Ed25519 only
 * (RFC 8037), verified with `node:crypto` — no new dependency; the plugin's
 * `jsonwebtoken` cannot verify EdDSA. Everything fails closed: any parse,
 * header, key, signature, or claim problem yields `{ valid: false, reason }`,
 * never a throw, so the grant handler can map it straight to an OAuth
 * `invalid_client` error and an audit reason.
 *
 * Verification contract (see the #159 design review):
 * - header `alg` is exactly `EdDSA`; `typ`, when present, is `JWT`; any `crit`
 *   is rejected (we implement no extensions).
 * - key selected from the client's registered JWK Set: `kid` present → must
 *   match exactly one registered key; `kid` absent → the set must hold exactly
 *   one key. Keys must be public OKP/Ed25519 (a private `d` is rejected).
 * - `iss` = `sub` = the authenticating client_id (all three, exactly).
 * - `aud` equals the resolved token-endpoint URL — a string, or a
 *   single-element array (RFC 7519 allows an array; more than one audience is
 *   rejected as ambiguous).
 * - `exp` required, in the future, and no more than `maxExpiresInSeconds`
 *   (default 60) out; `iat` required and not in the future; `nbf`, when
 *   present, must have passed. All checks allow `clockToleranceSeconds`
 *   (default 5) of skew.
 * - `jti` required (non-empty string, ≤ 256 chars). Replay is NOT enforced
 *   here — callers must run the returned `jti` through MCPAssertionJtiStore.
 */

import { createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto';

/** RFC 7523 §2.2 value for `client_assertion_type`. */
export const CLIENT_ASSERTION_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const DEFAULT_MAX_EXPIRES_IN_SECONDS = 60;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
/** Bound what a client can force into the replay table. */
const MAX_JTI_LENGTH = 256;
/**
 * Cap on the whole compact JWT before any split/decode work — a legitimate
 * Ed25519 assertion with our claim set is well under 1KB, so 8KB is generous.
 * Same defense-in-depth family as the repo's 2048-char request-path cap.
 */
const MAX_ASSERTION_LENGTH = 8192;
/** Ed25519 signatures are always exactly 64 bytes (RFC 8032). */
const ED25519_SIGNATURE_LENGTH = 64;

/**
 * Strict base64url alphabet (RFC 4648 §5, unpadded). `Buffer.from(s,
 * 'base64url')` silently skips invalid characters, which would let two
 * distinct token strings decode to the same payload — validate first.
 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/** Claims of a successfully verified assertion. */
export interface ClientAssertionClaims {
	iss: string;
	sub: string;
	/** The single verified audience (unwrapped if presented as an array). */
	aud: string;
	exp: number;
	iat: number;
	jti: string;
}

export type ClientAssertionResult = { valid: true; claims: ClientAssertionClaims } | { valid: false; reason: string };

export interface VerifyClientAssertionParams {
	/** The `client_assertion` value — a compact-serialized JWT. */
	assertion: string;
	/** The client_id being authenticated; must equal `iss` and `sub`. */
	clientId: string;
	/** Resolved token-endpoint URL; must equal `aud` exactly. */
	tokenEndpoint: string;
	/** The client's registered public JWK Set keys (OKP/Ed25519). */
	jwks: Record<string, unknown>[];
	/** Maximum allowed `exp - now`. Default 60 (issue req 1). */
	maxExpiresInSeconds?: number;
	/** Clock-skew allowance for `exp`/`iat`/`nbf`. Default 5. */
	clockToleranceSeconds?: number;
}

function fail(reason: string): ClientAssertionResult {
	return { valid: false, reason };
}

function decodeSegment(segment: string): Record<string, unknown> | null {
	if (!BASE64URL_PATTERN.test(segment)) return null;
	let parsed: unknown;
	try {
		parsed = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
	} catch {
		return null;
	}
	return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
		? (parsed as Record<string, unknown>)
		: null;
}

/**
 * Load a registered JWK as an Ed25519 public KeyObject. Returns null (reject)
 * unless the JWK is exactly a public OKP/Ed25519 key — in particular a key
 * carrying private material (`d`) must never have been registered, and must
 * never verify, so it is rejected here as defense-in-depth against a
 * registration-validation gap.
 */
function loadEd25519PublicKey(jwk: Record<string, unknown>): KeyObject | null {
	if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return null;
	if (typeof jwk.x !== 'string' || jwk.x.length === 0) return null;
	if ('d' in jwk) return null;
	try {
		return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
	} catch {
		return null;
	}
}

/**
 * Select the verification key per the JWKS `kid` rules (mirrors
 * tokenIssuer.verifyAccessTokenWithKeySet): a presented `kid` must match
 * exactly one registered key — never fall back to "try every key"; no `kid`
 * requires an unambiguous single-key set.
 */
function selectKey(
	jwks: Record<string, unknown>[],
	kid: unknown
): { jwk: Record<string, unknown> } | { error: string } {
	if (!Array.isArray(jwks) || jwks.length === 0) {
		return { error: 'client has no registered JWKs' };
	}
	// Registration (#161) should never store non-object entries, but this
	// module promises "never throws" — so a null/primitive element must fail
	// the lookup, not TypeError inside it.
	if (kid !== undefined) {
		if (typeof kid !== 'string' || kid.length === 0) return { error: 'assertion kid must be a non-empty string' };
		const matches = jwks.filter((k) => k !== null && typeof k === 'object' && k.kid === kid);
		if (matches.length !== 1) return { error: 'assertion kid does not match exactly one registered key' };
		return { jwk: matches[0] };
	}
	if (jwks.length !== 1) {
		return { error: 'assertion kid is required when multiple keys are registered' };
	}
	const singleKey = jwks[0];
	if (singleKey === null || typeof singleKey !== 'object') {
		return { error: 'registered JWK is malformed' };
	}
	return { jwk: singleKey };
}

/**
 * Verify a client assertion end-to-end (structure → header → key → signature
 * → claims). Signature is checked before claims so a claims-shaped error can
 * never be probed without possession of the private key.
 */
export function verifyClientAssertion(params: VerifyClientAssertionParams): ClientAssertionResult {
	const { assertion, clientId, tokenEndpoint, jwks } = params;
	const maxExpiresIn = params.maxExpiresInSeconds ?? DEFAULT_MAX_EXPIRES_IN_SECONDS;
	const clockTolerance = params.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;

	if (typeof assertion !== 'string' || assertion.length === 0) {
		return fail('client_assertion is required');
	}
	if (assertion.length > MAX_ASSERTION_LENGTH) {
		return fail('client_assertion exceeds the maximum allowed length');
	}
	if (typeof clientId !== 'string' || clientId.length === 0) {
		return fail('client_id is required');
	}

	const segments = assertion.split('.');
	if (segments.length !== 3) {
		return fail('client_assertion is not a compact JWT');
	}
	const [headerSegment, payloadSegment, signatureSegment] = segments;

	const header = decodeSegment(headerSegment);
	if (!header) {
		return fail('client_assertion header is malformed');
	}
	// Exact-alg pinning: blocks `none` and any RS/HS/ES downgrade before key work.
	if (header.alg !== 'EdDSA') {
		return fail('client_assertion alg must be EdDSA');
	}
	// RFC 7515 §4.1.9: `typ` is optional; when present it must be JWT
	// (case-insensitive per its definition).
	if (header.typ !== undefined && (typeof header.typ !== 'string' || header.typ.toUpperCase() !== 'JWT')) {
		return fail('client_assertion typ must be JWT');
	}
	// RFC 7515 §4.1.11: `crit` demands the listed extensions be understood; we
	// implement none, so any `crit` fails closed.
	if (header.crit !== undefined) {
		return fail('client_assertion crit extensions are not supported');
	}

	const selected = selectKey(jwks, header.kid);
	if ('error' in selected) {
		return fail(selected.error);
	}
	const publicKey = loadEd25519PublicKey(selected.jwk);
	if (!publicKey) {
		return fail('registered JWK is not a public Ed25519 key');
	}

	if (!BASE64URL_PATTERN.test(signatureSegment)) {
		return fail('client_assertion signature is malformed');
	}
	const signature = Buffer.from(signatureSegment, 'base64url');
	if (signature.length !== ED25519_SIGNATURE_LENGTH) {
		return fail('client_assertion signature is malformed');
	}
	// Ed25519 verification takes no digest algorithm (pass null); the signing
	// input is the raw ASCII of "header.payload" (RFC 7515 §5.1).
	let signatureOk: boolean;
	try {
		signatureOk = verifySignature(null, Buffer.from(`${headerSegment}.${payloadSegment}`), publicKey, signature);
	} catch {
		signatureOk = false;
	}
	if (!signatureOk) {
		return fail('client_assertion signature verification failed');
	}

	const payload = decodeSegment(payloadSegment);
	if (!payload) {
		return fail('client_assertion payload is malformed');
	}

	// RFC 7523 §3: iss = sub = client_id, all bound to the authenticating client.
	if (payload.iss !== clientId) {
		return fail('client_assertion iss does not match client_id');
	}
	if (payload.sub !== clientId) {
		return fail('client_assertion sub does not match client_id');
	}

	// `aud` must be the token endpoint, exactly — a string or a single-element
	// array. Multiple audiences are rejected as ambiguous (design review: no
	// prefix/wildcard/multi-audience comparisons).
	const aud = Array.isArray(payload.aud) && payload.aud.length === 1 ? payload.aud[0] : payload.aud;
	if (typeof aud !== 'string' || aud !== tokenEndpoint) {
		return fail('client_assertion aud does not match the token endpoint');
	}

	const now = Math.floor(Date.now() / 1000);

	const exp = payload.exp;
	if (typeof exp !== 'number' || !Number.isFinite(exp)) {
		return fail('client_assertion exp is required');
	}
	if (exp <= now - clockTolerance) {
		return fail('client_assertion has expired');
	}
	if (exp > now + maxExpiresIn + clockTolerance) {
		return fail(`client_assertion exp exceeds the maximum window of ${maxExpiresIn}s`);
	}

	const iat = payload.iat;
	if (typeof iat !== 'number' || !Number.isFinite(iat)) {
		return fail('client_assertion iat is required');
	}
	if (iat > now + clockTolerance) {
		return fail('client_assertion iat is in the future');
	}

	if (payload.nbf !== undefined) {
		if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) {
			return fail('client_assertion nbf is invalid');
		}
		if (payload.nbf > now + clockTolerance) {
			return fail('client_assertion is not yet valid');
		}
	}

	const jti = payload.jti;
	if (typeof jti !== 'string' || jti.length === 0 || jti.length > MAX_JTI_LENGTH) {
		return fail('client_assertion jti is required');
	}

	return {
		valid: true,
		claims: { iss: clientId, sub: clientId, aud, exp, iat, jti },
	};
}
