/**
 * RFC 7523 §3 Client-Assertion Verification (private_key_jwt)
 *
 * Verifies the `client_assertion` JWT a client presents to the token endpoint:
 * headless agents on the client_credentials grant (#159/#160) and, with
 * `private_key_jwt` permitted, interactive CIMD clients on the
 * authorization_code and refresh_token grants. Verified with `node:crypto` —
 * no new dependency. Everything fails closed: any parse, header, key,
 * signature, or claim problem yields `{ valid: false, reason }`, never a
 * throw, so callers can map it straight to an OAuth `invalid_client` error and
 * an audit reason. Reasons never contain the assertion or key material.
 *
 * Verification contract:
 * - header `alg` is one of the algorithms the CALLER allows for this client
 *   (RS256, ES256, EdDSA; the headless path allows EdDSA only). `none` and
 *   `HS*` are never accepted. The selected key's type — and its JWK `alg`,
 *   when present — must match the header `alg` (RFC 8725 §3.1: one key, one
 *   algorithm).
 * - `typ`, when present, is `JWT` or `client-authentication+jwt`
 *   (RFC 7523bis §4; an optional `application/` prefix is tolerated); any
 *   other explicit type is rejected. `crit` is rejected (no extensions).
 * - header `jku`, `jwk`, `x5u` and `x5c` are rejected: keys come only from the
 *   client's registered set, never from the assertion.
 * - key selected from the client's registered JWK Set: `kid` present → must
 *   match exactly one registered key; `kid` absent → the set must hold exactly
 *   one key. Keys must be public (no private or symmetric members), `use` sig
 *   when present, RSA keys at least 2048 bits, EC keys on P-256, OKP keys
 *   Ed25519.
 * - `iss` = `sub` = the authenticating client_id (all three, exactly).
 * - `aud` exactly equals one of the caller's accepted audience values — a
 *   string, or a single-element array (RFC 7519 allows an array; more than one
 *   audience is rejected as ambiguous). The matched form is reported.
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

/** RFC 7523bis §4 explicit type for client-authentication JWTs. */
export const CLIENT_AUTHENTICATION_JWT_TYPE = 'client-authentication+jwt';

/** Signature algorithms a client assertion may use (subject to per-client policy). */
export type AssertionAlgorithm = 'RS256' | 'ES256' | 'EdDSA';
export const ASSERTION_ALGORITHMS: readonly AssertionAlgorithm[] = ['RS256', 'ES256', 'EdDSA'];

/** How an accepted `aud` value was matched — recorded by callers, never the assertion itself. */
export type AudienceForm = 'issuer' | 'token_endpoint';

/** One accepted audience value and the form it represents. Compared by exact string equality. */
export interface AcceptedAudience {
	value: string;
	form: AudienceForm;
}

const DEFAULT_MAX_EXPIRES_IN_SECONDS = 60;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 5;
/** Bound what a client can force into the replay table. */
const MAX_JTI_LENGTH = 256;
/**
 * Cap on the whole compact JWT before any split/decode work — a legitimate
 * assertion with our claim set (even with an RSA-4096 signature) is well
 * under 2KB, so 8KB is generous. Same defense-in-depth family as the repo's
 * 2048-char request-path cap.
 */
const MAX_ASSERTION_LENGTH = 8192;
/** Ed25519 signatures are always exactly 64 bytes (RFC 8032); ES256 JWS signatures are r||s, 64 bytes (RFC 7518 §3.4). */
const FIXED_SIGNATURE_LENGTH: Partial<Record<AssertionAlgorithm, number>> = { EdDSA: 64, ES256: 64 };
/** RFC 7518 §3.3: RSA keys used with RS256 must be at least 2048 bits. */
export const MIN_RSA_MODULUS_BITS = 2048;
/** Upper bound on RSA key size — bounds verification cost for attacker-supplied keys. */
const MAX_RSA_MODULUS_BITS = 8192;
/** Private or symmetric JWK members: a key carrying any of them is never usable. */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
/** Header parameters that carry or point at keys; never trusted (keys come only from the registered set). */
const KEY_BEARING_HEADER_PARAMETERS = ['jku', 'jwk', 'x5u', 'x5c'];

/**
 * Strict base64url alphabet (RFC 4648 §5, unpadded). `Buffer.from(s,
 * 'base64url')` silently skips invalid characters, which would let two
 * distinct token strings decode to the same payload — validate first.
 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/** Human-readable key family per algorithm, used in rejection reasons. */
const KEY_FAMILY: Record<AssertionAlgorithm, string> = { RS256: 'RSA', ES256: 'EC P-256', EdDSA: 'Ed25519' };

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

export type ClientAssertionResult =
	| {
			valid: true;
			claims: ClientAssertionClaims;
			/** Which accepted audience matched. */
			audienceForm: AudienceForm;
			/** The verified header algorithm. */
			alg: AssertionAlgorithm;
	  }
	| { valid: false; reason: string; unknownKid?: boolean };

export interface VerifyClientAssertionParams {
	/** The `client_assertion` value — a compact-serialized JWT. */
	assertion: string;
	/** The client_id being authenticated; must equal `iss` and `sub`. */
	clientId: string;
	/**
	 * Accepted `aud` values. When omitted, `tokenEndpoint` is the sole accepted
	 * value (the original headless contract).
	 */
	audiences?: AcceptedAudience[];
	/** Resolved token-endpoint URL; the sole accepted `aud` when `audiences` is omitted. */
	tokenEndpoint?: string;
	/** The client's registered public JWK Set keys. */
	jwks: Record<string, unknown>[];
	/**
	 * Algorithms this client may use: the policy for its shape, narrowed to its
	 * document's `token_endpoint_auth_signing_alg` when present. Default: EdDSA
	 * only (the headless contract).
	 */
	allowedAlgorithms?: readonly AssertionAlgorithm[];
	/** Maximum allowed `exp - now`. Default 60. */
	maxExpiresInSeconds?: number;
	/** Clock-skew allowance for `exp`/`iat`/`nbf`. Default 5. */
	clockToleranceSeconds?: number;
}

function fail(reason: string, extra?: { unknownKid?: boolean }): ClientAssertionResult {
	return extra?.unknownKid ? { valid: false, reason, unknownKid: true } : { valid: false, reason };
}

/**
 * Normalize a window option (seconds) to a safe finite number, falling back to
 * the conservative default on anything non-finite. These options are the
 * enforcement boundary for the RFC 7523 §3 validity-window checks, and the
 * comparisons below fail OPEN on `NaN`/`Infinity` (e.g. `exp > now + NaN` is
 * always false, so a far-future `exp` would be accepted). Callers may wire
 * these from config, where `${ENV}`/quoted-YAML can deliver a string or
 * garbage — so coerce here, mirroring token.ts's `coerceTtl`. `allowZero`
 * distinguishes the tolerance (0 is a valid "no skew") from the max window
 * (0 would be a nonsensical always-reject, treated as misconfig → default).
 */
function coerceWindowSeconds(value: unknown, fallback: number, allowZero: boolean): number {
	const n = typeof value === 'number' ? value : Number(value);
	if (!Number.isFinite(n) || n < 0 || (n === 0 && !allowZero)) return fallback;
	return n;
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

/** The algorithm a JWK's key type implies, or null for unsupported key types. */
export function algorithmForKeyType(jwk: Record<string, unknown>): AssertionAlgorithm | null {
	if (jwk.kty === 'RSA') return 'RS256';
	if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
	if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
	return null;
}

function isBase64urlString(value: unknown): value is string {
	return typeof value === 'string' && BASE64URL_PATTERN.test(value);
}

/** Import the public key for `alg` from its JWK members only (never the whole object). Null on any problem. */
function importPublicKey(jwk: Record<string, unknown>, alg: AssertionAlgorithm): KeyObject | null {
	try {
		if (alg === 'RS256') {
			if (!isBase64urlString(jwk.n) || !isBase64urlString(jwk.e)) return null;
			const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
			const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
			if (key.asymmetricKeyType !== 'rsa' || bits < MIN_RSA_MODULUS_BITS || bits > MAX_RSA_MODULUS_BITS) return null;
			return key;
		}
		if (alg === 'ES256') {
			if (!isBase64urlString(jwk.x) || !isBase64urlString(jwk.y)) return null;
			const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
			if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return null;
			return key;
		}
		if (!isBase64urlString(jwk.x) || jwk.x.length !== 43) return null;
		const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
		return key.asymmetricKeyType === 'ed25519' ? key : null;
	} catch {
		return null;
	}
}

/**
 * Why a JWK cannot serve as a public signature-verification key, or null when
 * it can. Shared by the verifier (defense in depth) and by key-set validation
 * for inline `jwks` and fetched `jwks_uri` documents.
 */
export function publicSigningKeyIssue(jwk: unknown): string | null {
	if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return 'key must be a JWK object';
	const k = jwk as Record<string, unknown>;
	for (const member of PRIVATE_JWK_MEMBERS) {
		if (member in k) return 'key carries private or symmetric key material';
	}
	if (k.use !== undefined && k.use !== 'sig') return 'key use must be sig';
	if (k.key_ops !== undefined && (!Array.isArray(k.key_ops) || !k.key_ops.includes('verify'))) {
		return 'key_ops must include verify';
	}
	if (k.kid !== undefined && (typeof k.kid !== 'string' || k.kid.length === 0 || k.kid.length > 256)) {
		return 'kid must be a non-empty string of at most 256 characters';
	}
	const alg = algorithmForKeyType(k);
	if (!alg) return 'key type is not supported (RSA, EC P-256 or OKP Ed25519)';
	if (k.alg !== undefined && k.alg !== alg) return `key alg must be ${alg} for its key type`;
	if (!importPublicKey(k, alg)) {
		return alg === 'RS256'
			? `key material is malformed or the RSA modulus is outside ${MIN_RSA_MODULUS_BITS}-${MAX_RSA_MODULUS_BITS} bits`
			: 'key material is malformed';
	}
	return null;
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
): { jwk: Record<string, unknown> } | { error: string; unknownKid?: boolean } {
	if (!Array.isArray(jwks) || jwks.length === 0) {
		return { error: 'client has no registered JWKs' };
	}
	// Registration should never store non-object entries, but this module
	// promises "never throws" — so a null/primitive element must fail the
	// lookup, not TypeError inside it.
	if (kid !== undefined) {
		if (typeof kid !== 'string' || kid.length === 0) return { error: 'assertion kid must be a non-empty string' };
		const matches = jwks.filter((k) => k !== null && typeof k === 'object' && k.kid === kid);
		if (matches.length === 0) {
			return { error: 'assertion kid does not match exactly one registered key', unknownKid: true };
		}
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

/** `typ` policy: absent, `JWT`, or `client-authentication+jwt` (case-insensitive, optional `application/`). */
function typAccepted(typ: unknown): boolean {
	if (typ === undefined) return true;
	if (typeof typ !== 'string') return false;
	const normalized = typ.toLowerCase().replace(/^application\//, '');
	return normalized === 'jwt' || normalized === CLIENT_AUTHENTICATION_JWT_TYPE;
}

function verifyWithKey(alg: AssertionAlgorithm, signingInput: Buffer, key: KeyObject, signature: Buffer): boolean {
	try {
		if (alg === 'EdDSA') return verifySignature(null, signingInput, key, signature);
		if (alg === 'ES256') return verifySignature('sha256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature);
		return verifySignature('sha256', signingInput, key, signature);
	} catch {
		return false;
	}
}

/**
 * Verify a client assertion end-to-end (structure → header → key → signature
 * → claims). Signature is checked before claims so a claims-shaped error can
 * never be probed without possession of the private key.
 */
export function verifyClientAssertion(params: VerifyClientAssertionParams): ClientAssertionResult {
	const { assertion, clientId, jwks } = params;
	// Coerce the window options up front — a NaN/Infinity here would make the
	// time-window comparisons fail open (see coerceWindowSeconds).
	const maxExpiresIn = coerceWindowSeconds(params.maxExpiresInSeconds, DEFAULT_MAX_EXPIRES_IN_SECONDS, false);
	const clockTolerance = coerceWindowSeconds(params.clockToleranceSeconds, DEFAULT_CLOCK_TOLERANCE_SECONDS, true);
	const allowedAlgorithms = (params.allowedAlgorithms ?? ['EdDSA']).filter((a) => ASSERTION_ALGORITHMS.includes(a));
	const audiences: AcceptedAudience[] =
		params.audiences ??
		(typeof params.tokenEndpoint === 'string' ? [{ value: params.tokenEndpoint, form: 'token_endpoint' }] : []);

	if (typeof assertion !== 'string' || assertion.length === 0) {
		return fail('client_assertion is required');
	}
	if (assertion.length > MAX_ASSERTION_LENGTH) {
		return fail('client_assertion exceeds the maximum allowed length');
	}
	if (typeof clientId !== 'string' || clientId.length === 0) {
		return fail('client_id is required');
	}
	if (allowedAlgorithms.length === 0) {
		return fail('no client_assertion algorithm is permitted for this client');
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
	// Exact-alg allowlist: blocks `none`, HS* and any algorithm this client may
	// not use before any key work.
	if (typeof header.alg !== 'string' || !allowedAlgorithms.includes(header.alg as AssertionAlgorithm)) {
		return fail(`client_assertion alg must be ${allowedAlgorithms.join(' or ')}`);
	}
	const alg = header.alg as AssertionAlgorithm;
	if (!typAccepted(header.typ)) {
		return fail(`client_assertion typ must be JWT or ${CLIENT_AUTHENTICATION_JWT_TYPE}`);
	}
	// RFC 7515 §4.1.11: `crit` demands the listed extensions be understood; we
	// implement none, so any `crit` fails closed.
	if (header.crit !== undefined) {
		return fail('client_assertion crit extensions are not supported');
	}
	// Keys come only from the client's registered set, never from the assertion.
	for (const parameter of KEY_BEARING_HEADER_PARAMETERS) {
		if (header[parameter] !== undefined) {
			return fail(`client_assertion header parameter ${parameter} is not accepted`);
		}
	}

	const selected = selectKey(jwks, header.kid);
	if ('error' in selected) {
		return fail(selected.error, { unknownKid: selected.unknownKid });
	}
	const keyIssue = publicSigningKeyIssue(selected.jwk);
	if (keyIssue) {
		return fail(`registered JWK is not a public ${KEY_FAMILY[alg]} key: ${keyIssue}`);
	}
	// One key, one algorithm (RFC 8725 §3.1): the key's type must imply the header alg.
	if (algorithmForKeyType(selected.jwk) !== alg) {
		return fail(`registered JWK is not a public ${KEY_FAMILY[alg]} key`);
	}
	const publicKey = importPublicKey(selected.jwk, alg);
	if (!publicKey) {
		return fail(`registered JWK is not a public ${KEY_FAMILY[alg]} key`);
	}

	if (!BASE64URL_PATTERN.test(signatureSegment)) {
		return fail('client_assertion signature is malformed');
	}
	const signature = Buffer.from(signatureSegment, 'base64url');
	const expectedLength = FIXED_SIGNATURE_LENGTH[alg] ?? (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) / 8;
	if (signature.length !== expectedLength) {
		return fail('client_assertion signature is malformed');
	}
	// The signing input is the raw ASCII of "header.payload" (RFC 7515 §5.1).
	if (!verifyWithKey(alg, Buffer.from(`${headerSegment}.${payloadSegment}`), publicKey, signature)) {
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

	// `aud` must exactly equal one accepted value — a string or a
	// single-element array. Multiple audiences are rejected as ambiguous (no
	// prefix/wildcard/multi-audience comparisons).
	const aud = Array.isArray(payload.aud) && payload.aud.length === 1 ? payload.aud[0] : payload.aud;
	const matchedAudience = typeof aud === 'string' ? audiences.find((a) => a.value === aud) : undefined;
	if (!matchedAudience) {
		return fail('client_assertion aud does not match an accepted audience');
	}

	const now = Math.floor(Date.now() / 1000);

	const exp = payload.exp;
	if (typeof exp !== 'number' || !Number.isFinite(exp)) {
		return fail('client_assertion exp is required');
	}
	if (exp <= now - clockTolerance) {
		return fail('client_assertion has expired');
	}
	// Primary window bound: `exp` is capped relative to NOW, so any single
	// assertion is usable for at most ~maxExpiresIn seconds of wall-clock
	// regardless of what `iat` claims — a far-future `exp` is rejected here.
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
	// A non-positive lifetime is malformed — expired-at-issuance tokens are
	// already unusable via the now-relative bound above; reject them as
	// structurally invalid rather than letting them ride the tolerance window.
	if (exp <= iat) {
		return fail('client_assertion lifetime (exp - iat) must be positive');
	}
	// Strictness bound (defense-in-depth): reject an assertion whose self-declared
	// lifetime (exp - iat) exceeds the policy window even when `exp` sits inside
	// the now-relative bound above.
	if (exp - iat > maxExpiresIn + clockTolerance) {
		return fail(`client_assertion lifetime (exp - iat) exceeds the maximum window of ${maxExpiresIn}s`);
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
	if (typeof jti !== 'string' || jti.length === 0) {
		return fail('client_assertion jti is required');
	}
	if (jti.length > MAX_JTI_LENGTH) {
		return fail('client_assertion jti exceeds the maximum length');
	}

	return {
		valid: true,
		claims: { iss: clientId, sub: clientId, aud: matchedAudience.value, exp, iat, jti },
		audienceForm: matchedAudience.form,
		alg,
	};
}
