/**
 * ChatGPT token-request fixtures in the shape of a recorded exchange.
 *
 * ChatGPT's code exchange and refreshes were recorded against a test
 * authorization server that advertised both `none` and `private_key_jwt`.
 * These fixtures keep the recorded protocol shape and none of the recorded
 * credentials: assertions are signed here with a freshly generated TEST key,
 * JTIs are fresh, and timestamps are rebased to the test clock.
 *
 * Recorded shape:
 * - RS256 with a 2048-bit RSA key; header `typ: "JWT"` and the key's `kid`.
 * - `iss` = `sub` = the stable client ID; `aud` a single string, the token
 *   endpoint URL; `exp` = `iat` + 60 and `nbf` = `iat`; a UUID `jti`; no other
 *   claims.
 * - Code exchange form: the assertion pair, `client_id`, `grant_type`,
 *   `resource`, `code`, `code_verifier`, `redirect_uri`.
 * - Refresh form: the assertion pair, `client_id`, `grant_type`, `resource`,
 *   `refresh_token`.
 * - No Authorization header.
 * - Where the server advertised only `none`, the same forms without the
 *   assertion pair.
 * - Four refreshes followed the code exchange, 0.826, 3.566, 5.418 and 6.612
 *   seconds after it, each with a new assertion.
 */

import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { CHATGPT_CIMD_DOCUMENT, CHATGPT_CLIENT_ID, CHATGPT_REDIRECT_URI } from './cimdFixtures.js';

export { CHATGPT_CIMD_DOCUMENT, CHATGPT_CLIENT_ID, CHATGPT_REDIRECT_URI };

/** The document's same-origin key location. */
export const CHATGPT_JWKS_URI = CHATGPT_CIMD_DOCUMENT.jwks_uri;

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** Recorded assertion lifetime (`exp` - `iat`), in seconds. */
export const CAPTURE_ASSERTION_LIFETIME_SECONDS = 60;

/** Recorded refresh times, in milliseconds after the code exchange. */
export const CAPTURE_REFRESH_OFFSETS_MS = Object.freeze([826, 3566, 5418, 6612]);

/**
 * A TEST signing key in the recorded shape: RSA 2048, published as a JWK with
 * `kid`, `alg: RS256` and `use: sig`.
 */
export function createCaptureSigner({ kid = 'test-rs256-2048' } = {}) {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
	const publicJwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
	return { kid, privateKey, publicJwk, jwks: { keys: [publicJwk] } };
}

function b64url(value) {
	return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/**
 * A client assertion in the recorded shape, signed with `signer`.
 * `audience` is the single-string `aud` (the token endpoint URL in the
 * recording; pass the issuer for the issuer-audience variant). `nowMs` is the
 * test clock. `claims` and `header` override recorded values, for negative
 * cases only.
 */
export function captureAssertion(
	signer,
	{ audience, nowMs = Date.now(), jti = randomUUID(), clientId = CHATGPT_CLIENT_ID, claims = {}, header = {} }
) {
	if (typeof audience !== 'string') throw new TypeError('captureAssertion needs a single-string audience');
	const iat = Math.floor(nowMs / 1000);
	const h = b64url({ alg: 'RS256', kid: signer.kid, typ: 'JWT', ...header });
	const p = b64url({
		aud: audience,
		exp: iat + CAPTURE_ASSERTION_LIFETIME_SECONDS,
		iat,
		iss: clientId,
		jti,
		nbf: iat,
		sub: clientId,
		...claims,
	});
	const signature = sign('sha256', Buffer.from(`${h}.${p}`), signer.privateKey).toString('base64url');
	return `${h}.${p}.${signature}`;
}

function withAssertion(form, assertion) {
	if (assertion === undefined) return form;
	return { client_assertion: assertion, client_assertion_type: CLIENT_ASSERTION_TYPE, ...form };
}

/**
 * The recorded code-exchange form. Without `assertion`, the none-only
 * variant: the same form without the assertion pair.
 */
export function captureCodeForm({
	assertion,
	resource,
	code,
	codeVerifier,
	redirectUri = CHATGPT_REDIRECT_URI,
	clientId = CHATGPT_CLIENT_ID,
}) {
	return withAssertion(
		{
			client_id: clientId,
			code,
			code_verifier: codeVerifier,
			grant_type: 'authorization_code',
			redirect_uri: redirectUri,
			resource,
		},
		assertion
	);
}

/**
 * The recorded refresh form. Without `assertion`, the none-only variant.
 */
export function captureRefreshForm({ assertion, resource, refreshToken, clientId = CHATGPT_CLIENT_ID }) {
	return withAssertion(
		{
			client_id: clientId,
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			resource,
		},
		assertion
	);
}

/** The recorded request carried no Authorization header. */
export const CAPTURE_REQUEST_HEADERS = Object.freeze({});
