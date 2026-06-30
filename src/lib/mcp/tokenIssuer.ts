/**
 * MCP Access-Token Issuer
 *
 * Mints and verifies RS256 JWT access tokens, and serializes public keys to
 * JWK form for the JWKS endpoint. Tokens are stateless and audience-bound
 * (RFC 8707 / RFC 9068-aligned): the `aud` claim carries the canonical MCP
 * resource URI, so Stage 5's `withMCPAuth` can reject tokens minted for a
 * different resource. No upstream IdP token is ever embedded.
 *
 * RS256 only in v1 — `jsonwebtoken` cannot emit EdDSA. EdDSA would require a
 * JOSE implementation and is deferred (see #86 follow-up).
 */

import { createPublicKey, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import type { MCPSigningKeyRecord } from '../../types.ts';

export interface MintAccessTokenParams {
	issuer: string;
	subject: string;
	/** Canonical resource URI — becomes the `aud` claim (RFC 8707). */
	audience: string;
	clientId: string;
	scope?: string;
	/** Access-token lifetime in seconds. */
	ttlSeconds: number;
	/**
	 * JWT ID (`jti` claim). Callers SHOULD generate this with `randomUUID()`
	 * before calling so they can capture it for audit/hook events without
	 * decoding the signed token. When omitted a fresh UUID is generated here.
	 */
	jti?: string;
}

/**
 * Sign an access token. `iat`/`exp` are set from `ttlSeconds`; `jti` is taken
 * from `params.jti` (or generated fresh when omitted). Registered claims are
 * populated via jsonwebtoken's options so the payload carries only
 * `client_id` + `scope`.
 *
 * Returns an object containing both the signed token string and the `jti`
 * so callers can use the id for audit records without re-parsing the JWT.
 */
export function signAccessToken(
	params: MintAccessTokenParams,
	key: MCPSigningKeyRecord
): { token: string; jti: string } {
	const jti = params.jti ?? randomUUID();
	const payload: Record<string, unknown> = { client_id: params.clientId };
	if (params.scope) payload.scope = params.scope;
	const token = jwt.sign(payload, key.private_key_pem, {
		algorithm: 'RS256',
		keyid: key.kid,
		issuer: params.issuer,
		audience: params.audience,
		subject: params.subject,
		jwtid: jti,
		expiresIn: params.ttlSeconds,
	});
	return { token, jti };
}

export interface VerifyOptions {
	audience?: string;
	issuer?: string;
}

/**
 * Verify an access token against a public key. Primarily for tests; Stage 5
 * performs production verification against the published JWKS via
 * {@link verifyAccessTokenWithKeySet}.
 */
export function verifyAccessToken(token: string, publicKeyPem: string, options?: VerifyOptions): jwt.JwtPayload {
	return jwt.verify(token, publicKeyPem, {
		algorithms: ['RS256'],
		audience: options?.audience,
		issuer: options?.issuer,
	}) as jwt.JwtPayload;
}

export interface VerifyWithKeySetOptions {
	/** Required `aud` claim — the canonical MCP resource URI (RFC 8707). */
	audience: string;
	/** Required `iss` claim — the authorization-server issuer. */
	issuer: string;
}

/**
 * Verify an access token against a set of published signing keys (the JWKS),
 * selecting the key by the token header's `kid`:
 *
 * - `kid` present → the matching key MUST exist; an unknown `kid` throws (never
 *   silently falls back to another key — that would let a token reference a
 *   retired/foreign key and still verify against a current one).
 * - `kid` absent → the sole key is used. Ambiguous (the set has >1 key) or an
 *   empty set throws.
 *
 * Signature is verified RS256-only (pinning `algorithms` blocks `alg: none`
 * and RS/HS confusion), and `audience` + `issuer` are enforced. Throws on any
 * failure so callers (withMCPAuth) can fail closed. This is the production
 * counterpart to {@link verifyAccessToken} and keeps all `jsonwebtoken` usage
 * inside this module.
 */
export function verifyAccessTokenWithKeySet(
	token: string,
	keys: MCPSigningKeyRecord[],
	options: VerifyWithKeySetOptions
): jwt.JwtPayload {
	if (!keys || keys.length === 0) {
		throw new Error('no signing keys available');
	}

	// Decode (without verifying) only to read the header's `kid` for key
	// selection. The signature is still verified below against the selected key.
	const decoded = jwt.decode(token, { complete: true });
	if (!decoded || typeof decoded === 'string') {
		throw new Error('malformed token');
	}

	const kid = decoded.header?.kid;
	let key: MCPSigningKeyRecord | undefined;
	if (kid) {
		key = keys.find((k) => k.kid === kid);
		if (!key) throw new Error('unknown key id');
	} else {
		if (keys.length !== 1) throw new Error('key id required to select among multiple keys');
		key = keys[0];
	}

	return jwt.verify(token, key.public_key_pem, {
		algorithms: ['RS256'],
		audience: options.audience,
		issuer: options.issuer,
	}) as jwt.JwtPayload;
}

/**
 * Serialize an RSA public key (PEM) to a JWK for publication at the JWKS
 * endpoint. Includes `use`, `alg`, and `kid` so verifiers can select the key.
 */
export function publicKeyToJwk(publicKeyPem: string, kid: string, alg = 'RS256'): Record<string, string> {
	const jwk = createPublicKey(publicKeyPem).export({ format: 'jwk' }) as { n: string; e: string };
	return {
		kty: 'RSA',
		n: jwk.n,
		e: jwk.e,
		alg,
		use: 'sig',
		kid,
	};
}
