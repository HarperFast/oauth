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
}

/**
 * Sign an access token. `iat`/`exp` are set from `ttlSeconds`, `jti` is a fresh
 * UUID, and registered claims are populated via jsonwebtoken's options so the
 * payload carries only `client_id` + `scope`.
 */
export function signAccessToken(params: MintAccessTokenParams, key: MCPSigningKeyRecord): string {
	const payload: Record<string, unknown> = { client_id: params.clientId };
	if (params.scope) payload.scope = params.scope;
	return jwt.sign(payload, key.private_key_pem, {
		algorithm: 'RS256',
		keyid: key.kid,
		issuer: params.issuer,
		audience: params.audience,
		subject: params.subject,
		jwtid: randomUUID(),
		expiresIn: params.ttlSeconds,
	});
}

export interface VerifyOptions {
	audience?: string;
	issuer?: string;
}

/**
 * Verify an access token against a public key. Primarily for tests; Stage 5
 * performs production verification against the published JWKS.
 */
export function verifyAccessToken(token: string, publicKeyPem: string, options?: VerifyOptions): jwt.JwtPayload {
	return jwt.verify(token, publicKeyPem, {
		algorithms: ['RS256'],
		audience: options?.audience,
		issuer: options?.issuer,
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
