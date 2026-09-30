/**
 * Client key-set validation for private_key_jwt (interactive CIMD clients).
 *
 * Pure helpers shared by CIMD document validation (inline `jwks`, the
 * `jwks_uri` origin policy) and the `jwks_uri` fetcher (fetched JWK Sets).
 * No I/O here.
 *
 * Key policy: only public signature keys are kept — RSA (2048-8192 bits),
 * EC P-256 and OKP Ed25519 — and only their key material is retained. A set
 * carrying any private or symmetric member is rejected outright (CIMD §4.1:
 * private key material MUST NOT appear). Keys marked for another use
 * (`use` ≠ sig) or of an unsupported type are skipped, not trusted.
 *
 * `jwks_uri` policy: https only, no userinfo, no fragment, no IP-literal
 * host, and on the client ID's exact origin unless the operator allowlists
 * another origin (`clientIdMetadataDocuments.privateKeyJwt.jwksUriAllowedOrigins`).
 */

import { isIP } from 'node:net';
import { publicSigningKeyIssue } from './clientAssertion.ts';

/** Most keys a client's set may hold; bounds selection and verification work. */
export const MAX_CLIENT_JWKS_KEYS = 16;
/** Upper bound on a `jwks_uri`, mirroring MAX_CLIENT_ID_LENGTH. */
const MAX_JWKS_URI_LENGTH = 2048;
/** JWK members retained in the cache: key material and selection metadata only. */
const RETAINED_JWK_MEMBERS = ['kty', 'kid', 'alg', 'use', 'key_ops', 'n', 'e', 'crv', 'x', 'y'];
/** Private or symmetric members: a set carrying any of them is refused. */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

function isIpLiteralHost(hostname: string): boolean {
	const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
	return isIP(bare) !== 0;
}

/**
 * Why `jwksUri` is not an acceptable key location for `clientId`, or null.
 * `allowedOrigins` holds exact, normalized origins (see config normalization).
 */
export function jwksUriIssue(
	jwksUri: unknown,
	clientId: string,
	allowedOrigins: readonly string[] = []
): string | null {
	if (typeof jwksUri !== 'string' || jwksUri.length === 0 || jwksUri.length > MAX_JWKS_URI_LENGTH) {
		return `jwks_uri must be a non-empty string of at most ${MAX_JWKS_URI_LENGTH} characters`;
	}
	if (!jwksUri.startsWith('https://')) return 'jwks_uri must use https';
	let url: URL;
	try {
		url = new URL(jwksUri);
	} catch {
		return 'jwks_uri is not a valid URL';
	}
	if (url.protocol !== 'https:') return 'jwks_uri must use https';
	if (url.username || url.password) return 'jwks_uri must not contain userinfo';
	if (url.hash) return 'jwks_uri must not contain a fragment';
	if (isIpLiteralHost(url.hostname)) return 'jwks_uri host must not be an IP literal';
	if (!isJwksUriOnClientOrigin(jwksUri, clientId) && !allowedOrigins.includes(url.origin)) {
		return 'jwks_uri must be on the client ID origin or an allowed origin';
	}
	return null;
}

/** True when `jwksUri` is on the client ID's exact origin (scheme, host, port). */
export function isJwksUriOnClientOrigin(jwksUri: string, clientId: string): boolean {
	try {
		return new URL(jwksUri).origin === new URL(clientId).origin;
	} catch {
		return false;
	}
}

/**
 * Validate a JWK Set document and return only the usable public keys' key
 * material, or the reason the set is unusable.
 */
export function publicKeySetFromDocument(doc: unknown): { keys: Record<string, unknown>[] } | { error: string } {
	if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { error: 'JWK Set must be a JSON object' };
	const keys = (doc as { keys?: unknown }).keys;
	if (!Array.isArray(keys)) return { error: 'JWK Set must contain a keys array' };
	if (keys.length === 0 || keys.length > MAX_CLIENT_JWKS_KEYS) {
		return { error: `JWK Set must hold between 1 and ${MAX_CLIENT_JWKS_KEYS} keys` };
	}
	const usable: Record<string, unknown>[] = [];
	for (const key of keys) {
		if (!key || typeof key !== 'object' || Array.isArray(key))
			return { error: 'every JWK Set entry must be an object' };
		const k = key as Record<string, unknown>;
		if (PRIVATE_JWK_MEMBERS.some((member) => member in k)) {
			return { error: 'JWK Set must contain only public keys (found private or symmetric key material)' };
		}
		// Keys for another use or of an unsupported type are never trusted for signatures.
		if (publicSigningKeyIssue(k) !== null) continue;
		const retained: Record<string, unknown> = {};
		for (const member of RETAINED_JWK_MEMBERS) {
			if (k[member] !== undefined) retained[member] = k[member];
		}
		usable.push(retained);
	}
	if (usable.length === 0) return { error: 'JWK Set holds no usable public signature key' };
	if (usable.length > 1) {
		const kids = usable.map((k) => k.kid);
		if (kids.some((kid) => kid === undefined)) {
			return { error: 'JWK Set keys must each have a kid when more than one signature key is present' };
		}
		if (new Set(kids).size !== kids.length) return { error: 'JWK Set keys must have unique kid values' };
	}
	return { keys: usable };
}
