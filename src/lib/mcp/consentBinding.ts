/**
 * CIMD consent browser binding
 *
 * The consent interstitial (#166) is only meaningful if the browser that
 * approves it is the browser the upstream authorization completes in. Without
 * a binding, a malicious CIMD client can fetch the interstitial itself,
 * confirm it, and hand the victim the resulting upstream IdP URL — the victim
 * never sees the client identity or redirect-host disclosure but an existing
 * IdP session still produces an authorization code at the attacker's
 * redirect_uri.
 *
 * Binding: when the interstitial is served, a random nonce is set as an
 * HttpOnly cookie and its SHA-256 hash is stored in the confirm token's
 * `mcp` state. POST /oauth/mcp/confirm requires the cookie to hash-match, and
 * the hash is carried through the upstream CSRF state so the OAuth callback
 * re-checks the same cookie before minting an MCP authorization code.
 * SameSite=Lax keeps the cookie on the top-level redirect back from the IdP
 * while excluding it from cross-site subresource/framed requests.
 *
 * Only the hash ever leaves the cookie: the state payload lives server-side
 * in the CSRF store, so a party that observes or replays state tokens still
 * cannot reconstruct the cookie value.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from '../../types.ts';

export const CONSENT_COOKIE_NAME = 'mcp_consent';

/** Must comfortably outlast the interstitial pause plus the upstream IdP login. */
const CONSENT_COOKIE_MAX_AGE_S = 900;

export function generateConsentNonce(): string {
	return randomBytes(32).toString('base64url');
}

export function hashConsentNonce(nonce: string): string {
	return createHash('sha256').update(nonce).digest('base64url');
}

/** Set-Cookie value pairing the interstitial page with its confirm token. */
export function buildConsentCookie(nonce: string): string {
	return `${CONSENT_COOKIE_NAME}=${nonce}; Max-Age=${CONSENT_COOKIE_MAX_AGE_S}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/** Read the consent nonce from the request's Cookie header, if present. */
export function readConsentNonce(request: Request | undefined): string | undefined {
	const header = request?.headers?.cookie;
	if (typeof header !== 'string' || !header) return undefined;
	for (const part of header.split(';')) {
		const eq = part.indexOf('=');
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() === CONSENT_COOKIE_NAME) {
			return part.slice(eq + 1).trim();
		}
	}
	return undefined;
}

/** Constant-time check that `nonce` hashes to `expectedHash`. */
export function consentNonceMatches(nonce: string | undefined, expectedHash: string | undefined): boolean {
	if (!nonce || !expectedHash) return false;
	const actual = Buffer.from(hashConsentNonce(nonce));
	const expected = Buffer.from(expectedHash);
	return actual.length === expected.length && timingSafeEqual(actual, expected);
}
