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
 * Binding: when the interstitial is served, a random nonce is set as a cookie
 * and its SHA-256 hash is stored in the confirm token's `mcp` state. POST
 * /oauth/mcp/confirm requires the cookie to hash-match, and the hash is carried
 * through the upstream CSRF state so the OAuth callback re-checks the same
 * cookie before minting an MCP authorization code.
 *
 * Cookie hardening:
 * - `__Host-` prefix: the browser only accepts a `__Host-`-named cookie when it
 *   is `Secure`, `Path=/`, and has NO `Domain` — which means a sibling origin
 *   (evil.example.com attacking auth.example.com) CANNOT plant a parent-domain
 *   cookie to forge the binding. Plain `SameSite=Lax` does not stop that,
 *   because sibling subdomains are same-site. (RFC 6265bis §4.1.3.2.)
 * - Per-flow name: the cookie name embeds a random flow id (also carried in the
 *   confirm/upstream state), so concurrent authorization flows in the same
 *   browser (parallel tabs) don't overwrite each other's binding.
 * - `SameSite=Lax` keeps the cookie on the top-level redirect back from the
 *   IdP while excluding it from cross-site subresource/framed requests;
 *   `HttpOnly` keeps it out of script.
 *
 * Only the hash ever leaves the cookie: the state payload lives server-side in
 * the CSRF store, so a party that observes or replays state tokens still cannot
 * reconstruct the cookie value. Cookies expire via `Max-Age`; per-flow naming
 * makes explicit clearing unnecessary for correctness.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from '../../types.ts';

/** `__Host-` prefix + a per-flow id suffix. See module header for why. */
const CONSENT_COOKIE_PREFIX = '__Host-mcp_consent_';

/** Must comfortably outlast the interstitial pause plus the upstream IdP login. */
const CONSENT_COOKIE_MAX_AGE_S = 900;

/** Random, cookie-name-safe id identifying one authorization flow. */
export function generateConsentFlowId(): string {
	return randomBytes(16).toString('base64url');
}

export function generateConsentNonce(): string {
	return randomBytes(32).toString('base64url');
}

export function hashConsentNonce(nonce: string): string {
	return createHash('sha256').update(nonce).digest('base64url');
}

function cookieName(flowId: string): string {
	return CONSENT_COOKIE_PREFIX + flowId;
}

/**
 * Set-Cookie value pairing the interstitial page with its confirm token.
 * `__Host-` requires exactly `Secure` + `Path=/` + no `Domain`.
 */
export function buildConsentCookie(flowId: string, nonce: string): string {
	return `${cookieName(flowId)}=${nonce}; Max-Age=${CONSENT_COOKIE_MAX_AGE_S}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/**
 * Read this flow's consent nonce from the request's Cookie header, if present.
 *
 * Simple split parser, first name-match wins. Safe because both the name
 * suffix (flow id) and the value (nonce) are base64url — no `=`, `;`, quotes,
 * or spaces — and `__Host-` naming means a same-name cookie can only be set
 * by this origin over TLS at `Path=/` (one cookie per name+host+path in the
 * jar). Revisit the parser if the encoding ever changes.
 */
export function readConsentNonce(request: Request | undefined, flowId: string | undefined): string | undefined {
	if (!flowId) return undefined;
	const header = request?.headers?.cookie;
	if (typeof header !== 'string' || !header) return undefined;
	const name = cookieName(flowId);
	for (const part of header.split(';')) {
		const eq = part.indexOf('=');
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() === name) {
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
