/**
 * OAuth browser binding via a stable per-browser secret cookie.
 *
 * Every browser-initiated OAuth flow — human login and all MCP authorize paths
 * — binds to the browser that started it, closing login-CSRF /
 * authorization-code-injection attacks where an attacker-initiated flow is
 * completed in a victim's browser.
 *
 * Binding: when a flow is initiated, this module reads (or generates) a single
 * stable `__Host-oauth_browser` cookie. The SHA-256 hash of the secret is
 * stored in the server-side flow state (CSRF token or confirm token); the
 * callback/confirm step re-reads the cookie and constant-time-checks the hash.
 * Only the hash leaves this server; the cookie value never appears in state.
 *
 * Single stable cookie design (resolves issue #205 — per-flow cookie exhaustion):
 * - Each browser carries ONE `__Host-oauth_browser` cookie across all flows.
 *   Parallel tabs share it (same browser — the property we bind on).
 * - The secret is generated once and reused; Max-Age is refreshed on every
 *   flow initiation so active browsers never hit silent expiry.
 * - Abandoned flows leave only server-side CSRF rows, which Harper's built-in
 *   table expiration already reaps — no per-flow cookie, no accumulation.
 *
 * Cookie hardening:
 * - `__Host-` prefix: only accepted when `Secure`, `Path=/`, no `Domain` —
 *   a sibling origin cannot plant a parent-domain cookie to forge the binding
 *   (RFC 6265bis §4.1.3.2).
 * - `HttpOnly` keeps it out of script.
 * - `SameSite=Lax` sends the cookie on the top-level redirect back from the
 *   upstream IdP while excluding cross-site subresource/framed requests.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readRawHeader } from '../requestHeaders.ts';
import type { Request } from '../../types.ts';

export const BROWSER_SECRET_COOKIE_NAME = '__Host-oauth_browser';

/**
 * Rolling 7-day lifetime: refreshed on every flow initiation so an active
 * browser never hits silent expiry. An inactive browser's cookie expires
 * naturally and a new secret is generated on the next flow.
 */
const BROWSER_SECRET_MAX_AGE_S = 7 * 24 * 60 * 60;

/** Generate a new cryptographically random browser secret. */
export function generateBrowserSecret(): string {
	return randomBytes(32).toString('base64url');
}

/** SHA-256 (base64url) of the browser secret. Only the hash is stored server-side. */
export function hashBrowserSecret(secret: string): string {
	return createHash('sha256').update(secret).digest('base64url');
}

/**
 * Build the `Set-Cookie` value for the stable browser secret.
 * `__Host-` requires exactly `Secure` + `Path=/` + no `Domain`.
 * Always call this on every flow initiation to refresh the rolling Max-Age.
 */
export function buildBrowserSecretCookie(secret: string): string {
	return `${BROWSER_SECRET_COOKIE_NAME}=${secret}; Max-Age=${BROWSER_SECRET_MAX_AGE_S}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/**
 * Read the browser secret from the request's Cookie header.
 *
 * Simple split parser, first name-match wins. Safe because the cookie name is
 * a fixed constant and the value is base64url — no `=`, `;`, quotes, or
 * spaces — and `__Host-` naming means a same-name cookie can only be set by
 * this origin over TLS at `Path=/`. Revisit the parser if the encoding changes.
 */
export function readBrowserSecret(request: Request | undefined): string | undefined {
	const header = readCookieHeader(request);
	if (typeof header !== 'string' || !header) return undefined;
	for (const part of header.split(';')) {
		const eq = part.indexOf('=');
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() === BROWSER_SECRET_COOKIE_NAME) {
			return part.slice(eq + 1).trim() || undefined;
		}
	}
	return undefined;
}

/**
 * Read the raw `Cookie` header, wrapper-aware (`getRequestHeader`'s three shapes)
 * — reading `request.headers.cookie` directly is undefined against Harper's live
 * runtime wrapper, which would fail the binding check closed for every browser
 * flow.
 *
 * Unlike `getRequestHeader` (first value only), repeated `Cookie` lines must ALL
 * be parsed: HTTP/2 cookie crumbling — and transports that preserve repeated
 * header fields as an array — can put the binding cookie in a non-first crumb.
 * Join array crumbs with `"; "` so the parser sees every cookie; dropping the
 * tail would reject valid callbacks with a binding mismatch.
 */
function readCookieHeader(request: Request | undefined): string | undefined {
	const raw = readRawHeader(request?.headers, 'cookie');
	if (raw == null) return undefined;
	return Array.isArray(raw) ? raw.join('; ') : String(raw);
}

/** Constant-time check that `secret` hashes to `expectedHash`. */
export function browserSecretMatches(secret: string | undefined, expectedHash: string | undefined): boolean {
	if (!secret || !expectedHash) return false;
	const actual = Buffer.from(hashBrowserSecret(secret));
	const expected = Buffer.from(expectedHash);
	return actual.length === expected.length && timingSafeEqual(actual, expected);
}
