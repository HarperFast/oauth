/**
 * OAuth browser binding — stable per-browser secret cookie.
 *
 * Binds the human login flow to the browser that initiated it, closing the
 * login-CSRF shape where an attacker-minted state+code is delivered to a
 * victim's browser to silently log them in as the attacker.  Session binding
 * (the #185 fix) only covers flows started while already logged in because
 * Harper 4.7.29 gives logged-out requests no session id; this module closes
 * the gap for the primary login path.
 *
 * Mechanism: on login initiation, read or generate one stable
 * `__Host-oauth_browser` cookie.  Its SHA-256 hash is stored server-side in
 * the CSRF state (`browserNonceHash`).  The callback re-reads the cookie and
 * constant-time-checks the hash before any upstream code exchange.  Only the
 * hash leaves the server; the cookie value never appears in state.
 *
 * `__Host-` cookie hardening: accepted only when `Secure` + `Path=/` + no
 * `Domain` — a sibling origin cannot plant a parent-domain cookie to forge the
 * binding (RFC 6265bis §4.1.3.2).  Requires HTTPS in production; the same
 * trade-off applies to all __Host- cookies.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from '../types.ts';

export const BROWSER_SECRET_COOKIE_NAME = '__Host-oauth_browser';

/** Rolling 7-day lifetime; refreshed on every flow initiation. */
const BROWSER_SECRET_MAX_AGE_S = 7 * 24 * 60 * 60;

/** Generate a cryptographically random browser secret. */
export function generateBrowserSecret(): string {
	return randomBytes(32).toString('base64url');
}

/** SHA-256 (base64url) of the browser secret.  Only the hash is stored server-side. */
export function hashBrowserSecret(secret: string): string {
	return createHash('sha256').update(secret).digest('base64url');
}

/**
 * Build the `Set-Cookie` value for the stable browser secret.
 * `__Host-` requires `Secure` + `Path=/` + no `Domain`.
 * Call on every flow initiation to refresh the rolling Max-Age.
 */
export function buildBrowserSecretCookie(secret: string): string {
	return `${BROWSER_SECRET_COOKIE_NAME}=${secret}; Max-Age=${BROWSER_SECRET_MAX_AGE_S}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/**
 * Read the Cookie header from a Harper 4 request.
 *
 * Harper 4 exposes `request.headers` as a custom Headers object with `.get()`.
 * HTTP/2 crumbling (and transports that preserve repeated header fields as an
 * array) can split Cookie across multiple values — join all crumbs so the
 * binding cookie is found regardless of which crumb carries it.
 * Tests pass a plain object with a `.cookie` property.  Handle both.
 */
function readCookieHeader(request: Request | undefined): string | undefined {
	const headers = request?.headers as any;
	if (!headers) return undefined;
	// Harper 4 runtime: Headers object with .get()
	if (typeof headers.get === 'function') {
		const raw = headers.get('cookie');
		if (raw == null) return undefined;
		return Array.isArray(raw) ? raw.join('; ') : String(raw);
	}
	// Test doubles: plain object
	const raw = headers.cookie;
	if (raw == null) return undefined;
	return Array.isArray(raw) ? raw.join('; ') : String(raw);
}

/**
 * Read the browser secret from the request's Cookie header.
 *
 * Simple split parser, first name-match wins.  Safe because the cookie name
 * is a fixed constant and the value is base64url (no `=`, `;`, quotes, or
 * spaces inside the value itself).
 */
export function readBrowserSecret(request: Request | undefined): string | undefined {
	const header = readCookieHeader(request);
	if (typeof header !== 'string' || !header) return undefined;
	for (const part of header.split(';')) {
		const eq = part.indexOf('=');
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() === BROWSER_SECRET_COOKIE_NAME) {
			const value = part.slice(eq + 1).trim();
			return /^[A-Za-z0-9_-]{1,64}$/.test(value) ? value : undefined;
		}
	}
	return undefined;
}

/** Constant-time check that `secret` hashes to `expectedHash`. */
export function browserSecretMatches(secret: string | undefined, expectedHash: string | undefined): boolean {
	if (typeof secret !== 'string' || typeof expectedHash !== 'string' || !secret || !expectedHash) return false;
	const actual = Buffer.from(hashBrowserSecret(secret));
	const expected = Buffer.from(expectedHash);
	return actual.length === expected.length && timingSafeEqual(actual, expected);
}
