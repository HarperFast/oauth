/**
 * Browser binding via stable per-browser `__Host-oauth_browser` cookie.
 *
 * Stores a SHA-256 hash of the cookie in the CSRF state; verified constant-time
 * at callback before any code exchange.  Only the hash leaves the server.
 * `__Host-` requires `Secure` + `Path=/` + no `Domain` (HTTPS only).
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from '../types.ts';

export const BROWSER_SECRET_COOKIE_NAME = '__Host-oauth_browser';

/** Rolling 7-day lifetime; refreshed on every flow initiation. */
const BROWSER_SECRET_MAX_AGE_S = 7 * 24 * 60 * 60;

export function generateBrowserSecret(): string {
	return randomBytes(32).toString('base64url');
}

/** SHA-256 (base64url) of the browser secret.  Only the hash is stored server-side. */
export function hashBrowserSecret(secret: string): string {
	return createHash('sha256').update(secret).digest('base64url');
}

/** Build Set-Cookie value; `__Host-` requires `Secure` + `Path=/` + no `Domain`. Refreshes Max-Age. */
export function buildBrowserSecretCookie(secret: string): string {
	return `${BROWSER_SECRET_COOKIE_NAME}=${secret}; Max-Age=${BROWSER_SECRET_MAX_AGE_S}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}

/** Extract Cookie header, joining Harper 4 Header array crumbs; falls back to plain-object for test doubles. */
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

/** Parse the `__Host-oauth_browser` cookie value from the request. */
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
