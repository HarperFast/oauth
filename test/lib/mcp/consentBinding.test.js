/**
 * Tests for the stable browser-binding cookie helpers.
 *
 * #205: per-flow cookies collapsed to one stable __Host-oauth_browser secret.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	BROWSER_SECRET_COOKIE_NAME,
	browserSecretMatches,
	buildBrowserSecretCookie,
	generateBrowserSecret,
	hashBrowserSecret,
	readBrowserSecret,
} from '../../../dist/lib/mcp/consentBinding.js';

describe('consentBinding', () => {
	it('generates unique url-safe browser secrets', () => {
		assert.notEqual(generateBrowserSecret(), generateBrowserSecret());
		assert.match(generateBrowserSecret(), /^[A-Za-z0-9_-]{40,}$/);
	});

	it('buildBrowserSecretCookie uses the stable __Host- name and required attributes', () => {
		const cookie = buildBrowserSecretCookie('secret-value');
		assert.match(cookie, new RegExp(`^${BROWSER_SECRET_COOKIE_NAME}=secret-value; `));
		assert.match(cookie, /Secure/);
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /SameSite=Lax/);
		assert.match(cookie, /Path=\//);
		assert.match(cookie, /Max-Age=\d+/);
		// __Host- forbids a Domain attribute (blocks sibling injection).
		assert.doesNotMatch(cookie, /Domain=/i);
	});

	it('readBrowserSecret reads the stable cookie from a plain object header', () => {
		const request = { headers: { cookie: `a=1; ${BROWSER_SECRET_COOKIE_NAME}=my-secret ; b=2` } };
		assert.equal(readBrowserSecret(request), 'my-secret');
	});

	it('readBrowserSecret returns undefined when absent', () => {
		assert.equal(readBrowserSecret(undefined), undefined);
		assert.equal(readBrowserSecret({ headers: {} }), undefined);
		assert.equal(readBrowserSecret({ headers: { cookie: '' } }), undefined);
		assert.equal(readBrowserSecret({ headers: { cookie: 'other=1' } }), undefined);
		assert.equal(readBrowserSecret({ headers: { cookie: 'no-equals-sign' } }), undefined);
	});

	it('readBrowserSecret reads from a Harper .asObject headers wrapper', () => {
		const request = { headers: { asObject: { cookie: `x=1; ${BROWSER_SECRET_COOKIE_NAME}=wrapped-secret` } } };
		assert.equal(readBrowserSecret(request), 'wrapped-secret');
	});

	it('readBrowserSecret reads from a Web Headers object (.get)', () => {
		const request = { headers: new Headers({ cookie: `${BROWSER_SECRET_COOKIE_NAME}=web-headers-secret` }) };
		assert.equal(readBrowserSecret(request), 'web-headers-secret');
	});

	it('finds the binding cookie when the Cookie header is an array (HTTP/2 crumbling)', () => {
		const request = { headers: { cookie: ['other=1', `${BROWSER_SECRET_COOKIE_NAME}=array-secret`, 'z=2'] } };
		assert.equal(readBrowserSecret(request), 'array-secret');
	});

	it('finds the binding cookie in an array via .asObject wrapper', () => {
		const request = { headers: { asObject: { cookie: ['a=1', `${BROWSER_SECRET_COOKIE_NAME}=array-obj-secret`] } } };
		assert.equal(readBrowserSecret(request), 'array-obj-secret');
	});

	it('browserSecretMatches round-trips and rejects mismatches', () => {
		const secret = generateBrowserSecret();
		const hash = hashBrowserSecret(secret);
		assert.equal(browserSecretMatches(secret, hash), true);
		assert.equal(browserSecretMatches('other-secret', hash), false);
		assert.equal(browserSecretMatches(undefined, hash), false);
		assert.equal(browserSecretMatches(secret, undefined), false);
		assert.equal(browserSecretMatches(secret, 'not-a-hash'), false);
	});

	// --- #205 exhaustion-regression tests ---

	it('#205 (a): N repeated flow initiations leave exactly ONE stable cookie — no accumulation', () => {
		// Simulate a browser that already has the stable cookie.
		const firstSecret = generateBrowserSecret();
		const requestWithCookie = { headers: { cookie: `${BROWSER_SECRET_COOKIE_NAME}=${firstSecret}` } };

		// Each flow initiation should read the existing secret and produce ONE cookie.
		const cookies = [];
		for (let i = 0; i < 10; i++) {
			const existingSecret = readBrowserSecret(requestWithCookie);
			const browserSecret = existingSecret ?? generateBrowserSecret();
			cookies.push(buildBrowserSecretCookie(browserSecret));
		}

		// All cookies should use the SAME stable name (no per-flow suffix).
		for (const cookie of cookies) {
			assert.match(cookie, new RegExp(`^${BROWSER_SECRET_COOKIE_NAME}=`), 'stable name only');
			// Must not contain any per-flow variant name.
			assert.doesNotMatch(cookie, /__Host-mcp_consent_|__Host-oauth_login_/);
		}

		// All cookies carry the same secret (the pre-existing one is reused).
		const secrets = cookies.map((c) => c.split(';')[0].split('=').slice(1).join('='));
		assert.ok(
			secrets.every((s) => s === firstSecret),
			'reuses the existing secret across all flow initiations'
		);

		// Only ONE distinct cookie name appears, regardless of how many flows ran.
		const names = new Set(cookies.map((c) => c.split('=')[0]));
		assert.equal(names.size, 1, 'exactly one cookie name produced across all flows');
	});

	it('#205 (b): binding still rejects cross-browser completion (security property survives)', () => {
		// Browser A initiates the flow.
		const secretA = generateBrowserSecret();
		const hashA = hashBrowserSecret(secretA);

		// Browser B's cookie (different secret) attempts to complete the flow.
		const secretB = generateBrowserSecret();

		assert.equal(browserSecretMatches(secretB, hashA), false, 'cross-browser attempt rejected');
		assert.equal(browserSecretMatches(secretA, hashA), true, 'initiating browser accepted');
	});

	it('#205 (c): stable secret survives an abandoned flow and still binds the next one', () => {
		// Browser has the stable cookie.
		const secret = generateBrowserSecret();
		const requestWithCookie = { headers: { cookie: `${BROWSER_SECRET_COOKIE_NAME}=${secret}` } };

		// Flow 1 is initiated.
		const hash1 = hashBrowserSecret(readBrowserSecret(requestWithCookie) ?? generateBrowserSecret());
		assert.equal(browserSecretMatches(secret, hash1), true, 'flow 1 bound');

		// Flow 1 is abandoned (no completion). Browser initiates flow 2.
		const hash2 = hashBrowserSecret(readBrowserSecret(requestWithCookie) ?? generateBrowserSecret());
		assert.equal(browserSecretMatches(secret, hash2), true, 'flow 2 also bound by same secret');

		// The hashes are identical (same secret, same hash function).
		assert.equal(hash1, hash2, 'stable secret produces stable hash across flows');
	});
});
