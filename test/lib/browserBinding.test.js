/**
 * Tests for the browser-binding cookie helpers (GHSA-xf67 backport).
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
} from '../../dist/lib/browserBinding.js';

describe('browserBinding', () => {
	it('generates unique url-safe browser secrets', () => {
		assert.notEqual(generateBrowserSecret(), generateBrowserSecret());
		// base64url — no +, /, or = padding
		assert.match(generateBrowserSecret(), /^[A-Za-z0-9_-]+$/);
	});

	it('hashBrowserSecret produces consistent SHA-256 base64url output', () => {
		const secret = 'test-secret';
		assert.equal(hashBrowserSecret(secret), hashBrowserSecret(secret));
		assert.notEqual(hashBrowserSecret(secret), hashBrowserSecret('other'));
		assert.match(hashBrowserSecret(secret), /^[A-Za-z0-9_-]+$/);
	});

	it('buildBrowserSecretCookie includes all required cookie attributes', () => {
		const cookie = buildBrowserSecretCookie('mysecret');
		assert.ok(cookie.startsWith(`${BROWSER_SECRET_COOKIE_NAME}=mysecret`));
		assert.ok(cookie.includes('Path=/'));
		assert.ok(cookie.includes('Secure'));
		assert.ok(cookie.includes('HttpOnly'));
		assert.ok(cookie.includes('SameSite=Lax'));
		assert.ok(cookie.includes('Max-Age='));
	});

	describe('readBrowserSecret', () => {
		it('reads the secret from a plain-object headers cookie', () => {
			const secret = generateBrowserSecret();
			const request = { headers: { cookie: `${BROWSER_SECRET_COOKIE_NAME}=${secret}` } };
			assert.equal(readBrowserSecret(request), secret);
		});

		it('reads the secret when other cookies precede it', () => {
			const secret = 'abc123';
			const request = {
				headers: { cookie: `other=value; ${BROWSER_SECRET_COOKIE_NAME}=${secret}; trailing=x` },
			};
			assert.equal(readBrowserSecret(request), secret);
		});

		it('reads the secret via .get() (Harper 4 runtime Headers shape)', () => {
			const secret = 'runtime-secret';
			const request = {
				headers: {
					get: (name) => (name === 'cookie' ? `${BROWSER_SECRET_COOKIE_NAME}=${secret}` : null),
				},
			};
			assert.equal(readBrowserSecret(request), secret);
		});

		it('returns undefined when the cookie is absent', () => {
			assert.equal(readBrowserSecret({ headers: { cookie: 'other=value' } }), undefined);
			assert.equal(readBrowserSecret({ headers: {} }), undefined);
			assert.equal(readBrowserSecret(undefined), undefined);
		});
	});

	describe('browserSecretMatches', () => {
		it('returns true for a matching secret and hash', () => {
			const secret = generateBrowserSecret();
			assert.ok(browserSecretMatches(secret, hashBrowserSecret(secret)));
		});

		it('returns false for a mismatched secret', () => {
			const secret = generateBrowserSecret();
			assert.ok(!browserSecretMatches('wrong-secret', hashBrowserSecret(secret)));
		});

		it('returns false when secret or hash is undefined/empty', () => {
			assert.ok(!browserSecretMatches(undefined, hashBrowserSecret('x')));
			assert.ok(!browserSecretMatches('x', undefined));
			assert.ok(!browserSecretMatches('', 'anyhash'));
		});
	});
});
