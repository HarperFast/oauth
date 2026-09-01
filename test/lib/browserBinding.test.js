// Tests for the browser-binding cookie helpers.
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

		it('reads the secret when .get() returns an array of cookie crumbs (HTTP/2 crumbling)', () => {
			// Harper 4 Headers can split Cookie across array crumbs — binding cookie may be in any.
			const secret = 'crumbled-secret';
			const request = {
				headers: {
					get: (name) =>
						name === 'cookie' ? ['session=abc', `${BROWSER_SECRET_COOKIE_NAME}=${secret}`, 'other=1'] : null,
				},
			};
			assert.equal(readBrowserSecret(request), secret);
		});

		it('reads the secret from a plain-object headers.cookie array', () => {
			const secret = 'plain-array-secret';
			const request = {
				headers: { cookie: [`other=x`, `${BROWSER_SECRET_COOKIE_NAME}=${secret}`] },
			};
			assert.equal(readBrowserSecret(request), secret);
		});

		it('returns undefined when the cookie is absent', () => {
			assert.equal(readBrowserSecret({ headers: { cookie: 'other=value' } }), undefined);
			assert.equal(readBrowserSecret({ headers: {} }), undefined);
			assert.equal(readBrowserSecret(undefined), undefined);
		});

		it('returns the secret for a valid 43-char base64url value', () => {
			const secret = generateBrowserSecret();
			assert.equal(secret.length, 43);
			assert.match(secret, /^[A-Za-z0-9_-]+$/);
			const request = { headers: { cookie: `${BROWSER_SECRET_COOKIE_NAME}=${secret}` } };
			assert.equal(readBrowserSecret(request), secret);
		});

		it('returns undefined for a malformed cookie value (contains disallowed chars)', () => {
			const malformed = 'abc!@#$%^&*()malformed value with spaces';
			const request = { headers: { cookie: `${BROWSER_SECRET_COOKIE_NAME}=${malformed}` } };
			assert.equal(readBrowserSecret(request), undefined);
		});

		it('returns undefined for an over-length cookie value (65+ chars)', () => {
			const overLength = 'a'.repeat(65);
			const request = { headers: { cookie: `${BROWSER_SECRET_COOKIE_NAME}=${overLength}` } };
			assert.equal(readBrowserSecret(request), undefined);
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

		it('returns false without throwing when either argument is a non-string (number, object)', () => {
			assert.doesNotThrow(() => {
				assert.ok(!browserSecretMatches(/** @type {any} */ (42), hashBrowserSecret('x')));
				assert.ok(!browserSecretMatches('x', /** @type {any} */ (42)));
				assert.ok(!browserSecretMatches(/** @type {any} */ ({ valueOf: () => 'x' }), hashBrowserSecret('x')));
				assert.ok(!browserSecretMatches(/** @type {any} */ (null), hashBrowserSecret('x')));
			});
		});
	});
});
