/**
 * Tests for Okta OAuth provider
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider } from '../../../dist/lib/providers/index.js';

describe('Okta Provider', () => {
	it('should return Okta provider config', () => {
		const okta = getProvider('okta');
		assert.ok(okta);
		assert.equal(okta.provider, 'okta');
		assert.equal(okta.scope, 'openid profile email groups');
		assert.equal(okta.usernameClaim, 'preferred_username');
		assert.equal(okta.emailClaim, 'email');
		assert.equal(okta.nameClaim, 'name');
		assert.equal(okta.roleClaim, 'groups');
		assert.equal(okta.defaultRole, 'user');
		assert.equal(okta.preferIdToken, true);
		assert.ok(okta.configure, 'Okta should have configure function');

		// Okta URLs should be empty until configured
		assert.equal(okta.authorizationUrl, '');
		assert.equal(okta.tokenUrl, '');
		assert.equal(okta.userInfoUrl, '');
		assert.equal(okta.jwksUri, '');
		assert.equal(okta.issuer, '');
	});

	it('should configure Okta with domain', () => {
		const okta = getProvider('okta');
		assert.ok(okta.configure);

		const configured = okta.configure('dev-12345.okta.com');
		assert.equal(configured.authorizationUrl, 'https://dev-12345.okta.com/oauth2/v1/authorize');
		assert.equal(configured.tokenUrl, 'https://dev-12345.okta.com/oauth2/v1/token');
		assert.equal(configured.userInfoUrl, 'https://dev-12345.okta.com/oauth2/v1/userinfo');
		assert.equal(configured.jwksUri, 'https://dev-12345.okta.com/oauth2/v1/keys');
		assert.equal(configured.issuer, 'https://dev-12345.okta.com');
	});

	it('should handle domain with https:// prefix', () => {
		const okta = getProvider('okta');

		const configured = okta.configure('https://dev-12345.okta.com');
		assert.equal(configured.authorizationUrl, 'https://dev-12345.okta.com/oauth2/v1/authorize');
		assert.equal(configured.tokenUrl, 'https://dev-12345.okta.com/oauth2/v1/token');
		assert.equal(configured.userInfoUrl, 'https://dev-12345.okta.com/oauth2/v1/userinfo');
	});

	it('should throw error when domain is not provided', () => {
		const okta = getProvider('okta');

		assert.throws(
			() => {
				okta.configure('');
			},
			{
				message: 'Okta provider requires domain configuration',
			}
		);
	});

	it('should throw error for file:// protocol', () => {
		const okta = getProvider('okta');

		assert.throws(
			() => {
				okta.configure('file:///some/path');
			},
			{
				message: /Invalid Okta domain/,
			}
		);
	});

	it('should throw error for non-Okta domain', () => {
		const okta = getProvider('okta');

		assert.throws(
			() => {
				okta.configure('evil.com');
			},
			{
				message: /Invalid Okta domain.*Must be one of/,
			}
		);
	});

	it('should reject private IPs and localhost (SSRF protection)', () => {
		const okta = getProvider('okta');

		assert.throws(() => okta.configure('localhost'), /cannot be a private IP/);
		assert.throws(() => okta.configure('127.0.0.1'), /cannot be a private IP/);
		assert.throws(() => okta.configure('169.254.169.254'), /cannot be a private IP/);
	});

	it('should support okta-emea.com domain', () => {
		const okta = getProvider('okta');

		const configured = okta.configure('dev-12345.okta-emea.com');
		assert.equal(configured.authorizationUrl, 'https://dev-12345.okta-emea.com/oauth2/v1/authorize');
		assert.equal(configured.issuer, 'https://dev-12345.okta-emea.com');
	});

	it('should support oktapreview.com domain', () => {
		const okta = getProvider('okta');

		const configured = okta.configure('dev-12345.oktapreview.com');
		assert.equal(configured.authorizationUrl, 'https://dev-12345.oktapreview.com/oauth2/v1/authorize');
		assert.equal(configured.issuer, 'https://dev-12345.oktapreview.com');
	});

	describe('custom authorization server (authServer, #264)', () => {
		it('derives path-inclusive endpoints and issuer when authServer is given', () => {
			const okta = getProvider('okta');
			const configured = okta.configure('dev-1.okta.com', 'default');

			assert.equal(configured.authorizationUrl, 'https://dev-1.okta.com/oauth2/default/v1/authorize');
			assert.equal(configured.tokenUrl, 'https://dev-1.okta.com/oauth2/default/v1/token');
			assert.equal(configured.userInfoUrl, 'https://dev-1.okta.com/oauth2/default/v1/userinfo');
			assert.equal(configured.jwksUri, 'https://dev-1.okta.com/oauth2/default/v1/keys');
			// Unlike the org AS, a custom AS issuer includes the auth-server path.
			assert.equal(configured.issuer, 'https://dev-1.okta.com/oauth2/default');
		});

		it('supports a generated auth-server id', () => {
			const okta = getProvider('okta');
			const configured = okta.configure('dev-1.okta.com', 'aus1a2b3c4d5e6f7g8h9');

			assert.equal(configured.authorizationUrl, 'https://dev-1.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9/v1/authorize');
			assert.equal(configured.issuer, 'https://dev-1.okta.com/oauth2/aus1a2b3c4d5e6f7g8h9');
		});

		it('omitted authServer keeps the org authorization server (unchanged)', () => {
			const okta = getProvider('okta');
			const configured = okta.configure('dev-1.okta.com');

			assert.equal(configured.authorizationUrl, 'https://dev-1.okta.com/oauth2/v1/authorize');
			assert.equal(configured.issuer, 'https://dev-1.okta.com');
		});

		it('rejects an explicitly empty authServer instead of silently falling back to the org authorization server', () => {
			// `if (authServer)` would treat '' the same as omitted (undefined) and
			// silently derive the org AS — losing any custom-AS access policies the
			// operator thought they were pinning. `authServer !== undefined` makes
			// an explicit '' reach validateOktaAuthServer, which rejects it.
			const okta = getProvider('okta');
			assert.throws(() => okta.configure('dev-1.okta.com', ''), /authServer/);
		});

		it('rejects an explicit null authServer the same way', () => {
			const okta = getProvider('okta');
			assert.throws(() => okta.configure('dev-1.okta.com', null), /authServer/);
		});

		it('rejects an authServer containing a path separator', () => {
			const okta = getProvider('okta');
			assert.throws(() => okta.configure('dev-1.okta.com', 'a/../b'), /authServer/);
			assert.throws(() => okta.configure('dev-1.okta.com', '/etc/passwd'), /authServer/);
		});

		it('rejects an authServer with disallowed characters', () => {
			const okta = getProvider('okta');
			assert.throws(() => okta.configure('dev-1.okta.com', 'a b'), /authServer/);
			assert.throws(() => okta.configure('dev-1.okta.com', 'a?b'), /authServer/);
		});

		it('rejects an authServer over the length limit', () => {
			const okta = getProvider('okta');
			assert.throws(() => okta.configure('dev-1.okta.com', 'a'.repeat(65)), /authServer/);
		});
	});
});
