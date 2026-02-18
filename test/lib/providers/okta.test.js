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
});
