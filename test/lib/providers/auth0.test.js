/**
 * Tests for Auth0 OAuth provider
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider } from '../../../dist/lib/providers/index.js';

describe('Auth0 Provider', () => {
	it('should return Auth0 provider config', () => {
		const auth0 = getProvider('auth0');
		assert.ok(auth0);
		assert.equal(auth0.provider, 'auth0');
		assert.equal(auth0.scope, 'openid profile email');
		assert.equal(auth0.usernameClaim, 'email');
		// defaultRole is not in provider preset - it's added by the main config
		assert.ok(auth0.configure, 'Auth0 should have configure function');

		// Auth0 URLs should be empty until configured
		assert.equal(auth0.authorizationUrl, '');
		assert.equal(auth0.tokenUrl, '');
		assert.equal(auth0.userInfoUrl, '');
	});

	it('should configure Auth0 with domain', () => {
		const auth0 = getProvider('auth0');
		assert.ok(auth0.configure);

		const configured = auth0.configure('my-tenant.auth0.com');
		assert.equal(configured.authorizationUrl, 'https://my-tenant.auth0.com/authorize');
		assert.equal(configured.tokenUrl, 'https://my-tenant.auth0.com/oauth/token');
		assert.equal(configured.userInfoUrl, 'https://my-tenant.auth0.com/userinfo');
		assert.equal(configured.jwksUri, 'https://my-tenant.auth0.com/.well-known/jwks.json');
		assert.equal(configured.issuer, 'https://my-tenant.auth0.com/');
	});

	it('should clean domain input - remove https://', () => {
		const auth0 = getProvider('auth0');

		const configured = auth0.configure('https://my-tenant.auth0.com');
		assert.equal(configured.authorizationUrl, 'https://my-tenant.auth0.com/authorize');
	});

	it('should clean domain input - remove trailing slash', () => {
		const auth0 = getProvider('auth0');

		const configured = auth0.configure('my-tenant.auth0.com/');
		assert.equal(configured.authorizationUrl, 'https://my-tenant.auth0.com/authorize');
	});

	it('should clean domain input - handle both https:// and trailing slash', () => {
		const auth0 = getProvider('auth0');

		const configured = auth0.configure('https://my-tenant.auth0.com/');
		assert.equal(configured.authorizationUrl, 'https://my-tenant.auth0.com/authorize');
		assert.equal(configured.tokenUrl, 'https://my-tenant.auth0.com/oauth/token');
	});

	it('should throw error when domain is not provided', () => {
		const auth0 = getProvider('auth0');

		assert.throws(
			() => {
				auth0.configure('');
			},
			{
				message: 'Auth0 provider requires domain configuration',
			}
		);
	});
});
