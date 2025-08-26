/**
 * Tests for Google OAuth provider
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider } from '../../../dist/lib/providers/index.js';

describe('Google Provider', () => {
	it('should return Google provider config', () => {
		const google = getProvider('google');
		assert.ok(google);
		assert.equal(google.provider, 'google');
		assert.equal(google.authorizationUrl, 'https://accounts.google.com/o/oauth2/v2/auth');
		assert.equal(google.tokenUrl, 'https://oauth2.googleapis.com/token');
		assert.equal(google.userInfoUrl, 'https://www.googleapis.com/oauth2/v3/userinfo');
		assert.equal(google.jwksUri, 'https://www.googleapis.com/oauth2/v3/certs');
		assert.equal(google.issuer, 'https://accounts.google.com');
		assert.equal(google.scope, 'openid profile email');
		assert.equal(google.usernameClaim, 'email');
		// defaultRole is not in provider preset - it's added by the main config
	});

	it('should support ID token validation', () => {
		const google = getProvider('google');
		assert.ok(google.jwksUri);
		assert.ok(google.issuer);
	});

	it('should have correct token response mode', () => {
		const google = getProvider('google');
		// Google supports both access_token and id_token
		assert.ok(google.scope.includes('openid'));
	});
});
