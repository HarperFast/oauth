/**
 * Tests for Azure AD OAuth provider
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider } from '../../../dist/lib/providers/index.js';

describe('Azure Provider', () => {
	it('should return Azure AD provider config', () => {
		const azure = getProvider('azure');
		assert.ok(azure);
		assert.equal(azure.provider, 'azure');
		assert.ok(azure.authorizationUrl.includes('microsoftonline.com'));
		assert.ok(azure.tokenUrl.includes('microsoftonline.com'));
		assert.equal(azure.userInfoUrl, 'https://graph.microsoft.com/v1.0/me');
		assert.equal(azure.scope, 'openid profile email User.Read');
		assert.equal(azure.usernameClaim, 'email');
		// defaultRole is not in provider preset - it's added by the main config
		assert.ok(azure.configure, 'Azure should have configure function');
	});

	it('should default to common tenant', () => {
		const azure = getProvider('azure');
		assert.ok(azure.authorizationUrl.includes('/common/'));
		assert.ok(azure.tokenUrl.includes('/common/'));
		assert.ok(azure.jwksUri.includes('/common/'));
	});

	it('should configure Azure with tenant ID', () => {
		const azure = getProvider('azure');
		assert.ok(azure.configure);

		const configured = azure.configure('my-tenant-id');
		assert.ok(configured.authorizationUrl.includes('my-tenant-id'));
		assert.ok(configured.tokenUrl.includes('my-tenant-id'));
		assert.ok(configured.jwksUri.includes('my-tenant-id'));
		assert.equal(configured.issuer, 'https://login.microsoftonline.com/my-tenant-id/v2.0');
	});

	it('should handle microsoft alias', () => {
		const microsoft = getProvider('microsoft');
		assert.ok(microsoft);
		assert.equal(microsoft.provider, 'azure');
	});

	it('should support v2.0 endpoints', () => {
		const azure = getProvider('azure');
		assert.ok(azure.authorizationUrl.includes('/v2.0/'));
		assert.ok(azure.tokenUrl.includes('/v2.0/'));
	});

	it('should throw error when configure is called without tenantId', () => {
		const azure = getProvider('azure');
		assert.ok(azure.configure);

		assert.throws(() => azure.configure(''), {
			message: 'Azure AD provider requires tenantId configuration',
		});

		assert.throws(() => azure.configure(null), {
			message: 'Azure AD provider requires tenantId configuration',
		});

		assert.throws(() => azure.configure(undefined), {
			message: 'Azure AD provider requires tenantId configuration',
		});
	});
});
