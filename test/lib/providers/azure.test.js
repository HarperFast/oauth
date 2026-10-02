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

		const tenantId = '12345678-1234-1234-1234-123456789012';
		const configured = azure.configure(tenantId);
		assert.ok(configured.authorizationUrl.includes(tenantId));
		assert.ok(configured.tokenUrl.includes(tenantId));
		assert.ok(configured.jwksUri.includes(tenantId));
		assert.equal(configured.issuer, `https://login.microsoftonline.com/${tenantId}/v2.0`);
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

	describe('alias tenantIds no longer set a literal (wrong) issuer (#264)', () => {
		// configure('common'/'organizations'/'consumers') previously set a
		// literal issuer like 'https://login.microsoftonline.com/common/v2.0',
		// which no real token's `iss` could ever equal. Deriving — or
		// intentionally leaving unset — the issuer for these aliases is now
		// `resolveAzureIssuerBinding`'s job (src/lib/azureIssuer.ts); the
		// preset itself only derives endpoints for them.
		for (const alias of ['common', 'organizations', 'consumers']) {
			it(`configure('${alias}') derives endpoints but no literal issuer`, () => {
				const azure = getProvider('azure');
				const configured = azure.configure(alias);
				assert.ok(configured.authorizationUrl.includes(`/${alias}/`));
				assert.ok(configured.tokenUrl.includes(`/${alias}/`));
				assert.ok(configured.jwksUri.includes(`/${alias}/`));
				assert.equal(configured.issuer, undefined);
			});
		}

		it('a real tenant GUID still gets a direct issuer (unaffected)', () => {
			const azure = getProvider('azure');
			const tenantId = '12345678-1234-1234-1234-123456789012';
			const configured = azure.configure(tenantId);
			assert.equal(configured.issuer, `https://login.microsoftonline.com/${tenantId}/v2.0`);
		});
	});
});
