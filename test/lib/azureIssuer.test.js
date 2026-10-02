/**
 * Tests for Azure AD / Entra ID issuer resolution (HarperFast/oauth#264).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AZURE_CONSUMERS_TENANT_ID, isAzureJwksUri, resolveAzureIssuerBinding } from '../../dist/lib/azureIssuer.js';

const GUID_A = '12345678-1234-1234-1234-123456789012';
const GUID_B = '87654321-4321-4321-4321-210987654321';

function baseConfig(overrides = {}) {
	return {
		provider: 'azure',
		clientId: 'c',
		clientSecret: 's',
		authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
		tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
		userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
		jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
		issuer: null,
		...overrides,
	};
}

describe('isAzureJwksUri', () => {
	it('is true for any login.microsoftonline.com jwksUri regardless of path shape', () => {
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/common/discovery/v2.0/keys'), true);
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/anything/at/all'), true);
	});

	it('is false for a different host, malformed URL, or absent value', () => {
		assert.equal(isAzureJwksUri('https://idp.example.com/jwks'), false);
		assert.equal(isAzureJwksUri('not a url'), false);
		assert.equal(isAzureJwksUri(null), false);
		assert.equal(isAzureJwksUri(undefined), false);
		assert.equal(isAzureJwksUri(''), false);
	});
});

describe('resolveAzureIssuerBinding', () => {
	it('is a no-op for a non-Azure jwksUri, regardless of issuer', () => {
		const config = {
			jwksUri: 'https://idp.example.com/jwks',
			authorizationUrl: 'https://idp.example.com/authorize',
			issuer: null,
		};
		resolveAzureIssuerBinding(config, 'custom-idp');
		assert.equal(config.jwksUri, 'https://idp.example.com/jwks');
		assert.equal(config.issuer, null);
	});

	it('is a no-op for an Azure-host lookalike with extra path segments', () => {
		const config = baseConfig({ jwksUri: 'https://login.microsoftonline.com/a/b/discovery/v2.0/keys' });
		resolveAzureIssuerBinding(config, 'azure');
		assert.equal(config.jwksUri, 'https://login.microsoftonline.com/a/b/discovery/v2.0/keys');
		assert.equal(config.issuer, null);
	});

	describe('real tenant GUID (tenant-exclusive, no shared pool)', () => {
		it('sets a direct issuer when none is pinned', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: null,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
			// Unchanged — no rewrite needed for an already tenant-exclusive endpoint.
			assert.equal(config.jwksUri, `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`);
		});

		it('lowercases an uppercase tenant GUID segment before building the issuer', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A.toUpperCase()}/discovery/v2.0/keys`,
				issuer: null,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});

		it('leaves a matching explicit pin untouched', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});

		it('throws when an explicit pin names a different tenant than the jwksUri', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_B}/v2.0`,
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /different tenant/);
		});

		it('is idempotent — calling it twice does not throw or change the result', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: null,
			});
			resolveAzureIssuerBinding(config, 'azure');
			const afterFirst = { ...config };
			resolveAzureIssuerBinding(config, 'azure');
			assert.deepEqual(config, afterFirst);
		});
	});

	describe('shared alias authorities (common/organizations/consumers) — adoption requires a pin', () => {
		for (const alias of ['common', 'organizations', 'consumers']) {
			it(`'${alias}' with no pin is untouched (byte-identical to today)`, () => {
				const config = baseConfig({
					jwksUri: `https://login.microsoftonline.com/${alias}/discovery/v2.0/keys`,
					issuer: null,
				});
				resolveAzureIssuerBinding(config, 'azure');
				assert.equal(config.jwksUri, `https://login.microsoftonline.com/${alias}/discovery/v2.0/keys`);
				assert.equal(config.issuer, null);
			});

			it(`'${alias}' with a single valid tenant-GUID pin redirects to that tenant's own endpoint`, () => {
				const config = baseConfig({
					jwksUri: `https://login.microsoftonline.com/${alias}/discovery/v2.0/keys`,
					issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0`,
				});
				resolveAzureIssuerBinding(config, 'azure');
				assert.equal(config.jwksUri, `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`);
				assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
			});
		}

		it('consumers can be pinned to the documented fixed tenant GUID constant', () => {
			const config = baseConfig({
				jwksUri: 'https://login.microsoftonline.com/consumers/discovery/v2.0/keys',
				issuer: `https://login.microsoftonline.com/${AZURE_CONSUMERS_TENANT_ID}/v2.0`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(
				config.jwksUri,
				`https://login.microsoftonline.com/${AZURE_CONSUMERS_TENANT_ID}/discovery/v2.0/keys`
			);
			assert.equal(config.issuer, `https://login.microsoftonline.com/${AZURE_CONSUMERS_TENANT_ID}/v2.0`);
		});

		it('rejects an array pin — exactly one tenant, never several, through one provider (#264)', () => {
			const config = baseConfig({
				jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
				issuer: [
					`https://login.microsoftonline.com/${GUID_A}/v2.0`,
					`https://login.microsoftonline.com/${GUID_B}/v2.0`,
				],
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /array/);
		});

		it('rejects a non-Azure-shaped pin', () => {
			const config = baseConfig({
				jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
				issuer: 'https://sts.example.com/not-azure',
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /not a usable Azure tenant issuer/);
		});

		it('rewrite collapses into the tenant-exclusive case: a second call is a no-op', () => {
			const config = baseConfig({
				jwksUri: 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
				issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			const afterFirst = { ...config };
			resolveAzureIssuerBinding(config, 'azure');
			assert.deepEqual(config, afterFirst);
		});

		it('uppercase GUID in the pin still resolves and compares correctly', () => {
			const config = baseConfig({
				jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
				issuer: `https://login.microsoftonline.com/${GUID_A.toUpperCase()}/v2.0`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.jwksUri, `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`);
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});
	});
});
