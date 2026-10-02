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
	it('is true only for an UNPINNED shared alias authority’s exact v2.0 keys-endpoint shape', () => {
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/common/discovery/v2.0/keys'), true);
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/organizations/discovery/v2.0/keys'), true);
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/consumers/discovery/v2.0/keys'), true);
	});

	it('is false for a real-tenant-GUID segment — resolveAzureIssuerBinding always sets a usable issuer for it (or throws), so hasUsableIssuer already short-circuits every caller before this is reached', () => {
		assert.equal(isAzureJwksUri(`https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`), false);
	});

	it('is false for a tenant-DOMAIN segment (e.g. a verified .onmicrosoft.com domain, which Azure also accepts here) — resolveAzureIssuerBinding never recognizes or binds it, so it must not be silently exempted from #231 §4/discovery', () => {
		assert.equal(
			isAzureJwksUri('https://login.microsoftonline.com/contoso.onmicrosoft.com/discovery/v2.0/keys'),
			false
		);
	});

	it('is false for an Azure-host jwksUri in an unrecognized shape — resolveAzureIssuerBinding never touches it, so it must not be silently exempted from #231 §4/discovery', () => {
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/common/discovery/keys'), false); // the older, non-v2.0 shape
		assert.equal(isAzureJwksUri('https://login.microsoftonline.com/anything/at/all'), false);
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

		it('derives the v1 (sts.windows.net) issuer form when no pin is given and authorizationUrl is a v1 authorize endpoint', () => {
			// Mirrors the pinned branch's form check: an unpinned real-tenant-GUID
			// config must derive the SAME form a pin would have been required to
			// match, not always v2 regardless of what authorizationUrl actually
			// issues.
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/oauth2/authorize`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: null,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://sts.windows.net/${GUID_A}/`);
		});

		it('still derives the v2 issuer form when authorizationUrl is unrecognized (not v1 or v2 shaped)', () => {
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/custom/authorize-path`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: null,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});

		it('leaves an already-canonical matching explicit pin untouched', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});

		it('canonicalizes a same-tenant pin with a trailing slash — jwt.verify compares issuer strings exactly', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0/`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});

		it('canonicalizes a same-tenant pin with an uppercase GUID', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_A.toUpperCase()}/v2.0`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
		});

		it('keeps a same-tenant pin given in the older sts.windows.net (v1) form AS v1 — when authorizationUrl is ALSO a v1 authorize endpoint', () => {
			// Which `iss` form a real token carries depends on the authorize
			// endpoint, not the jwksUri — collapsing this to v2 would break
			// verification for every real v1 token. But the pin must actually
			// match that endpoint's form (see the mismatch tests below) — a v1
			// pin is only safe when `authorizationUrl` really is v1.
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/oauth2/authorize`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://sts.windows.net/${GUID_A}/`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://sts.windows.net/${GUID_A}/`);
		});

		it('canonicalizes a v1 pin’s case and trailing slash without changing its form', () => {
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/oauth2/authorize`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://sts.windows.net/${GUID_A.toUpperCase()}`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://sts.windows.net/${GUID_A}/`);
		});

		it('rejects a v1 pin when authorizationUrl is a v2 authorize endpoint — the preset always generates v2, so a stray v1 pin would fail jwt.verify on every real token', () => {
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/oauth2/v2.0/authorize`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://sts.windows.net/${GUID_A}/`,
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /wrong Azure issuer form/);
		});

		it('rejects a v2 pin when authorizationUrl is a v1 authorize endpoint', () => {
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/oauth2/authorize`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0`,
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /wrong Azure issuer form/);
		});

		it('rejects a same-tenant array mixing v1 and v2 forms when authorizationUrl has a recognized (v2) shape — one element always names the wrong form', () => {
			const config = baseConfig({
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/oauth2/v2.0/authorize`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: [`https://login.microsoftonline.com/${GUID_A}/v2.0`, `https://sts.windows.net/${GUID_A}/`],
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /wrong Azure issuer form/);
		});

		it('does not additionally constrain the pin’s form when authorizationUrl is an unrecognized Azure shape — only the tenant is checked there', () => {
			const config = baseConfig({
				// Neither the v1 (`/oauth2/authorize`) nor v2 (`/oauth2/v2.0/authorize`)
				// suffix — a shape this module doesn't classify.
				authorizationUrl: `https://login.microsoftonline.com/${GUID_A}/custom/authorize-path`,
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://sts.windows.net/${GUID_A}/`,
			});
			resolveAzureIssuerBinding(config, 'azure');
			assert.equal(config.issuer, `https://sts.windows.net/${GUID_A}/`);
		});

		it('throws when an explicit pin names a different tenant than the jwksUri', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: `https://login.microsoftonline.com/${GUID_B}/v2.0`,
			});
			assert.throws(() => resolveAzureIssuerBinding(config, 'azure'), /different tenant/);
		});

		it('throws when an array pin has one element naming a different tenant than the jwksUri', () => {
			const config = baseConfig({
				jwksUri: `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`,
				issuer: [`https://login.microsoftonline.com/${GUID_A}/v2.0`, `https://sts.windows.net/${GUID_B}/`],
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

		it('a throwing advisory logger does not abort the pinned-alias rewrite', () => {
			const config = baseConfig({
				jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
				issuer: `https://login.microsoftonline.com/${GUID_A}/v2.0`,
			});
			const throwingLogger = {
				info: () => {
					throw new Error('logger blew up');
				},
			};
			resolveAzureIssuerBinding(config, 'azure', throwingLogger);
			assert.equal(config.jwksUri, `https://login.microsoftonline.com/${GUID_A}/discovery/v2.0/keys`);
			assert.equal(config.issuer, `https://login.microsoftonline.com/${GUID_A}/v2.0`);
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
