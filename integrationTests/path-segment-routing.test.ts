/**
 * Regression guard for the symptom Dawson reported on 2026-05-22 (CM/Studio
 * Okta SSO):
 *
 *   "providerName is 'oauth', not the {configId} described, that isn't passed"
 *
 * If parseRoute extracted the literal "oauth" path prefix as providerName
 * (rather than the segment after it), requests to /oauth/<tenantId>/login
 * would resolve to whatever provider is registered under the name "oauth" —
 * with the rest of the URL becoming the action — and would NOT produce the
 * expected tenant-shaped 302.
 *
 * This test configures two providers — one literally named "oauth" (a decoy)
 * and one named "oac-oauth-tenant" (deliberately containing the substring
 * "oauth" to also catch over-aggressive stripping) — with distinctive
 * client_ids, then asserts that /oauth/oac-oauth-tenant/login redirects to
 * the tenant provider's authorizationUrl with the tenant's client_id. Any
 * regression that breaks path-segment routing will fail this assertion.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual } from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'path-segment-routing-app');

const TENANT_CLIENT_ID = 'oauth-tenant-client-id';
const DECOY_CLIENT_ID = 'decoy-oauth-client-id';

suite('OAuth Resource routes by URL path segment (not literal "oauth")', (ctx: ContextWithHarper) => {
	before(async () => {
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: getHarperBinPath(),
			env: {
				OAUTH_TENANT_CLIENT_ID: TENANT_CLIENT_ID,
				OAUTH_DECOY_CLIENT_ID: DECOY_CLIENT_ID,
			},
			config: { logging: { stdStreams: true } },
		});
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('/oauth/oac-oauth-tenant/login dispatches to the tenant provider', async () => {
		const response = await fetch(`${ctx.harper.httpURL}/oauth/oac-oauth-tenant/login`, {
			redirect: 'manual',
		});

		strictEqual(response.status, 302, `expected 302 redirect, got ${response.status}`);
		const location = response.headers.get('location');
		strictEqual(typeof location, 'string', 'Location header missing');
		const url = new URL(location!);

		// The tenant provider's authorizationUrl is http://tenant.test/authorize;
		// the decoy's is http://decoy.test/authorize. A parseRoute that returned
		// "oauth" as providerName would either 404 (action mismatch) or pull
		// the decoy's client_id — both fail these assertions.
		strictEqual(url.origin, 'http://tenant.test');
		strictEqual(url.pathname, '/authorize');
		strictEqual(
			url.searchParams.get('client_id'),
			TENANT_CLIENT_ID,
			`client_id was ${url.searchParams.get('client_id')} — expected tenant's (${TENANT_CLIENT_ID}), decoy's is ${DECOY_CLIENT_ID}`
		);
	});
});
