/**
 * Regression guard for the symptom Dawson reported on 2026-05-22 (CM/Studio
 * Okta SSO):
 *
 *   "providerName is 'oauth', not the {configId} described, that isn't passed"
 *
 * Diagnosis would be that the plugin extracts the literal "oauth" path
 * prefix as providerName instead of the segment after it. If true, requests
 * to /oauth/<tenantId>/login would dispatch to the provider literally named
 * "oauth" regardless of what tenantId the caller asked for.
 *
 * This test configures TWO providers — one literally named "oauth" (a
 * decoy) and one named "oac-tenant-acme" — with distinctive client_ids,
 * then asserts a request to /oauth/oac-tenant-acme/login redirects with
 * the TENANT's client_id, not the decoy's. If parseRoute ever regresses
 * into returning the literal "oauth" segment, the assertion will fail
 * because the decoy provider's authorization URL would be used.
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

const TENANT_CLIENT_ID = 'tenant-acme-client-id';
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

	test('/oauth/oac-tenant-acme/login dispatches to the tenant provider', async () => {
		const response = await fetch(`${ctx.harper.httpURL}/oauth/oac-tenant-acme/login`, {
			redirect: 'manual',
		});

		strictEqual(response.status, 302, `expected 302 redirect, got ${response.status}`);
		const location = response.headers.get('location');
		strictEqual(typeof location, 'string', 'Location header missing');
		const url = new URL(location!);

		// The tenant provider's authorizationUrl is http://tenant.test/authorize;
		// the decoy's is http://decoy.test/authorize. If parseRoute returned
		// "oauth" instead of "oac-tenant-acme", we'd land at decoy.test.
		strictEqual(
			url.origin + url.pathname,
			'http://tenant.test/authorize',
			`request was routed to ${url.origin} — expected tenant.test (decoy is decoy.test)`
		);
		strictEqual(
			url.searchParams.get('client_id'),
			TENANT_CLIENT_ID,
			`client_id was ${url.searchParams.get('client_id')} — expected tenant's (${TENANT_CLIENT_ID}), decoy's is ${DECOY_CLIENT_ID}`
		);
	});
});
