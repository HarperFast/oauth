/**
 * Verifies that ${VAR} placeholders in the OAuth plugin's provider config
 * are substituted with values from process.env when the plugin loads under
 * Harper v5. Boots a real Harper instance with the OAuth plugin installed
 * (via npm pack into the fixture) and asserts the substituted client_id
 * appears on the authorization redirect.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual } from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import {
	setupHarperWithFixture,
	teardownHarper,
	type ContextWithHarper,
} from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'oauth-app');

const EXPECTED_CLIENT_ID = 'integration-test-client-id';
const EXPECTED_CLIENT_SECRET = 'integration-test-client-secret';

suite('OAuth plugin env-var substitution under Harper v5', (ctx: ContextWithHarper) => {
	before(async () => {
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: getHarperBinPath(),
			env: {
				OAUTH_TEST_CLIENT_ID: EXPECTED_CLIENT_ID,
				OAUTH_TEST_CLIENT_SECRET: EXPECTED_CLIENT_SECRET,
			},
			config: {
				logging: { stdStreams: true },
			},
		});
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('login redirect carries the substituted client_id', async () => {
		const response = await fetch(`${ctx.harper.httpURL}/oauth/test-provider/login`, {
			redirect: 'manual',
		});
		strictEqual(response.status, 302, `expected 302, got ${response.status}`);
		const location = response.headers.get('location');
		strictEqual(typeof location, 'string', 'Location header missing');
		const url = new URL(location!);
		strictEqual(
			url.origin + url.pathname,
			'http://example.test/authorize',
			'authorization URL was not constructed from configured authorizationUrl'
		);
		strictEqual(
			url.searchParams.get('client_id'),
			EXPECTED_CLIENT_ID,
			'client_id was not substituted from ${OAUTH_TEST_CLIENT_ID}'
		);
	});
});
