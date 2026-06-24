/**
 * End-to-end proof that withMCPAuth's spec response survives Harper's core
 * auth. Harper's core auth is a default-group HTTP middleware that consumes
 * `Authorization: Bearer` and 401s any token it can't validate as a Harper
 * operation token — stamping `WWW-Authenticate: Basic`, NOT the Bearer
 * challenge MCP clients require. This test registers withMCPAuth in both
 * supported models and asserts the FINAL response carries
 * `WWW-Authenticate: Bearer resource_metadata="..."`:
 *
 *   - /mcp     (urlPath subroute) — routed dispatch isolates the chain, so core
 *              auth never runs for it.
 *   - /mcp-dg  (default group, `before: authentication`) — withMCPAuth runs
 *              outermost and short-circuits before core auth.
 *
 * The discriminating case is a request bearing a *non-Harper* bearer token: a
 * `Basic` challenge in the response would mean core auth ran first and won.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, ok, match } from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'mcp-auth-app');
const PRM_URL = 'https://mcp.test/.well-known/oauth-protected-resource';

suite('withMCPAuth: 401 + WWW-Authenticate: Bearer survives core auth', (ctx: ContextWithHarper) => {
	before(async () => {
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: getHarperBinPath(),
			config: { logging: { stdStreams: true } },
		});
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	// Both registration models must produce the same spec-compliant challenge.
	for (const path of ['/mcp', '/mcp-dg']) {
		test(`${path}: unauthenticated request → 401 + Bearer PRM challenge`, async () => {
			const res = await fetch(`${ctx.harper.httpURL}${path}`, { method: 'POST' });
			strictEqual(res.status, 401, `expected 401, got ${res.status}`);
			const wa = res.headers.get('www-authenticate');
			ok(wa, 'WWW-Authenticate header present');
			match(wa!, /^Bearer /, `expected a Bearer challenge, got: ${wa}`);
			ok(wa!.includes(`resource_metadata="${PRM_URL}"`), `challenge must point at the PRM URL; got: ${wa}`);
		});

		test(`${path}: non-Harper bearer token → still Bearer (core auth did not win)`, async () => {
			const res = await fetch(`${ctx.harper.httpURL}${path}`, {
				method: 'POST',
				headers: { authorization: 'Bearer not-a-real-mcp-token' },
			});
			strictEqual(res.status, 401, `expected 401, got ${res.status}`);
			const wa = res.headers.get('www-authenticate');
			ok(
				wa?.startsWith('Bearer '),
				`expected Bearer (a 'Basic' challenge would mean core auth handled the token first); got: ${wa}`
			);
		});
	}
});
