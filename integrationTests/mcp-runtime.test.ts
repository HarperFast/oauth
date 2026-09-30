/**
 * Runtime characterization against a booted Harper, not mocks:
 *
 *   1. Per-record replay retention: a client-assertion jti row written by
 *      MCPAssertionJtiStore expires at its own expiry (the later of the
 *      assertion's exp and insertion time, plus 60 s), not at the table
 *      default of 120 s, and is refused as a replay until then.
 *   2. Concurrent presentations of one jti: the number the store accepts is
 *      recorded as observed (see the harper#1745 residual in
 *      assertionJtiStore.ts); a presentation after the burst is refused.
 *   3. Concurrent refreshes of one refresh token through POST
 *      /oauth/mcp/token: the outcomes are recorded as observed (rotation is
 *      not atomic; see refreshTokenStore.ts). If any refresh is refused as
 *      superseded, the family must be revoked and every token issued in the
 *      race refused; otherwise a token that lost the race is refused and
 *      revokes the family.
 *
 * The fixture's TEST-ONLY /mcp-test routes call the plugin's own stores; no
 * CIMD document is fetched. Observations are printed as test diagnostics.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setTimeout as sleep } from 'node:timers/promises';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'mcp-runtime-app');
const CLIENT_ID = 'runtime-public-client';

suite('MCP runtime: replay retention and concurrent refresh', (ctx: ContextWithHarper) => {
	before(async () => {
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: getHarperBinPath(),
			config: { logging: { stdStreams: true } },
		});
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	async function testRoute(path: string, params: Record<string, string | number> = {}): Promise<any> {
		const url = new URL(`/mcp-test${path}`, ctx.harper.httpURL);
		for (const [name, value] of Object.entries(params)) url.searchParams.set(name, String(value));
		const res = await fetch(url);
		strictEqual(res.status, 200, `${path}: ${res.status}`);
		return res.json();
	}

	function refresh(refreshToken: string): Promise<Response> {
		return fetch(new URL('/oauth/mcp/token', ctx.harper.httpURL), {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: CLIENT_ID }),
		});
	}

	const hashOf = (token: string) => createHash('sha256').update(token).digest('base64url');

	test('replay rows expire at their own expiry, not the table default', { timeout: 120_000 }, async (t) => {
		const client = 'https://agent.test/replay-client.json';
		const nowSeconds = Math.floor(Date.now() / 1000);
		const short = { jti: randomUUID(), exp: nowSeconds + 2 }; // row expires at exp + 60 s
		const long = { jti: randomUUID(), exp: nowSeconds + 90 }; // row outlives the 120 s table default
		for (const row of [short, long]) {
			strictEqual((await testRoute('/replay', { client_id: client, ...row })).fresh, true);
			strictEqual((await testRoute('/replay', { client_id: client, ...row })).fresh, false, 'a replay is refused');
		}
		for (const row of [short, long]) {
			const stored = await testRoute('/replay-row', { client_id: client, jti: row.jti });
			const expected = (row.exp + 60) * 1000;
			t.diagnostic(`row exp+60s=${expected} mirrored=${stored.expires_at} harper expiresAt=${stored.expiresAt}`);
			strictEqual(stored.exists, true);
			strictEqual(stored.expires_at, expected);
			strictEqual(stored.expiresAt, expected, "Harper's per-record expiry is the row's own");
		}

		const waitMs = (short.exp + 60) * 1000 - Date.now() + 1_500;
		await sleep(Math.max(0, waitMs));
		strictEqual(
			(await testRoute('/replay', { client_id: client, ...long })).fresh,
			false,
			'the long-lived row is still retained'
		);
		strictEqual((await testRoute('/replay-row', { client_id: client, jti: short.jti })).exists, false);
		strictEqual(
			(await testRoute('/replay', { client_id: client, ...short })).fresh,
			true,
			'after its expiry the short-lived row no longer blocks the jti'
		);
	});

	test('concurrent presentations of one jti (characterization)', async (t) => {
		const client = 'https://agent.test/concurrent-client.json';
		const row = { client_id: client, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 60 };
		const results = await Promise.all(Array.from({ length: 8 }, () => testRoute('/replay', row)));
		const accepted = results.filter((r) => r.fresh).length;
		t.diagnostic(`8 concurrent presentations of one jti: ${accepted} accepted, ${8 - accepted} refused`);
		ok(accepted >= 1);
		strictEqual((await testRoute('/replay', row)).fresh, false, 'a presentation after the burst is refused');
	});

	test('concurrent refreshes of one refresh token (characterization)', async (t) => {
		const { refreshToken, familyId } = await testRoute('/seed-family');
		const first = await refresh(refreshToken);
		strictEqual(first.status, 200, 'a sequential refresh rotates');
		const current = (await first.json()).refresh_token as string;
		const afterFirst = await testRoute('/family', { id: familyId });
		strictEqual(afterFirst.client_auth_method, 'none', 'the binding survives a rotation on Harper');
		strictEqual(afterFirst.current_token_hash, hashOf(current));

		const responses = await Promise.all(Array.from({ length: 5 }, () => refresh(current)));
		const bodies = await Promise.all(responses.map((r) => r.json()));
		const issued = bodies.filter((b) => typeof b.refresh_token === 'string').map((b) => b.refresh_token as string);
		const errors = bodies.filter((b) => b.error).map((b) => `${b.error}: ${b.error_description}`);
		const family = await testRoute('/family', { id: familyId });
		const live = issued.filter((token) => hashOf(token) === family.current_token_hash);
		t.diagnostic(
			`5 concurrent refreshes of one token: ${issued.length} issued a token, errors ${JSON.stringify(errors)}; ` +
				`${live.length} issued token(s) match the stored hash; family revoked: ${family.revoked}`
		);
		ok(issued.length >= 1, 'at least one refresh succeeds');
		strictEqual(family.client_auth_method, 'none');

		const superseded = bodies.some((b) => b.error === 'invalid_grant' && /superseded/.test(b.error_description));
		const orphans = issued.filter((token) => hashOf(token) !== family.current_token_hash);
		if (superseded) {
			// A refresh refused as superseded must have revoked the family, so no
			// token issued in the race refreshes, including the stored one.
			strictEqual(family.revoked, true, 'a superseded presentation revokes the family');
			for (const token of issued) {
				const res = await refresh(token);
				t.diagnostic(`a token issued in the race, after the revocation: ${res.status}`);
				strictEqual(res.status, 400, 'a revoked family refreshes no token');
			}
		} else {
			// Otherwise more than one refresh rotated the family: a token that lost
			// the race is refused and revokes the family.
			ok(orphans.length > 0, 'without a superseded presentation, the race left orphaned tokens');
			const res = await refresh(orphans[0]);
			strictEqual(res.status, 400);
			strictEqual((await res.json()).error, 'invalid_grant');
			strictEqual((await testRoute('/family', { id: familyId })).revoked, true, 'an orphan revokes the family');
			for (const token of live) strictEqual((await refresh(token)).status, 400, 'the stored token dies too');
		}
	});
});
