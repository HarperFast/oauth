/**
 * Runtime characterization against a booted Harper, not mocks:
 *
 *   1. Per-record replay retention: a client-assertion jti row written by
 *      MCPAssertionJtiStore expires at its own expiry (the later of the
 *      assertion's exp and insertion time, plus 60 s), not at the table
 *      default of 120 s, and is refused as a replay until then.
 *   2. A single presentation of a fresh jti is accepted. Concurrent
 *      presentations of one jti: at most one is accepted (an atomic counter;
 *      see assertionJtiStore.ts), and a presentation after the burst is
 *      refused.
 *   3. Concurrent refreshes of one refresh token through POST
 *      /oauth/mcp/token (rotation is not atomic; see refreshTokenStore.ts):
 *      at least one refresh succeeds. If any refresh is refused as
 *      superseded, the family must be revoked and every token issued in the
 *      race refused; otherwise a token that lost the race is refused and
 *      revokes the family.
 *   4. A family's rotation and revocation are partial updates: a rotation
 *      written after a revocation keeps the revocation and every other field.
 *   5. A form-encoded refresh with client_id sent twice is judged on the first
 *      value (Harper 5.1.9, without HarperFast/harper#2953): invalid_client when
 *      the first is unknown, consuming nothing, and a refresh when it is the
 *      client.
 *   6. A headless client_credentials grant through POST /oauth/mcp/token, which
 *      runs inside Harper's REST request transaction: a fresh assertion is
 *      accepted, and its replay is refused with invalid_grant.
 *   7. On that grant, a form body with resource sent twice is judged on the
 *      first value, as in 5: invalid_target when the first is not the MCP
 *      resource, consuming nothing, and accepted when it is; vendor_options as
 *      a JSON array and vendor sent twice in a form body are ignored.
 *
 * The fixture's TEST-ONLY /mcp-test routes call the plugin's own stores
 * outside a request transaction. The fixture serves the headless client's
 * CIMD document through the plugin's resolver seams; nothing is fetched over
 * the network.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createHash, createPrivateKey, randomUUID, sign } from 'node:crypto';
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

// The fixture's TEST-ONLY headless client; runtime-app.js publishes the public
// half of the key derived from the same label in its CIMD document.
const HEADLESS_CLIENT_ID = 'https://agent.test/headless/agent.json';
const HEADLESS_KEY = createPrivateKey({
	key: Buffer.concat([
		Buffer.from('302e020100300506032b657004220420', 'hex'),
		createHash('sha256').update('mcp-runtime-app headless test key').digest(),
	]),
	format: 'der',
	type: 'pkcs8',
});

function headlessAssertion(): string {
	const now = Math.floor(Date.now() / 1000);
	const segment = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
	const signingInput = `${segment({ alg: 'EdDSA', typ: 'JWT' })}.${segment({
		iss: HEADLESS_CLIENT_ID,
		sub: HEADLESS_CLIENT_ID,
		aud: 'https://mcp.test',
		iat: now,
		exp: now + 30,
		jti: randomUUID(),
	})}`;
	return `${signingInput}.${sign(null, Buffer.from(signingInput), HEADLESS_KEY).toString('base64url')}`;
}

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

	const clientCredentialsParams = (assertion: string) => ({
		grant_type: 'client_credentials',
		client_id: HEADLESS_CLIENT_ID,
		client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
		client_assertion: assertion,
	});

	/** A form-encoded client_credentials request; `extra` pairs are appended, so a name may repeat. */
	function clientCredentials(assertion: string, extra: [string, string][] = []): Promise<Response> {
		const body = new URLSearchParams(clientCredentialsParams(assertion));
		for (const [name, value] of extra) body.append(name, value);
		return fetch(new URL('/oauth/mcp/token', ctx.harper.httpURL), {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body,
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

	test('concurrent presentations of one jti: at most one is accepted', async () => {
		const client = 'https://agent.test/concurrent-client.json';
		const single = { client_id: client, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 60 };
		strictEqual((await testRoute('/replay', single)).fresh, true, 'a single fresh presentation is accepted');
		for (let burst = 0; burst < 20; burst++) {
			const row = { client_id: client, jti: randomUUID(), exp: Math.floor(Date.now() / 1000) + 60 };
			const results = await Promise.all(Array.from({ length: 8 }, () => testRoute('/replay', row)));
			ok(results.filter((r) => r.fresh).length <= 1, 'at most one presentation is accepted');
			strictEqual((await testRoute('/replay', row)).fresh, false, 'a presentation after the burst is refused');
		}
	});

	test('client_credentials through POST /oauth/mcp/token: a fresh assertion is accepted, its replay is invalid_grant', async () => {
		const assertion = headlessAssertion();
		const first = await clientCredentials(assertion);
		const issued = await first.json();
		strictEqual(first.status, 200, JSON.stringify(issued));
		strictEqual(typeof issued.access_token, 'string');
		const replay = await clientCredentials(assertion);
		const refused = await replay.json();
		strictEqual(replay.status, 400, JSON.stringify(refused));
		strictEqual(refused.error, 'invalid_grant');
	});

	test('client_credentials with resource sent twice in a form body is judged on the first value', async () => {
		const assertion = headlessAssertion();
		const refused = await clientCredentials(assertion, [
			['resource', 'https://other.test/mcp'],
			['resource', 'https://mcp.test/mcp'],
		]);
		const refusal = await refused.json();
		strictEqual(refused.status, 400, JSON.stringify(refusal));
		strictEqual(refusal.error, 'invalid_target');
		const accepted = await clientCredentials(assertion, [
			['resource', 'https://mcp.test/mcp'],
			['resource', 'https://other.test/mcp'],
		]);
		strictEqual(accepted.status, 200, `the refusal consumed nothing: ${JSON.stringify(await accepted.json())}`);
	});

	test('client_credentials ignores vendor_options as a JSON array and vendor sent twice in a form body', async () => {
		const json = await fetch(new URL('/oauth/mcp/token', ctx.harper.httpURL), {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ ...clientCredentialsParams(headlessAssertion()), vendor_options: ['a', 'b'] }),
		});
		strictEqual(json.status, 200, JSON.stringify(await json.json()));
		const form = await clientCredentials(headlessAssertion(), [
			['vendor', 'a'],
			['vendor', 'b'],
		]);
		strictEqual(form.status, 200, JSON.stringify(await form.json()));
	});

	test('a rotation written after a revocation keeps it and every other field', async () => {
		const { familyId } = await testRoute('/seed-family');
		await testRoute('/revoke', { id: familyId });
		await testRoute('/rotate', { id: familyId, hash: 'rotated-hash' });
		const family = await testRoute('/family', { id: familyId });
		strictEqual(family.revoked, true);
		strictEqual(family.current_token_hash, 'rotated-hash');
		strictEqual(family.client_id, CLIENT_ID);
		strictEqual(family.client_auth_method, 'none');
		strictEqual(family.resource, 'https://mcp.test/mcp');
	});

	test('a form-encoded refresh with client_id sent twice is judged on the first value', async () => {
		const { refreshToken, familyId } = await testRoute('/seed-family');
		const before = await testRoute('/family', { id: familyId });
		const refreshAs = (first: string, second: string) => {
			const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: first });
			body.append('client_id', second);
			return fetch(new URL('/oauth/mcp/token', ctx.harper.httpURL), {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body,
			});
		};
		const unknownFirst = await refreshAs('unknown-client', CLIENT_ID);
		strictEqual(unknownFirst.status, 401);
		strictEqual((await unknownFirst.json()).error, 'invalid_client');
		strictEqual((await testRoute('/family', { id: familyId })).current_token_hash, before.current_token_hash);
		strictEqual((await refreshAs(CLIENT_ID, 'unknown-client')).status, 200, 'the second client_id is not used');
	});

	test('concurrent refreshes of one refresh token (characterization)', async () => {
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
		const family = await testRoute('/family', { id: familyId });
		const live = issued.filter((token) => hashOf(token) === family.current_token_hash);
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
