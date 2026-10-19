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
 *   5. A form-encoded refresh with client_id sent twice uses the first value
 *      on the old Harper parser; a parser with HarperFast/harper#2953 makes
 *      either ordering invalid_request.
 *   6. A headless client_credentials grant through POST /oauth/mcp/token, which
 *      runs inside Harper's REST request transaction: a fresh assertion is
 *      accepted, and its replay is refused with invalid_grant.
 *   7. On that grant, a form body with resource sent twice uses the first
 *      value on the old parser; a parser with HarperFast/harper#2953 checks
 *      both values. Vendor_options as a JSON array and vendor sent twice in
 *      a form body are ignored.
 *
 * A second suite boots the same fixture with Harper's native application MCP
 * profile enabled and checks that the plugin's `oauth` resource is excluded
 * from the generated tools (#281) at startup and across provider-state
 * reloads, while a TEST-ONLY control resource stays listed and callable and
 * the REST surface keeps its login redirect and no-provider error payload.
 *
 * The fixture's TEST-ONLY /mcp-test routes call the plugin's own stores
 * outside a request transaction. The fixture serves the headless client's
 * CIMD document through the plugin's resolver seams; nothing is fetched over
 * the network.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createHash, createPrivateKey, randomUUID, sign } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setTimeout as sleep } from 'node:timers/promises';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

/** HARPER_INTEGRATION_TEST_INSTALL_SCRIPT selects an explicit Harper build; otherwise the locked one. */
function selectedHarperBinPath(): string {
	return process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT || getHarperBinPath();
}

function formParserKeepsRepeatedValues(): boolean {
	const parserPath = join(dirname(require.resolve('harper')), 'server', 'serverHelpers', 'contentTypes.js');
	const { getDeserializer } = require(parserPath);
	const parsed = getDeserializer('application/x-www-form-urlencoded')(
		'resource=first&resource=second&client_id=first&client_id=second'
	);
	if (Array.isArray(parsed.resource)) {
		strictEqual(parsed.resource.join(','), 'first,second');
		strictEqual(parsed.client_id.join(','), 'first,second');
		return true;
	}
	strictEqual(parsed.resource, 'first', 'the installed parser has the old repeated-field shape');
	strictEqual(parsed.client_id, 'first', 'the installed parser has the old repeated-field shape');
	return false;
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

	test('client_credentials with resource sent twice follows the installed form parser', async () => {
		const keepsRepeats = formParserKeepsRepeatedValues();
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
		const outcome = await accepted.json();
		strictEqual(accepted.status, keepsRepeats ? 400 : 200, JSON.stringify(outcome));
		if (keepsRepeats) strictEqual(outcome.error, 'invalid_target');
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

	test('a form-encoded refresh with client_id sent twice follows the installed form parser', async () => {
		const keepsRepeats = formParserKeepsRepeatedValues();
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
		strictEqual(unknownFirst.status, keepsRepeats ? 400 : 401);
		strictEqual((await unknownFirst.json()).error, keepsRepeats ? 'invalid_request' : 'invalid_client');
		strictEqual((await testRoute('/family', { id: familyId })).current_token_hash, before.current_token_hash);
		const clientFirst = await refreshAs(CLIENT_ID, 'unknown-client');
		strictEqual(clientFirst.status, keepsRepeats ? 400 : 200);
		if (keepsRepeats) strictEqual((await clientFirst.json()).error, 'invalid_request');
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

suite('Native application MCP: the OAuth resource is not a generated tool (#281)', (ctx: ContextWithHarper) => {
	const harperBinPath = selectedHarperBinPath();
	const MCP_ACCEPT = 'application/json, text/event-stream';
	const MCP_PROTOCOL_VERSION = '2025-06-18';
	let configPath: string;
	let configuredYaml: string;
	let authorization: string;
	let nextId = 1;

	before(async () => {
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath,
			config: { logging: { stdStreams: true }, mcp: { application: { mountPath: '/mcp' } } },
		});
		configPath = join(ctx.harper.dataRootDir, 'components', 'mcp-runtime-app', 'config.yaml');
		configuredYaml = await readFile(configPath, 'utf8');
		authorization = `Basic ${Buffer.from(`${ctx.harper.admin.username}:${ctx.harper.admin.password}`).toString('base64')}`;
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	async function rpc(sessionId: string | undefined, method: string, params: object = {}): Promise<Response> {
		const headers: Record<string, string> = {
			'Authorization': authorization,
			'Content-Type': 'application/json',
			'Accept': MCP_ACCEPT,
		};
		if (sessionId) {
			headers['mcp-session-id'] = sessionId;
			headers['mcp-protocol-version'] = MCP_PROTOCOL_VERSION;
		}
		return fetch(new URL('/mcp', ctx.harper.httpURL), {
			method: 'POST',
			headers,
			body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
		});
	}

	async function openSession(): Promise<string> {
		const res = await rpc(undefined, 'initialize', {
			protocolVersion: MCP_PROTOCOL_VERSION,
			capabilities: {},
			clientInfo: { name: 'oauth-281-native-mcp-check', version: '1.0.0' },
		});
		const body = await res.json();
		strictEqual(res.status, 200, `initialize: ${res.status} ${JSON.stringify(body)}`);
		ok(body.result?.capabilities?.tools, `native MCP must advertise tools: ${JSON.stringify(body)}`);
		const sessionId = res.headers.get('mcp-session-id');
		ok(sessionId, 'initialize returns an MCP session id');
		const initialized = await fetch(new URL('/mcp', ctx.harper.httpURL), {
			method: 'POST',
			headers: {
				'Authorization': authorization,
				'Content-Type': 'application/json',
				'Accept': MCP_ACCEPT,
				'mcp-session-id': sessionId,
				'mcp-protocol-version': MCP_PROTOCOL_VERSION,
			},
			body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
		});
		strictEqual(initialized.status, 202, 'notifications/initialized is accepted');
		await initialized.arrayBuffer();
		return sessionId;
	}

	async function toolNames(sessionId: string): Promise<string[]> {
		const names: string[] = [];
		let cursor: string | undefined;
		do {
			const res = await rpc(sessionId, 'tools/list', cursor ? { cursor } : {});
			const body = await res.json();
			strictEqual(res.status, 200, `tools/list: ${JSON.stringify(body)}`);
			ok(Array.isArray(body.result?.tools), `tools/list result: ${JSON.stringify(body)}`);
			for (const tool of body.result.tools) names.push(tool.name);
			cursor = body.result.nextCursor;
		} while (cursor);
		return names;
	}

	async function callTool(sessionId: string, name: string): Promise<any> {
		const res = await rpc(sessionId, 'tools/call', { name, arguments: {} });
		strictEqual(res.status, 200, `tools/call ${name}: ${res.status}`);
		return res.json();
	}

	/** Positive control first, so an absent oauth tool is attributable to its export metadata, not to MCP being off. */
	async function assertOAuthToolsExcluded(label: string): Promise<void> {
		const sessionId = await openSession();
		// Harper rebuilds the generated tools asynchronously after component registration.
		const deadline = Date.now() + 20_000;
		let names = await toolNames(sessionId);
		while (!names.includes('get_NativeMcpControl') && Date.now() < deadline) {
			await sleep(250);
			names = await toolNames(sessionId);
		}
		ok(names.includes('get_NativeMcpControl'), `${label}: control tool listed (${names.join(', ')})`);
		const control = await callTool(sessionId, 'get_NativeMcpControl');
		ok(!control.error && !control.result?.isError, `${label}: control tool callable: ${JSON.stringify(control)}`);
		ok(JSON.stringify(control.result).includes('native-mcp'), `${label}: control tool reached its handler`);

		for (const name of ['get_oauth', 'create_oauth']) {
			ok(!names.includes(name), `${label}: ${name} must not be a native MCP tool (${names.join(', ')})`);
			const call = await callTool(sessionId, name);
			ok(!call.result, `${label}: ${name} must not be invocable: ${JSON.stringify(call)}`);
			strictEqual(call.error?.code, -32601, `${label}: ${name} is an unknown tool: ${JSON.stringify(call)}`);
			ok(String(call.error?.message).includes(name), `${label}: ${name} refused as unknown`);
		}
	}

	async function loginResponse(): Promise<Response> {
		return fetch(new URL('/oauth/test/login', ctx.harper.httpURL), { redirect: 'manual' });
	}

	/**
	 * Which `oauth` registration REST is serving. The no-provider fallback's `{ status: 503, body }`
	 * carries no headers, so Harper serializes the whole object as a JSON 200 payload.
	 */
	async function oauthRestState(): Promise<string> {
		const res = await loginResponse();
		if (res.status === 302) {
			await res.arrayBuffer();
			const location = new URL(res.headers.get('location') ?? '');
			return location.origin + location.pathname === 'http://idp.test/authorize' ? 'provider' : `302 ${location}`;
		}
		const text = await res.text();
		try {
			const payload = JSON.parse(text);
			if (payload.status === 503 && payload.body?.error === 'No valid OAuth providers configured') return 'fallback';
		} catch {}
		return `${res.status} ${text.slice(0, 200)}`;
	}

	/**
	 * Waits for REST to serve `state`. With `yaml`, rewrites the config until REST reflects it: the
	 * file watcher can coalesce writes that land close together.
	 */
	async function waitForRestState(state: string, yaml?: string): Promise<void> {
		const deadline = Date.now() + 30_000;
		let last = '';
		let nextWrite = 0;
		while (Date.now() < deadline) {
			if (yaml !== undefined && Date.now() >= nextWrite) {
				await writeFile(configPath, yaml);
				nextWrite = Date.now() + 2_000;
			}
			last = await oauthRestState().catch((error) => `${error} (${error?.cause?.code ?? error?.cause})`);
			if (last === state) return;
			await sleep(250);
		}
		throw new Error(`REST did not reach the ${state} state within 30s (last: ${last})`);
	}

	function noProviderYaml(): string {
		const lines = configuredYaml.split('\n');
		const start = lines.indexOf('  providers:');
		const end = lines.indexOf('  mcp:');
		ok(start > 0 && end > start, 'fixture config has a providers block before mcp');
		return [...lines.slice(0, start), '  providers: {}', ...lines.slice(end)].join('\n');
	}

	test('excludes get_oauth/create_oauth at startup and keeps REST login', async (t) => {
		const harperPackage = JSON.parse(await readFile(join(dirname(harperBinPath), '..', '..', 'package.json'), 'utf8'));
		t.diagnostic(`Harper ${harperPackage.version}, Node ${process.version}`);
		await waitForRestState('provider');
		await assertOAuthToolsExcluded('startup');
	});

	test('a reload to no providers keeps the OAuth fallback out of native MCP and serves its REST error', async () => {
		await waitForRestState('fallback', noProviderYaml());
		await assertOAuthToolsExcluded('no-provider reload');
	});

	test('restoring providers restores login without restoring the generated OAuth tools', async () => {
		await waitForRestState('provider', configuredYaml);
		await assertOAuthToolsExcluded('provider reload');
	});
});
