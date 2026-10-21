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
 * The fixture's TEST-ONLY /mcp-test routes call the plugin's own stores
 * outside a request transaction. The fixture serves the headless client's
 * CIMD document through the plugin's resolver seams; nothing is fetched over
 * the network.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createHash, createPrivateKey, randomBytes, randomUUID, sign } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setTimeout as sleep } from 'node:timers/promises';
import {
	setupHarperWithFixture,
	teardownHarper,
	sendOperation,
	type ContextWithHarper,
	type HarperTestContext,
	type StartedHarperTestContext,
} from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return process.env.HARPER_BIN_PATH || join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

function harperSupportsBearerValidator(binPath: string): boolean {
	return existsSync(join(dirname(binPath), '..', 'security', 'bearerValidators.js'));
}

function formParserKeepsRepeatedValues(): boolean {
	const parserPath = join(dirname(dirname(getHarperBinPath())), 'server', 'serverHelpers', 'contentTypes.js');
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

suite('Native application MCP: the OAuth resource is not a generated tool (#281)', (ctx) => {
	const harperBinPath = process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT || getHarperBinPath();
	// Bounds each request and its body read; the polling deadlines below cannot interrupt a stalled await.
	const requestTimeoutMs = 10_000;
	let configPath: string;
	let configuredYaml: string;
	let authorization: string;
	const harperCtx: HarperTestContext = ctx;
	let started: StartedHarperTestContext;

	before(async () => {
		started = await setupHarperWithFixture(harperCtx, fixturePath, {
			harperBinPath,
			config: { logging: { stdStreams: true }, mcp: { application: { mountPath: '/mcp' } } },
		});
		configPath = join(started.harper.dataRootDir, 'components', 'mcp-runtime-app', 'config.yaml');
		configuredYaml = await readFile(configPath, 'utf8');
		authorization = `Basic ${Buffer.from(`${started.harper.admin.username}:${started.harper.admin.password}`).toString('base64')}`;
	});

	after(async () => {
		if (started) {
			await teardownHarper(started);
			return;
		}
		// Setup rejected. After copying the fixture the helper has recorded only the data root, not a
		// process or address teardownHarper could release, so remove that directory alone.
		const dataRootDir = harperCtx.harper?.dataRootDir;
		if (dataRootDir) await rm(dataRootDir, { recursive: true, force: true, maxRetries: 10 });
	});

	async function rpc(
		sessionId: string | undefined,
		message: object,
		authHeader: string = authorization
	): Promise<Response> {
		return fetch(new URL('/mcp', started.harper.httpURL), {
			method: 'POST',
			headers: {
				'Authorization': authHeader,
				'Content-Type': 'application/json',
				'Accept': 'application/json, text/event-stream',
				...(sessionId && { 'mcp-session-id': sessionId, 'mcp-protocol-version': '2025-06-18' }),
			},
			body: JSON.stringify({ jsonrpc: '2.0', ...message }),
			signal: AbortSignal.timeout(requestTimeoutMs),
		});
	}

	async function request(
		sessionId: string,
		method: string,
		params: object,
		authHeader: string = authorization
	): Promise<any> {
		let res: Response;
		let body: any;
		try {
			res = await rpc(sessionId, { id: randomUUID(), method, params }, authHeader);
			body = await res.json();
		} catch (error) {
			throw new Error(`${method}: no complete JSON-RPC response`, { cause: error });
		}
		strictEqual(res.status, 200, `${method}: ${JSON.stringify(body)}`);
		return body;
	}

	let provisionedMcpUser = false;
	async function completeMcpOAuthFlow(): Promise<string> {
		if (!provisionedMcpUser) {
			await sendOperation(started.harper, {
				operation: 'add_user',
				username: 'mcp-oauth-user',
				password: 'McpOauthUserP@ss123!',
				active: true,
				role: 'super_user',
			});
			provisionedMcpUser = true;
		}
		const seedRes = await fetch(new URL('/mcp-test/seed-family', started.harper.httpURL));
		strictEqual(seedRes.status, 200);
		await seedRes.body?.cancel();

		const redirectUri = 'https://client.test/cb';
		const codeVerifier = randomBytes(32).toString('base64url');
		const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
		const clientState = randomBytes(8).toString('hex');

		const authorizeUrl = new URL('/oauth/mcp/authorize', started.harper.httpURL);
		authorizeUrl.searchParams.set('response_type', 'code');
		authorizeUrl.searchParams.set('client_id', CLIENT_ID);
		authorizeUrl.searchParams.set('redirect_uri', redirectUri);
		authorizeUrl.searchParams.set('code_challenge', codeChallenge);
		authorizeUrl.searchParams.set('code_challenge_method', 'S256');
		authorizeUrl.searchParams.set('resource', 'https://mcp.test/mcp');
		authorizeUrl.searchParams.set('state', clientState);

		const authorizeRes = await fetch(authorizeUrl, { redirect: 'manual' });
		strictEqual(authorizeRes.status, 302, 'MCP authorize must redirect to upstream IdP');
		const idpLocation = authorizeRes.headers.get('location');
		ok(idpLocation, 'MCP authorize must set Location');
		const browserCookie = authorizeRes.headers.getSetCookie().find((c) => c.startsWith('__Host-oauth_browser'));
		ok(browserCookie, 'MCP authorize must set __Host-oauth_browser cookie');
		const browserCookiePair = browserCookie!.split(';')[0];
		await authorizeRes.body?.cancel();

		const upstreamState = new URL(idpLocation!).searchParams.get('state');
		ok(upstreamState, 'upstream redirect must carry state');

		const callbackUrl = new URL('/oauth/test/callback', started.harper.httpURL);
		callbackUrl.searchParams.set('code', 'upstream-code-279');
		callbackUrl.searchParams.set('state', upstreamState!);
		const callbackRes = await fetch(callbackUrl, {
			redirect: 'manual',
			headers: { cookie: browserCookiePair },
		});
		strictEqual(callbackRes.status, 302, 'OAuth callback must redirect back to MCP client redirect_uri');
		const finalLocation = callbackRes.headers.get('location');
		ok(finalLocation, 'OAuth callback must set Location');
		await callbackRes.body?.cancel();

		const mcpCode = new URL(finalLocation!).searchParams.get('code');
		ok(mcpCode, 'final redirect must carry an MCP authorization code');

		const tokenRes = await fetch(new URL('/oauth/mcp/token', started.harper.httpURL), {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: mcpCode!,
				code_verifier: codeVerifier,
				redirect_uri: redirectUri,
				client_id: CLIENT_ID,
			}),
		});
		const tokenBody = (await tokenRes.json()) as any;
		strictEqual(tokenRes.status, 200, `MCP token exchange must return 200: ${JSON.stringify(tokenBody)}`);
		ok(typeof tokenBody.access_token === 'string', 'token response must include access_token');
		return tokenBody.access_token;
	}

	async function mintTestToken(params: Record<string, string | number>): Promise<string> {
		const url = new URL('/mcp-test/mint-token', started.harper.httpURL);
		for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
		const res = await fetch(url);
		strictEqual(res.status, 200);
		return ((await res.json()) as any).accessToken;
	}

	async function assertOAuthToolsExcluded(label: string): Promise<void> {
		const init = await rpc(undefined, {
			id: randomUUID(),
			method: 'initialize',
			params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'oauth-281', version: '1' } },
		});
		const sessionId = init.headers.get('mcp-session-id');
		ok(sessionId, `initialize: ${init.status} ${await init.text()}`);
		strictEqual((await rpc(sessionId, { method: 'notifications/initialized' })).status, 202);

		// Harper 5.1 rebuilds application tools on a schema-change event after component load.
		const deadline = Date.now() + 20_000;
		let list = await request(sessionId, 'tools/list', {});
		while (
			!list.result.tools.some((tool: { name: string }) => tool.name === 'get_NativeMcpControl') &&
			Date.now() < deadline
		) {
			await sleep(250);
			list = await request(sessionId, 'tools/list', {});
		}
		const names: string[] = list.result.tools.map((tool: { name: string }) => tool.name);
		strictEqual(list.result.nextCursor, undefined, `${label}: one page lists every tool`);
		ok(names.includes('get_NativeMcpControl'), `${label}: control tool listed (${names})`);
		const control = await request(sessionId, 'tools/call', { name: 'get_NativeMcpControl', arguments: {} });
		ok(
			!control.result?.isError && JSON.stringify(control.result).includes('native-mcp'),
			`${label}: control tool callable: ${JSON.stringify(control)}`
		);

		for (const name of ['get_oauth', 'create_oauth']) {
			ok(!names.includes(name), `${label}: ${name} must not be a native MCP tool (${names})`);
			const call = await request(sessionId, 'tools/call', { name, arguments: {} });
			strictEqual(call.error?.code, -32601, `${label}: ${name} must be an unknown tool: ${JSON.stringify(call)}`);
		}
	}

	async function waitForLogin(expected: 'redirect' | 'fallback'): Promise<void> {
		const deadline = Date.now() + 30_000;
		let last = '';
		while (Date.now() < deadline) {
			let res: Response;
			let text: string;
			try {
				res = await fetch(new URL('/oauth/test/login', started.harper.httpURL), {
					redirect: 'manual',
					signal: AbortSignal.timeout(requestTimeoutMs),
				});
				text = await res.text();
			} catch (error) {
				throw new Error(`REST login (${expected}): no complete response (last: ${last})`, { cause: error });
			}
			last = `${res.status} ${res.headers.get('location') ?? text.slice(0, 200)}`;
			if (expected === 'redirect') {
				if (last.startsWith('302 http://idp.test/authorize?')) return;
			} else if (res.status === 200) {
				// The fallback's `{ status: 503, body }` has no headers, so Harper serializes the whole object.
				const payload = JSON.parse(text);
				if (payload.status === 503 && payload.body?.error === 'No valid OAuth providers configured') return;
			}
			await sleep(250);
		}
		throw new Error(`REST login did not reach ${expected} within 30s (last: ${last})`);
	}

	test('excludes get_oauth/create_oauth at startup and keeps REST login', { timeout: 120_000 }, async (t) => {
		const { version } = JSON.parse(await readFile(join(dirname(harperBinPath), '..', '..', 'package.json'), 'utf8'));
		t.diagnostic(`Harper ${version}, Node ${process.version}`);
		await waitForLogin('redirect');
		await assertOAuthToolsExcluded('startup');
	});

	test(
		'serves the no-provider REST error while OAuth tools remain absent from the current catalog',
		{ timeout: 120_000 },
		async () => {
			const noProviderYaml = configuredYaml.replace(/^ {2}providers:\n(?: {4}.*\n)+/m, '  providers: {}\n');
			ok(noProviderYaml !== configuredYaml, 'fixture config has a providers block');
			// Replace the watched file atomically: an in-place write can be read while truncated, which
			// OptionsWatcher reports as remove then ready, never as the change this plugin listens for.
			await writeFile(`${configPath}.tmp`, noProviderYaml);
			await rename(`${configPath}.tmp`, configPath);
			await waitForLogin('fallback');
			await assertOAuthToolsExcluded('no-provider reload');
		}
	);

	test(
		'restores REST login while OAuth tools remain absent from the current catalog',
		{ timeout: 120_000 },
		async () => {
			await writeFile(`${configPath}.tmp`, configuredYaml);
			await rename(`${configPath}.tmp`, configPath);
			await waitForLogin('redirect');
			await assertOAuthToolsExcluded('provider reload');
		}
	);

	test(
		'withMCPAuth populates request.user for a provisioned Harper user and leaves role-less subjects without request.user (#279)',
		{ timeout: 120_000 },
		async () => {
			const accessToken = await completeMcpOAuthFlow();
			const provisionedRes = await fetch(new URL('/mcp-custom', started.harper.httpURL), {
				headers: { Authorization: `Bearer ${accessToken}` },
				signal: AbortSignal.timeout(requestTimeoutMs),
			});
			strictEqual(provisionedRes.status, 200);
			const provisionedBody = (await provisionedRes.json()) as any;
			strictEqual(provisionedBody.user, 'mcp-oauth-user');
			strictEqual(provisionedBody.hasRolePermission, true);
			strictEqual(provisionedBody.mcpSub, 'mcp-oauth-user');

			const unprovisionedToken = await mintTestToken({ sub: 'unprovisioned-agent' });
			const unprovisionedRes = await fetch(new URL('/mcp-custom', started.harper.httpURL), {
				headers: { Authorization: `Bearer ${unprovisionedToken}` },
				signal: AbortSignal.timeout(requestTimeoutMs),
			});
			strictEqual(unprovisionedRes.status, 200);
			const unprovisionedBody = (await unprovisionedRes.json()) as any;
			strictEqual(unprovisionedBody.user, null, 'role-less getUser view must not populate request.user');
			strictEqual(unprovisionedBody.hasRolePermission, false);
			strictEqual(unprovisionedBody.mcpSub, 'unprovisioned-agent');
		}
	);

	test(
		'completes the plugin OAuth flow and authenticates native /mcp tools/list and tools/call via registerBearerValidator (#279)',
		{ timeout: 120_000 },
		async (t) => {
			const capsRes = await fetch(new URL('/mcp-test/capabilities', started.harper.httpURL));
			strictEqual(capsRes.status, 200);
			const caps = (await capsRes.json()) as { hasBearerValidator: boolean };
			strictEqual(
				caps.hasBearerValidator,
				harperSupportsBearerValidator(harperBinPath),
				'runtime server.registerBearerValidator capability matches installed Harper binary'
			);
			if (
				process.env.REQUIRE_BEARER_VALIDATOR &&
				process.env.REQUIRE_BEARER_VALIDATOR !== '0' &&
				process.env.REQUIRE_BEARER_VALIDATOR !== 'false'
			) {
				ok(
					caps.hasBearerValidator,
					'REQUIRE_BEARER_VALIDATOR is set, so the Harper under test must expose server.registerBearerValidator'
				);
			}
			if (!caps.hasBearerValidator) {
				t.skip('installed Harper does not expose server.registerBearerValidator (HarperFast/harper#3313)');
				return;
			}

			const accessToken = await completeMcpOAuthFlow();
			const bearerAuth = `Bearer ${accessToken}`;

			const init = await rpc(
				undefined,
				{
					id: randomUUID(),
					method: 'initialize',
					params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'oauth-279', version: '1' } },
				},
				bearerAuth
			);
			const sessionId = init.headers.get('mcp-session-id');
			ok(sessionId, `initialize with plugin Bearer token: ${init.status} ${await init.text()}`);
			strictEqual((await rpc(sessionId, { method: 'notifications/initialized' }, bearerAuth)).status, 202);

			const list = await request(sessionId, 'tools/list', {}, bearerAuth);
			const names: string[] = list.result.tools.map((tool: { name: string }) => tool.name);
			ok(names.includes('get_NativeMcpControl'), `tools/list with plugin Bearer token lists control tool (${names})`);

			const control = await request(
				sessionId,
				'tools/call',
				{ name: 'get_NativeMcpControl', arguments: {} },
				bearerAuth
			);
			const controlText = JSON.stringify(control.result);
			ok(
				!control.result?.isError && controlText.includes('native-mcp') && controlText.includes('mcp-oauth-user'),
				`tools/call executes as mapped Harper user mcp-oauth-user: ${JSON.stringify(control)}`
			);

			const wrongAudToken = await mintTestToken({ aud: 'https://other.test/mcp' });
			const wrongAudRes = await rpc(
				undefined,
				{ id: randomUUID(), method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } },
				`Bearer ${wrongAudToken}`
			);
			strictEqual(wrongAudRes.status, 401, 'wrong-audience MCP token must be rejected with 401');
			await wrongAudRes.body?.cancel();

			const expiredToken = await mintTestToken({ ttl: -60 });
			const expiredRes = await rpc(
				undefined,
				{ id: randomUUID(), method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } },
				`Bearer ${expiredToken}`
			);
			strictEqual(expiredRes.status, 401, 'expired MCP token must be rejected with 401');
			await expiredRes.body?.cancel();

			const nonMcpRes = await fetch(new URL('/NativeMcpControl', started.harper.httpURL), {
				headers: { Authorization: bearerAuth },
				signal: AbortSignal.timeout(requestTimeoutMs),
			});
			strictEqual(nonMcpRes.status, 401, 'MCP token scoped to /mcp must be rejected on non-MCP route');
			await nonMcpRes.body?.cancel();

			const opTokens = (await sendOperation(started.harper, {
				operation: 'create_authentication_tokens',
				username: 'mcp-oauth-user',
				password: 'McpOauthUserP@ss123!',
			})) as { operation_token: string };
			ok(typeof opTokens?.operation_token === 'string', 'Harper issued an operation_token');
			const opRes = await fetch(new URL('/NativeMcpControl', started.harper.httpURL), {
				headers: { Authorization: `Bearer ${opTokens.operation_token}` },
				signal: AbortSignal.timeout(requestTimeoutMs),
			});
			strictEqual(opRes.status, 200, 'Harper operation_token must remain unaffected by MCP Bearer validator');
			await opRes.body?.cancel();

			const mcpDisabledYaml = configuredYaml.replace('    enabled: true\n', '    enabled: false\n');
			ok(mcpDisabledYaml !== configuredYaml, 'fixture config has mcp.enabled: true');
			try {
				await writeFile(`${configPath}.tmp`, mcpDisabledYaml);
				await rename(`${configPath}.tmp`, configPath);
				const disableDeadline = Date.now() + 30_000;
				while (Date.now() < disableDeadline) {
					const wk = await fetch(new URL('/.well-known/oauth-protected-resource/mcp', started.harper.httpURL), {
						signal: AbortSignal.timeout(requestTimeoutMs),
					});
					await wk.body?.cancel();
					if (wk.status === 404) break;
					await sleep(200);
				}
				const disabledRes = await rpc(
					undefined,
					{ id: randomUUID(), method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } },
					bearerAuth
				);
				strictEqual(
					disabledRes.status,
					401,
					'disabling mcp.enabled on reload must dispose the Bearer validator and reject previously used tokens (authCacheable: false)'
				);
				await disabledRes.body?.cancel();
			} finally {
				await writeFile(`${configPath}.tmp`, configuredYaml);
				await rename(`${configPath}.tmp`, configPath);
				const restoreDeadline = Date.now() + 30_000;
				while (Date.now() < restoreDeadline) {
					const wk = await fetch(new URL('/.well-known/oauth-protected-resource/mcp', started.harper.httpURL), {
						signal: AbortSignal.timeout(requestTimeoutMs),
					});
					await wk.body?.cancel();
					if (wk.status === 200) break;
					await sleep(200);
				}
			}
		}
	);
});
