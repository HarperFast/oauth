/**
 * MCP OAuth Stage 7 — End-to-End Integration Test
 *
 * Drives the FULL MCP OAuth round-trip against a booted Harper fixture using a
 * hand-rolled HTTP client and a Node-owned stub upstream IdP server:
 *
 *   1. GET /mcp (no auth)         → 401 + WWW-Authenticate: Bearer resource_metadata
 *   2. Fetch PRM                  → RFC 9728 shape
 *   3. Fetch AS metadata          → RFC 8414 shape (S256, resource_parameter_supported)
 *   4. DCR (POST /register)       → client_id issued
 *   5. PKCE authorize             → 302 to stub IdP
 *   6. Stub IdP callback          → final 302 to redirect_uri?code=<mcp_code>
 *   7. Token exchange             → access_token + refresh_token
 *   8. Authenticated /mcp call    → 200 with echoed claims
 *   9. Refresh rotation           → new tokens; second use → invalid_grant
 *
 * Negative cases:
 *   - code_challenge_method=plain at /authorize → rejected
 *   - missing resource at /authorize            → rejected
 *   - garbage bearer token at /mcp             → 401
 *   - Authorization in query string            → treated as unauthenticated (401)
 *   - Upstream IdP token absent from all client-visible responses
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok, match, doesNotMatch } from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'mcp-oauth');

// ── PKCE helpers ─────────────────────────────────────────────────────────────

function generateCodeVerifier(): string {
	// RFC 7636 §4.1: 43-128 unreserved chars. base64url(32 bytes) = 43 chars.
	return randomBytes(32).toString('base64url');
}

function deriveCodeChallenge(verifier: string): string {
	// RFC 7636 §4.2: S256 = base64url(sha256(verifier))
	return createHash('sha256').update(verifier).digest('base64url');
}

// ── URL query helpers ─────────────────────────────────────────────────────────

function parseQuery(urlOrSearch: string): URLSearchParams {
	// Works with full URLs or just query strings.
	try {
		return new URL(urlOrSearch).searchParams;
	} catch {
		return new URLSearchParams(urlOrSearch.startsWith('?') ? urlOrSearch.slice(1) : urlOrSearch);
	}
}

// ── Stub IdP server ───────────────────────────────────────────────────────────

// Unique sentinel the test will check is ABSENT from all client-visible responses.
const STUB_UPSTREAM_ACCESS_TOKEN = `stub-upstream-token-${randomBytes(8).toString('hex')}`;
const STUB_USER_SUB = 'stub-user-42';
const STUB_USER_EMAIL = 'stub@example.com';

/**
 * Start a minimal HTTP server that plays the role of the upstream IdP.
 *
 * GET  /authorize — immediately redirects back to the plugin's upstream callback,
 *                   passing through the `state` and a fake `code`. The callback
 *                   path on Harper is GET /oauth/<provider>/callback.
 * POST /token     — returns a fake access_token + minimal id_token shape.
 * GET  /userinfo  — returns the stub user object.
 *
 * The redirect target (Harper's callback URL) is derived at request time from
 * the `harperBaseUrl` captured after Harper starts.
 */
function startStubIdp(getHarperBaseUrl: () => string): Promise<{
	port: number;
	close: () => Promise<void>;
}> {
	return new Promise((resolve, reject) => {
		const server = createServer((req: IncomingMessage, res: ServerResponse) => {
			const url = new URL(req.url ?? '/', `http://127.0.0.1`);
			const path = url.pathname;

			if (req.method === 'GET' && path === '/authorize') {
				// Echo state and issue a fake upstream code back to the plugin's callback.
				const state = url.searchParams.get('state') ?? '';
				const upstreamCode = `upstream-code-${randomBytes(8).toString('hex')}`;
				const callbackUrl = new URL(`/oauth/stub/callback`, getHarperBaseUrl());
				callbackUrl.searchParams.set('code', upstreamCode);
				callbackUrl.searchParams.set('state', state);
				res.writeHead(302, { Location: callbackUrl.toString() });
				res.end();
				return;
			}

			if (req.method === 'POST' && path === '/token') {
				// Return a fake upstream token. The plugin calls this to exchange the
				// upstream code; the response is consumed internally and MUST NOT reach
				// the MCP client.
				const body = JSON.stringify({
					access_token: STUB_UPSTREAM_ACCESS_TOKEN,
					token_type: 'Bearer',
					expires_in: 3600,
				});
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(body);
				return;
			}

			if (req.method === 'GET' && path === '/userinfo') {
				// The generic provider fetches userinfo with the upstream access token.
				// The `email` claim becomes the username (generic provider's usernameClaim).
				const body = JSON.stringify({
					sub: STUB_USER_SUB,
					email: STUB_USER_EMAIL,
					name: 'Stub User',
				});
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(body);
				return;
			}

			res.writeHead(404);
			res.end('not found');
		});

		server.listen(0, '127.0.0.1', () => {
			const addr = server.address();
			if (!addr || typeof addr === 'string') {
				reject(new Error('Stub IdP: unexpected address shape'));
				return;
			}
			resolve({
				port: addr.port,
				close: () =>
					new Promise<void>((res, rej) => {
						server.close((err) => (err ? rej(err) : res()));
						// Node's global fetch (undici) pools/keep-alives connections, so
						// server.close() would otherwise wait for the keep-alive timeout.
						// Force-close sockets so teardown doesn't hang.
						server.closeAllConnections();
					}),
			});
		});

		server.on('error', reject);
	});
}

// ── Test suite ────────────────────────────────────────────────────────────────

suite('MCP OAuth Stage 7: full round-trip e2e', (ctx: ContextWithHarper) => {
	let idpPort: number;
	let closeIdp: (() => Promise<void>) | undefined;

	before(async () => {
		// Start the stub IdP first so we can read its ephemeral port, then pass
		// the URLs to Harper via the `env` option (merged into the spawned child's
		// environment alongside process.env — same as env-var-substitution.test.ts).
		let harperBaseUrl = ''; // filled in after Harper starts; read lazily by stub IdP
		const idp = await startStubIdp(() => harperBaseUrl);
		idpPort = idp.port;
		closeIdp = idp.close;

		const stubBase = `http://127.0.0.1:${idpPort}`;
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: getHarperBinPath(),
			config: { logging: { stdStreams: true } },
			env: {
				STUB_IDP_AUTHORIZE_URL: `${stubBase}/authorize`,
				STUB_IDP_TOKEN_URL: `${stubBase}/token`,
				STUB_IDP_USERINFO_URL: `${stubBase}/userinfo`,
			},
		});

		harperBaseUrl = ctx.harper.httpURL;
	});

	after(async () => {
		await teardownHarper(ctx);
		// Guard: if startStubIdp rejected in before(), closeIdp is undefined —
		// calling it would throw a TypeError that masks the real setup failure.
		await closeIdp?.();
	});

	// ── Step 1: unauthenticated GET /mcp → 401 + Bearer challenge ────────────

	test('step 1: GET /mcp without auth → 401 + WWW-Authenticate: Bearer resource_metadata', async () => {
		const res = await fetch(`${ctx.harper.httpURL}/mcp`, { method: 'GET' });
		strictEqual(res.status, 401);
		const wa = res.headers.get('www-authenticate');
		ok(wa, 'WWW-Authenticate header must be present');
		match(wa!, /^Bearer /i, 'must be a Bearer challenge');
		ok(wa!.includes('resource_metadata='), 'challenge must include resource_metadata param');
		await res.body?.cancel();
	});

	// ── Step 2: Fetch PRM → RFC 9728 shape ───────────────────────────────────

	test('step 2: fetch PRM → RFC 9728 shape with resource + authorization_servers', async () => {
		// The WWW-Authenticate challenge points at the PRM. Extract it.
		const unauthedRes = await fetch(`${ctx.harper.httpURL}/mcp`, { method: 'GET' });
		const wa = unauthedRes.headers.get('www-authenticate') ?? '';
		await unauthedRes.body?.cancel();

		// Extract resource_metadata URL from the challenge header.
		// Shape: Bearer resource_metadata="https://mcp.test/.well-known/..."
		const prmMatch = /resource_metadata="([^"]+)"/.exec(wa);
		ok(prmMatch, `could not extract resource_metadata URL from: ${wa}`);
		const prmUrl = prmMatch![1];

		// The pinned issuer is https://mcp.test but requests go to localhost.
		// Fetch the PRM path against the local Harper base URL.
		const prmPath = new URL(prmUrl).pathname + new URL(prmUrl).search;
		const prmRes = await fetch(`${ctx.harper.httpURL}${prmPath}`);
		strictEqual(prmRes.status, 200, 'PRM must return 200');

		const prm = (await prmRes.json()) as any;
		ok(prm.resource, 'PRM must have resource field');
		ok(
			Array.isArray(prm.authorization_servers) && prm.authorization_servers.length > 0,
			'PRM must have authorization_servers array'
		);
	});

	// ── Step 3: Fetch AS metadata → RFC 8414 shape ───────────────────────────

	test('step 3: AS metadata → RFC 8414 shape with S256 + resource_parameter_supported', async () => {
		const res = await fetch(`${ctx.harper.httpURL}/.well-known/oauth-authorization-server`);
		strictEqual(res.status, 200, 'AS metadata must return 200');

		const meta = (await res.json()) as any;
		ok(meta.issuer, 'must have issuer');
		ok(meta.authorization_endpoint, 'must have authorization_endpoint');
		ok(meta.token_endpoint, 'must have token_endpoint');
		ok(meta.registration_endpoint, 'must have registration_endpoint');
		ok(meta.jwks_uri, 'must have jwks_uri');
		ok(
			Array.isArray(meta.code_challenge_methods_supported) && meta.code_challenge_methods_supported.includes('S256'),
			'must support S256 code challenge method'
		);
		strictEqual(meta.resource_parameter_supported, true, 'must advertise resource_parameter_supported: true');
	});

	// ── Steps 4-9: full round-trip ────────────────────────────────────────────
	// Share state across steps by running them sequentially inside a single test.

	test('steps 4-9: DCR → PKCE authorize → stub IdP → token → authenticated call → refresh rotation', async () => {
		const base = ctx.harper.httpURL;

		// ── Step 4: DCR ────────────────────────────────────────────────────────
		// Use a loopback redirect_uri. We won't run a real server; we read the
		// 302 Location to capture the code (fetch with redirect: 'manual').
		const redirectUri = 'http://127.0.0.1:19999/cb';

		const dcrRes = await fetch(`${base}/oauth/mcp/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: [redirectUri] }),
		});
		// Read the body ONCE: a fetch Response body can only be consumed once, and
		// the assertion message is evaluated eagerly (even when the assertion passes),
		// so `${await dcrRes.text()}` inline here would consume it before json() below.
		const dcrText = await dcrRes.text();
		strictEqual(dcrRes.status, 201, `DCR must return 201; got ${dcrRes.status}: ${dcrText}`);

		const dcrBody = JSON.parse(dcrText) as any;
		const clientId = dcrBody.client_id as string;
		ok(clientId, 'DCR must issue a client_id');

		// ── Step 5: PKCE authorize ──────────────────────────────────────────────
		const codeVerifier = generateCodeVerifier();
		const codeChallenge = deriveCodeChallenge(codeVerifier);
		const clientState = randomBytes(8).toString('hex');

		const authorizeUrl = new URL(`${base}/oauth/mcp/authorize`);
		authorizeUrl.searchParams.set('response_type', 'code');
		authorizeUrl.searchParams.set('client_id', clientId);
		authorizeUrl.searchParams.set('redirect_uri', redirectUri);
		authorizeUrl.searchParams.set('code_challenge', codeChallenge);
		authorizeUrl.searchParams.set('code_challenge_method', 'S256');
		authorizeUrl.searchParams.set('resource', 'https://mcp.test/mcp');
		authorizeUrl.searchParams.set('state', clientState);

		// The authorize endpoint 302s to the stub IdP. We follow redirects
		// manually so we can inspect each hop.
		const authorizeRes = await fetch(authorizeUrl.toString(), { redirect: 'manual' });
		strictEqual(authorizeRes.status, 302, 'authorize must 302 to stub IdP');
		const idpLocation = authorizeRes.headers.get('location');
		ok(idpLocation, 'authorize must redirect to a location');
		await authorizeRes.body?.cancel();

		// The Location should point at the stub IdP /authorize endpoint.
		ok(idpLocation!.includes(`127.0.0.1:${idpPort}/authorize`), `expected redirect to stub IdP, got: ${idpLocation}`);

		// ── Step 6: Stub IdP → plugin callback → final redirect to redirect_uri ──
		// The stub IdP immediately 302s to GET /oauth/stub/callback on Harper.
		// That endpoint 302s to the MCP client redirect_uri with the MCP code.
		// We follow redirects manually to capture the final Location.

		// Step 6a: "follow" the redirect to stub IdP /authorize (it 302s to callback)
		const idpAuthorizeRes = await fetch(idpLocation!, { redirect: 'manual' });
		strictEqual(idpAuthorizeRes.status, 302, 'stub IdP /authorize must 302 to Harper callback');
		const harperCallbackLocation = idpAuthorizeRes.headers.get('location');
		ok(harperCallbackLocation, 'stub IdP must redirect to harper callback');
		await idpAuthorizeRes.body?.cancel();

		// Step 6b: "follow" to the Harper callback endpoint (it mints the MCP code
		// and 302s to the client redirect_uri with code + state).
		const harperCallbackUrl = new URL(harperCallbackLocation!);
		// The stub IdP redirect target is already an absolute URL to Harper's callback.
		const callbackRes = await fetch(harperCallbackUrl.toString(), { redirect: 'manual' });
		strictEqual(callbackRes.status, 302, 'Harper callback must 302 to client redirect_uri');
		const finalLocation = callbackRes.headers.get('location');
		ok(finalLocation, 'Harper callback must redirect to a location');
		await callbackRes.body?.cancel();

		// The final redirect goes to our redirect_uri with ?code=<mcp_code>&state=...
		const finalUrl = new URL(finalLocation!);
		ok(finalUrl.href.startsWith(redirectUri), `final redirect must target redirect_uri; got: ${finalUrl.href}`);
		const mcpCode = finalUrl.searchParams.get('code');
		ok(mcpCode, 'final redirect must carry a code');
		const returnedState = finalUrl.searchParams.get('state');
		strictEqual(returnedState, clientState, 'state must round-trip unchanged');

		// ── Step 7: Token exchange ──────────────────────────────────────────────
		const tokenRes = await fetch(`${base}/oauth/mcp/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: mcpCode!,
				code_verifier: codeVerifier,
				redirect_uri: redirectUri,
				client_id: clientId,
			}).toString(),
		});
		strictEqual(tokenRes.status, 200, `token exchange must return 200; got ${tokenRes.status}`);

		const tokenBody = (await tokenRes.json()) as any;
		const accessToken = tokenBody.access_token as string;
		const refreshToken = tokenBody.refresh_token as string;
		ok(accessToken, 'token response must include access_token');
		ok(refreshToken, 'token response must include refresh_token');
		strictEqual(tokenBody.token_type, 'Bearer');

		// The upstream IdP token must NOT appear in any client-visible response.
		const tokenBodyStr = JSON.stringify(tokenBody);
		doesNotMatch(
			tokenBodyStr,
			new RegExp(STUB_UPSTREAM_ACCESS_TOKEN),
			'upstream IdP access token must not appear in token response body'
		);

		// ── Step 8: Authenticated /mcp call ────────────────────────────────────
		const mcpRes = await fetch(`${base}/mcp`, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		strictEqual(mcpRes.status, 200, `authenticated /mcp must return 200; got ${mcpRes.status}`);

		const mcpBody = (await mcpRes.json()) as any;
		strictEqual(mcpBody.ok, true);
		// The generic provider maps email → username; the MCP auth code stores that as sub.
		strictEqual(mcpBody.sub, STUB_USER_EMAIL, 'sub must be the mapped username (email)');
		strictEqual(mcpBody.aud, 'https://mcp.test/mcp', 'aud must match the configured resource');
		strictEqual(mcpBody.client_id, clientId, 'client_id must match the registered client');

		// Upstream IdP token must not appear in the /mcp response body.
		const mcpBodyStr = JSON.stringify(mcpBody);
		doesNotMatch(
			mcpBodyStr,
			new RegExp(STUB_UPSTREAM_ACCESS_TOKEN),
			'upstream IdP access token must not appear in authenticated /mcp response'
		);

		// ── Step 9: Refresh rotation ────────────────────────────────────────────
		const refreshRes1 = await fetch(`${base}/oauth/mcp/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'refresh_token',
				refresh_token: refreshToken,
				client_id: clientId,
			}).toString(),
		});
		strictEqual(refreshRes1.status, 200, `first refresh must succeed; got ${refreshRes1.status}`);

		const refreshBody1 = (await refreshRes1.json()) as any;
		ok(refreshBody1.access_token, 'first refresh must return a new access_token');
		ok(refreshBody1.refresh_token, 'first refresh must return a new refresh_token');

		// Presenting the SAME (now superseded) refresh token again must → invalid_grant.
		const refreshRes2 = await fetch(`${base}/oauth/mcp/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'refresh_token',
				refresh_token: refreshToken, // same (superseded) token
				client_id: clientId,
			}).toString(),
		});
		strictEqual(refreshRes2.status, 400, 'replayed refresh token must return 400');
		const refreshErr = (await refreshRes2.json()) as any;
		strictEqual(refreshErr.error, 'invalid_grant', 'replayed refresh must return invalid_grant');
	});

	// ── Negative cases ────────────────────────────────────────────────────────

	test('negative: code_challenge_method=plain at /authorize → rejected', async () => {
		const base = ctx.harper.httpURL;
		const redirectUri = 'http://127.0.0.1:19998/cb';

		// Register a fresh client.
		const dcrRes = await fetch(`${base}/oauth/mcp/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: [redirectUri] }),
		});
		const { client_id: clientId } = (await dcrRes.json()) as any;

		const authorizeUrl = new URL(`${base}/oauth/mcp/authorize`);
		authorizeUrl.searchParams.set('response_type', 'code');
		authorizeUrl.searchParams.set('client_id', clientId);
		authorizeUrl.searchParams.set('redirect_uri', redirectUri);
		authorizeUrl.searchParams.set('code_challenge', 'a'.repeat(43)); // valid length, wrong method
		authorizeUrl.searchParams.set('code_challenge_method', 'plain'); // disallowed by OAuth 2.1
		authorizeUrl.searchParams.set('resource', 'https://mcp.test/mcp');
		authorizeUrl.searchParams.set('state', 'test-state');

		// The endpoint must redirect to redirect_uri with error=invalid_request.
		const res = await fetch(authorizeUrl.toString(), { redirect: 'manual' });
		strictEqual(res.status, 302, 'must 302 (redirect to error)');
		const loc = res.headers.get('location') ?? '';
		await res.body?.cancel();

		ok(loc.startsWith(redirectUri), `expected redirect to redirect_uri; got: ${loc}`);
		const params = parseQuery(loc);
		const error = params.get('error');
		strictEqual(error, 'invalid_request', `plain PKCE must be rejected with error=invalid_request; got: ${loc}`);
	});

	test('negative: missing resource at /authorize → rejected', async () => {
		const base = ctx.harper.httpURL;
		const redirectUri = 'http://127.0.0.1:19997/cb';

		const dcrRes = await fetch(`${base}/oauth/mcp/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: [redirectUri] }),
		});
		const { client_id: clientId } = (await dcrRes.json()) as any;

		const codeVerifier = generateCodeVerifier();
		const codeChallenge = deriveCodeChallenge(codeVerifier);

		const authorizeUrl = new URL(`${base}/oauth/mcp/authorize`);
		authorizeUrl.searchParams.set('response_type', 'code');
		authorizeUrl.searchParams.set('client_id', clientId);
		authorizeUrl.searchParams.set('redirect_uri', redirectUri);
		authorizeUrl.searchParams.set('code_challenge', codeChallenge);
		authorizeUrl.searchParams.set('code_challenge_method', 'S256');
		// NOTE: resource param intentionally omitted

		const res = await fetch(authorizeUrl.toString(), { redirect: 'manual' });
		strictEqual(res.status, 302, 'must 302 (redirect to error)');
		const loc = res.headers.get('location') ?? '';
		await res.body?.cancel();

		ok(loc.startsWith(redirectUri), `expected redirect to redirect_uri; got: ${loc}`);
		const params = parseQuery(loc);
		const error = params.get('error');
		strictEqual(
			error,
			'invalid_target',
			`missing resource must be rejected with error=invalid_target (RFC 8707); got: ${loc}`
		);
	});

	test('negative: garbage bearer token at /mcp → 401', async () => {
		const res = await fetch(`${ctx.harper.httpURL}/mcp`, {
			headers: { Authorization: 'Bearer this-is-not-a-real-token' },
		});
		strictEqual(res.status, 401, 'garbage token must return 401');
		const wa = res.headers.get('www-authenticate');
		ok(wa?.startsWith('Bearer '), 'must return a Bearer challenge on 401');
		await res.body?.cancel();
	});

	test('negative: Authorization in query string → treated as unauthenticated (401)', async () => {
		// RFC 6750 §2.3 discourages bearer tokens in query strings, and withMCPAuth
		// only reads the Authorization header. A token in the query string must be
		// ignored — the request is treated as unauthenticated.
		const url = new URL(`${ctx.harper.httpURL}/mcp`);
		url.searchParams.set('access_token', 'this-should-be-ignored');
		const res = await fetch(url.toString(), { method: 'GET' });
		strictEqual(res.status, 401, 'query-string token must be ignored → 401');
		await res.body?.cancel();
	});
});
