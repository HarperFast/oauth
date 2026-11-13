/**
 * Integration test: MCP authorization through the application's own session
 * (mcp.sessionLogin), against a real Harper with no upstream providers.
 *
 * Proves what unit tests mock: Harper core resolves the cookie session a
 * password sign-in created on a top-level authorize GET (no Origin, so the
 * cookie name derives from Host) and on the confirm POST (Origin), and the
 * resulting code redeems to a token for that user on a withMCPAuth route.
 * Requests go through node:http so the Host header can be the issuer's host,
 * as a browser on that origin would send it.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok, match } from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import {
	setupHarperWithFixture,
	teardownHarper,
	sendOperation,
	type ContextWithHarper,
} from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);
const fixturePath = join(import.meta.dirname, 'fixtures', 'mcp-session-login-app');
const ISSUER = 'https://mcp.test';
const USERNAME = 'session-user';
const PASSWORD = randomBytes(12).toString('hex');
const REDIRECT_URI = 'http://127.0.0.1:19998/cb';

interface Reply {
	status: number;
	headers: Record<string, string | string[] | undefined>;
	body: string;
}

function send(
	base: string,
	method: string,
	path: string,
	{ headers = {}, body }: { headers?: Record<string, string>; body?: string } = {}
): Promise<Reply> {
	const url = new URL(path, base);
	return new Promise((resolve, reject) => {
		const req = httpRequest(
			{
				host: url.hostname,
				port: url.port,
				method,
				path: url.pathname + url.search,
				headers: { host: 'mcp.test', ...headers, ...(body ? { 'content-length': Buffer.byteLength(body) } : {}) },
			},
			(res) => {
				let text = '';
				res.setEncoding('utf8');
				res.on('data', (chunk) => (text += chunk));
				res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: text }));
			}
		);
		req.on('error', reject);
		if (body) req.write(body);
		req.end();
	});
}

/** name=value pairs from Set-Cookie headers, for a Cookie header. */
function cookiesFrom(reply: Reply): string[] {
	const setCookie = reply.headers['set-cookie'];
	return (Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : []).map((cookie) => cookie.split(';')[0]);
}

suite('MCP sessionLogin: password session → consent → token', (ctx: ContextWithHarper) => {
	before(async () => {
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: join(dirname(require.resolve('harper')), 'bin', 'harper.js'),
			config: { logging: { stdStreams: true } },
		});
		await sendOperation(ctx.harper, {
			operation: 'add_user',
			username: USERNAME,
			password: PASSWORD,
			active: true,
			role: 'super_user',
		});
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('authorizes a client for the signed-in user, once', async () => {
		const base = ctx.harper.httpURL;
		const register = await send(base, 'POST', '/oauth/mcp/register', {
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ redirect_uris: [REDIRECT_URI], client_name: 'Session test client' }),
		});
		strictEqual(register.status, 201, register.body);
		const clientId = JSON.parse(register.body).client_id;

		const verifier = randomBytes(32).toString('base64url');
		const authorizePath =
			'/oauth/mcp/authorize?' +
			new URLSearchParams({
				response_type: 'code',
				client_id: clientId,
				redirect_uri: REDIRECT_URI,
				code_challenge: createHash('sha256').update(verifier).digest('base64url'),
				code_challenge_method: 'S256',
				resource: `${ISSUER}/mcp`,
				state: 'client-state',
			}).toString();

		const signedOut = await send(base, 'GET', authorizePath);
		strictEqual(signedOut.status, 302, signedOut.body);
		match(String(signedOut.headers.location), /^\/sign-in\?return=%2Foauth%2Fmcp%2Fauthorize%3F/);

		const signIn = await send(base, 'POST', '/SignIn', {
			headers: { 'content-type': 'application/json', 'origin': ISSUER },
			body: JSON.stringify({ username: USERNAME, password: PASSWORD }),
		});
		strictEqual(signIn.status, 200, signIn.body);
		const sessionCookies = cookiesFrom(signIn);
		ok(
			sessionCookies.some((cookie) => cookie.startsWith('mcp_test-hdb-session=')),
			String(sessionCookies)
		);

		const consent = await send(base, 'GET', authorizePath, { headers: { cookie: sessionCookies.join('; ') } });
		strictEqual(consent.status, 200, consent.body);
		match(consent.body, new RegExp(`Signed in as <strong>${USERNAME}</strong>`));
		const token = consent.body.match(/name="consent_token" value="([^"]+)"/)?.[1];
		ok(token, 'consent page carries a consent token');
		const cookies = [...sessionCookies, ...cookiesFrom(consent)].join('; ');

		const approve = (origin: string) =>
			send(base, 'POST', '/oauth/mcp/confirm', {
				headers: { 'content-type': 'application/x-www-form-urlencoded', origin, 'cookie': cookies },
				body: new URLSearchParams({ consent_token: token!, decision: 'approve' }).toString(),
			});

		strictEqual((await approve('https://evil.test')).status, 400);
		const approved = await approve(ISSUER);
		strictEqual(approved.status, 302, approved.body);
		const callback = new URL(String(approved.headers.location));
		strictEqual(callback.origin + callback.pathname, REDIRECT_URI);
		strictEqual(callback.searchParams.get('state'), 'client-state');
		const code = callback.searchParams.get('code');
		ok(code, 'redirect carries a code');
		strictEqual((await approve(ISSUER)).status, 400, 'a consent approves once');

		const tokenReply = await send(base, 'POST', '/oauth/mcp/token', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: code!,
				redirect_uri: REDIRECT_URI,
				client_id: clientId,
				code_verifier: verifier,
				resource: `${ISSUER}/mcp`,
			}).toString(),
		});
		strictEqual(tokenReply.status, 200, tokenReply.body);
		const accessToken = JSON.parse(tokenReply.body).access_token;

		const mcp = await send(base, 'GET', '/mcp', { headers: { authorization: `Bearer ${accessToken}` } });
		strictEqual(mcp.status, 200, mcp.body);
		strictEqual(JSON.parse(mcp.body).sub, USERNAME);
	});
});
