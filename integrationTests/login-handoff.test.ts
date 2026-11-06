/**
 * Integration tests: sign-in handoff to an allowlisted origin
 * (postLoginRedirectOrigins, HarperFast/central-manager#911).
 *
 * Against a real Harper, this proves the part unit tests can only mock: Harper
 * core names the session cookie after the request's `Origin`, so a redeem
 * called with the allowlisted page's `Origin` creates THAT origin's session
 * (`<origin minus scheme, first non-word char → _>-hdb-session`), and the
 * callback on the registered redirect URI creates none.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok, match } from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { setupHarperWithFixture, teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'login-handoff-app');

const PREVIEW = 'https://pr-12.app.preview.test';
const OTHER_PREVIEW = 'https://pr-13.app.preview.test';
// Harper core's sessionCookiePrefix: scheme stripped, the FIRST non-word char replaced.
const PREVIEW_COOKIE = 'pr_12.app.preview.test-hdb-session=';
const EMAIL = 'preview-user@nowhere.test';

function startStubIdp(getHarperBaseUrl: () => string): Promise<{ port: number; close: () => Promise<void> }> {
	return new Promise((resolve, reject) => {
		const server = createServer((req: IncomingMessage, res: ServerResponse) => {
			const url = new URL(req.url ?? '/', 'http://127.0.0.1');
			if (req.method === 'GET' && url.pathname === '/authorize') {
				const callbackUrl = new URL('/oauth/stub/callback', getHarperBaseUrl());
				callbackUrl.searchParams.set('code', `stub-code-${randomBytes(8).toString('hex')}`);
				callbackUrl.searchParams.set('state', url.searchParams.get('state') ?? '');
				res.writeHead(302, { Location: callbackUrl.toString() });
				res.end();
				return;
			}
			if (req.method === 'POST' && url.pathname === '/token') {
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(
					JSON.stringify({
						access_token: `stub-upstream-${randomBytes(8).toString('hex')}`,
						token_type: 'Bearer',
						expires_in: 3600,
					})
				);
				return;
			}
			if (req.method === 'GET' && url.pathname === '/userinfo') {
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(JSON.stringify({ sub: 'stub-sub', email: EMAIL, name: 'Preview User' }));
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
						server.closeAllConnections();
					}),
			});
		});
		server.on('error', reject);
	});
}

/** Login → stub IdP → callback. Returns the callback response and the browser-binding cookie pair. */
async function driveLogin(baseUrl: string, redirect: string) {
	const loginRes = await fetch(`${baseUrl}/oauth/stub/login?redirect=${encodeURIComponent(redirect)}`, {
		redirect: 'manual',
	});
	strictEqual(loginRes.status, 302);
	await loginRes.body?.cancel();
	const browserCookie = loginRes.headers
		.getSetCookie()
		.find((c) => c.startsWith('__Host-oauth_browser'))!
		.split(';')[0];
	const idpRes = await fetch(loginRes.headers.get('location')!, { redirect: 'manual' });
	await idpRes.body?.cancel();
	const callbackRes = await fetch(idpRes.headers.get('location')!, {
		redirect: 'manual',
		headers: { cookie: browserCookie },
	});
	await callbackRes.body?.cancel();
	return { callbackRes, browserCookie };
}

function redeem(baseUrl: string, origin: string, cookie: string, code: string) {
	return fetch(`${baseUrl}/oauth/handoff`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'Origin': origin, 'Cookie': cookie },
		body: JSON.stringify({ code }),
	});
}

suite('sign-in handoff to an allowlisted origin', (ctx: ContextWithHarper) => {
	let closeIdp: (() => Promise<void>) | undefined;

	before(async () => {
		let baseUrl = '';
		const idp = await startStubIdp(() => baseUrl);
		closeIdp = idp.close;
		const stubBase = `http://127.0.0.1:${idp.port}`;
		await setupHarperWithFixture(ctx, fixturePath, {
			harperBinPath: getHarperBinPath(),
			config: { logging: { stdStreams: true } },
			env: {
				STUB_IDP_AUTHORIZE_URL: `${stubBase}/authorize`,
				STUB_IDP_TOKEN_URL: `${stubBase}/token`,
				STUB_IDP_USERINFO_URL: `${stubBase}/userinfo`,
				HANDOFF_ORIGINS: 'https://*.app.preview.test',
				// The debug /user route is loopback-only; the harness binds 127.0.0.x.
				DEBUG_ALLOWED_IPS: '127.,::ffff:127.',
			},
		});
		baseUrl = ctx.harper.httpURL;
	});

	after(async () => {
		try {
			await teardownHarper(ctx);
		} finally {
			await closeIdp?.();
		}
	});

	test('the callback hands off with a fragment code and creates no session of its own', async () => {
		const { callbackRes } = await driveLogin(ctx.harper.httpURL, `${PREVIEW}/#/check-oauth`);
		strictEqual(callbackRes.status, 302);
		const location = callbackRes.headers.get('location')!;
		match(location, /^https:\/\/pr-12\.app\.preview\.test\/#\/check-oauth\?oauth_handoff=[A-Za-z0-9_-]{43}$/);
		ok(
			!callbackRes.headers.getSetCookie().some((c) => c.includes('hdb-session=')),
			'no session is written on the callback origin'
		);
	});

	test('the redeem creates the session under the calling origin’s cookie name, once', async () => {
		const { callbackRes, browserCookie } = await driveLogin(ctx.harper.httpURL, `${PREVIEW}/#/check-oauth`);
		const code = new URL(callbackRes.headers.get('location')!).hash.split('oauth_handoff=')[1];

		// Wrong origin first: refused before the code is touched.
		const wrongOrigin = await redeem(ctx.harper.httpURL, 'https://evil.test', browserCookie, code);
		strictEqual(wrongOrigin.status, 403);
		strictEqual((await wrongOrigin.json()).error, 'origin_not_allowed');

		const res = await redeem(ctx.harper.httpURL, PREVIEW, browserCookie, code);
		strictEqual(res.status, 200, await res.clone().text());
		strictEqual((await res.json()).authenticated, true);
		const sessionCookie = res.headers.getSetCookie().find((c) => c.startsWith(PREVIEW_COOKIE));
		ok(sessionCookie, `expected a ${PREVIEW_COOKIE}… cookie; got ${JSON.stringify(res.headers.getSetCookie())}`);
		const sessionPair = sessionCookie!.split(';')[0];

		// The session resolves for the preview's Origin…
		const me = await fetch(`${ctx.harper.httpURL}/oauth/stub/user`, {
			headers: { Origin: PREVIEW, Cookie: sessionPair },
		});
		strictEqual((await me.json()).email, EMAIL);
		// …and not for another origin presenting the same cookie.
		const other = await fetch(`${ctx.harper.httpURL}/oauth/stub/user`, {
			headers: { Origin: OTHER_PREVIEW, Cookie: sessionPair },
		});
		const otherBody = other.status === 200 ? await other.json() : {};
		ok(otherBody.email !== EMAIL, 'the session is partitioned by Origin');

		// Single use.
		const replay = await redeem(ctx.harper.httpURL, PREVIEW, browserCookie, code);
		strictEqual(replay.status, 400);
		strictEqual((await replay.json()).error, 'invalid_grant');
	});

	test('a code redeemed from a different browser is refused', async () => {
		const { callbackRes, browserCookie } = await driveLogin(ctx.harper.httpURL, `${PREVIEW}/#/check-oauth`);
		const code = new URL(callbackRes.headers.get('location')!).hash.split('oauth_handoff=')[1];
		// Well-formed, so the refusal comes from the stored binding, not the cookie shape check.
		const res = await redeem(ctx.harper.httpURL, PREVIEW, `__Host-oauth_browser=${'A'.repeat(43)}`, code);
		strictEqual(res.status, 400);
		strictEqual((await res.json()).error, 'invalid_grant');
		ok(!res.headers.getSetCookie().some((c) => c.includes('hdb-session=')));
		// The refused presentation left the code for the browser that started the sign-in.
		strictEqual((await redeem(ctx.harper.httpURL, PREVIEW, browserCookie, code)).status, 200);
	});

	test('a redirect to an origin not on the list keeps today’s path-only behavior', async () => {
		const { callbackRes } = await driveLogin(ctx.harper.httpURL, 'https://evil.test/#/check-oauth');
		strictEqual(callbackRes.headers.get('location'), '/#/check-oauth');
		ok(callbackRes.headers.getSetCookie().some((c) => c.includes('hdb-session=')));
	});
});
