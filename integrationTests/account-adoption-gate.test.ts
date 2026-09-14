/**
 * Integration tests: account-adoption gate
 *
 * An OAuth login whose IdP-mapped username matches an existing hdb_user must
 * NOT inherit that account's role unless the claim is verified: an email claim
 * backed by email_verified === true from a JWKS-signed ID token.
 *
 * Tests cover:
 *   – Regression guard: unverified-claim collision is now denied.
 *   – No-op proofs: role-less login (no matching account) is unchanged.
 *
 * Not yet covered here (tracked in #230): end-to-end verified-claim adoption
 * through real JWKS verification, and the `allowUnverifiedClaimInheritance`
 * escape hatch.
 */

import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { join, dirname } from 'node:path';
import { createRequire } from 'node:module';
import {
	setupHarperWithFixture,
	teardownHarper,
	sendOperation,
	type ContextWithHarper,
} from '@harperfast/integration-testing';

const require = createRequire(import.meta.url);

function getHarperBinPath(): string {
	return join(dirname(require.resolve('harper')), 'bin', 'harper.js');
}

const fixturePath = join(import.meta.dirname, 'fixtures', 'f2-repro-app');

// The privileged hdb_user that the attacker collides with.
const VICTIM_USERNAME = 'victimadmin';
const VICTIM_PASSWORD = 'VictimP@ssw0rd123!';

// An email that matches no hdb_user (role-less login control case).
const ROLELESS_EMAIL = 'newuser@nowhere.test';

// Mutable: controls what the stub IdP returns in /userinfo.
let stubbedEmail = VICTIM_USERNAME;

// ── Stub IdP ─────────────────────────────────────────────────────────────────

/**
 * Minimal stub IdP for the human OAuth flow:
 *   GET  /authorize  → immediately 302 back to Harper's /oauth/stub/callback
 *   POST /token      → returns a fake upstream access token (no id_token)
 *   GET  /userinfo   → returns { email: stubbedEmail }
 *
 * No id_token is issued so idTokenSignatureVerified is always false —
 * reproducing the unsafe path that the gate must block.
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
				const state = url.searchParams.get('state') ?? '';
				const code = `stub-code-${randomBytes(8).toString('hex')}`;
				const callbackUrl = new URL(`/oauth/stub/callback`, getHarperBaseUrl());
				callbackUrl.searchParams.set('code', code);
				callbackUrl.searchParams.set('state', state);
				res.writeHead(302, { Location: callbackUrl.toString() });
				res.end();
				return;
			}

			if (req.method === 'POST' && path === '/token') {
				res.writeHead(200, { 'Content-Type': 'application/json' });
				// No id_token — only the userinfo endpoint is consulted.
				// This is the unsafe path: email_verified comes from an unsigned source.
				res.end(
					JSON.stringify({
						access_token: `stub-upstream-${randomBytes(8).toString('hex')}`,
						token_type: 'Bearer',
						expires_in: 3600,
					})
				);
				return;
			}

			if (req.method === 'GET' && path === '/userinfo') {
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(
					JSON.stringify({
						sub: `stub-sub-${randomBytes(4).toString('hex')}`,
						email: stubbedEmail,
						// email_verified deliberately omitted — unverified claim.
						name: 'Stub User',
					})
				);
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

// ── OAuth login helper ────────────────────────────────────────────────────────

/**
 * Drive the full human OAuth login flow. Returns the hdb-session cookie pair
 * ("name=value") if one was issued, or null if the callback did not set one.
 */
async function driveOAuthLogin(harperBaseUrl: string): Promise<string | null> {
	const loginRes = await fetch(`${harperBaseUrl}/oauth/stub/login`, { redirect: 'manual' });
	strictEqual(loginRes.status, 302, `login must redirect; got ${loginRes.status}`);
	await loginRes.body?.cancel();

	const browserSetCookie = loginRes.headers.getSetCookie().find((c) => c.startsWith('__Host-oauth_browser'));
	ok(browserSetCookie, 'login must set __Host-oauth_browser browser-binding cookie');
	const browserCookiePair = browserSetCookie!.split(';')[0];

	const idpLocation = loginRes.headers.get('location');
	ok(idpLocation, 'login must redirect to stub IdP');

	const idpRes = await fetch(idpLocation!, { redirect: 'manual' });
	strictEqual(idpRes.status, 302, `stub IdP /authorize must redirect; got ${idpRes.status}`);
	const callbackLocation = idpRes.headers.get('location');
	ok(callbackLocation, 'stub IdP must redirect to Harper callback');
	await idpRes.body?.cancel();

	const callbackRes = await fetch(callbackLocation!, {
		redirect: 'manual',
		headers: { cookie: browserCookiePair },
	});
	await callbackRes.body?.cancel();

	const sessionSetCookie = callbackRes.headers.getSetCookie().find((c) => c.includes('hdb-session='));
	if (!sessionSetCookie) return null;
	return sessionSetCookie.split(';')[0];
}

// ── Operations API helper ─────────────────────────────────────────────────────

async function callOperationsWithSession(
	operationsApiUrl: string,
	hostname: string,
	sessionCookiePair: string,
	operation: Record<string, unknown>
): Promise<{ status: number; body: any }> {
	const restOrigin = `http://${hostname}:9926`;
	const res = await fetch(operationsApiUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Origin': restOrigin,
			'Cookie': sessionCookiePair,
		},
		body: JSON.stringify(operation),
	});
	return { status: res.status, body: await res.json() };
}

// ── Test suite ────────────────────────────────────────────────────────────────

suite('account-adoption gate: unverified claim must not inherit existing account', (ctx: ContextWithHarper) => {
	let closeIdp: (() => Promise<void>) | undefined;

	before(async () => {
		let harperBaseUrl = '';
		const idp = await startStubIdp(() => harperBaseUrl);
		closeIdp = idp.close;

		const stubBase = `http://127.0.0.1:${idp.port}`;
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

		await sendOperation(ctx.harper, {
			operation: 'add_user',
			username: VICTIM_USERNAME,
			password: VICTIM_PASSWORD,
			active: true,
			role: 'super_user',
		});
	});

	after(async () => {
		try {
			await teardownHarper(ctx);
		} finally {
			await closeIdp?.();
		}
	});

	test('deny: unverified email claim matching an existing account must not inherit its role', async () => {
		stubbedEmail = VICTIM_USERNAME;

		// The stub IdP returns email=victimadmin with no email_verified and no
		// id_token — this is the unverified-claim path the gate must block.
		const sessionCookiePair = await driveOAuthLogin(ctx.harper.httpURL);

		// An unverified-claim collision with an existing account is denied outright
		// (access_denied), so the callback establishes NO session cookie. Asserting this
		// deterministically is the regression guard: were the gate to adopt the account,
		// a (super_user) session cookie would be present here. (A super_user operation
		// cannot be probed once no cookie is set — this harness's loopback auth bypass
		// would answer 200 for an unauthenticated loopback call regardless of the session;
		// the roleless-session → 403 path is covered by the role-less login test below,
		// where a non-null session.user is resolved and the bypass is never reached.)
		strictEqual(
			sessionCookiePair,
			null,
			`an unverified-claim collision must be denied with no session cookie; got a cookie: ${sessionCookiePair}`
		);
	});

	test('no-op: role-less login (no matching account) is unchanged', async () => {
		stubbedEmail = ROLELESS_EMAIL;

		const sessionCookiePair = await driveOAuthLogin(ctx.harper.httpURL);

		// A login that doesn't match any hdb_user is always role-less —
		// the gate must not block it.
		ok(sessionCookiePair, 'role-less login must set a session cookie');

		const { status } = await callOperationsWithSession(
			ctx.harper.operationsAPIURL,
			ctx.harper.hostname,
			sessionCookiePair!,
			{ operation: 'list_users' }
		);
		strictEqual(status, 403, 'role-less session must be denied super_user operations');
	});
});
