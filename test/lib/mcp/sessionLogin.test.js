/**
 * Tests for MCP authorization through the host application's session (mcp.sessionLogin).
 */

import { describe, it, before, after, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { handleAuthorize, handleAuthorizeConfirm } from '../../../dist/lib/mcp/authorize.js';
import { handleMCPPost } from '../../../dist/lib/mcp/index.js';
import { sessionUsername } from '../../../dist/lib/mcp/sessionLogin.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';
import { resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';
import { resetMCPSessionConsentsTableCache } from '../../../dist/lib/mcp/sessionConsentStore.js';
import { BROWSER_SECRET_COOKIE_NAME } from '../../../dist/lib/mcp/consentBinding.js';
import { HookManager, MCP_SESSION_AUTHORIZE_TIMEOUT_MS } from '../../../dist/lib/hookManager.js';
import { normalizeMcpSecurityConfig } from '../../../dist/lib/config.js';

const ISSUER = 'https://app.example.com';
const CLIENT = {
	client_id: 'client-1',
	client_name: 'Example <Client>',
	redirect_uris: ['https://mcp-client.example.com/cb'],
	grant_types: ['authorization_code', 'refresh_token'],
	response_types: ['code'],
	token_endpoint_auth_method: 'none',
};
const QUERY = {
	client_id: CLIENT.client_id,
	redirect_uri: CLIENT.redirect_uris[0],
	response_type: 'code',
	code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
	code_challenge_method: 'S256',
	resource: `${ISSUER}/mcp`,
	state: 'client-state',
};
const CONFIG = {
	enabled: true,
	issuer: ISSUER,
	sessionLogin: { loginUrl: '/#/sign-in?redirect={returnTo}', switchAccountUrl: '/#/sign-out?redirect={returnTo}' },
};
const BROWSER_SECRET = 'b'.repeat(43);

function target(params) {
	return { get: (name) => params[name] };
}

function request({ user = 'usr_1', sessionUser = user, origin, browserSecret = BROWSER_SECRET, authorization } = {}) {
	const headers = { host: 'app.example.com' };
	if (origin) headers.origin = origin;
	if (authorization) headers.authorization = authorization;
	if (browserSecret) headers.cookie = `${BROWSER_SECRET_COOKIE_NAME}=${browserSecret}`;
	return {
		protocol: 'https',
		host: 'app.example.com',
		headers,
		session: sessionUser ? { id: 'sess-1', user: sessionUser } : {},
		user: user ? { username: user } : undefined,
	};
}

function hooks(onMCPSessionAuthorize) {
	const manager = new HookManager();
	manager.register(onMCPSessionAuthorize ? { onMCPSessionAuthorize } : {});
	return manager;
}

function consentTokenOf(page) {
	return page.body.match(/name="consent_token" value="([^"]+)"/)?.[1];
}

describe('mcp.sessionLogin', () => {
	let originalDatabases;
	let consents;
	let authCodes;

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		resetMCPClientsTableCache();
		resetMCPAuthCodesTableCache();
		resetMCPSessionConsentsTableCache();
		consents = new Map();
		authCodes = new Map();
		const encoded = { ...CLIENT };
		for (const field of ['redirect_uris', 'grant_types', 'response_types'])
			encoded[field] = JSON.stringify(CLIENT[field]);
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: { get: async (id) => (id === CLIENT.client_id ? encoded : null) },
				mcp_auth_codes: { put: async (record) => authCodes.set(record.code, record) },
				mcp_session_consents: {
					get: async (id) => (consents.has(id) ? { ...consents.get(id) } : null),
					put: async (record) => consents.set(record.id, { ...record }),
					patch: async (id, changes) => {
						const row = consents.get(id);
						for (const [key, value] of Object.entries(changes)) {
							row[key] = value?.__op__ === 'add' ? Number(row[key] ?? 0) + value.value : value;
						}
					},
				},
			},
		};
	});

	async function showConsent(options = {}, manager = hooks()) {
		return handleAuthorize(request(options), target(QUERY), CONFIG, {}, undefined, manager);
	}

	function confirm(token, decision = 'approve', options = {}, manager = hooks(), config = CONFIG) {
		return handleMCPPost(
			'confirm',
			request({ origin: ISSUER, ...options }),
			{ consent_token: token, decision },
			config,
			{},
			manager
		);
	}

	describe('authorize', () => {
		it('sends a signed-out browser to the sign-in page with the authorize request to return to', async () => {
			const response = await showConsent({ user: null, sessionUser: null });
			assert.equal(response.status, 302);
			const location = response.headers.Location;
			assert.ok(location.startsWith('/#/sign-in?redirect='));
			const returnTo = decodeURIComponent(location.slice('/#/sign-in?redirect='.length));
			assert.ok(returnTo.startsWith('/oauth/mcp/authorize?'));
			const params = new URL(returnTo, ISSUER).searchParams;
			for (const [key, value] of Object.entries(QUERY)) assert.equal(params.get(key), value);
			assert.equal(consents.size, 0);
		});

		it('does not treat a request carrying an Authorization header as signed in', async () => {
			const response = await showConsent({ authorization: 'Basic dXNyXzE6cHc=' });
			assert.equal(response.status, 302);
			assert.equal(consents.size, 0);
		});

		it('does not treat an identity other than the session user as signed in', async () => {
			assert.equal(sessionUsername(request({ user: 'usr_2', sessionUser: 'usr_1' })), undefined);
			assert.equal(sessionUsername(request()), 'usr_1');
		});

		it('shows a consent page naming the account, bound to the session user and browser', async () => {
			const response = await showConsent(
				{},
				hooks(async () => ({ allow: true, displayName: 'Ann <ann@example.com>' }))
			);
			assert.equal(response.status, 200);
			assert.match(response.headers['Content-Security-Policy'], /frame-ancestors 'none'/);
			assert.match(response.headers['Content-Security-Policy'], /form-action 'self'/);
			assert.equal(response.headers['Cache-Control'], 'no-store');
			assert.equal(response.headers['X-Frame-Options'], 'DENY');
			assert.match(response.headers['Set-Cookie'], new RegExp(`^${BROWSER_SECRET_COOKIE_NAME}=${BROWSER_SECRET}`));
			assert.match(response.body, /Ann &lt;ann@example.com&gt;/);
			assert.match(response.body, /Example &lt;Client&gt;/);
			assert.doesNotMatch(response.body, /<Client>/);
			assert.match(response.body, /value="deny"/);
			assert.ok(consentTokenOf(response));
			const [row] = consents.values();
			assert.equal(row.user, 'usr_1');
			assert.equal(row.uses, 0);
		});

		it('refuses on the page, without storing a consent, when the hook refuses', async () => {
			const response = await showConsent(
				{},
				hooks(async () => ({ allow: false, description: 'Staff <b>accounts</b> are not allowed' }))
			);
			assert.equal(response.status, 200);
			assert.match(response.body, /Staff &lt;b&gt;accounts&lt;\/b&gt; are not allowed/);
			assert.match(response.body, /Use a different account/);
			assert.match(response.body, /error=access_denied/);
			assert.equal(consents.size, 0);
		});
	});

	describe('confirm', () => {
		it('mints a code for the session user on approval', async () => {
			const token = consentTokenOf(await showConsent());
			const response = await confirm(token);
			assert.equal(response.status, 302);
			const location = new URL(response.headers.Location);
			assert.equal(location.origin + location.pathname, CLIENT.redirect_uris[0]);
			assert.equal(location.searchParams.get('state'), QUERY.state);
			const code = location.searchParams.get('code');
			assert.equal(authCodes.get(code).user, 'usr_1');
			assert.equal(authCodes.get(code).client_id, CLIENT.client_id);
		});

		it('returns access_denied when the user denies, and the consent is spent', async () => {
			const token = consentTokenOf(await showConsent());
			const denied = await confirm(token, 'deny');
			assert.equal(new URL(denied.headers.Location).searchParams.get('error'), 'access_denied');
			assert.equal((await confirm(token)).status, 400);
			assert.equal(authCodes.size, 0);
		});

		for (const [name, options] of [
			['a foreign Origin', { origin: 'https://evil.example.com' }],
			['no Origin', { origin: undefined }],
			['another signed-in account', { user: 'usr_2', sessionUser: 'usr_2' }],
			['another browser', { browserSecret: 'c'.repeat(43) }],
			['an Authorization header', { authorization: 'Bearer x' }],
		]) {
			it(`refuses ${name} without spending the consent`, async () => {
				const token = consentTokenOf(await showConsent());
				const refused = await handleMCPPost(
					'confirm',
					request({ origin: ISSUER, ...options }),
					{ consent_token: token, decision: 'approve' },
					CONFIG,
					{},
					hooks()
				);
				assert.equal(refused.status, 400);
				assert.equal(authCodes.size, 0);
				assert.equal((await confirm(token)).status, 302);
			});
		}

		it('refuses a second approval of the same consent', async () => {
			const token = consentTokenOf(await showConsent());
			assert.equal((await confirm(token)).status, 302);
			const again = await confirm(token);
			assert.equal(again.status, 400);
			assert.equal(authCodes.size, 1);
		});

		it('refuses with access_denied when the hook refuses at approval', async () => {
			const token = consentTokenOf(await showConsent());
			const response = await confirm(
				token,
				'approve',
				{},
				hooks(async ({ phase }) => (phase === 'approve' ? { allow: false } : { allow: true }))
			);
			assert.equal(new URL(response.headers.Location).searchParams.get('error'), 'access_denied');
			assert.equal(authCodes.size, 0);
		});

		it('refuses once sessionLogin has been turned off', async () => {
			const token = consentTokenOf(await showConsent());
			const response = await confirm(token, 'approve', {}, hooks(), { enabled: true, issuer: ISSUER });
			assert.equal(response.status, 400);
			assert.equal(authCodes.size, 0);
		});

		it('refuses a malformed or repeated consent token', async () => {
			assert.equal((await confirm('short')).status, 400);
			assert.equal((await confirm(['a'.repeat(43), 'b'.repeat(43)])).status, 400);
			assert.equal((await confirm('a'.repeat(43), 'maybe')).status, 400);
		});

		it('refuses an upstream confirm token in session mode', async () => {
			const response = await handleAuthorizeConfirm(request({ origin: ISSUER }), { confirm_token: 'x' }, CONFIG, {});
			assert.equal(response.status, 400);
		});
	});

	describe('onMCPSessionAuthorize contract', () => {
		const input = { user: 'usr_1', clientId: 'c', phase: 'approve' };

		it('allows without a hook', async () => {
			assert.equal((await new HookManager().callOnMCPSessionAuthorize(input, {})).allow, true);
		});

		for (const [name, hook] of [
			['undefined', async () => undefined],
			['allow: "true"', async () => ({ allow: 'true' })],
			[
				'a sync throw',
				() => {
					throw new Error('boom');
				},
			],
			[
				'a rejection',
				async () => {
					throw new Error('boom');
				},
			],
		]) {
			it(`refuses on ${name}`, async () => {
				assert.equal((await hooks(hook).callOnMCPSessionAuthorize(input, {})).allow, false);
			});
		}

		it('refuses and aborts the hook when it does not answer in time', async () => {
			mock.timers.enable({ apis: ['setTimeout'] });
			try {
				let signal;
				const pending = hooks((args) => {
					signal = args.signal;
					return new Promise(() => {});
				}).callOnMCPSessionAuthorize(input, {});
				await Promise.resolve();
				await Promise.resolve();
				mock.timers.tick(MCP_SESSION_AUTHORIZE_TIMEOUT_MS);
				assert.equal((await pending).allow, false);
				assert.equal(signal.aborted, true);
			} finally {
				mock.timers.reset();
			}
		});
	});

	describe('config', () => {
		const normalize = (sessionLogin) => normalizeMcpSecurityConfig({ enabled: true, issuer: ISSUER, sessionLogin });

		it('accepts a same-origin path with one {returnTo}', () => {
			assert.doesNotThrow(() => normalize({ loginUrl: '/#/sign-in?redirect={returnTo}' }));
		});

		for (const loginUrl of [
			undefined,
			'${LOGIN_URL}',
			'https://evil.example.com/{returnTo}',
			'//evil.example.com/{returnTo}',
			'/sign-in',
			'/sign-in?a={returnTo}&b={returnTo}',
			'/sign in?r={returnTo}',
			'/sign-in?r={returnTo}"onload=',
			'/\\evil.example.com/{returnTo}',
		]) {
			it(`rejects loginUrl ${JSON.stringify(loginUrl)}`, () => {
				assert.throws(() => normalize({ loginUrl }));
			});
		}

		it('stays inert while MCP is disabled', () => {
			assert.doesNotThrow(() => normalizeMcpSecurityConfig({ enabled: false, sessionLogin: { loginUrl: 'nope' } }));
		});
	});
});
