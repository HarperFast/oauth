/**
 * OAuth session-validation HTTP middleware (src/index.ts) — persist-failure handling.
 *
 * A clearOAuthSession persist failure must deny the request rather than continue to `next()`
 * serving the stale, supposedly-revoked identity Harper already resolved onto `request`.
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleApplication, registerHooks } from '../dist/index.js';
import { createMockLogger } from './helpers/mockFn.js';

describe('OAuth session-validation middleware — persist-failure handling (#265, #266)', () => {
	let scope;
	let middleware;
	let logger;

	beforeEach(async () => {
		middleware = null;
		logger = createMockLogger();
		scope = {
			logger,
			options: {
				_config: {
					debug: false,
					redirectUri: 'https://app.test.com/oauth',
					providers: {
						github: {
							provider: 'github',
							clientId: 'test-client-id',
							clientSecret: 'test-client-secret',
						},
					},
				},
				getAll() {
					return this._config;
				},
				on() {},
			},
			server: {
				// The session-validation middleware is registered with no `options` arg; the
				// well-known MCP route handlers registered afterward each pass `{ urlPath }` —
				// capture only the former so a later registration doesn't overwrite it.
				http(fn, options) {
					if (!options) middleware = fn;
				},
			},
			resources: { set() {} },
			on() {},
		};
		await handleApplication(scope);
	});

	it('returns 503 (no-store) instead of next() when the provider-not-found clear fails to persist', async () => {
		const request = {
			session: {
				id: 'sess-1',
				oauth: { providerConfigId: 'unknown-provider', accessToken: 'tok' },
				// No .update → clearOAuthSession can't persist the clear.
			},
		};
		const next = () => ({ status: 200, body: { ran: true } });

		const result = await middleware(request, next);

		assert.equal(result.status, 503);
		assert.equal(result.headers['Cache-Control'], 'no-store');
		// Raw server.http listener — nothing else serializes this response, so the body must
		// already be a JSON string, not the plain object literal.
		assert.equal(typeof result.body, 'string');
		assert.deepEqual(JSON.parse(result.body), {
			error: 'session_invalidation_failed',
			message: 'Unable to validate session, please retry',
		});
		assert.equal(result.headers['Content-Type'], 'application/json');
	});

	it('still continues to next() when the provider-not-found clear persists fine', async () => {
		const request = {
			session: {
				id: 'sess-1',
				update: async () => {},
				oauth: { providerConfigId: 'unknown-provider', accessToken: 'tok' },
			},
		};
		const next = () => ({ status: 200, body: { ran: true } });

		const result = await middleware(request, next);

		assert.equal(result.status, 200);
		assert.equal(result.body.ran, true);
	});

	it('returns 503 (no-store) instead of next() when an expired-session clear fails to persist', async () => {
		const request = {
			session: {
				id: 'sess-1',
				oauth: {
					providerConfigId: 'github',
					accessToken: 'tok',
					refreshToken: undefined, // no refresh token → straight to clearOAuthSession
					expiresAt: Date.now() - 1000, // expired
				},
				// No .update → clearOAuthSession can't persist the clear.
			},
		};
		const next = () => ({ status: 200, body: { ran: true } });

		const result = await middleware(request, next);

		assert.equal(result.status, 503);
		assert.equal(result.headers['Cache-Control'], 'no-store');
		assert.equal(typeof result.body, 'string');
	});

	it('gives each 503 response its own headers object (no cross-request shared state)', async () => {
		const request = () => ({
			session: { id: 'sess-1', oauth: { providerConfigId: 'unknown-provider', accessToken: 'tok' } },
		});
		const next = () => ({ status: 200, body: { ran: true } });

		const first = await middleware(request(), next);
		const second = await middleware(request(), next);

		assert.notEqual(first.headers, second.headers, 'each response must get its own headers object');
		first.headers['X-Mutated-By-Test'] = 'true';
		assert.equal(second.headers['X-Mutated-By-Test'], undefined);
	});

	it('still continues to next() when an expired session is cleanly invalidated (persists fine)', async () => {
		const request = {
			session: {
				id: 'sess-1',
				update: async () => {},
				oauth: {
					providerConfigId: 'github',
					accessToken: 'tok',
					refreshToken: undefined,
					expiresAt: Date.now() - 1000,
				},
			},
		};
		const next = () => ({ status: 200, body: { ran: true } });

		const result = await middleware(request, next);

		assert.equal(result.status, 200);
		assert.equal(result.body.ran, true);
	});

	it('passes through requests with no OAuth session data', async () => {
		const request = { session: {} };
		const next = () => ({ status: 200, body: { ran: true } });

		const result = await middleware(request, next);

		assert.equal(result.status, 200);
		assert.equal(result.body.ran, true);
	});

	describe('dynamic resolution — invalid Azure issuer pin, cooldown (#264/#271)', () => {
		// A stale pin that doesn't name the configured tenant — buildProviderConfig throws AzureIssuerBindingError.
		const badAzureHookConfig = {
			provider: 'azure',
			clientId: 'c',
			clientSecret: 's',
			tenantId: '12345678-1234-1234-1234-123456789012',
			issuer: 'https://login.microsoftonline.com/87654321-4321-4321-4321-210987654321/v2.0',
			redirectUri: 'https://app.test.com/oauth',
		};

		it('clears the session (the stale identity is never served) and does not re-run the resolve hook within the 30s cooldown', async () => {
			let resolveCount = 0;
			registerHooks({
				onResolveProvider: async () => {
					resolveCount++;
					return badAzureHookConfig;
				},
			});

			let updateCalled = 0;
			// Each call gets its OWN session object — one per request, same as
			// production (Harper loads a fresh session per request). Reusing one
			// mutable object across calls would hide a real bug: clearOAuthSession
			// wipes `.oauth` in memory, so a second call against the SAME object
			// would hit the "no OAuth session data" early-return before ever
			// reaching the cooldown logic, trivially (and wrongly) appearing to
			// pass.
			const makeRequest = () => ({
				session: {
					id: 'sess-1',
					update: async () => {
						updateCalled++;
					},
					oauth: { providerConfigId: 'bad-azure-tenant', accessToken: 'tok' },
				},
			});
			const next = () => ({ status: 200, body: { ran: true } });

			const first = await middleware(makeRequest(), next);
			assert.equal(first.status, 200, 'the session is cleared, then next() proceeds');
			assert.equal(updateCalled, 1, 'the session clear was persisted — the stale identity is not served');
			assert.equal(resolveCount, 1);

			// A second, independent request for the same provider, still within
			// the cooldown, must not re-run the resolve hook (and re-throw).
			const second = await middleware(makeRequest(), next);
			assert.equal(second.status, 200, 'that session is cleared too, independent of the cooldown');
			assert.equal(resolveCount, 1, 'the hook must not be re-run while the failure is cooling down');
		});

		it('re-runs the resolve hook once the 30s cooldown elapses', async () => {
			let resolveCount = 0;
			registerHooks({
				onResolveProvider: async () => {
					resolveCount++;
					return badAzureHookConfig;
				},
			});

			const makeRequest = () => ({
				session: {
					id: 'sess-1',
					update: async () => {},
					oauth: { providerConfigId: 'bad-azure-tenant-2', accessToken: 'tok' },
				},
			});
			const next = () => ({ status: 200, body: { ran: true } });

			await middleware(makeRequest(), next);
			assert.equal(resolveCount, 1);

			const realNow = Date.now;
			Date.now = () => realNow() + 31_000;
			try {
				await middleware(makeRequest(), next);
				assert.equal(resolveCount, 2, 'the hook runs again once the 30s cooldown elapses');
			} finally {
				Date.now = realNow;
			}
		});
	});
});
