/**
 * OAuth session-validation HTTP middleware (src/index.ts) — persist-failure handling.
 *
 * #265/#266 fixed clearOAuthSession to report (not throw on, not silently swallow) a failed
 * persist. This covers the middleware's own reaction to that report: a persist failure must
 * deny the request rather than continue to `next()` serving the stale, supposedly-revoked
 * identity Harper already resolved onto `request`.
 */
import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleApplication } from '../dist/index.js';
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
});
