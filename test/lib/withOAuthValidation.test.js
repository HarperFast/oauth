/**
 * Tests for withOAuthValidation
 *
 * Covers Resource API v2 integration: the wrapper must find the request
 * via `this.getContext()` because v2 method signatures (`receive(target, data)`,
 * `get(target)`, etc.) do not pass the request as an argument.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { withOAuthValidation } from '../../dist/lib/withOAuthValidation.js';

describe('withOAuthValidation', () => {
	let mockProviders;
	let mockLogger;

	beforeEach(() => {
		mockLogger = {
			info: () => {},
			warn: () => {},
			error: () => {},
			debug: () => {},
		};

		mockProviders = {
			github: {
				provider: {
					refreshAccessToken: async () => ({
						access_token: 'new-access',
						expires_in: 3600,
						token_type: 'Bearer',
					}),
					config: { provider: 'github' },
				},
				config: { provider: 'github' },
			},
		};
	});

	/**
	 * Build a mock Resource API v2 target: a class instance whose `getContext()`
	 * returns the request. Method arguments don't contain the request.
	 */
	function makeV2Resource(methodImpl, context) {
		return {
			getContext() {
				return context;
			},
			async get(target, data) {
				return methodImpl('get', target, data);
			},
			async post(target, data) {
				return methodImpl('post', target, data);
			},
		};
	}

	function makeSession(overrides = {}) {
		return {
			id: 'sess-1',
			oauth: {
				provider: 'github',
				accessToken: 'token-abc',
				refreshToken: undefined,
				...overrides.oauth,
			},
			oauthUser: { username: 'alice', email: 'alice@example.com', role: 'user' },
			update: async () => {},
			...overrides,
		};
	}

	describe('Resource API v2 (request from this.getContext())', () => {
		it('passes through to the underlying method when context has a valid OAuth session', async () => {
			const context = { session: makeSession() };
			const calls = [];
			const resource = makeV2Resource((method, target, data) => {
				calls.push({ method, target, data });
				return { status: 200, body: { ok: true } };
			}, context);

			const wrapped = withOAuthValidation(resource, { providers: mockProviders, logger: mockLogger });

			const result = await wrapped.get({ path: '/x' }, { q: 1 });

			assert.equal(result.status, 200);
			assert.equal(calls.length, 1);
			assert.equal(calls[0].method, 'get');
			assert.deepEqual(calls[0].target, { path: '/x' });
		});

		it('returns 401 when requireAuth is true and no OAuth data is in the session', async () => {
			const context = { session: { id: 'sess-no-oauth' } }; // no .oauth field
			const calls = [];
			const resource = makeV2Resource((method) => {
				calls.push({ method });
				return { status: 200 };
			}, context);

			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const result = await wrapped.get({ path: '/protected' });

			assert.equal(result.status, 401);
			assert.equal(result.body.error, 'Unauthorized');
			assert.equal(calls.length, 0, 'underlying method should not be called');
		});

		it('passes through unvalidated when requireAuth is false and no OAuth data is in the session', async () => {
			const context = { session: { id: 'sess-no-oauth' } };
			const calls = [];
			const resource = makeV2Resource((method) => {
				calls.push({ method });
				return { status: 200 };
			}, context);

			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: false,
			});

			const result = await wrapped.get({ path: '/public' });

			assert.equal(result.status, 200);
			assert.equal(calls.length, 1, 'underlying method should be called');
		});

		it('invokes onValidationError when provided instead of returning a default 401', async () => {
			const context = { session: { id: 'sess-no-oauth' } };
			const resource = makeV2Resource(() => ({ status: 200 }), context);

			const seenErrors = [];
			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: (request, error) => {
					seenErrors.push({ hasRequest: !!request, error });
					return { status: 418, body: { custom: true } };
				},
			});

			const result = await wrapped.get({ path: '/protected' });

			assert.equal(result.status, 418);
			assert.equal(result.body.custom, true);
			assert.equal(seenErrors.length, 1);
			assert.equal(seenErrors[0].hasRequest, true);
			assert.equal(seenErrors[0].error, 'OAuth authentication required');
		});

		it('clears stale session data when the provider referenced by session is not configured (requireAuth: false)', async () => {
			const context = {
				session: makeSession({ oauth: { provider: 'ghost-provider', accessToken: 'stale' } }),
			};
			const calls = [];
			const resource = makeV2Resource((method) => {
				calls.push({ method, sessionOAuth: context.session.oauth });
				return { status: 200 };
			}, context);

			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders, // only has 'github'
				logger: mockLogger,
				requireAuth: false,
			});

			await wrapped.get({ path: '/x' });

			assert.equal(calls.length, 1);
			assert.equal(calls[0].sessionOAuth, undefined, 'stale oauth metadata should be cleared');
		});

		// The two failure-path cases below are the ones the fix was actually
		// written to enable: before the v2-context change they wouldn't even
		// reach `validateAndRefreshSession` (the old `args.find` returned no
		// request) and the wrapper silently passed through. Now they must
		// genuinely reject with 401.

		it('returns 401 when the session references a provider not in the registry (requireAuth: true)', async () => {
			const context = {
				session: makeSession({ oauth: { provider: 'ghost-provider', accessToken: 'stale' } }),
			};
			const calls = [];
			const resource = makeV2Resource((method) => {
				calls.push({ method });
				return { status: 200 };
			}, context);

			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders, // only has 'github'
				logger: mockLogger,
				requireAuth: true,
			});

			const result = await wrapped.get({ path: '/protected' });

			assert.equal(result.status, 401, 'should reject rather than silently pass through');
			assert.equal(result.body.error, 'Unauthorized');
			assert.match(result.body.message, /not configured/);
			assert.equal(calls.length, 0, 'underlying method must not run');
			assert.equal(context.session.oauth, undefined, 'stale oauth metadata should be cleared');
		});

		it('returns 401 when the access token is expired and no refresh token is available (requireAuth: true)', async () => {
			const context = {
				session: makeSession({
					oauth: {
						provider: 'github',
						accessToken: 'expired-token',
						expiresAt: Date.now() - 60_000, // expired one minute ago
						refreshToken: undefined,
					},
				}),
			};
			const calls = [];
			const resource = makeV2Resource((method) => {
				calls.push({ method });
				return { status: 200 };
			}, context);

			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const result = await wrapped.get({ path: '/protected' });

			assert.equal(result.status, 401, 'should reject on expired token with no refresh path');
			assert.equal(result.body.error, 'Unauthorized');
			assert.match(result.body.message, /expired/i);
			assert.equal(calls.length, 0, 'underlying method must not run');
		});
	});

	describe('non-HTTP methods pass through untouched', () => {
		it('does not wrap arbitrary methods', async () => {
			const context = { session: makeSession() };
			const resource = {
				...makeV2Resource(() => ({ status: 200 }), context),
				helper: () => 'helper-result',
			};
			const wrapped = withOAuthValidation(resource, { providers: mockProviders, logger: mockLogger });

			assert.equal(wrapped.helper(), 'helper-result');
		});
	});

	describe('fallthrough: no context available', () => {
		it('passes through when requireAuth is false and the resource has no getContext', async () => {
			// Simulates a method called without v2 context
			const calls = [];
			const resource = {
				async get(target, data) {
					calls.push({ target, data });
					return { status: 200 };
				},
			};
			const wrapped = withOAuthValidation(resource, { providers: mockProviders, logger: mockLogger });

			const result = await wrapped.get({ path: '/noop' }, 'irrelevant');

			assert.equal(result.status, 200);
			assert.equal(calls.length, 1);
		});

		it('returns 401 when requireAuth is true and no context is available (fail-closed)', async () => {
			// When getContext() is missing (or yields no session) and auth is
			// required, the wrapper must reject. Passing through would silently
			// bypass OAuth on any code path that didn't provide a v2 context.
			const calls = [];
			const resource = {
				async get(target) {
					calls.push({ target });
					return { status: 200 };
				},
			};
			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const result = await wrapped.get({ path: '/protected' });

			assert.equal(result.status, 401, 'must reject rather than silently pass through');
			assert.equal(result.body.error, 'Unauthorized');
			assert.match(result.body.message, /context/i);
			assert.equal(calls.length, 0, 'underlying method must not run');
		});

		it('does NOT invoke onValidationError in the no-context path (its signature requires a Request)', async () => {
			// The no-context fail-closed branch deliberately skips
			// onValidationError: the callback's signature is
			// `(request: Request, error) => any` and callers are entitled
			// to read `request.session` / `.ip` / `.headers`. Passing
			// `undefined` as `request` would break the contract and turn
			// a clean 401 into a runtime TypeError inside user code.
			const resource = {
				async get() {
					return { status: 200, passedThrough: true };
				},
			};

			let handlerCalled = false;
			const wrapped = withOAuthValidation(resource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: () => {
					handlerCalled = true;
					return { status: 418, body: { shouldNotSeeThis: true } };
				},
			});

			const result = await wrapped.get({ path: '/protected' });

			assert.equal(handlerCalled, false, 'onValidationError must not be called without a valid request');
			assert.equal(result.status, 401, 'must return the default 401, not the custom handler response');
			assert.equal(result.body.error, 'Unauthorized');
		});
	});
});
