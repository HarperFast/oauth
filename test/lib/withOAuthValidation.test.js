/**
 * Tests for withOAuthValidation
 *
 * Exercises the subclass-based wrapper: `withOAuthValidation(ResourceClass, opts)`
 * returns a subclass of `ResourceClass`. Harper registers the subclass via
 * `resources.set(...)` and instantiates it per request; the subclass's
 * HTTP-method overrides run OAuth validation before delegating to `super`.
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
	 * Minimal Resource-like base class for tests. Accepts `(id, context)`
	 * in the constructor and exposes `getContext()` — matching the real
	 * Harper Resource base class contract closely enough for wrapper tests.
	 */
	class MockResource {
		static loadAsInstance = false;

		constructor(id, context) {
			this._id = id;
			this._context = context ?? null;
		}

		getContext() {
			return this._context;
		}
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

	describe('Wrapped-class registration surface', () => {
		it('returns a subclass of the input class (instanceof preserved)', () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(MyResource, { providers: mockProviders, logger: mockLogger });

			const instance = new Wrapped('x', { session: makeSession() });
			assert.ok(instance instanceof MyResource, 'wrapped instance must be an instance of the base class');
			assert.ok(instance instanceof MockResource, 'wrapped instance must be an instance of the grand-parent class');
		});

		it('inherits static properties from the base class (e.g., loadAsInstance)', () => {
			class MyResource extends MockResource {
				static loadAsInstance = false;
			}
			const Wrapped = withOAuthValidation(MyResource, { providers: mockProviders, logger: mockLogger });

			assert.equal(Wrapped.loadAsInstance, false);
		});
	});

	describe('HTTP methods run validation before delegating', () => {
		it('passes through to the underlying method when OAuth session is valid', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get(target) {
					calls.push({ target });
					return { status: 200, body: { ok: true } };
				}
			}
			const Wrapped = withOAuthValidation(MyResource, { providers: mockProviders, logger: mockLogger });

			const instance = new Wrapped('x', { session: makeSession() });
			const result = await instance.get({ path: '/x' });

			assert.equal(result.status, 200);
			assert.deepEqual(result.body, { ok: true });
			assert.equal(calls.length, 1);
		});

		it('returns 401 when requireAuth is true and session has no OAuth data', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const instance = new Wrapped('x', { session: { id: 'no-oauth' } });
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 401);
			assert.equal(result.body.error, 'Unauthorized');
			assert.equal(calls.length, 0, 'underlying method must not run');
		});

		it('passes through when requireAuth is false and session has no OAuth data', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: false,
			});

			const instance = new Wrapped('x', { session: { id: 'no-oauth' } });
			const result = await instance.get({ path: '/public' });

			assert.equal(result.status, 200);
			assert.equal(calls.length, 1);
		});

		it('invokes onValidationError when provided and validation fails', async () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
			}

			const seen = [];
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: (request, error) => {
					seen.push({ hasRequest: !!request, error });
					return { status: 418, body: { custom: true } };
				},
			});

			const instance = new Wrapped('x', { session: { id: 'no-oauth' } });
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 418);
			assert.equal(result.body.custom, true);
			assert.equal(seen.length, 1);
			assert.equal(seen[0].hasRequest, true);
			assert.equal(seen[0].error, 'OAuth authentication required');
		});

		it('clears stale session data when the provider is not in the registry (requireAuth: false)', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push({ sessionOAuth: this._context.session.oauth });
					return { status: 200 };
				}
			}

			const context = {
				session: makeSession({ oauth: { provider: 'ghost-provider', accessToken: 'stale' } }),
			};
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders, // only has 'github'
				logger: mockLogger,
				requireAuth: false,
			});

			const instance = new Wrapped('x', context);
			await instance.get({ path: '/x' });

			assert.equal(calls.length, 1);
			assert.equal(calls[0].sessionOAuth, undefined, 'stale oauth metadata should be cleared');
		});

		it('returns 401 when the session references an unknown provider (requireAuth: true)', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}
			const context = {
				session: makeSession({ oauth: { provider: 'ghost-provider', accessToken: 'stale' } }),
			};
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 401);
			assert.match(result.body.message, /not configured/);
			assert.equal(calls.length, 0);
			assert.equal(context.session.oauth, undefined, 'stale oauth metadata should be cleared');
		});

		it('returns 401 when the access token is expired and no refresh token is available (requireAuth: true)', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}
			const context = {
				session: makeSession({
					oauth: {
						provider: 'github',
						accessToken: 'expired-token',
						expiresAt: Date.now() - 60_000,
						refreshToken: undefined,
					},
				}),
			};
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 401);
			assert.match(result.body.message, /expired/i);
			assert.equal(calls.length, 0);
		});
	});

	describe('Non-HTTP methods pass through untouched', () => {
		it('does not wrap arbitrary methods', async () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
				helper() {
					return 'helper-result';
				}
			}
			const Wrapped = withOAuthValidation(MyResource, { providers: mockProviders, logger: mockLogger });

			const instance = new Wrapped('x', { session: makeSession() });
			assert.equal(instance.helper(), 'helper-result');
		});
	});

	describe('No context available', () => {
		it('passes through when requireAuth is false and there is no session on the context', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(MyResource, { providers: mockProviders, logger: mockLogger });

			const instance = new Wrapped('x', {}); // context without session
			const result = await instance.get({ path: '/noop' });

			assert.equal(result.status, 200);
			assert.equal(calls.length, 1);
		});

		it('returns 401 when requireAuth is true and there is no session on the context (fail-closed)', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			const instance = new Wrapped('x', {}); // context without session
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 401);
			assert.match(result.body.message, /context/i);
			assert.equal(calls.length, 0);
		});

		it('does NOT invoke onValidationError in the no-context path', async () => {
			// The no-context fail-closed branch deliberately skips
			// onValidationError: the callback signature is
			// `(request: Request, error) => any` and callers read
			// `request.session` / `.ip` / `.headers`. Passing `undefined`
			// would turn a clean 401 into a TypeError in user code.
			class MyResource extends MockResource {
				async get() {
					return { status: 200, passedThrough: true };
				}
			}

			let handlerCalled = false;
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: () => {
					handlerCalled = true;
					return { status: 418, body: { shouldNotSeeThis: true } };
				},
			});

			const instance = new Wrapped('x', {}); // no session
			const result = await instance.get({ path: '/protected' });

			assert.equal(handlerCalled, false, 'onValidationError must not be called without a valid request');
			assert.equal(result.status, 401);
			assert.equal(result.body.error, 'Unauthorized');
		});
	});

	describe('All five HTTP verbs route through the delegate', () => {
		// Each override in the wrapper calls `delegate(this, '<verb>', args)`.
		// The verb string is the only connection between the override and the
		// prototype lookup — a typo would silently bypass OAuth validation on
		// that verb. Exercise all five both for enforcement and delegation.
		for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
			it(`${method}: returns 401 with requireAuth and no OAuth data`, async () => {
				const calls = [];
				class MyResource extends MockResource {
					async [method]() {
						calls.push(method);
						return { status: 200 };
					}
				}
				const Wrapped = withOAuthValidation(MyResource, {
					providers: mockProviders,
					logger: mockLogger,
					requireAuth: true,
				});

				const instance = new Wrapped('x', { session: { id: 'no-oauth' } });
				const result = await instance[method]({ path: '/protected' });

				assert.equal(result.status, 401, `${method} must enforce OAuth`);
				assert.equal(calls.length, 0, `${method} must not run underlying method`);
			});

			it(`${method}: delegates to parent on valid session`, async () => {
				const calls = [];
				class MyResource extends MockResource {
					async [method](target) {
						calls.push({ method, target });
						return { status: 200, verb: method };
					}
				}
				const Wrapped = withOAuthValidation(MyResource, { providers: mockProviders, logger: mockLogger });

				const instance = new Wrapped('x', { session: makeSession() });
				const result = await instance[method]({ path: '/x' });

				assert.equal(result.status, 200);
				assert.equal(result.verb, method, `${method} override must call the parent's ${method}`);
				assert.equal(calls.length, 1);
			});
		}
	});

	describe('onValidationError receives un-mutated request in clearing paths', () => {
		// The "unknown provider" and "no provider name" branches clear stale
		// session data. The callback must see the request BEFORE the clear,
		// or audit/logging handlers reading request.session.oauth / oauthUser
		// silently get `undefined`.
		it('unknown-provider branch: callback sees full session, session is cleared after', async () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
			}

			const seen = [];
			const context = {
				session: makeSession({
					oauth: { provider: 'ghost-provider', accessToken: 'stale' },
				}),
			};

			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders, // only has 'github'
				logger: mockLogger,
				requireAuth: true,
				onValidationError: (request, error) => {
					seen.push({
						oauthAtCall: request.session.oauth && { ...request.session.oauth },
						oauthUserAtCall: request.session.oauthUser && { ...request.session.oauthUser },
						error,
					});
					return { status: 401, body: { custom: true } };
				},
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 401);
			assert.equal(seen.length, 1);
			assert.ok(seen[0].oauthAtCall, 'callback must see oauth metadata BEFORE it is cleared');
			assert.equal(seen[0].oauthAtCall.provider, 'ghost-provider');
			assert.ok(seen[0].oauthUserAtCall, 'callback must see oauthUser metadata BEFORE it is cleared');
			// Session IS cleared after the callback returns
			assert.equal(context.session.oauth, undefined);
			assert.equal(context.session.oauthUser, undefined);
		});

		it('no-provider-name branch: callback sees full session, session is cleared after', async () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
			}

			const seen = [];
			const context = {
				session: makeSession({
					// OAuth data exists but has no `provider` field — invalid state
					oauth: { accessToken: 'orphan', someOtherField: 'x' },
				}),
			};

			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: (request, error) => {
					seen.push({
						oauthAtCall: request.session.oauth && { ...request.session.oauth },
						oauthUserAtCall: request.session.oauthUser && { ...request.session.oauthUser },
						error,
					});
					return { status: 401, body: { custom: true } };
				},
			});

			const instance = new Wrapped('x', context);
			await instance.get({ path: '/protected' });

			assert.equal(seen.length, 1);
			assert.ok(seen[0].oauthAtCall, 'callback must see oauth before clearing');
			assert.equal(seen[0].oauthAtCall.accessToken, 'orphan');
			assert.equal(context.session.oauth, undefined, 'session cleared after callback');
		});
	});

	describe('Undefined super methods', () => {
		it('returns undefined if the base class does not define the HTTP method', async () => {
			// Matches Harper's own "method not implemented" behavior:
			// `resource.<method>?.(…)` short-circuits to undefined, and
			// Harper renders that as 404 / method-not-allowed. The
			// wrapper still runs validation first so unreachable verbs
			// are defense-in-depth protected.
			class GetOnly extends MockResource {
				async get() {
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(GetOnly, { providers: mockProviders, logger: mockLogger });

			const instance = new Wrapped('x', { session: makeSession() });
			const result = await instance.post({ path: '/x' }, { data: 1 });
			assert.equal(result, undefined);
		});
	});
});
