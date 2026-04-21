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
import { withOAuthValidation, getOAuthProviders } from '../../dist/lib/withOAuthValidation.js';

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
					// Explicit property access — Harper's GenericTrackedObject
					// does NOT support `{ ...obj }` spread (per CLAUDE.md
					// Non-Obvious Gotchas). Tests that snapshot via spread
					// would silently yield empty objects in production and
					// mislead integrators who copy the callback pattern.
					const oauth = request.session.oauth;
					const oauthUser = request.session.oauthUser;
					seen.push({
						oauthAtCall: oauth && {
							provider: oauth.provider,
							accessToken: oauth.accessToken,
						},
						oauthUserAtCall: oauthUser && {
							username: oauthUser.username,
							email: oauthUser.email,
							role: oauthUser.role,
						},
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
					const oauth = request.session.oauth;
					seen.push({
						oauthAtCall: oauth && {
							accessToken: oauth.accessToken,
							someOtherField: oauth.someOtherField,
						},
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

	describe('Expired token with requireAuth: true invokes onValidationError', () => {
		// The !validation.valid path is the most common real-world
		// failure: a logged-in user's token has expired and can't be
		// refreshed. Two cases matter here:
		//
		// (a) Handler returns a custom response → that response is what
		//     the caller sees.
		// (b) Handler returns undefined (plausible — a pure logging
		//     callback). The wrapper MUST fall back to the default 401
		//     rather than propagating `undefined` as a "no problem"
		//     sentinel, which would silently invoke the protected method.
		it('handler returns a response — wrapper returns it verbatim', async () => {
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
						accessToken: 'expired',
						expiresAt: Date.now() - 60_000,
						refreshToken: undefined,
					},
				}),
			};
			const seen = [];
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: (request, error) => {
					seen.push({ error, hasRequest: !!request });
					return { status: 418, body: { custom: true } };
				},
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(result.status, 418);
			assert.equal(result.body.custom, true);
			assert.equal(calls.length, 0, 'protected method must not run');
			assert.equal(seen.length, 1);
			assert.match(seen[0].error, /expired/i);
		});

		it('handler returns undefined — wrapper falls back to default 401 (no silent bypass)', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200, shouldNeverHappen: true };
				}
			}
			const context = {
				session: makeSession({
					oauth: {
						provider: 'github',
						accessToken: 'expired',
						expiresAt: Date.now() - 60_000,
						refreshToken: undefined,
					},
				}),
			};
			let handlerCalled = false;
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				// Plausible real-world shape: a pure logging callback
				// that happens to return void. Must NOT be interpreted
				// as "continue."
				onValidationError: () => {
					handlerCalled = true;
					// no return — returns undefined
				},
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(handlerCalled, true, 'handler must be invoked');
			assert.equal(result.status, 401, 'must fail closed on undefined handler return');
			assert.equal(result.body.error, 'Unauthorized');
			assert.match(result.body.message, /expired/i);
			assert.equal(calls.length, 0, 'protected method must NOT run — this is the silent-bypass case');
		});
	});

	describe('Expired token with requireAuth: false passes through and clears the session', () => {
		// New reachable behavior post-v5: `validateAndRefreshSession`
		// calls `clearOAuthSession` internally when the token is expired
		// and no refresh token is available. When `requireAuth` is false
		// the wrapper falls through to the underlying method — but the
		// session's oauth data has already been cleared as a side effect.
		it('underlying method runs; session.oauth is cleared', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get(target) {
					// Capture session state AT method invocation — by this
					// point validateAndRefreshSession should have cleared
					// the stale oauth fields.
					calls.push({
						target,
						oauthAfterValidate: this._context.session.oauth,
						oauthUserAfterValidate: this._context.session.oauthUser,
					});
					return { status: 200, body: { ran: true } };
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
				requireAuth: false,
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/mixed' });

			assert.equal(result.status, 200, 'underlying method must run when requireAuth is false');
			assert.equal(result.body.ran, true);
			assert.equal(calls.length, 1);
			assert.equal(
				calls[0].oauthAfterValidate,
				undefined,
				'stale oauth metadata must be cleared before the underlying method observes the session'
			);
			assert.equal(
				calls[0].oauthUserAfterValidate,
				undefined,
				'stale oauthUser metadata must be cleared before the underlying method observes the session'
			);
		});
	});
});

describe('getOAuthProviders', () => {
	const fakeRegistry = { github: { provider: {}, config: { provider: 'github' } } };

	it('returns the provider registry from a parent scope', () => {
		const oauthResource = { providers: fakeRegistry };
		const scope = {
			parent: {
				resources: {
					get: (name) => (name === 'oauth' ? oauthResource : undefined),
				},
			},
			resources: {
				get: () => undefined,
			},
		};

		assert.equal(getOAuthProviders(scope), fakeRegistry);
	});

	it('returns the provider registry from the same scope when no parent lookup matches', () => {
		const oauthResource = { providers: fakeRegistry };
		const scope = {
			parent: { resources: { get: () => undefined } },
			resources: {
				get: (name) => (name === 'oauth' ? oauthResource : undefined),
			},
		};

		assert.equal(getOAuthProviders(scope), fakeRegistry);
	});

	it('returns null when no oauth resource is found in either scope', () => {
		const scope = {
			parent: { resources: { get: () => undefined } },
			resources: { get: () => undefined },
		};

		assert.equal(getOAuthProviders(scope), null);
	});

	it('returns null when the lookup throws (swallows traversal errors)', () => {
		const scope = {
			parent: {
				resources: {
					get: () => {
						throw new Error('boom');
					},
				},
			},
		};

		assert.equal(getOAuthProviders(scope), null);
	});
});
