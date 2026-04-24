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
		// IMPORTANT: this session has NO `delete()` method. That matters
		// for tests that hit `clearOAuthSession` (e.g. expired-token
		// paths): those tests exercise the in-memory fallback inside
		// `clearOAuthSession`, not the production `session.delete(id)`
		// path. For production-shaped behavior use
		// `makeProductionLikeSession` below.
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

	// A Harper-production-shaped session: provides `delete(id)` like the
	// real hdb_session record so `clearOAuthSession` takes the
	// `session.delete(id)` branch (full DB destruction) instead of the
	// in-memory fallback.
	function makeProductionLikeSession(overrides = {}) {
		const base = makeSession(overrides);
		const deleteCalls = [];
		base.delete = async (id) => {
			deleteCalls.push(id);
		};
		// Expose the spy ledger for assertions
		base.__deleteCalls = deleteCalls;
		return base;
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

	describe('Unimplemented verbs preserve 405 semantics', () => {
		// When the parent class doesn't implement an HTTP verb, the
		// wrapper MUST NOT define one either — otherwise Harper's REST
		// dispatcher sees a callable method that returns `undefined`
		// and serializes that as 204 No Content (wrong), masking the
		// correct 405 Method Not Allowed signal.
		it('leaves Wrapped.prototype.<verb> undefined when the parent does not define it', () => {
			class GetOnly extends MockResource {
				async get() {
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(GetOnly, { providers: mockProviders, logger: mockLogger });

			const instance = new Wrapped('x', { session: makeSession() });
			assert.equal(typeof instance.get, 'function', 'get is defined — Wrapped wraps it');
			assert.equal(typeof instance.post, 'undefined', 'post is NOT wrapped — preserves 405');
			assert.equal(typeof instance.put, 'undefined');
			assert.equal(typeof instance.patch, 'undefined');
			assert.equal(typeof instance.delete, 'undefined');
		});

		it('leaves Wrapped.<verb> static undefined when the parent has no static for it', () => {
			// MockResource only defines the instance get. It has no
			// static get/post/etc. on itself (test-shape base). Wrapped
			// must match.
			class GetOnly extends MockResource {
				async get() {
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(GetOnly, { providers: mockProviders, logger: mockLogger });

			// No static methods installed — MockResource doesn't have any.
			assert.equal(typeof Wrapped.get, 'undefined');
			assert.equal(typeof Wrapped.post, 'undefined');
		});
	});

	describe('Static-method dispatch bypass is closed', () => {
		// Harper v5's migration guide recommends `static async get(target)`
		// on Resource classes. When a user follows that pattern, Harper
		// dispatches at the STATIC level — our instance-method overrides
		// alone can't intercept, so validation would be silently skipped.
		// The wrapper installs static overrides for exactly this reason.

		// A Resource-shaped base that also exposes statics (closer to the
		// real Harper Resource base than plain `MockResource`). Each
		// static dispatches to an instance method when present.
		class StaticCapableResource {
			static loadAsInstance = false;
			constructor(id, context) {
				this._id = id;
				this._context = context ?? null;
			}
			getContext() {
				return this._context;
			}
		}
		for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
			StaticCapableResource[method] = function (target, request) {
				const instance = new this(target?.id ?? 'sid', request);
				return instance[method]?.(target);
			};
		}

		it('intercepts user-defined static get (v5-recommended pattern)', async () => {
			let staticRan = false;
			class StaticUser extends StaticCapableResource {
				// User-defined STATIC method — this would bypass the
				// previous Proxy/instance-only wrapper. The wrapper's
				// static override must fire validation BEFORE this runs.
				static async get(target, request) {
					staticRan = true;
					return { status: 200, body: { user: request.session.oauthUser.email } };
				}
			}
			const Wrapped = withOAuthValidation(StaticUser, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			// Call at the static level exactly like Harper does
			const result = await Wrapped.get({ path: '/protected' }, { session: makeSession() });

			assert.equal(result.status, 200);
			assert.equal(result.body.user, 'alice@example.com');
			assert.equal(staticRan, true, 'user static ran (validation let it through)');
		});

		it('returns 401 at the static entry when requireAuth is true and no OAuth data', async () => {
			let staticRan = false;
			class StaticUser extends StaticCapableResource {
				static async get() {
					staticRan = true;
					return { status: 200, body: { shouldNotSeeThis: true } };
				}
			}
			const Wrapped = withOAuthValidation(StaticUser, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			// No OAuth on the session — must be rejected at static entry,
			// before the user's static runs.
			const result = await Wrapped.get({ path: '/protected' }, { session: { id: 'no-oauth' } });

			assert.equal(result.status, 401, 'static entry must enforce OAuth for user-static case');
			assert.equal(staticRan, false, 'user static must NOT run on auth failure');
		});

		it('intercepts user-defined static post (3-arg shape: target, data, request)', async () => {
			// Harper's REST dispatcher uses two distinct arg shapes:
			//   GET/DELETE            → (target, request)          — 2 args
			//   POST/PUT/PATCH        → (target, data, request)    — 3 args
			// The wrapper picks the request up from `args[args.length - 1]`
			// so both shapes work. The other static-dispatch tests only
			// exercise the 2-arg GET shape, so a refactor that changes the
			// extraction to `args[1]` ("always the second arg") would break
			// 3-arg verbs silently — it'd read `data` into the context check
			// and either 401 unconditionally (breaking requireAuth: false) or
			// pass through without validation. Pin the 3-arg path directly.
			let staticRan = false;
			let seenData;
			class PostResource extends StaticCapableResource {
				static async post(_target, data, request) {
					staticRan = true;
					seenData = data;
					return {
						status: 201,
						body: { user: request.session.oauthUser.email, created: data },
					};
				}
			}
			const Wrapped = withOAuthValidation(PostResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			// Unauthenticated 3-arg call — validation must fire against args[2]
			// (the real request), not args[1] (the body).
			const denied = await Wrapped.post({ path: '/items' }, { name: 'new-item' }, { session: { id: 'no-oauth' } });
			assert.equal(denied.status, 401, '3-arg dispatch must enforce OAuth against the request arg');
			assert.equal(staticRan, false, 'user static must NOT run on auth failure');

			// Authenticated 3-arg call — user static runs and receives the body.
			const ok = await Wrapped.post({ path: '/items' }, { name: 'new-item' }, { session: makeSession() });
			assert.equal(ok.status, 201);
			assert.equal(ok.body.user, 'alice@example.com');
			assert.deepEqual(seenData, { name: 'new-item' }, 'data arg (args[1]) must survive the wrapper');
		});

		it('validation runs only once per request across the static→instance chain', async () => {
			// Instance-method case: Harper calls the static (Resource
			// base's transactional dispatch), which creates an instance
			// and calls instance get. Both layers go through the wrapper.
			// The WeakSet dedup must keep validation to a single network
			// hit per request.
			let validateCalls = 0;
			const countingProvider = {
				provider: {
					refreshAccessToken: async () => ({ access_token: 'new', expires_in: 3600, token_type: 'Bearer' }),
					config: { provider: 'github' },
				},
				config: { provider: 'github' },
			};
			let instanceRan = 0;
			class InstanceUser extends StaticCapableResource {
				async get() {
					instanceRan += 1;
					return { status: 200 };
				}
			}
			// Spy on validation: count how many times mockProviders.github is consulted.
			// We approximate by counting how often the validation helper reaches the
			// provider lookup — every validation pass reads providers[providerName].
			const spiedProviders = new Proxy(
				{ github: countingProvider },
				{
					get(target, prop) {
						if (prop === 'github') validateCalls += 1;
						return target[prop];
					},
				}
			);

			const Wrapped = withOAuthValidation(InstanceUser, {
				providers: spiedProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			// Static entry, the realistic Harper dispatch path
			await Wrapped.get({ path: '/x' }, { session: makeSession() });

			assert.equal(instanceRan, 1, 'instance method runs exactly once');
			assert.equal(validateCalls, 1, 'validation runs exactly once (no double-hit)');
		});

		it('405 preservation: unimplemented verbs shadowed with undefined when base exposes all statics', () => {
			// Harper's real Resource base defines `static <verb> = transactional(...)`
			// for every HTTP verb — every user subclass INHERITS a truthy
			// static for every verb. A simple `typeof ResourceClass[method] ===
			// 'function'` check would cause the wrapper to install an auth
			// override for every verb, turning an expected 405 (from Harper's
			// `missingMethod` branch in server/REST.ts:117) into a 401 when
			// requireAuth is true, or a 204 passthrough otherwise. The wrapper
			// MUST shadow unimplemented verbs with `undefined` so REST
			// dispatch's `resource.<verb> ? ... : missingMethod(...)` check
			// takes the 405 branch.
			class GetOnly extends StaticCapableResource {
				async get() {
					return { status: 200 };
				}
			}
			const Wrapped = withOAuthValidation(GetOnly, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
			});

			// User implements GET via instance method — wrapped (static leg
			// intercepts for validation; inherited transactional reaches the
			// instance method).
			assert.equal(typeof Wrapped.get, 'function');
			// All other verbs: inherited from StaticCapableResource (mimicking
			// Harper's Resource base). The wrapper MUST explicitly shadow
			// these with `undefined`, otherwise Harper's REST dispatcher sees
			// a truthy static and skips the 405 branch.
			assert.equal(typeof Wrapped.post, 'undefined', 'post must be undefined to preserve Harper 405');
			assert.equal(typeof Wrapped.put, 'undefined', 'put must be undefined to preserve Harper 405');
			assert.equal(typeof Wrapped.patch, 'undefined', 'patch must be undefined to preserve Harper 405');
			assert.equal(typeof Wrapped.delete, 'undefined', 'delete must be undefined to preserve Harper 405');
		});

		it('405 preservation: user-owned static overrides inherited shadowing', () => {
			// When the user defines their OWN static for a verb (Harper v5
			// migration guide's recommended pattern), the wrapper must
			// install a validation override — not shadow to undefined.
			class PostAsStatic extends StaticCapableResource {
				static async post(_target, request) {
					return { status: 201, body: { email: request.session.oauthUser.email } };
				}
			}
			const Wrapped = withOAuthValidation(PostAsStatic, {
				providers: mockProviders,
				logger: mockLogger,
			});

			assert.equal(typeof Wrapped.post, 'function', 'user own-static gets wrapped for validation');
			// Verbs the user neither declared as own-static nor as instance
			// method remain shadowed, even though the base class exposes them.
			assert.equal(typeof Wrapped.get, 'undefined', 'get still shadowed');
			assert.equal(typeof Wrapped.put, 'undefined', 'put still shadowed');
			assert.equal(typeof Wrapped.delete, 'undefined', 'delete still shadowed');
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

		// The expired-token path has explicit fail-closed coverage above.
		// The `!providerName` and `!providerData` stale-provider paths use
		// the SAME `callCallbackOrDeny` helper with the SAME `?? defaultDeny`
		// semantics — but each path deserves its own direct test, because a
		// future refactor that inlines the callback invocation on ONE branch
		// without `defaultDeny` would silently bypass auth there and the
		// expired-token test would still pass, giving false confidence.
		it('no-provider-name branch: handler returns undefined — wrapper falls back to default 401', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200, shouldNeverHappen: true };
				}
			}
			const context = {
				// Session has an oauth object but no `provider` — hits the
				// `!providerName` branch in validateOAuthForRequest.
				session: makeSession({ oauth: { accessToken: 'stale', provider: undefined } }),
			};
			let handlerCalled = false;
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: () => {
					handlerCalled = true;
					// no return — returns undefined
				},
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(handlerCalled, true, 'handler must be invoked on stale-session branch');
			assert.equal(result.status, 401, 'must fail closed on undefined handler return');
			assert.equal(result.body.error, 'Unauthorized');
			assert.match(result.body.message, /invalid/i);
			assert.equal(calls.length, 0, 'protected method must NOT run — silent-bypass guard');
		});

		it('unknown-provider branch: handler returns undefined — wrapper falls back to default 401', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200, shouldNeverHappen: true };
				}
			}
			const context = {
				// Session references a provider that's not in the registry —
				// hits the `!providerData` branch in validateOAuthForRequest.
				session: makeSession({ oauth: { provider: 'ghost-provider', accessToken: 'stale' } }),
			};
			let handlerCalled = false;
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: () => {
					handlerCalled = true;
					// no return — returns undefined
				},
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/protected' });

			assert.equal(handlerCalled, true, 'handler must be invoked on unknown-provider branch');
			assert.equal(result.status, 401, 'must fail closed on undefined handler return');
			assert.equal(result.body.error, 'Unauthorized');
			assert.match(result.body.message, /not configured/i);
			assert.equal(calls.length, 0, 'protected method must NOT run — silent-bypass guard');
		});

		it('production-path session: callback sees full oauth data (not mutated by clearOAuthSession)', async () => {
			// `validateAndRefreshSession` calls `clearOAuthSession` as a
			// side effect before returning `{valid: false}`. In the
			// production path (session with a `delete()` method),
			// `clearOAuthSession` calls `session.delete(session.id)` and
			// does NOT mutate the in-memory session object. So the
			// `onValidationError` callback — invoked after that —
			// still observes the full oauth/oauthUser data. Pin this
			// behavior so it can't regress silently.
			const session = makeProductionLikeSession({
				oauth: {
					provider: 'github',
					accessToken: 'expired',
					expiresAt: Date.now() - 60_000,
					refreshToken: undefined,
				},
			});
			const calls = [];
			class MyResource extends MockResource {
				async get() {
					calls.push('called');
					return { status: 200 };
				}
			}

			const seen = [];
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: true,
				onValidationError: (request) => {
					const oauth = request.session.oauth;
					const oauthUser = request.session.oauthUser;
					seen.push({
						oauthProvider: oauth?.provider,
						oauthAccessToken: oauth?.accessToken,
						oauthUserEmail: oauthUser?.email,
					});
					return { status: 401, body: { ok: true } };
				},
			});

			const instance = new Wrapped('x', { session });
			await instance.get({ path: '/protected' });

			assert.equal(calls.length, 0, 'protected method must not run');
			assert.equal(seen.length, 1);
			assert.equal(seen[0].oauthProvider, 'github', 'oauth.provider must be readable in production path');
			assert.equal(seen[0].oauthAccessToken, 'expired', 'oauth.accessToken must be readable in production path');
			assert.equal(seen[0].oauthUserEmail, 'alice@example.com', 'oauthUser.email must be readable');
			assert.deepEqual(session.__deleteCalls, ['sess-1'], 'session.delete(id) was called');
		});
	});

	describe('onValidationError is only invoked when requireAuth is true', () => {
		// `onValidationError` exists to let integrators customize the
		// 401 response (or add logging). It is documented to fire ONLY
		// when `requireAuth` is true: with `requireAuth: false` the
		// wrapper's contract is "pass through; clean up stale state as
		// a side effect" and the callback is explicitly NOT called.
		// Integrators reading the JSDoc should not expect to use
		// `onValidationError` as an audit hook for mixed-auth resources.

		it('stale-provider + requireAuth: false → callback NOT invoked (session still cleaned)', async () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
			}
			const context = {
				session: makeSession({ oauth: { provider: 'ghost-provider', accessToken: 'stale' } }),
			};
			let handlerCalled = false;
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: false,
				onValidationError: () => {
					handlerCalled = true;
					return { status: 500, body: { shouldNotSeeThis: true } };
				},
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/mixed' });

			assert.equal(handlerCalled, false, 'callback must NOT fire when requireAuth is false');
			assert.equal(result.status, 200, 'underlying method runs');
			assert.equal(context.session.oauth, undefined, 'stale session data still cleaned up');
		});

		it('expired-token + requireAuth: false → callback NOT invoked (passthrough)', async () => {
			class MyResource extends MockResource {
				async get() {
					return { status: 200 };
				}
			}
			const session = makeProductionLikeSession({
				oauth: {
					provider: 'github',
					accessToken: 'expired',
					expiresAt: Date.now() - 60_000,
					refreshToken: undefined,
				},
			});
			let handlerCalled = false;
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: false,
				onValidationError: () => {
					handlerCalled = true;
					return { status: 500, body: { shouldNotSeeThis: true } };
				},
			});

			const instance = new Wrapped('x', { session });
			const result = await instance.get({ path: '/mixed' });

			assert.equal(handlerCalled, false, 'callback must NOT fire when requireAuth is false');
			assert.equal(result.status, 200, 'underlying method runs');
		});
	});

	describe('Expired token with requireAuth: false passes through — cleanup semantics', () => {
		// `validateAndRefreshSession` calls `clearOAuthSession` as a side
		// effect when the token is expired and no refresh token is
		// available. When `requireAuth` is false the wrapper falls
		// through to the underlying method, which runs with a session
		// that's about to be (or has already been) cleaned up.
		//
		// `clearOAuthSession` has TWO code paths depending on whether
		// the session provides a `delete(id)` method:
		//   - with `delete`:  production path — Harper destroys the DB
		//                     session record. The in-memory session
		//                     object's oauth fields are NOT touched.
		//   - without:        in-memory fallback — deletes `oauth` and
		//                     `oauthUser` fields directly.
		//
		// Both paths are exercised below so behavior is pinned down for
		// integrators.

		it('fallback path (no session.delete): underlying method runs, oauth fields cleared in-memory', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get(target) {
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
			// In the fallback path, clearOAuthSession deletes the in-memory
			// oauth fields directly, so the resource observes an empty session.
			assert.equal(calls[0].oauthAfterValidate, undefined);
			assert.equal(calls[0].oauthUserAfterValidate, undefined);
		});

		it('production path (session.delete present): underlying method runs, delete(id) called with session id', async () => {
			const calls = [];
			class MyResource extends MockResource {
				async get(target) {
					// In the production path, `clearOAuthSession` invokes
					// `session.delete(session.id)` — it does NOT mutate the
					// in-memory session object. So by the time the resource
					// runs, the DB record is doomed but the in-memory oauth
					// fields may still be populated.
					calls.push({
						target,
						oauthAfterValidate: this._context.session.oauth,
					});
					return { status: 200, body: { ran: true } };
				}
			}
			const session = makeProductionLikeSession({
				oauth: {
					provider: 'github',
					accessToken: 'expired-token',
					expiresAt: Date.now() - 60_000,
					refreshToken: undefined,
				},
			});
			const context = { session };
			const Wrapped = withOAuthValidation(MyResource, {
				providers: mockProviders,
				logger: mockLogger,
				requireAuth: false,
			});

			const instance = new Wrapped('x', context);
			const result = await instance.get({ path: '/mixed' });

			assert.equal(result.status, 200, 'underlying method must still run when requireAuth is false');
			assert.equal(result.body.ran, true);
			assert.equal(calls.length, 1);
			// The production path destroys the DB record via session.delete(session.id).
			assert.deepEqual(
				session.__deleteCalls,
				['sess-1'],
				'clearOAuthSession must call session.delete(session.id) in the production path'
			);
			// The in-memory session object isn't mutated by the production path —
			// documenting this so integrators know what the resource observes.
			assert.ok(
				calls[0].oauthAfterValidate !== undefined,
				'production path does not mutate the in-memory session object'
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
