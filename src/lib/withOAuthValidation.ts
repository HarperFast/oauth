/**
 * OAuth Session Validation Wrapper
 *
 * Wraps a Harper Resource **class** so HTTP methods run OAuth session
 * validation (and automatic token refresh) before the wrapped method
 * executes. The returned value is a subclass of the input class: Harper
 * registers it via `resources.set(...)` and invokes it through the
 * standard `static getResource` lifecycle. Per-request instances inherit
 * `getContext()` from the user's base `Resource`, so the validation runs
 * against the real request context with no extra plumbing.
 */

import type { Context, SourceContext } from 'harper';
import type { Request, Logger, ProviderRegistry } from '../types.ts';
import { validateAndRefreshSession } from './sessionValidator.ts';

export interface OAuthValidationOptions {
	/** OAuth provider registry from plugin initialization */
	providers: ProviderRegistry;
	/** Logger instance for debugging */
	logger?: Logger;
	/** Whether to require OAuth authentication (401 if not present) */
	requireAuth?: boolean;
	/**
	 * Custom error handler for validation failures.
	 *
	 * **Only invoked when `requireAuth` is `true`**. When `requireAuth`
	 * is `false` the wrapper passes through silently on any validation
	 * failure (cleaning up stale session data as a side effect) — this
	 * callback is not called. If you need audit logging on a mixed-auth
	 * resource, set `requireAuth: true` on that resource, or log from
	 * your own `logger` (which IS always invoked).
	 *
	 * **Session state visibility depending on the failure path:**
	 * - `!hasOAuth` — `request.session.oauth` is already `undefined`
	 *   (there never was any).
	 * - `!providerName` / `!providerData` (stale-provider paths) — the
	 *   callback is invoked BEFORE session cleanup, so
	 *   `request.session.oauth` and `.oauthUser` are readable.
	 * - `!validation.valid` (expired token with no refresh token) —
	 *   `validateAndRefreshSession` has ALREADY called
	 *   `clearOAuthSession` internally before the callback runs. On a
	 *   production Harper session this calls `session.delete(session.id)`
	 *   (DB record destroyed; in-memory fields untouched). On a session
	 *   without a `delete()` method it falls back to in-memory deletion
	 *   of `.oauth` / `.oauthUser`. The callback is still invoked, but
	 *   the session state it observes depends on which path ran.
	 */
	onValidationError?: (request: Request, error: string) => any;
}

type MaybeContext = Context | SourceContext | undefined;

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

/**
 * Run OAuth validation for a request context.
 *
 * Returns `undefined` when the wrapped method should continue. Returns
 * a response object (or the result of `onValidationError`) when the
 * wrapped method should be short-circuited.
 *
 * `onValidationError` is called only on paths where a concrete `request`
 * exists and validation failed semantically (no OAuth data, invalid
 * provider, expired session, etc.). It is **not** invoked on the
 * no-context path, since the callback's signature requires a `Request`
 * and callers are entitled to read `request.session` / `.ip` / `.headers`.
 */
async function validateOAuthForRequest(context: MaybeContext, options: OAuthValidationOptions): Promise<any> {
	const { providers, logger, requireAuth = false, onValidationError } = options;
	const request: Request | undefined =
		(context as any)?.session !== undefined ? (context as unknown as Request) : undefined;

	// No v2 context / no session → fail-closed when requireAuth, otherwise passthrough.
	// We do NOT call onValidationError here: the callback signature requires
	// a Request, and callers read request.session / .ip / .headers. Passing
	// `undefined` would turn a clean 401 into a TypeError in user code.
	if (!request) {
		if (requireAuth) {
			return {
				status: 401,
				body: {
					error: 'Unauthorized',
					message: 'No request context available',
				},
			};
		}
		return undefined;
	}

	// When onValidationError is provided, we still always need a
	// fall-back 401 to return if the handler returns `undefined` — e.g.
	// a plain logging callback like `async (req, err) => { log(err) }`.
	// Without the fallback, `undefined` would propagate as "no problem"
	// and silently bypass auth. We use `??` everywhere the handler is
	// invoked so a no-return handler is indistinguishable, security-wise,
	// from no handler at all.
	const callCallbackOrDeny = async (request: Request, error: string, defaultDeny: any): Promise<any> => {
		if (!onValidationError) return defaultDeny;
		const result = await onValidationError(request, error);
		return result ?? defaultDeny;
	};

	const hasOAuth = request.session?.oauth !== undefined;
	if (!hasOAuth) {
		if (requireAuth) {
			const error = 'OAuth authentication required';
			return callCallbackOrDeny(request, error, {
				status: 401,
				body: { error: 'Unauthorized', message: error },
			});
		}
		return undefined;
	}

	const clearStaleOAuth = () => {
		if (request.session) {
			delete request.session.oauth;
			delete request.session.oauthUser;
		}
	};

	const providerName = request.session?.oauth?.provider;
	if (!providerName) {
		if (requireAuth) {
			const error = 'Invalid OAuth session data';
			// Invoke the callback BEFORE clearing so it can read
			// request.session.oauth / .oauthUser (audit logging, etc.).
			const response = await callCallbackOrDeny(request, error, {
				status: 401,
				body: { error: 'Unauthorized', message: error },
			});
			clearStaleOAuth();
			return response;
		}
		clearStaleOAuth();
		return undefined;
	}

	const providerData = providers[providerName];
	if (!providerData) {
		logger?.warn?.(`OAuth provider '${providerName}' not found for session validation`);
		if (requireAuth) {
			const error = `OAuth provider '${providerName}' not configured`;
			// Same ordering as above: callback sees un-mutated request.
			const response = await callCallbackOrDeny(request, error, {
				status: 401,
				body: { error: 'Unauthorized', message: error },
			});
			clearStaleOAuth();
			return response;
		}
		clearStaleOAuth();
		return undefined;
	}

	const validation = await validateAndRefreshSession(request, providerData.provider, logger);
	if (!validation.valid) {
		logger?.info?.(`OAuth session validation failed: ${validation.error}`);
		if (requireAuth) {
			const error = validation.error || 'OAuth session expired';
			return callCallbackOrDeny(request, error, {
				status: 401,
				body: {
					error: 'Unauthorized',
					message: 'OAuth session expired. Please log in again.',
					details: validation.error,
				},
			});
		}
		return undefined;
	}

	if (validation.refreshed) {
		logger?.debug?.(`OAuth token refreshed for ${providerName} session`);
	}

	return undefined;
}

/**
 * Wrap a Harper `Resource` class so each HTTP method runs OAuth session
 * validation before the user-defined method executes.
 *
 * @example
 * ```typescript
 * // In your application component:
 * import { Resource } from 'harper';
 * import { withOAuthValidation } from '@harperfast/oauth';
 *
 * export function handleApplication(scope) {
 *   const oauthPlugin = scope.parent.resources.get('oauth');
 *
 *   class MyResource extends Resource {
 *     static loadAsInstance = false;
 *     async get(target) {
 *       const request = this.getContext();
 *       return { user: request.session.oauthUser };
 *     }
 *   }
 *
 *   const Protected = withOAuthValidation(MyResource, {
 *     providers: oauthPlugin.providers,
 *     requireAuth: true,
 *     logger: scope.logger,
 *   });
 *
 *   // Register the wrapped class — Harper handles instantiation per request
 *   scope.resources.set('protected', Protected);
 * }
 * ```
 *
 * Notes:
 * - The wrapper returns a **subclass** of `ResourceClass`. All static
 *   properties (including `loadAsInstance`) and static methods
 *   (including `getResource`) are inherited, so Harper's registration
 *   and dispatch lifecycle works unchanged.
 * - Validation is installed at BOTH static and instance levels so
 *   either Harper v5 dispatch pattern is intercepted:
 *   - User defines `async get(target)` (instance method): Harper's
 *     Resource base static `get` creates a Wrapped instance and
 *     invokes the instance method, which runs validation first.
 *   - User defines `static async get(target)` (v5-recommended pattern
 *     per Harper's migration guide): Harper calls `Wrapped.get`
 *     directly at the static level. Our static override catches this
 *     and runs validation before delegating.
 * - Only the verbs the user class actually implements (own static OR
 *   own instance method) get overridden. Unimplemented verbs are
 *   explicitly shadowed with `undefined` on the wrapper to blot out
 *   the Resource base's inherited transactional static, so Harper's
 *   native "405 Method Not Allowed" response (via `missingMethod` at
 *   server/REST.ts:117) is preserved — rather than our wrapper running
 *   validation on a verb the user never meant to expose.
 * - Validation is de-duplicated across the static→instance call chain
 *   via a per-request `WeakSet`. Both the request object AND
 *   `request.getContext?.()` are stamped, because Harper's transactional
 *   wrapper normalizes the request during dispatch — the object the
 *   instance method observes via `this.getContext()` may be a different
 *   reference than the one the static override saw. `validateAndRefresh
 *   Session` can hit the network for token refresh; running it twice per
 *   request would waste a round-trip.
 *
 * Session-cleanup semantics (intentional divergence — important for
 * integrators using `requireAuth: false`):
 * - Stale-provider paths (no provider name on session, or provider
 *   not in registry): the wrapper clears only the in-memory `oauth`
 *   and `oauthUser` fields via a local helper. The session record
 *   itself survives — "provider not configured" may be a recoverable
 *   config issue.
 * - Expired-token path (`validateAndRefreshSession` returns
 *   `{valid: false}`): `validateAndRefreshSession` internally calls
 *   `clearOAuthSession`, which on a Harper production session
 *   invokes `session.delete(session.id)` — the DB record is destroyed.
 *   This is terminal: the user is logged out, not just detached from
 *   OAuth. `requireAuth: false` resources still receive the
 *   passthrough call, but they observe a session that is about to
 *   stop existing on the next request.
 */
export function withOAuthValidation<T extends abstract new (...args: any[]) => any>(
	ResourceClass: T,
	options: OAuthValidationOptions
): T {
	const parentProto = (ResourceClass as any).prototype;

	// Dedupe validation across the static→instance call chain. When Harper's
	// dispatch calls our static override, validation runs. If the parent
	// static is Resource's base transactional wrapper, it will then create
	// an instance and call the instance method — which is ALSO one of our
	// overrides (when we added one). Without dedupe, validation runs twice
	// per request and refreshAccessToken may hit the network twice.
	//
	// Harper's `transactional` wrapper and `getResource` normalize the
	// request via `request.getContext?.() || request` before constructing
	// the per-request instance, so `this.getContext()` in the instance
	// path may resolve to a DIFFERENT object than the `request` argument
	// the static received. We stamp both references (and check both on
	// lookup) so dedup works regardless of which one the instance observes.
	const validated = new WeakSet<object>();

	const markValidated = (ctx: any): void => {
		if (!ctx || typeof ctx !== 'object') return;
		validated.add(ctx);
		const inner = typeof ctx.getContext === 'function' ? ctx.getContext() : undefined;
		if (inner && typeof inner === 'object' && inner !== ctx) validated.add(inner);
	};

	const hasValidated = (ctx: any): boolean => {
		if (!ctx || typeof ctx !== 'object') return false;
		if (validated.has(ctx)) return true;
		const inner = typeof ctx.getContext === 'function' ? ctx.getContext() : undefined;
		return !!(inner && typeof inner === 'object' && validated.has(inner));
	};

	const validateOnce = async (context: any): Promise<any> => {
		if (hasValidated(context)) return undefined;
		const deny = await validateOAuthForRequest(context, options);
		if (deny !== undefined) return deny;
		markValidated(context);
		return undefined;
	};

	const Wrapped = class extends (ResourceClass as any) {};

	// Per-verb installation decision. Harper's Resource base defines a
	// static transactional wrapper for every HTTP verb, so inheritance
	// alone makes `(ResourceClass as any)[method]` truthy for every verb
	// — we can't use the static's presence to tell whether the USER
	// implements a verb. We infer user intent from:
	//   1. an OWN static on the class (v5-recommended `static async get`
	//      pattern), or
	//   2. an instance method on the prototype chain above Resource
	//      (Resource.prototype does not define these as functions, so a
	//      truthy parentProto[method] implies the user defined it).
	// When neither is present we SHADOW the inherited static with
	// `undefined` so REST dispatch (`resource.get ? ... : missingMethod`)
	// falls through to Harper's native 405 path instead of our wrapper
	// running validation on a verb the user never meant to expose.
	for (const method of HTTP_METHODS) {
		const hasOwnStatic = Object.prototype.hasOwnProperty.call(ResourceClass, method);
		const parentInstanceMethod = typeof parentProto?.[method] === 'function' ? parentProto[method] : undefined;
		const userImplements = hasOwnStatic || parentInstanceMethod !== undefined;

		if (!userImplements) {
			// Shadow the inherited Resource base transactional so REST.ts's
			// `resource.method ? ... : missingMethod(resource, method)` check
			// takes the 405 branch. Without this, the inherited transactional
			// would run and our wrapper would still validate — turning an
			// expected 405 into a 401 (or, with requireAuth: false, a 204 from
			// the transactional's `resource.method?.()` optional chain).
			(Wrapped as any)[method] = undefined;
			continue;
		}

		// Instance-method override — validates when the parent's static
		// dispatch (our own wrapper, or the inherited transactional)
		// eventually creates an instance and calls the instance method.
		if (parentInstanceMethod) {
			(Wrapped.prototype as any)[method] = async function (this: any, ...args: any[]) {
				const context = typeof this?.getContext === 'function' ? this.getContext() : undefined;
				const deny = await validateOnce(context);
				if (deny !== undefined) return deny;
				return parentInstanceMethod.apply(this, args);
			};
		}

		// Static-method override — intercepts Harper's direct class-level
		// dispatch before either the user's own static or the inherited
		// transactional runs. Without this, a user defining `static async
		// get` (the v5-recommended pattern) bypasses validation entirely,
		// and a user defining an instance `get` would have validation
		// skipped on the static-call leg before the transactional creates
		// an instance.
		//
		// REST dispatch arg shapes (server/REST.ts:117–125):
		//   GET/DELETE: (target, request)
		//   POST/PUT/PATCH: (target, data, request)
		// The request (carrying `.session`) is always the last argument.
		const parentStatic = (ResourceClass as any)[method];
		if (typeof parentStatic === 'function') {
			(Wrapped as any)[method] = async function (...args: any[]) {
				const request = args.length > 0 ? args[args.length - 1] : undefined;
				const deny = await validateOnce(request);
				if (deny !== undefined) return deny;
				return parentStatic.apply(Wrapped, args);
			};
		}
	}

	return Wrapped as unknown as T;
}

/**
 * Helper to get OAuth providers from the OAuth plugin
 * Call this from your application to access the provider registry
 *
 * @example
 * ```typescript
 * import { getOAuthProviders } from '@harperfast/oauth';
 *
 * export function handleApplication(scope) {
 *   const providers = getOAuthProviders(scope);
 *   // Use providers with withOAuthValidation
 * }
 * ```
 */
export function getOAuthProviders(scope: any): ProviderRegistry | null {
	try {
		// Try to get OAuth plugin from parent scope
		const oauthResource = scope.parent?.resources?.get?.('oauth');
		if (oauthResource?.providers) {
			return oauthResource.providers;
		}

		// Try to get from same scope (if plugin is loaded at same level)
		const localOAuth = scope.resources?.get?.('oauth');
		if (localOAuth?.providers) {
			return localOAuth.providers;
		}

		return null;
	} catch {
		// OAuth module not loaded or accessible
		return null;
	}
}
