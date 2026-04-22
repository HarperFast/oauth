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
 * - The five standard HTTP methods — `get`, `post`, `put`, `patch`,
 *   `delete` — are overridden to run validation first. Other methods
 *   (subscriptions, helpers, etc.) pass through untouched.
 * - If the parent class does not define an HTTP method, the wrapper
 *   still runs validation, then returns `undefined` — matching
 *   Harper's "method not implemented" behavior. This means validation
 *   runs even on unhandled verbs (defense-in-depth).
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
	// Capture the parent prototype so we can look up HTTP methods directly
	// without using `super` (TypeScript doesn't allow optional chaining on
	// `super` member access, and the `delete` keyword as a method name via
	// `super` trips up some compilation targets). Prototype lookup walks
	// the chain, so inherited methods are found too.
	const parentProto = (ResourceClass as any).prototype;

	const delegate = async (instance: any, method: string, args: any[]) => {
		const deny = await validateOAuthForRequest(instance.getContext?.(), options);
		if (deny !== undefined) return deny;
		const parentMethod = parentProto?.[method];
		return typeof parentMethod === 'function' ? parentMethod.apply(instance, args) : undefined;
	};

	const Wrapped = class extends (ResourceClass as any) {
		async get(...args: any[]) {
			return delegate(this, 'get', args);
		}
		async post(...args: any[]) {
			return delegate(this, 'post', args);
		}
		async put(...args: any[]) {
			return delegate(this, 'put', args);
		}
		async patch(...args: any[]) {
			return delegate(this, 'patch', args);
		}
		async delete(...args: any[]) {
			return delegate(this, 'delete', args);
		}
	};
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
