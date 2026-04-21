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
	/** Custom error handler for validation failures */
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

	const hasOAuth = request.session?.oauth !== undefined;
	if (!hasOAuth) {
		if (requireAuth) {
			const error = 'OAuth authentication required';
			if (onValidationError) return onValidationError(request, error);
			return { status: 401, body: { error: 'Unauthorized', message: error } };
		}
		return undefined;
	}

	const providerName = request.session?.oauth?.provider;
	if (!providerName) {
		if (request.session) {
			delete request.session.oauth;
			delete request.session.oauthUser;
		}
		if (requireAuth) {
			const error = 'Invalid OAuth session data';
			if (onValidationError) return onValidationError(request, error);
			return { status: 401, body: { error: 'Unauthorized', message: error } };
		}
		return undefined;
	}

	const providerData = providers[providerName];
	if (!providerData) {
		logger?.warn?.(`OAuth provider '${providerName}' not found for session validation`);
		if (request.session) {
			delete request.session.oauth;
			delete request.session.oauthUser;
		}
		if (requireAuth) {
			const error = `OAuth provider '${providerName}' not configured`;
			if (onValidationError) return onValidationError(request, error);
			return { status: 401, body: { error: 'Unauthorized', message: error } };
		}
		return undefined;
	}

	const validation = await validateAndRefreshSession(request, providerData.provider, logger);
	if (!validation.valid) {
		logger?.info?.(`OAuth session validation failed: ${validation.error}`);
		if (requireAuth) {
			const error = validation.error || 'OAuth session expired';
			if (onValidationError) return onValidationError(request, error);
			return {
				status: 401,
				body: {
					error: 'Unauthorized',
					message: 'OAuth session expired. Please log in again.',
					details: validation.error,
				},
			};
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
