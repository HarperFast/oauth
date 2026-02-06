/**
 * OAuth Session Validation Wrapper
 *
 * Wraps Harper resources to add automatic OAuth session validation and token refresh
 * before handling any request. This enables transparent token management for protected endpoints.
 */

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

/**
 * Wraps a Harper resource to add automatic OAuth session validation
 *
 * This wrapper intercepts all resource method calls (get, post, put, patch, delete)
 * and validates/refreshes OAuth tokens before passing the request to the original resource.
 *
 * @example
 * ```typescript
 * // In your application component:
 * import { withOAuthValidation } from '@harperfast/oauth';
 *
 * export function handleApplication(scope) {
 *   // Get OAuth providers from the OAuth plugin
 *   const oauthPlugin = scope.parent.resources.get('oauth');
 *
 *   // Wrap your protected resource
 *   const myResource = {
 *     async get(target, request) {
 *       // This code only runs if OAuth session is valid
 *       return { user: request.session.oauthUser };
 *     }
 *   };
 *
 *   scope.resources.set('protected', withOAuthValidation(myResource, {
 *     providers: oauthPlugin.providers,
 *     requireAuth: true,
 *     logger: scope.logger
 *   }));
 * }
 * ```
 */
export function withOAuthValidation(resource: any, options: OAuthValidationOptions): any {
	const { providers, logger, requireAuth = false, onValidationError } = options;

	// Create a proxy that wraps all resource methods
	return new Proxy(resource, {
		get(target, prop: string) {
			const originalMethod = target[prop];

			// Only wrap HTTP methods
			if (!['get', 'post', 'put', 'patch', 'delete'].includes(prop)) {
				return originalMethod;
			}

			// Return wrapped method with OAuth validation
			return async function (this: any, ...args: any[]) {
				// Extract request from arguments (usually last or second argument)
				const request: Request | undefined = args.find((arg) => arg?.session !== undefined);

				if (!request) {
					// No request object found - just pass through
					return originalMethod.apply(this, args);
				}

				// Check if session has OAuth data
				const hasOAuth = request.session?.oauth !== undefined;

				if (!hasOAuth) {
					if (requireAuth) {
						// OAuth authentication required but not present
						const error = 'OAuth authentication required';
						if (onValidationError) {
							return onValidationError(request, error);
						}
						return {
							status: 401,
							body: {
								error: 'Unauthorized',
								message: error,
							},
						};
					}
					// OAuth not required, pass through
					return originalMethod.apply(this, args);
				}

				// Get provider for this OAuth session
				const providerName = request.session?.oauth?.provider;
				if (!providerName) {
					// No provider name in session - invalid OAuth data
					if (request.session) {
						delete request.session.oauth;
						delete request.session.oauthUser;
					}
					if (requireAuth) {
						const error = 'Invalid OAuth session data';
						if (onValidationError) {
							return onValidationError(request, error);
						}
						return {
							status: 401,
							body: {
								error: 'Unauthorized',
								message: error,
							},
						};
					}
					return originalMethod.apply(this, args);
				}

				const providerData = providers[providerName];

				if (!providerData) {
					logger?.warn?.(`OAuth provider '${providerName}' not found for session validation`);
					// Provider not found - clear OAuth data and continue
					if (request.session) {
						delete request.session.oauth;
						delete request.session.oauthUser;
					}
					if (requireAuth) {
						const error = `OAuth provider '${providerName}' not configured`;
						if (onValidationError) {
							return onValidationError(request, error);
						}
						return {
							status: 401,
							body: {
								error: 'Unauthorized',
								message: error,
							},
						};
					}
					return originalMethod.apply(this, args);
				}

				// Validate and refresh session
				const validation = await validateAndRefreshSession(request, providerData.provider, logger);

				if (!validation.valid) {
					// Session validation failed
					logger?.info?.(`OAuth session validation failed: ${validation.error}`);

					if (requireAuth) {
						const error = validation.error || 'OAuth session expired';
						if (onValidationError) {
							return onValidationError(request, error);
						}
						return {
							status: 401,
							body: {
								error: 'Unauthorized',
								message: 'OAuth session expired. Please log in again.',
								details: validation.error,
							},
						};
					}

					// Not requiring auth, but validation failed - continue without OAuth
					return originalMethod.apply(this, args);
				}

				// Session is valid (and possibly refreshed)
				if (validation.refreshed) {
					logger?.debug?.(`OAuth token refreshed for ${providerName} session`);
				}

				// Call original method with validated/refreshed session
				return originalMethod.apply(this, args);
			};
		},
	});
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
