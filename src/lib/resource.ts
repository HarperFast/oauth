/**
 * OAuth Resource
 *
 * Harper resource class for handling OAuth REST endpoints
 */

import type { Request, RequestTarget, Logger, ProviderRegistry } from '../types.ts';
import { handleLogin, handleCallback, handleLogout, handleUserInfo, handleTestPage } from './handlers.ts';
import { validateAndRefreshSession } from './sessionValidator.ts';
import type { HookManager } from './hookManager.ts';

/**
 * Create an OAuth resource with the given configuration
 * Returns a resource object that Harper can use directly
 */
export function createOAuthResource(
	providers: ProviderRegistry,
	debugMode: boolean,
	hookManager: HookManager,
	logger?: Logger
): any {
	const notFound = {
		status: 404,
		body: { error: 'Not found' },
	};

	const resource = {
		// Expose hookManager for programmatic hook registration
		hookManager,
		// Expose providers for use with withOAuthValidation
		providers,
		/**
		 * Handle GET requests
		 */
		async get(target: RequestTarget | string, request: Request): Promise<any> {
			// Target can be an object with id, pathname, or a string
			const id = typeof target === 'string' ? target : target?.id || target?.pathname || '';
			const pathParts = (id || '').split('/').filter((p) => p);
			const providerName = pathParts[0];
			const action = pathParts[1];

			// Special case: /oauth/test without provider (debug mode only)
			if (providerName === 'test' && !action) {
				if (!debugMode) return notFound;
				return handleTestPage(logger);
			}

			// If no provider specified
			if (!providerName) {
				if (!debugMode) return notFound;

				// Debug mode: show full provider info
				return {
					message: 'OAuth providers',
					logout: 'POST /oauth/logout',
					providers: Object.keys(providers).map((name) => ({
						name,
						provider: providers[name].config.provider,
						endpoints: {
							login: `/oauth/${name}/login`,
							callback: `/oauth/${name}/callback`,
							user: `/oauth/${name}/user`,
							refresh: `/oauth/${name}/refresh`,
							test: `/oauth/${name}/test`,
						},
					})),
				};
			}

			// Check if provider exists
			const providerData = providers[providerName];
			if (!providerData) {
				return {
					status: 404,
					body: {
						error: 'Provider not found',
						available: Object.keys(providers),
					},
				};
			}

			const { provider, config } = providerData;

			switch (action) {
				case 'login':
					return handleLogin(request, provider, config, logger);
				case 'callback':
					// Pass the target object directly - it should have a get() method for query params
					return handleCallback(request, target as RequestTarget, provider, config, hookManager, logger);
				case 'user': {
					// Debug mode only
					if (!debugMode) return notFound;

					// Validate and refresh session if needed before returning user info
					const validation = await validateAndRefreshSession(request, provider, logger, hookManager);
					if (!validation.valid) {
						return {
							status: 401,
							body: {
								authenticated: false,
								error: validation.error || 'Session expired',
								message: 'OAuth session is no longer valid. Please log in again.',
							},
						};
					}

					return handleUserInfo(request, validation.refreshed);
				}
				case 'refresh': {
					// Debug mode only
					if (!debugMode) return notFound;

					// Validate session before attempting refresh
					const validation = await validateAndRefreshSession(request, provider, logger, hookManager);
					if (!validation.valid) {
						return {
							status: 401,
							body: {
								error: validation.error || 'Session expired',
								message: 'OAuth session is no longer valid. Please log in again.',
							},
						};
					}

					// Return refresh status
					return {
						status: 200,
						body: {
							message: validation.refreshed ? 'Token refreshed successfully' : 'Token is still valid',
							refreshed: validation.refreshed,
							expiresAt: request.session?.oauth?.expiresAt,
						},
					};
				}
				case 'test': {
					// Debug mode only
					if (!debugMode) return notFound;
					return handleTestPage(logger);
				}
				default: {
					// Debug mode only
					if (!debugMode) return notFound;
					// Show provider configuration info
					return {
						message: `OAuth provider: ${providerName}`,
						provider: config.provider,
						configured: true,
						logout: 'POST /oauth/logout',
						endpoints: {
							login: `/oauth/${providerName}/login`,
							callback: `/oauth/${providerName}/callback`,
							user: `/oauth/${providerName}/user`,
							refresh: `/oauth/${providerName}/refresh`,
							test: `/oauth/${providerName}/test`,
						},
					};
				}
			}
		},

		/**
		 * Handle POST requests
		 */
		async post(target: RequestTarget | string, _body: any, request: Request): Promise<any> {
			// Target can be an object with id, pathname, or a string
			const id = typeof target === 'string' ? target : target?.id || target?.pathname || '';
			const pathParts = (id || '').split('/').filter((p) => p);
			const providerName = pathParts[0];

			// Handle generic logout endpoint (no provider required)
			if (providerName === 'logout') {
				return handleLogout(request, hookManager, logger);
			}

			// For other POST endpoints, provider is required
			return {
				status: 404,
				body: { error: 'Not found' },
			};
		},
	};

	return resource;
}
