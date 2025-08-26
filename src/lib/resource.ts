/**
 * OAuth Resource
 *
 * Harper resource class for handling OAuth REST endpoints
 */

import type { Request, RequestTarget, Logger, ProviderRegistry } from '../types.ts';
import {
	handleLogin,
	handleCallback,
	handleLogout,
	handleUserInfo,
	handleRefresh,
	handleTestPage,
} from './handlers.ts';

/**
 * Create an OAuth resource with the given configuration
 * Returns a resource object that Harper can use directly
 */
export function createOAuthResource(providers: ProviderRegistry, debugMode: boolean, logger?: Logger): any {
	const notFound = {
		status: 404,
		body: { error: 'Not found' },
	};

	return {
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
					providers: Object.keys(providers).map((name) => ({
						name,
						provider: providers[name].config.provider,
						endpoints: {
							login: `/oauth/${name}/login`,
							callback: `/oauth/${name}/callback`,
							logout: `/oauth/${name}/logout`,
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
					return handleCallback(request, target as RequestTarget, provider, config, logger);
				case 'user': {
					// Debug mode only
					if (!debugMode) return notFound;
					return handleUserInfo(request);
				}
				case 'refresh': {
					// Debug mode only
					if (!debugMode) return notFound;
					return handleRefresh(request, provider, config, logger);
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
						endpoints: {
							login: `/oauth/${providerName}/login`,
							callback: `/oauth/${providerName}/callback`,
							logout: `/oauth/${providerName}/logout`,
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
			const action = pathParts[1];

			// Check if provider exists
			const providerData = providers[providerName];
			if (!providerData) {
				return debugMode
					? {
							status: 404,
							body: {
								error: 'Provider not found',
								available: Object.keys(providers),
							},
						}
					: notFound;
			}

			if (action === 'logout') {
				return handleLogout(request, logger);
			}

			return {
				status: 405,
				body: { error: 'Method not allowed' },
			};
		},
	};
}
