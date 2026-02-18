/**
 * OAuth Resource
 *
 * Harper resource class for handling OAuth REST endpoints
 */

import { Resource } from 'harperdb';
import type { RequestTarget } from 'harperdb';
import type { Request, Logger, ProviderRegistry, OAuthProviderConfig } from '../types.ts';
import { handleLogin, handleCallback, handleLogout, handleUserInfo, handleTestPage } from './handlers.ts';
import type { HookManager } from './hookManager.ts';

/**
 * Parsed route information from a request target
 */
export interface ParsedRoute {
	providerName: string;
	action: string;
	path: string;
}

/**
 * OAuth Resource - proper Harper Resource class for handling OAuth endpoints
 * Follows Resource API v2 pattern (loadAsInstance = false)
 */
export class OAuthResource extends Resource {
	static loadAsInstance = false; // Use Resource API v2

	// Store configuration as static properties (shared across all requests)
	static providers: ProviderRegistry = {};
	static debugMode: boolean = false;
	static hookManager: HookManager | null = null;
	static pluginDefaults: Partial<OAuthProviderConfig> = {};
	static cacheDynamicProviders: boolean = true;
	static logger: Logger | undefined = undefined;

	/**
	 * Configure the OAuth resource with providers and settings
	 * Called once during plugin initialization
	 */
	static configure(
		providers: ProviderRegistry,
		debugMode: boolean,
		hookManager: HookManager,
		pluginDefaults: Partial<OAuthProviderConfig>,
		logger?: Logger,
		cacheDynamicProviders: boolean = true
	): void {
		OAuthResource.providers = providers;
		OAuthResource.debugMode = debugMode;
		OAuthResource.hookManager = hookManager;
		OAuthResource.pluginDefaults = pluginDefaults;
		OAuthResource.logger = logger;
		OAuthResource.cacheDynamicProviders = cacheDynamicProviders;
	}

	/**
	 * Parse a request target into provider and action components
	 * Exported as static method for testability
	 */
	static parseRoute(target: RequestTarget): ParsedRoute {
		const id = target.id || target.pathname || '';
		const path = typeof id === 'string' ? id : String(id);

		// Validate path length to prevent DoS attacks with extremely long URLs
		if (path.length > 2048) {
			// Return empty route for oversized paths (will result in 404)
			return {
				providerName: '',
				action: '',
				path: '',
			};
		}

		const pathParts = path.split('/').filter((p) => p);

		return {
			providerName: pathParts[0] || '',
			action: pathParts[1] || '',
			path,
		};
	}

	/**
	 * Check if a route should return 404 in production mode
	 * Debug-only endpoints return 404 when debug mode is off
	 */
	static isDebugOnlyRoute(route: ParsedRoute): boolean {
		const { providerName, action } = route;

		// Root path (provider list) - debug only
		if (!providerName) return true;

		// Test endpoints - debug only
		if (providerName === 'test' && !action) return true;
		if (action === 'test') return true;

		// Debug info endpoints
		if (action === 'user' || action === 'refresh') return true;

		// Provider info (no action) - debug only
		if (providerName && !action) return true;

		return false;
	}

	/**
	 * Check if a request is allowed to access debug endpoints
	 * Uses IP allowlist for security (defaults to localhost only)
	 *
	 * @param request - The incoming request
	 * @param logger - Optional logger for access tracking
	 * @returns true if access is allowed, false otherwise
	 */
	static checkDebugAccess(request: Request, logger?: Logger): boolean {
		// Get IP allowlist from environment variable or use localhost-only default
		// Use ?? to allow empty string (which denies all access)
		const DEBUG_ALLOWED_IPS = process.env.DEBUG_ALLOWED_IPS ?? '127.0.0.1,::1';
		const allowedIps = DEBUG_ALLOWED_IPS.split(',').map((ip) => ip.trim());
		const clientIp = request.ip || '';

		// Check if client IP matches any allowed IP
		let ipAllowed = false;
		for (const allowed of allowedIps) {
			// Exact match
			if (allowed === clientIp) {
				ipAllowed = true;
				break;
			}
			// Simple prefix match for CIDR-like patterns (e.g., "10.0.0." matches "10.0.0.1")
			if (allowed.endsWith('.') && clientIp.startsWith(allowed)) {
				ipAllowed = true;
				break;
			}
		}

		// Log access attempt
		if (ipAllowed) {
			logger?.info?.('OAuth debug endpoint accessed', {
				ip: clientIp,
			});
		} else {
			logger?.warn?.('OAuth debug endpoint access denied - unauthorized IP', {
				ip: clientIp,
				allowedIps,
			});
		}

		return ipAllowed;
	}

	/**
	 * Build forbidden response for unauthorized debug access
	 */
	static forbiddenResponse(): any {
		return {
			status: 403,
			body: {
				error: 'Access forbidden',
				message: 'Debug endpoints are only accessible from allowed IPs.',
				hint: 'Set DEBUG_ALLOWED_IPS environment variable to allow access from your IP. Defaults to localhost only (127.0.0.1,::1).',
			},
		};
	}

	/**
	 * Build the standard 404 response
	 */
	static notFoundResponse() {
		return {
			status: 404,
			body: { error: 'Not found' },
		};
	}

	/**
	 * Build provider list response for root path
	 */
	static buildProviderListResponse(providers: ProviderRegistry): any {
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

	/**
	 * Build provider info response
	 */
	static buildProviderInfoResponse(providerName: string, providers: ProviderRegistry): any {
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

		return {
			message: `OAuth provider: ${providerName}`,
			provider: providerData.config.provider,
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

	/**
	 * Build token status response for /refresh endpoint
	 */
	static buildTokenStatusResponse(request: Request): any {
		const oauthData = request.session?.oauth;
		if (!oauthData || !oauthData.accessToken) {
			return {
				status: 401,
				body: {
					error: 'No OAuth session',
					message: 'OAuth session is no longer valid. Please log in again.',
				},
			};
		}

		return {
			status: 200,
			body: {
				message: 'Token is valid',
				provider: oauthData.provider,
				expiresAt: oauthData.expiresAt,
				lastRefreshed: oauthData.lastRefreshed,
			},
		};
	}

	/**
	 * Handle GET requests to OAuth endpoints
	 * Resource API v2 signature: get(target)
	 */
	async get(target: RequestTarget): Promise<any> {
		const providers = OAuthResource.providers;
		const debugMode = OAuthResource.debugMode;
		const logger = OAuthResource.logger;

		// Parse the route
		const route = OAuthResource.parseRoute(target);
		const { providerName, action } = route;

		// Get request from context (HarperDB provides the HTTP request here)
		const context = this.getContext();
		if (!context) {
			logger?.error?.('Request context is null or undefined');
			return {
				status: 500,
				body: { error: 'Internal server error' },
			};
		}
		const request = context as unknown as Request;

		// Check debug mode restrictions
		if (!debugMode && OAuthResource.isDebugOnlyRoute(route)) {
			return OAuthResource.notFoundResponse();
		}

		// If debug mode is enabled and this is a debug-only route, check IP allowlist
		if (debugMode && OAuthResource.isDebugOnlyRoute(route)) {
			if (!OAuthResource.checkDebugAccess(request, logger)) {
				return OAuthResource.forbiddenResponse();
			}
		}

		// Special case: /oauth/test without provider
		if (providerName === 'test' && !action) {
			return handleTestPage(logger);
		}

		// Root path - show provider list
		if (!providerName) {
			return OAuthResource.buildProviderListResponse(providers);
		}

		// Validate provider name format (basic security check)
		if (providerName.length > 128 || !/^[a-zA-Z0-9_-]+$/.test(providerName)) {
			return {
				status: 400,
				body: { error: 'Invalid provider name format' },
			};
		}

		// Check if provider exists in registry
		let providerData = providers[providerName];

		// If not found, try to resolve via hook
		if (!providerData && OAuthResource.hookManager?.hasHook('onResolveProvider')) {
			try {
				logger?.debug?.(`Provider "${providerName}" not found in registry, calling onResolveProvider hook`);

				const hookConfig = await OAuthResource.hookManager.callResolveProvider(providerName, logger);

				if (hookConfig) {
					// Hook resolved provider - build full config and register dynamically
					const { OAuthProvider } = await import('./OAuthProvider.ts');
					const { buildProviderConfig } = await import('./config.ts');

					// Build full provider config (handles Okta/Azure/Auth0 domain configuration)
					const pluginDefaults = OAuthResource.pluginDefaults || {};
					const config = buildProviderConfig(hookConfig, providerName, pluginDefaults);

					const provider = new OAuthProvider(config, logger);

					providerData = { provider, config };
					logger?.info?.(`Dynamically resolved provider: ${providerName}`);

					if (OAuthResource.cacheDynamicProviders) {
						providers[providerName] = providerData;
					}
				}
			} catch (error) {
				// Hook threw error - log and return 500
				logger?.error?.(`Error resolving provider ${providerName}:`, (error as Error).message);
				return {
					status: 500,
					body: { error: 'Failed to resolve OAuth provider' },
				};
			}
		}

		// Still not found - return 404
		if (!providerData) {
			return {
				status: 404,
				body: { error: 'OAuth provider not found' },
			};
		}

		const { provider, config } = providerData;
		const hookManager = OAuthResource.hookManager!;

		// Handle specific actions
		switch (action) {
			case 'login':
				return handleLogin(request, target, provider, config, providerName, logger);

			case 'callback':
				return handleCallback(request, target, provider, config, hookManager, providerName, logger);

			case 'user':
				return handleUserInfo(request, false);

			case 'refresh':
				return OAuthResource.buildTokenStatusResponse(request);

			case 'test':
				return handleTestPage(logger);

			default:
				// Provider info (no action specified)
				return OAuthResource.buildProviderInfoResponse(providerName, providers);
		}
	}

	/**
	 * Handle POST requests to OAuth endpoints
	 * Resource API v2 signature: post(target, data)
	 */
	async post(target: RequestTarget, _data: any): Promise<any> {
		const logger = OAuthResource.logger;
		const hookManager = OAuthResource.hookManager!;

		// Parse the route
		const route = OAuthResource.parseRoute(target);
		const { providerName } = route;

		// Get request from context (HarperDB provides the HTTP request here)
		const context = this.getContext();
		if (!context) {
			logger?.error?.('Request context is null or undefined');
			return {
				status: 500,
				body: { error: 'Internal server error' },
			};
		}
		const request = context as unknown as Request;

		// Handle logout endpoint
		if (providerName === 'logout') {
			return handleLogout(request, hookManager, logger);
		}

		// All other POST endpoints are not supported
		return OAuthResource.notFoundResponse();
	}

	/**
	 * Expose hookManager for programmatic hook registration
	 * This allows access via: scope.resources.get('oauth').hookManager
	 */
	static getHookManager(): HookManager | null {
		return OAuthResource.hookManager;
	}

	/**
	 * Expose providers for use with withOAuthValidation
	 * This allows access via: scope.resources.get('oauth').providers
	 */
	static getProviders(): ProviderRegistry {
		return OAuthResource.providers;
	}

	/**
	 * Reset configuration (useful for testing)
	 */
	static reset(): void {
		OAuthResource.providers = {};
		OAuthResource.debugMode = false;
		OAuthResource.hookManager = null;
		OAuthResource.pluginDefaults = {};
		OAuthResource.cacheDynamicProviders = true;
		OAuthResource.logger = undefined;
	}
}
