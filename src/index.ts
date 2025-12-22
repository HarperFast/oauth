/**
 * Harper OAuth Plugin
 *
 * Provides OAuth 2.0 authentication for Harper applications.
 * Supports any standard OAuth 2.0 provider through configuration.
 */

import { initializeProviders, expandEnvVar } from './lib/config.ts';
import { OAuthResource } from './lib/resource.ts';
import { validateAndRefreshSession } from './lib/sessionValidator.ts';
import { clearOAuthSession } from './lib/handlers.ts';
import { HookManager } from './lib/hookManager.ts';
import type { Scope, OAuthPluginConfig, ProviderRegistry, OAuthHooks } from './types.ts';

// Export HookManager class, OAuthResource class, and types
export { HookManager } from './lib/hookManager.ts';
export { OAuthResource } from './lib/resource.ts';
export type { OAuthHooks, OAuthUser, TokenResponse } from './types.ts';

// Store hooks registered at module load time and active hookManager
let pendingHooks: OAuthHooks | null = null;
let activeHookManager: HookManager | null = null;

/**
 * Register OAuth hooks programmatically
 * Call this from your application code to register lifecycle hooks
 *
 * This can be called:
 * - At module load time (before the plugin initializes) - hooks will be queued
 * - After plugin initialization - hooks will be applied immediately
 *
 * NOTE: This registers hooks at the module level, shared across all instances
 * of the OAuth plugin. For most applications with a single OAuth plugin instance,
 * this is the simplest and recommended approach.
 *
 * @example
 * ```typescript
 * import { registerHooks } from '@harperdb/oauth';
 *
 * // Can be called at module load time or later
 * registerHooks({
 *   onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
 *     console.log(`User logged in: ${oauthUser.username}`);
 *   }
 * });
 * ```
 */
export function registerHooks(hooks: OAuthHooks): void {
	if (activeHookManager) {
		// Plugin is already loaded - apply immediately
		activeHookManager.register(hooks);
	} else {
		// Plugin not loaded yet - queue for later
		pendingHooks = hooks;
	}
}

/**
 * Plugin entry point
 */
export async function handleApplication(scope: Scope): Promise<void> {
	const logger = scope.logger;
	let providers: ProviderRegistry = {};
	let debugMode = false;
	let isInitialized = false;

	// Create hookManager instance scoped to this application
	const hookManager = new HookManager(logger);

	// Set as active hookManager for late hook registration
	activeHookManager = hookManager;

	// Apply any hooks that were registered at module load time
	if (pendingHooks) {
		hookManager.register(pendingHooks);
		logger?.debug?.('Applied pending OAuth hooks');
		pendingHooks = null; // Clear pending hooks after applying
	}

	/**
	 * Update OAuth configuration when options change
	 */
	async function updateConfiguration() {
		const rawOptions = (scope.options.getAll() || {}) as OAuthPluginConfig;

		// Expand environment variables in plugin-level options
		const debugValue = expandEnvVar(rawOptions.debug);

		const options = { ...rawOptions, debug: debugValue };
		const previousDebugMode = debugMode;
		// Handle both boolean and string values (from environment variables)
		debugMode = options.debug === true || options.debug === 'true';

		// Log configuration update
		if (isInitialized) {
			logger?.info?.('OAuth configuration changed, updating providers...');
		} else {
			logger?.info?.('OAuth plugin loading with options:', JSON.stringify(options, null, 2));
			isInitialized = true;
		}

		// Re-initialize providers from new configuration
		// Clear existing providers and repopulate (don't reassign to preserve closure reference)
		const newProviders = initializeProviders(options, logger);
		Object.keys(providers).forEach((key) => delete providers[key]);
		Object.assign(providers, newProviders);

		// Update the resource with new providers
		if (Object.keys(providers).length === 0) {
			// No valid providers configured - register a simple error resource
			scope.resources.set('oauth', {
				async get() {
					return {
						status: 503,
						body: {
							error: 'No valid OAuth providers configured',
							message: 'Please check your OAuth configuration',
							example: options.providers
								? 'Check that all required fields are provided'
								: {
										providers: {
											github: {
												provider: 'github',
												clientId: '${OAUTH_GITHUB_CLIENT_ID}',
												clientSecret: '${OAUTH_GITHUB_CLIENT_SECRET}',
											},
										},
									},
						},
					};
				},
			});
		} else {
			// Configure the OAuth resource with providers and settings
			OAuthResource.configure(providers, debugMode, hookManager, logger);

			// Register the OAuth resource class
			scope.resources.set('oauth', OAuthResource);

			// Log all configured providers
			logger?.info?.('OAuth plugin ready:', {
				providers: Object.entries(providers).map(([name, data]) => ({
					name,
					type: data.config.provider,
					redirectUri: data.config.redirectUri,
				})),
			});
		}

		// Log debug mode change if it changed
		if (isInitialized && previousDebugMode !== debugMode) {
			logger?.info?.(`OAuth debug mode ${debugMode ? 'enabled' : 'disabled'}`);
		}
	}

	// Register HTTP middleware for automatic OAuth session validation
	// This runs on every HTTP request after authentication but before REST
	scope.server.http?.(async (request: any, next: (req: any) => any) => {
		// Only process requests with sessions that have OAuth data
		if (!request.session?.oauth) {
			return next(request);
		}

		// Get the provider for this OAuth session
		const providerName = request.session.oauth.provider;
		const providerData = providers[providerName];

		if (!providerData) {
			logger?.warn?.(`OAuth provider '${providerName}' not found, logging out user`);
			// Provider no longer exists - complete logout
			await clearOAuthSession(request.session, logger);
			return next(request);
		}

		// Validate and refresh session automatically
		const validation = await validateAndRefreshSession(request, providerData.provider, logger, hookManager);

		if (!validation.valid) {
			// Session is no longer valid (already cleaned up by validator)
			logger?.debug?.(`OAuth session invalidated: ${validation.error}`);
		} else if (validation.refreshed) {
			logger?.debug?.(`OAuth token auto-refreshed for ${providerName}`);
		}

		// Continue with the request (session updated if refreshed)
		return next(request);
	});

	// Concurrency control for configuration updates
	let updating = false;
	let pendingUpdate = false;

	/**
	 * Run configuration update with concurrency protection
	 */
	const runUpdate = async () => {
		if (updating) {
			pendingUpdate = true;
			return;
		}

		updating = true;
		try {
			await updateConfiguration();

			// If another update was requested while we were running, run again
			if (pendingUpdate) {
				pendingUpdate = false;
				await runUpdate();
			}
		} catch (error) {
			logger?.error?.('Failed to update OAuth configuration:', error);
		} finally {
			updating = false;
		}
	};

	// Initial configuration (errors propagate to plugin loader)
	await updateConfiguration();

	// Watch for configuration changes (errors caught internally)
	scope.options.on('change', () => {
		runUpdate().catch((error) => {
			logger?.error?.('Unexpected error in OAuth config update:', error);
		});
	});

	// Clean up on scope close
	scope.on('close', () => {
		logger?.info?.('OAuth plugin shutting down');
	});
}
