/**
 * Harper OAuth Plugin
 *
 * Provides OAuth 2.0 authentication for Harper applications.
 * Supports any standard OAuth 2.0 provider through configuration.
 */

import { initializeProviders } from './lib/config.ts';
import { createOAuthResource } from './lib/resource.ts';
import { validateAndRefreshSession } from './lib/sessionValidator.ts';
import { clearOAuthSession } from './lib/handlers.ts';
import { HookManager } from './lib/hookManager.ts';
import type { Scope, OAuthPluginConfig, ProviderRegistry, OAuthHooks } from './types.ts';

// Export HookManager class and types
export { HookManager } from './lib/hookManager.ts';
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

		// Expand environment variables in plugin-level options (lazily)
		const options: OAuthPluginConfig = { ...rawOptions };

		// Create lazy getters for all string values that look like env vars
		for (const [key, value] of Object.entries(rawOptions)) {
			if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
				const envVar = value.slice(2, -1);
				Object.defineProperty(options, key, {
					get() {
						const envValue = process.env[envVar];
						return envValue !== undefined && envValue !== '' ? envValue : value;
					},
					enumerable: true,
					configurable: true,
				});
			}
		}
		const previousDebugMode = debugMode;
		// Handle both boolean and string values (from environment variables)
		debugMode = options.debug === true || options.debug === 'true';

		// Log configuration update
		if (isInitialized) {
			logger?.info?.('OAuth configuration changed, updating providers...');
		} else {
			// Log raw options (don't stringify to avoid triggering lazy getters prematurely)
			logger?.info?.('OAuth plugin loading...');
			isInitialized = true;
		}

		// Re-initialize providers from new configuration
		providers = initializeProviders(options, logger);

		// Always register the OAuth resource with lazy initialization support
		// Even if no providers are initially configured, they may become available later
		scope.resources.set('oauth', createOAuthResource(providers, options, debugMode, hookManager, logger));

		// Log configured providers
		if (Object.keys(providers).length === 0) {
			logger?.warn?.('No OAuth providers configured yet - will attempt lazy initialization on first request');
		} else {
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
	scope.server.http(async (request: any, next: (req: any) => any) => {
		// Only process requests with sessions that have OAuth data
		if (!request.session?.oauth) {
			return next(request);
		}

		// Get the provider for this OAuth session
		const providerName = request.session.oauth.provider;
		let providerData = providers[providerName];

		// Try lazy initialization if provider not found (handles race condition with env var loading)
		if (!providerData) {
			const rawOptions = (scope.options.getAll() || {}) as OAuthPluginConfig;
			const { getOrInitializeProvider } = await import('./lib/config.ts');
			const initialized = getOrInitializeProvider(providerName, providers, rawOptions, logger);
			if (initialized) {
				providerData = initialized;
			}
		}

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
