/**
 * Harper OAuth Plugin
 *
 * Provides OAuth 2.0 authentication for Harper applications.
 * Supports any standard OAuth 2.0 provider through configuration.
 */

import { initializeProviders, expandEnvVar, expandEnvVarsDeep, extractPluginDefaults } from './lib/config.ts';
import { OAuthResource } from './lib/resource.ts';
import { validateAndRefreshSession } from './lib/sessionValidator.ts';
import { clearOAuthSession } from './lib/handlers.ts';
import { HookManager } from './lib/hookManager.ts';
import { DynamicProviderCache, DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS } from './lib/dynamicProviderCache.ts';
import { registerWellKnownHandlers } from './lib/mcp/wellKnown.ts';
import type { Scope, OAuthPluginConfig, ProviderRegistry, OAuthHooks } from './types.ts';

// Config can carry literal secrets (provider clientSecret, mcp.signingKeyPem,
// mcp.dynamicClientRegistration.initialAccessToken). Redact them before logging
// the options blob — logs are frequently shipped/retained outside the trust
// boundary. Deny-list by key-name substring; over-redaction in a log is safe.
const SENSITIVE_KEY_PATTERN = /secret|signingkeypem|initialaccesstoken|privatekey|password/i;

function redactSecrets(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(redactSecrets);
	if (value && typeof value === 'object') {
		const out: Record<string, unknown> = {};
		for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
			out[key] = SENSITIVE_KEY_PATTERN.test(key) ? '[REDACTED]' : redactSecrets(val);
		}
		return out;
	}
	return value;
}

// Export HookManager class, OAuthResource class, and types
export { HookManager } from './lib/hookManager.ts';
export { OAuthResource } from './lib/resource.ts';
export type { OAuthHooks, OAuthUser, TokenResponse } from './types.ts';

// Export multi-tenant SSO support
export { TenantManager } from './lib/tenantManager.ts';
export type { TenantConfig, TenantRegistryEntry } from './lib/tenantManager.ts';

// Export validation utilities for secure tenant configuration
export {
	validateDomainSafety,
	validateDomainAllowlist,
	validateEmailDomain,
	validateTenantId,
	sanitizeTenantName,
	validateAzureTenantId,
} from './lib/providers/validation.ts';

// Export provider utilities
export { getProvider } from './lib/providers/index.ts';

// Export OAuth session validation wrapper
export { withOAuthValidation, getOAuthProviders } from './lib/withOAuthValidation.ts';
export type { OAuthValidationOptions } from './lib/withOAuthValidation.ts';

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
 * import { registerHooks } from '@harperfast/oauth';
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

	// Harper v5's Scope type declares `resources` and `server` as optional,
	// but they are always assigned during Scope construction (Scope.ts:70-71).
	// Narrow once here so downstream code (including the nested
	// updateConfiguration closure) doesn't need optional chaining or
	// non-null assertions sprinkled throughout.
	if (!scope.resources || !scope.server) {
		throw new Error(
			'OAuth plugin: scope.resources or scope.server is unavailable. This indicates a Harper initialization problem.'
		);
	}
	const resources = scope.resources;
	const server = scope.server;

	let providers: ProviderRegistry = {};
	let debugMode = false;
	let isInitialized = false;
	let pluginDefaults: any = {}; // Store plugin defaults for dynamic provider resolution
	const dynamicProviderCache = new DynamicProviderCache(); // TTL cache for dynamically-resolved providers

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
			logger?.info?.('OAuth plugin loading with options:', JSON.stringify(redactSecrets(options), null, 2));
			isInitialized = true;
		}

		// Build the MCP config block up front so we can fail fast on an unsafe
		// combination before mutating any provider state. expandEnvVarsDeep so
		// sensitive leaves (mcp.dynamicClientRegistration.initialAccessToken) and
		// a pinned issuer/resource support ${ENV_VAR}.
		const mcpConfig = options.mcp ? expandEnvVarsDeep(options.mcp) : undefined;
		if (mcpConfig?.enabled && !mcpConfig.issuer) {
			// Without a pinned issuer, resolveIssuer() (wellKnown.ts) derives it from
			// the client-controlled Host header — and resolveResource() defaults to
			// `<issuer>/mcp`, so the `aud` bound into the minted code floats with it.
			// That lets a client influence the advertised `iss` and the audience —
			// audience confusion once Stage 4 issues tokens. A pinned issuer anchors
			// both; `resource` may still be overridden explicitly. A pinned `resource`
			// alone is NOT sufficient — it leaves `iss` Host-derived. See docs/configuration.md.
			throw new Error(
				'OAuth MCP is enabled but mcp.issuer is not set. ' +
					'Pin it explicitly (e.g. mcp.issuer: "https://your-host") so the issuer and ' +
					'token audience are not derived from the client-controlled Host header.'
			);
		}

		// Re-initialize providers from new configuration
		// Clear existing providers and repopulate (don't reassign to preserve closure reference)
		const newProviders = initializeProviders(options, logger);
		Object.keys(providers).forEach((key) => delete providers[key]);
		Object.assign(providers, newProviders);

		// Extract plugin defaults for dynamic provider resolution
		pluginDefaults = extractPluginDefaults(options);

		// Update dynamic provider cache TTL (clears stale entries on config change).
		// Defaults to a bounded TTL rather than forever so disabled/rotated
		// dynamic providers stop being served without a restart (see #105).
		dynamicProviderCache.updateTTL(options.cacheDynamicProviders ?? DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS);

		// Update the resource with new providers
		if (Object.keys(providers).length === 0) {
			// No valid providers configured - register a simple error resource
			resources.set('oauth', {
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
			// Configure the OAuth resource with providers and settings.
			// mcpConfig was built and validated above.
			OAuthResource.configure(
				providers,
				debugMode,
				hookManager,
				pluginDefaults,
				logger,
				dynamicProviderCache,
				mcpConfig
			);

			// Register the OAuth resource class
			resources.set('oauth', OAuthResource);

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
	server.http?.(async (request: any, next: (req: any) => any) => {
		// Only process requests with sessions that have OAuth data
		if (!request.session?.oauth) {
			return next(request);
		}

		// Get the provider config ID for this OAuth session
		// Use providerConfigId (new) or fall back to provider (old) for backwards compatibility
		const providerConfigId = request.session.oauth.providerConfigId || request.session.oauth.provider;
		let providerData = providers[providerConfigId] ?? dynamicProviderCache.get(providerConfigId);

		// If still not found, try to resolve via hook
		if (!providerData && hookManager?.hasHook('onResolveProvider')) {
			try {
				logger?.debug?.(
					`Provider config "${providerConfigId}" not in registry or cache, attempting dynamic resolution`
				);

				const hookConfig = await hookManager.callResolveProvider(providerConfigId, logger);

				if (hookConfig) {
					const { OAuthProvider } = await import('./lib/OAuthProvider.ts');
					const { buildProviderConfig } = await import('./lib/config.ts');

					const config = buildProviderConfig(hookConfig, providerConfigId, pluginDefaults);
					const provider = new OAuthProvider(config, logger);

					providerData = { provider, config };
					logger?.info?.(`Dynamically resolved provider for session validation: ${providerConfigId}`);
					dynamicProviderCache.set(providerConfigId, providerData);
				}
			} catch (error) {
				logger?.error?.(`Error resolving provider ${providerConfigId} for session:`, (error as Error).message);
			}
		}

		if (!providerData) {
			logger?.warn?.(`OAuth provider config '${providerConfigId}' not found, logging out user`);
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
			logger?.debug?.(`OAuth token auto-refreshed for ${providerConfigId}`);
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

	// Register MCP well-known metadata endpoints once. The handlers read the
	// current mcpConfig from OAuthResource at request time, so live config
	// changes apply without re-registering routes (Harper's server.http does
	// not support deregistration).
	registerWellKnownHandlers(server, () => OAuthResource.mcpConfig, logger);

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
