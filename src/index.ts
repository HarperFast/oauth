/**
 * Harper OAuth Plugin
 *
 * Provides OAuth 2.0 authentication for Harper applications.
 * Supports any standard OAuth 2.0 provider through configuration.
 */

import { initializeProviders } from './lib/config.ts';
import { createOAuthResource } from './lib/resource.ts';
import type { Scope, OAuthPluginConfig, ProviderRegistry } from './types.ts';

/**
 * Plugin entry point
 */
export async function handleApplication(scope: Scope): Promise<void> {
	const logger = scope.logger;
	let providers: ProviderRegistry = {};
	let debugMode = false;
	let isInitialized = false;

	// Check if sessions are enabled - OAuth plugin requires sessions to function
	const sessionsEnabled = process.env.ENABLE_SESSIONS !== 'false'; // Default to true if not set
	if (!sessionsEnabled) {
		logger?.error?.('OAuth plugin cannot initialize: Sessions are disabled. Set ENABLE_SESSIONS=true to use OAuth authentication.');
		return;
	}

	/**
	 * Update OAuth configuration when options change
	 */
	function updateConfiguration() {
		const options = (scope.options.getAll() || {}) as OAuthPluginConfig;
		const previousDebugMode = debugMode;
		debugMode = options.debug === true;

		// Log configuration update
		if (isInitialized) {
			logger?.info?.('OAuth configuration changed, updating providers...');
		} else {
			logger?.info?.('OAuth plugin loading with options:', JSON.stringify(options, null, 2));
			isInitialized = true;
		}

		// Re-initialize providers from new configuration
		providers = initializeProviders(options, logger);

		// Update the resource with new providers
		if (Object.keys(providers).length === 0) {
			// No valid providers configured
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
			// Register the OAuth resource with configured providers
			scope.resources.set('oauth', createOAuthResource(providers, debugMode, logger));

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

	// Register OAuth session validation hook for token refresh
	scope.auth.addHook('sessionValidate', async (session: any, _request: any) => {
		// Only handle OAuth sessions
		if (session.authProvider !== 'oauth') {
			return { valid: true };
		}

		const metadata = session.authProviderMetadata;
		if (!metadata) {
			logger?.warn?.('OAuth session missing metadata, invalidating');
			return { valid: false };
		}

		// Check if token needs refresh using pre-calculated threshold
		const now = Date.now();
		const isExpired = now >= metadata.refreshAt;
		const refreshNeeded = now >= metadata.refreshThreshold;

		// Block access if token is expired and no refresh token
		if (isExpired && !metadata.refreshToken) {
			logger?.warn?.('OAuth token expired and no refresh token available');
			return { valid: false };
		}

		// Attempt token refresh if needed and refresh token is available
		if (refreshNeeded && metadata.refreshToken) {
			// NOTE: Multiple concurrent requests may attempt to refresh the same token.
			// This is acceptable - OAuth providers handle duplicate refresh requests gracefully,
			// but we could refine this to only run a single concurrent refresh if needed.
			logger?.info?.(isExpired 
				? 'OAuth token expired, attempting refresh...' 
				: 'OAuth token approaching expiration (80% lifetime), refreshing proactively...');
			
			try {
				// Find the provider for this session
				const providerName = metadata.provider;
				const provider = providers[providerName];
				
				if (!provider) {
					logger?.error?.(`OAuth provider '${providerName}' not found for token refresh`);
					return { valid: false };
				}

				// Check if provider supports token refresh
				if (!provider.provider.refreshTokensWithMetadata) {
					logger?.warn?.(`OAuth provider '${providerName}' does not support token refresh`);
					return { valid: false };
				}

				// Refresh the token using provider method
				const newMetadata = await provider.provider.refreshTokensWithMetadata(metadata.refreshToken, metadata);

				logger?.info?.('OAuth token refreshed successfully');

				return {
					valid: true,
					updates: {
						authProviderMetadata: newMetadata
					}
				};
			} catch (error) {
				logger?.error?.('OAuth token refresh failed:', error);
				return { valid: false };
			}
		}

		return { valid: true };
	});

	// Initial configuration
	updateConfiguration();

	// Watch for configuration changes
	scope.options.on('change', () => {
		updateConfiguration();
	});

	// Clean up on scope close
	scope.on('close', () => {
		logger?.info?.('OAuth plugin shutting down');
	});
}
