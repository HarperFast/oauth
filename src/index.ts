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
