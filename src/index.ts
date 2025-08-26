/**
 * Harper OAuth Plugin
 *
 * Provides OAuth 2.0 authentication for Harper applications.
 * Supports any standard OAuth 2.0 provider through configuration.
 */

import { initializeProviders } from './lib/config.ts';
import { createOAuthResource } from './lib/resource.ts';
import type { Scope, OAuthPluginConfig } from './types.ts';

/**
 * Plugin entry point
 */
export async function handleApplication(scope: Scope): Promise<void> {
	const options = (scope.options.getAll() || {}) as OAuthPluginConfig;
	const logger = scope.logger;
	const debugMode = options.debug === true;

	// Log plugin initialization
	logger?.info?.('OAuth plugin loading with options:', JSON.stringify(options, null, 2));

	// Initialize providers from configuration
	const providers = initializeProviders(options, logger);

	// Check if we have any valid providers
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
		return;
	}

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
