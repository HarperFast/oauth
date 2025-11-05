/**
 * OAuth Configuration
 *
 * Provider configuration and initialization utilities
 */

import { OAuthProvider } from './OAuthProvider.ts';
import { getProvider } from './providers/index.ts';
import type {
	OAuthProviderConfig,
	OAuthPluginConfig,
	ProviderRegistry,
	ProviderRegistryEntry,
	Logger,
} from '../types.ts';

/**
 * Required fields for OAuth provider configuration
 */
const REQUIRED_PROVIDER_FIELDS = ['clientId', 'clientSecret', 'authorizationUrl', 'tokenUrl', 'userInfoUrl'] as const;

/**
 * Build configuration for a specific provider
 */
export function buildProviderConfig(
	providerConfig: Record<string, any>,
	providerName: string,
	pluginDefaults: Partial<OAuthProviderConfig> = {}
): OAuthProviderConfig {
	const options = providerConfig || {};

	// Create a proxy that lazily expands environment variables when accessed
	// This solves race conditions where env vars are loaded after plugin initialization
	const expandedOptions: Record<string, any> = {};
	for (const [key, value] of Object.entries(options)) {
		if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
			// Extract environment variable name
			const envVar = value.slice(2, -1);

			// Use getter for lazy evaluation
			Object.defineProperty(expandedOptions, key, {
				get() {
					const envValue = process.env[envVar];
					// Only use the env value if it's defined and not empty
					return envValue !== undefined && envValue !== '' ? envValue : value;
				},
				enumerable: true,
				configurable: true,
			});
		} else {
			expandedOptions[key] = value;
		}
	}

	// Check for known provider presets
	const providerType = expandedOptions.provider || providerName;
	const providerPreset = providerType ? getProvider(providerType) : null;

	// Build redirect URI with provider name in path
	const baseRedirectUri = expandedOptions.redirectUri || pluginDefaults.redirectUri || 'https://localhost:9953/oauth';
	const redirectUri = baseRedirectUri
		.replace('/oauth/callback', `/oauth/${providerName}/callback`)
		.replace(/\/oauth$/, `/oauth/${providerName}/callback`);

	// Merge configurations: plugin defaults -> preset -> options
	const config: OAuthProviderConfig = {
		// Plugin defaults
		scope: pluginDefaults.scope || 'openid profile email',
		usernameClaim: pluginDefaults.usernameClaim || 'email',
		defaultRole: pluginDefaults.defaultRole || 'user',
		postLoginRedirect: pluginDefaults.postLoginRedirect || '/oauth/test',

		// Provider type
		provider: 'generic',

		// Required fields (will be overridden if present)
		clientId: '',
		clientSecret: '',
		authorizationUrl: '',
		tokenUrl: '',
		userInfoUrl: '',

		// Provider preset (if available)
		...providerPreset,
	};

	// Manually copy expandedOptions to preserve getters (spread operator would invoke them)
	for (const key of Object.keys(expandedOptions)) {
		const descriptor = Object.getOwnPropertyDescriptor(expandedOptions, key);
		if (descriptor) {
			Object.defineProperty(config, key, descriptor);
		}
	}

	// Ensure redirect URI includes provider name (override any previous value)
	config.redirectUri = redirectUri;

	// Handle provider-specific configuration
	if (providerPreset?.configure) {
		let providerConfig;

		switch (config.provider) {
			case 'azure':
				if (expandedOptions.tenantId) {
					providerConfig = providerPreset.configure(expandedOptions.tenantId);
				}
				break;
			case 'auth0':
				if (expandedOptions.domain) {
					providerConfig = providerPreset.configure(expandedOptions.domain);
				}
				break;
		}

		if (providerConfig) {
			Object.assign(config, providerConfig);
		}
	}

	return config;
}

/**
 * Extract plugin-level defaults from options
 */
export function extractPluginDefaults(options: OAuthPluginConfig): Partial<OAuthProviderConfig> {
	const pluginDefaults: Partial<OAuthProviderConfig> = {};

	// Copy all non-provider config to defaults
	for (const [key, value] of Object.entries(options)) {
		if (key !== 'providers' && key !== 'debug') {
			pluginDefaults[key as keyof OAuthProviderConfig] = value as any;
		}
	}

	return pluginDefaults;
}

/**
 * Initialize OAuth providers from configuration
 */
export function initializeProviders(options: OAuthPluginConfig, logger?: Logger): ProviderRegistry {
	const providers: ProviderRegistry = {};

	// Providers configuration is required
	if (!options.providers || typeof options.providers !== 'object') {
		return providers;
	}

	// Extract plugin-level defaults
	const pluginDefaults = extractPluginDefaults(options);
	logger?.debug?.('Plugin defaults:', pluginDefaults);

	// Initialize each provider
	for (const [providerName, providerConfig] of Object.entries(options.providers)) {
		const config = buildProviderConfig(providerConfig, providerName, pluginDefaults);

		// Check if this provider is properly configured
		// Note: This triggers lazy env var expansion via getters
		const missingFields = REQUIRED_PROVIDER_FIELDS.filter((key) => {
			const value = config[key as keyof OAuthProviderConfig];
			// Consider env var placeholders as "missing" if they haven't been loaded yet
			return !value || (typeof value === 'string' && value.startsWith('${') && value.endsWith('}'));
		});

		if (missingFields.length > 0) {
			logger?.warn?.(`OAuth provider '${providerName}' not configured. Missing: ${missingFields.join(', ')}`);
			continue;
		}

		try {
			const provider = new OAuthProvider(config, logger);
			providers[providerName] = { provider, config };
			logger?.info?.(`OAuth provider '${providerName}' initialized (${config.provider})`);
		} catch (error) {
			logger?.error?.(`Failed to initialize OAuth provider '${providerName}':`, error);
		}
	}

	return providers;
}

/**
 * Get or lazily initialize a single provider by name
 * This handles race conditions where env vars are loaded after initial plugin initialization
 */
export function getOrInitializeProvider(
	providerName: string,
	providers: ProviderRegistry,
	options: OAuthPluginConfig,
	logger?: Logger
): ProviderRegistryEntry | null {
	// Check if provider already exists
	if (providers[providerName]) {
		return providers[providerName];
	}

	// Provider not initialized yet - try to initialize it now
	if (!options.providers || !options.providers[providerName]) {
		logger?.debug?.(`OAuth provider '${providerName}' not defined in configuration`);
		return null;
	}

	const pluginDefaults = extractPluginDefaults(options);
	const config = buildProviderConfig(options.providers[providerName], providerName, pluginDefaults);

	// Check if this provider is properly configured (with current env vars)
	const missingFields = REQUIRED_PROVIDER_FIELDS.filter((key) => {
		const value = config[key as keyof OAuthProviderConfig];
		return !value || (typeof value === 'string' && value.startsWith('${') && value.endsWith('}'));
	});

	if (missingFields.length > 0) {
		logger?.debug?.(`OAuth provider '${providerName}' cannot be initialized yet. Missing: ${missingFields.join(', ')}`);
		return null;
	}

	// Initialize the provider
	try {
		const provider = new OAuthProvider(config, logger);
		providers[providerName] = { provider, config };
		logger?.info?.(`OAuth provider '${providerName}' initialized on-demand (${config.provider})`);
		return providers[providerName];
	} catch (error) {
		logger?.error?.(`Failed to initialize OAuth provider '${providerName}':`, error);
		return null;
	}
}
