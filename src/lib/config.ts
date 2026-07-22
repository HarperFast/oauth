/**
 * OAuth Configuration
 *
 * Provider configuration and initialization utilities
 */

import { OAuthProvider } from './OAuthProvider.ts';
import { getProvider } from './providers/index.ts';
import { redactSecrets } from './redact.ts';
import type { OAuthProviderConfig, OAuthPluginConfig, ProviderRegistry, Logger } from '../types.ts';

/**
 * Expand environment variable in a string value
 *
 * If the value is a string in the format `${VAR_NAME}`, it will be replaced
 * with the value of the environment variable. Non-string values are returned unchanged.
 *
 * @example
 * expandEnvVar('${MY_VAR}') // Returns process.env.MY_VAR or '${MY_VAR}' if undefined
 * expandEnvVar('literal')   // Returns 'literal'
 * expandEnvVar(123)         // Returns 123
 * expandEnvVar(true)        // Returns true
 */
export function expandEnvVar(value: any): any {
	if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
		// Extract environment variable name
		const envVar = value.slice(2, -1);
		const envValue = process.env[envVar];
		// Only use env value if it exists (even if empty string)
		return envValue !== undefined ? envValue : value;
	}
	return value;
}

/**
 * Recursively expand `${ENV_VAR}` placeholders on every string leaf of a value.
 *
 * Used for structured config blocks (like `mcp`) where sensitive leaves
 * (e.g., `mcp.dynamicClientRegistration.initialAccessToken`) still need
 * env-var expansion but the block itself isn't a flat property bag.
 */
export function expandEnvVarsDeep<T>(value: T): T {
	if (typeof value === 'string') {
		return expandEnvVar(value);
	}
	if (Array.isArray(value)) {
		return value.map(expandEnvVarsDeep) as unknown as T;
	}
	if (value !== null && typeof value === 'object') {
		const expanded: Record<string, any> = {};
		for (const [key, item] of Object.entries(value as Record<string, any>)) {
			expanded[key] = expandEnvVarsDeep(item);
		}
		return expanded as T;
	}
	return value;
}

/**
 * Coerce a config value that documents a boolean but may arrive as an
 * env-expanded string (`enabled: ${FLAG}` → `"false"`). Returns the boolean
 * for `true`/`false` (case-insensitive), otherwise `undefined` (so callers
 * apply their own default). A real boolean passes through unchanged.
 */
export function coerceConfigBoolean(value: unknown): boolean | undefined {
	if (typeof value === 'boolean') return value;
	if (typeof value === 'string') {
		const v = value.trim().toLowerCase();
		if (v === 'true') return true;
		if (v === 'false') return false;
	}
	return undefined;
}

/**
 * Normalize one documented-boolean config field in place, TOTALLY: after this
 * call the field is either a real boolean or absent. Coercible values
 * (booleans, "true"/"false" strings) are coerced; anything else present —
 * including an unresolved `${ENV_VAR}` placeholder left by expandEnvVarsDeep
 * when the variable is unset — is DELETED with a warning, so the field's
 * documented default applies. Without this, a truthy junk value silently
 * flips whichever direction the consuming gate happens to test (e.g.
 * `refreshTokenRequiresOfflineAccess: ${FLAG}` with FLAG unset would activate
 * a documented default-off gate).
 */
function normalizeBooleanField(obj: Record<string, any>, field: string, path: string, logger?: Logger): void {
	const value = obj[field];
	if (value === undefined || value === null) return; // Absent (or bare YAML key) — default applies already.
	const coerced = coerceConfigBoolean(value);
	if (coerced !== undefined) {
		obj[field] = coerced;
		return;
	}
	const isUnresolvedPlaceholder = typeof value === 'string' && /^\$\{[^}]*\}$/.test(value.trim());
	logger?.warn?.(
		isUnresolvedPlaceholder
			? `MCP: ${path} is the unresolved env placeholder ${JSON.stringify(value)} (variable unset). ` +
					'Treating the option as absent — its documented default applies.'
			: `MCP: ${path} must be a boolean; got ${JSON.stringify(value)}. ` +
					'Treating the option as absent — its documented default applies.'
	);
	delete obj[field];
}

/**
 * Normalize the security-relevant fields of the `mcp` config block in place,
 * so a mis-typed value can never silently flip a gate:
 * - Every documented boolean (`mcp.enabled`,
 *   `mcp.refreshTokenRequiresOfflineAccess`, `mcp.clientCredentials.enabled`,
 *   `mcp.clientIdMetadataDocuments.enabled`,
 *   `mcp.dynamicClientRegistration.enabled`) is normalized totally via
 *   {@link normalizeBooleanField}: coerced to a real boolean, or removed with
 *   a warning so the documented default applies. Consumers may therefore gate
 *   on plain truthiness / `!== false` without re-validating types.
 * - `mcp.clientIdMetadataDocuments.allowedHosts` is normalized to an array of
 *   exact, lowercased hostnames. A scalar string (which `Array.includes` /
 *   `String.includes` would turn into substring matching) is wrapped into a
 *   single-element array; anything that isn't a string or array of strings is
 *   rejected rather than treated as "no restriction".
 */
export function normalizeMcpSecurityConfig(mcpConfig: Record<string, any>, logger?: Logger): void {
	normalizeBooleanField(mcpConfig, 'enabled', 'mcp.enabled', logger);
	normalizeBooleanField(
		mcpConfig,
		'refreshTokenRequiresOfflineAccess',
		'mcp.refreshTokenRequiresOfflineAccess',
		logger
	);

	const clientCredentials = mcpConfig.clientCredentials;
	if (clientCredentials && typeof clientCredentials === 'object') {
		normalizeBooleanField(clientCredentials, 'enabled', 'mcp.clientCredentials.enabled', logger);
	}

	const dcr = mcpConfig.dynamicClientRegistration;
	if (dcr && typeof dcr === 'object') {
		normalizeBooleanField(dcr, 'enabled', 'mcp.dynamicClientRegistration.enabled', logger);
	}

	const cimd = mcpConfig.clientIdMetadataDocuments;
	if (cimd && typeof cimd === 'object') {
		normalizeBooleanField(cimd, 'enabled', 'mcp.clientIdMetadataDocuments.enabled', logger);

		if (cimd.allowedHosts !== undefined) {
			const raw = Array.isArray(cimd.allowedHosts) ? cimd.allowedHosts : [cimd.allowedHosts];
			if (raw.some((h: unknown) => typeof h !== 'string')) {
				throw new Error(
					'mcp.clientIdMetadataDocuments.allowedHosts must be a hostname string or an array of hostname strings'
				);
			}
			cimd.allowedHosts = raw.map((h: string) => h.trim().toLowerCase()).filter((h: string) => h.length > 0);
		}
	}
}

/**
 * Build configuration for a specific provider
 */
export function buildProviderConfig(
	providerConfig: Record<string, any>,
	providerName: string,
	pluginDefaults: Partial<OAuthProviderConfig> = {}
): OAuthProviderConfig {
	const options = providerConfig || {};

	// Expand environment variables in config values
	const expandedOptions: Record<string, any> = {};
	for (const [key, value] of Object.entries(options)) {
		expandedOptions[key] = expandEnvVar(value);
	}

	// Check for known provider presets
	const providerType = expandedOptions.provider || providerName;
	const providerPreset = providerType ? getProvider(providerType) : null;

	// Build redirect URI with provider name in path
	const baseRedirectUri = expandedOptions.redirectUri || pluginDefaults.redirectUri || 'http://localhost:9926/oauth';
	const redirectUri = baseRedirectUri
		.replace('/oauth/callback', `/oauth/${providerName}/callback`)
		.replace(/\/oauth$/, `/oauth/${providerName}/callback`);

	// Merge configurations: plugin defaults -> preset -> options
	const config: OAuthProviderConfig = {
		// Plugin defaults
		scope: pluginDefaults.scope || 'openid profile email',
		usernameClaim: pluginDefaults.usernameClaim || 'email',
		defaultRole: pluginDefaults.defaultRole || 'user',
		postLoginRedirect: pluginDefaults.postLoginRedirect || '/',

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

		// Provider-specific options (with expanded env vars)
		...expandedOptions,

		// Ensure redirect URI includes provider name (override any previous value)
		redirectUri,
	};

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
			case 'okta':
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

	// Copy all non-provider config to defaults, expanding environment variables.
	// `mcp` is a structured top-level config block (not a provider-level default)
	// so it's excluded; it's threaded through OAuthResource.configure separately.
	for (const [key, value] of Object.entries(options)) {
		if (key !== 'providers' && key !== 'debug' && key !== 'mcp') {
			pluginDefaults[key as keyof OAuthProviderConfig] = expandEnvVar(value);
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
	logger?.debug?.('Plugin defaults:', redactSecrets(pluginDefaults));

	// Initialize each provider
	for (const [providerName, providerConfig] of Object.entries(options.providers)) {
		// `mcp` is a reserved path segment for the MCP OAuth endpoints
		// (/oauth/mcp/*). A provider keyed `mcp` is shadowed by the MCP dispatcher
		// (resource.ts) and would silently 404 at request time, so reject the
		// collision loudly at config load instead.
		if (providerName === 'mcp') {
			throw new Error(
				"OAuth provider name 'mcp' is reserved for the MCP OAuth endpoints (/oauth/mcp/*). Rename this provider."
			);
		}

		const config = buildProviderConfig(providerConfig, providerName, pluginDefaults);

		// Check if this provider is properly configured
		const requiredFields = ['clientId', 'clientSecret', 'authorizationUrl', 'tokenUrl', 'userInfoUrl'];
		const missingFields = requiredFields.filter((key) => !config[key as keyof OAuthProviderConfig]);

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
