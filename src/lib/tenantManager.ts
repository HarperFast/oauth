/**
 * Multi-Tenant SSO Manager
 *
 * Enables dynamic tenant routing for enterprise SSO
 * Supports Okta, Azure AD, Auth0, and any domain-based OAuth provider
 */

import type { OAuthProviderConfig, Logger } from '../types.ts';
import { getProvider } from './providers/index.ts';
import { validateTenantId, validateEmailDomain } from './providers/validation.ts';

export interface TenantConfig {
	/** Unique tenant identifier (e.g., 'acme-corp', 'globex') */
	tenantId: string;
	/** Tenant display name */
	name: string;
	/** OAuth provider type (okta, azure, auth0, etc.) */
	provider: 'okta' | 'azure' | 'auth0' | string;
	/** Provider-specific domain (for Okta/Auth0) or tenant ID (for Azure) */
	domain?: string;
	/** Azure AD specific tenant ID (alternative to domain) */
	azureTenantId?: string;
	/** OAuth client ID for this tenant */
	clientId: string;
	/** OAuth client secret for this tenant */
	clientSecret: string;
	/** Optional: Email domains that belong to this tenant */
	emailDomains?: string[];
	/** Optional: Custom scopes */
	scope?: string;
	/** Optional: Custom post-login redirect */
	postLoginRedirect?: string;
	/** Optional: Additional provider-specific config */
	additionalConfig?: Record<string, any>;
}

export interface TenantRegistryEntry {
	config: TenantConfig;
	providerConfig: OAuthProviderConfig;
}

export class TenantManager {
	private tenants: Map<string, TenantRegistryEntry> = new Map();
	private domainToTenant: Map<string, string> = new Map();
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Register a tenant with their OAuth provider configuration
	 * Supports Okta, Azure AD, Auth0, and custom providers
	 */
	registerTenant(tenant: TenantConfig): void {
		// Validate tenant ID format
		validateTenantId(tenant.tenantId);

		// Validate email domains
		if (tenant.emailDomains) {
			for (const domain of tenant.emailDomains) {
				validateEmailDomain(domain);
			}
		}

		// Get the base provider configuration
		const baseProvider = getProvider(tenant.provider);

		if (!baseProvider) {
			throw new Error(`Unknown provider type: ${tenant.provider}`);
		}

		// Apply provider-specific configuration
		// Note: Provider configure() methods now include security validation
		let providerSpecificConfig: Partial<OAuthProviderConfig> = {};

		if (baseProvider.configure) {
			switch (tenant.provider) {
				case 'okta':
				case 'auth0':
					if (!tenant.domain) {
						throw new Error(`${tenant.provider} provider requires domain configuration`);
					}
					providerSpecificConfig = baseProvider.configure(tenant.domain);
					break;

				case 'azure':
				case 'microsoft':
					if (!tenant.azureTenantId) {
						throw new Error('Azure AD provider requires azureTenantId configuration');
					}
					providerSpecificConfig = baseProvider.configure(tenant.azureTenantId);
					break;

				default:
					// For custom providers, pass domain or azureTenantId if available
					const configParam = tenant.domain || tenant.azureTenantId;
					if (configParam) {
						providerSpecificConfig = baseProvider.configure(configParam);
					}
			}
		}

		// Build the complete provider configuration
		const providerConfig: OAuthProviderConfig = {
			...baseProvider,
			...providerSpecificConfig,
			provider: tenant.provider,
			clientId: tenant.clientId,
			clientSecret: tenant.clientSecret,
			scope: tenant.scope || baseProvider.scope,
			postLoginRedirect: tenant.postLoginRedirect,
			...tenant.additionalConfig,
		};

		this.tenants.set(tenant.tenantId, {
			config: tenant,
			providerConfig,
		});

		// Map email domains to tenant (already validated above)
		if (tenant.emailDomains) {
			for (const domain of tenant.emailDomains) {
				const normalizedDomain = domain.toLowerCase();
				const existingTenantId = this.domainToTenant.get(normalizedDomain);

				if (existingTenantId && existingTenantId !== tenant.tenantId) {
					this.logger?.warn?.(
						`Email domain "${normalizedDomain}" is already mapped to tenant "${existingTenantId}". ` +
							`Overwriting with tenant "${tenant.tenantId}".`
					);
				}

				this.domainToTenant.set(normalizedDomain, tenant.tenantId);
			}
		}

		this.logger?.info?.(`Registered tenant: ${tenant.name} (${tenant.tenantId}) using ${tenant.provider} provider`);
	}

	/**
	 * Register multiple tenants at once
	 */
	registerTenants(tenants: TenantConfig[]): void {
		for (const tenant of tenants) {
			this.registerTenant(tenant);
		}
	}

	/**
	 * Get tenant by ID
	 *
	 * ⚠️ **Security Warning**: Returns full tenant configuration including clientSecret.
	 * This method is intended for internal use (hooks, OAuth flows) only.
	 * Never expose the returned TenantRegistryEntry directly in HTTP responses.
	 *
	 * @example
	 * // ✅ Safe: Use in hooks/internal logic
	 * const tenant = tenantManager.getTenant(provider);
	 * return { tenantName: tenant?.config.name };
	 *
	 * // ❌ Unsafe: Direct HTTP exposure
	 * return { tenant: tenantManager.getTenant(id) }; // Leaks clientSecret!
	 */
	getTenant(tenantId: string): TenantRegistryEntry | undefined {
		return this.tenants.get(tenantId);
	}

	/**
	 * Get tenant by email domain
	 *
	 * ⚠️ **Security Warning**: Returns full tenant configuration including clientSecret.
	 * This method is intended for internal use (hooks, OAuth flows) only.
	 * Never expose the returned TenantRegistryEntry directly in HTTP responses.
	 */
	getTenantByEmail(email: string): TenantRegistryEntry | undefined {
		const domain = email.split('@')[1]?.toLowerCase();
		if (!domain) return undefined;

		const tenantId = this.domainToTenant.get(domain);
		if (!tenantId) return undefined;

		return this.tenants.get(tenantId);
	}

	/**
	 * Get all registered tenants
	 *
	 * Note: clientSecret is automatically redacted for security.
	 * Secrets are only needed internally for OAuth flows.
	 */
	getAllTenants(): TenantConfig[] {
		return Array.from(this.tenants.values()).map((entry) => ({
			...entry.config,
			clientSecret: undefined as any, // Redact secret for security
		}));
	}

	/**
	 * Convert tenant configurations to provider registry format
	 * This can be merged with the standard provider registry
	 *
	 * ⚠️ **Security Warning**: Returns provider configurations including clientSecret.
	 * This method is intended for OAuth plugin initialization only.
	 * The returned configs are needed for OAuth token exchange flows.
	 * Never expose these configurations in HTTP responses.
	 */
	toProviderRegistry(): Record<string, { provider: any; config: OAuthProviderConfig }> {
		const registry: Record<string, { provider: any; config: OAuthProviderConfig }> = {};

		for (const [tenantId, entry] of this.tenants) {
			// We'll need to create a provider instance here
			// For now, return the config - the caller will need to instantiate OAuthProvider
			registry[tenantId] = {
				provider: null as any, // Will be instantiated by caller
				config: entry.providerConfig,
			};
		}

		return registry;
	}

	/**
	 * Load tenants from configuration
	 * Supports both static config and dynamic loading from database
	 */
	static fromConfig(config: { tenants?: TenantConfig[]; logger?: Logger }): TenantManager {
		const manager = new TenantManager(config.logger);

		if (config.tenants) {
			manager.registerTenants(config.tenants);
		}

		return manager;
	}
}
