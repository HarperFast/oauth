/**
 * Okta Multi-Tenant SSO Example
 *
 * Complete example showing how to configure multiple Okta tenants for different
 * organizations with tenant routing and user provisioning.
 */

import { registerHooks, TenantManager } from '@harperfast/oauth';

// Initialize tenant manager with multiple Okta organizations
const tenantManager = new TenantManager();

// Register Acme Corp's Okta instance
tenantManager.registerTenant({
	tenantId: 'acme-corp',
	name: 'Acme Corporation',
	provider: 'okta',
	domain: 'acme.okta.com',
	clientId: process.env.OKTA_ACME_CLIENT_ID,
	clientSecret: process.env.OKTA_ACME_CLIENT_SECRET,
	emailDomains: ['acme.com'],
	postLoginRedirect: '/dashboard',
});

// Register Globex Corp's Okta instance
tenantManager.registerTenant({
	tenantId: 'globex-corp',
	name: 'Globex Corporation',
	provider: 'okta',
	domain: 'globex.okta.com',
	clientId: process.env.OKTA_GLOBEX_CLIENT_ID,
	clientSecret: process.env.OKTA_GLOBEX_CLIENT_SECRET,
	emailDomains: ['globex.com'],
	postLoginRedirect: '/dashboard',
});

// Register OAuth hooks for multi-tenant behavior
registerHooks({
	// Resolve which tenant to use based on provider name
	// The provider name comes from the URL: /oauth/{providerName}/login
	async onResolveProvider(providerName, logger) {
		// Check if this is a tenant ID we know about
		const tenant = tenantManager.getTenant(providerName);
		if (tenant) {
			logger?.info?.(`Resolved tenant: ${tenant.config.name}`);
			return tenant.providerConfig;
		}

		// Not a known tenant
		return null;
	},

	// Provision user on first login
	async onLogin(_oauthUser, _tokenResponse, _session, _request, provider) {
		const tenant = tenantManager.getTenant(provider);

		// Store tenant info in session
		return {
			tenantId: provider,
			tenantName: tenant?.config.name,
			// You could also store additional tenant-specific data here
		};
	},
});
