/**
 * Azure AD OAuth Provider Configuration
 *
 * Supports both single-tenant and multi-tenant configurations
 */

import type { OAuthProviderConfig } from '../../types.ts';
import { validateAzureTenantId } from './validation.ts';

export const AzureADProvider: OAuthProviderConfig = {
	provider: 'azure',
	clientId: '', // Will be overridden by config
	clientSecret: '', // Will be overridden by config
	// Default to common endpoint (multi-tenant)
	authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
	tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
	userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
	jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
	issuer: null, // Varies by tenant
	scope: 'openid profile email User.Read',
	usernameClaim: 'email',
	emailClaim: 'email',
	nameClaim: 'displayName',

	// Azure-specific: configure endpoints based on tenant (`tenantId`: a real
	// tenant GUID, or one of the shared aliases 'common'/'organizations'/
	// 'consumers' — see `resolveAzureIssuerBinding`, HarperFast/oauth#264).
	configure: (tenantId: string): Partial<OAuthProviderConfig> => {
		// Validate Azure tenant ID format
		validateAzureTenantId(tenantId);

		const config: Partial<OAuthProviderConfig> = {
			authorizationUrl: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
			tokenUrl: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
			jwksUri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
		};

		// A real tenant GUID's issuer is fully determined by it. The shared
		// aliases have no single fixed issuer — leave unset for
		// `resolveAzureIssuerBinding` to resolve (or intentionally leave
		// unresolved).
		if (!/^(common|organizations|consumers)$/i.test(tenantId)) {
			config.issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
		}

		return config;
	},
};
