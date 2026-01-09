/**
 * Okta OAuth Provider Configuration
 *
 * Supports Okta's OAuth 2.0 / OIDC implementation
 * Requires domain configuration (e.g., 'dev-12345.okta.com')
 */

import type { OAuthProviderConfig } from '../../types.ts';
import { validateDomainSafety, validateDomainAllowlist } from './validation.ts';

export const OktaProvider: OAuthProviderConfig = {
	provider: 'okta',
	clientId: '', // Will be overridden by config
	clientSecret: '', // Will be overridden by config
	authorizationUrl: '', // Will be set by configure()
	tokenUrl: '', // Will be set by configure()
	userInfoUrl: '', // Will be set by configure()
	jwksUri: '', // Will be set by configure()
	issuer: '', // Will be set by configure()
	scope: 'openid profile email groups',
	usernameClaim: 'preferred_username',
	emailClaim: 'email',
	nameClaim: 'name',
	// Use 'groups' claim for role mapping (optional)
	roleClaim: 'groups',
	defaultRole: 'user',
	// Okta includes user info in ID token, prefer that
	preferIdToken: true,

	// Okta-specific: configure endpoints based on domain
	configure: (domain: string): Partial<OAuthProviderConfig> => {
		// Validate domain safety (SSRF protection, private IPs, etc.)
		const hostname = validateDomainSafety(domain, 'Okta');

		// Validate against Okta domain allowlist
		const ALLOWED_OKTA_DOMAINS = ['.okta.com', '.okta-emea.com', '.oktapreview.com'];
		validateDomainAllowlist(hostname, ALLOWED_OKTA_DOMAINS, 'Okta');

		// Use /oauth2/v1 (org authorization server - most compatible)
		// For /oauth2/default or custom auth servers, set authorizationUrl/tokenUrl/userInfoUrl directly in config
		const authServerPath = '/oauth2/v1';

		return {
			authorizationUrl: `https://${hostname}${authServerPath}/authorize`,
			tokenUrl: `https://${hostname}${authServerPath}/token`,
			userInfoUrl: `https://${hostname}${authServerPath}/userinfo`,
			jwksUri: `https://${hostname}${authServerPath}/keys`,
			issuer: `https://${hostname}${authServerPath}`,
		};
	},
};
