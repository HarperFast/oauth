/**
 * Okta OAuth Provider Configuration
 *
 * Supports Okta's OAuth 2.0 / OIDC implementation
 * Requires domain configuration (e.g., 'dev-12345.okta.com')
 */

import type { OAuthProviderConfig } from '../../types.ts';
import { validateDomainSafety, validateDomainAllowlist, validateOktaAuthServer } from './validation.ts';

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

	// Okta-specific: configure endpoints based on domain, and optionally a
	// named custom authorization server (HarperFast/oauth#264) — e.g.
	// `authServer: 'default'` for the `default` custom AS, or a generated ID.
	// Omitted, this derives the org authorization server exactly as before.
	configure: (domain: string, authServer?: string): Partial<OAuthProviderConfig> => {
		// Validate domain safety (SSRF protection, private IPs, etc.)
		const hostname = validateDomainSafety(domain, 'Okta');

		// Validate against Okta domain allowlist
		const ALLOWED_OKTA_DOMAINS = ['.okta.com', '.okta-emea.com', '.oktapreview.com'];
		validateDomainAllowlist(hostname, ALLOWED_OKTA_DOMAINS, 'Okta');

		if (authServer) {
			validateOktaAuthServer(authServer);
			// Custom authorization server: endpoints AND issuer both live under
			// /oauth2/{authServer} — unlike the org AS, the issuer includes the path.
			const authServerPath = `/oauth2/${authServer}`;
			return {
				authorizationUrl: `https://${hostname}${authServerPath}/v1/authorize`,
				tokenUrl: `https://${hostname}${authServerPath}/v1/token`,
				userInfoUrl: `https://${hostname}${authServerPath}/v1/userinfo`,
				jwksUri: `https://${hostname}${authServerPath}/v1/keys`,
				issuer: `https://${hostname}${authServerPath}`,
			};
		}

		// Use /oauth2/v1 (org authorization server - most compatible)
		const authServerPath = '/oauth2/v1';

		return {
			authorizationUrl: `https://${hostname}${authServerPath}/authorize`,
			tokenUrl: `https://${hostname}${authServerPath}/token`,
			userInfoUrl: `https://${hostname}${authServerPath}/userinfo`,
			jwksUri: `https://${hostname}${authServerPath}/keys`,
			// Org Authorization Server issuer is the base domain, not the API path
			issuer: `https://${hostname}`,
		};
	},
};
