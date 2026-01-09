/**
 * Auth0 OAuth Provider Preset
 *
 * Configuration for Auth0 OAuth 2.0 authentication.
 * Requires domain configuration.
 */

import type { OAuthProviderConfig } from '../../types.ts';
import { validateDomainSafety, validateDomainAllowlist } from './validation.ts';

export const auth0Provider: OAuthProviderConfig = {
	provider: 'auth0',
	clientId: '', // Will be overridden by config
	clientSecret: '', // Will be overridden by config
	authorizationUrl: '', // Will be set by configure()
	tokenUrl: '', // Will be set by configure()
	userInfoUrl: '', // Will be set by configure()
	scope: 'openid profile email',
	usernameClaim: 'email',
	defaultRole: 'user',

	// URLs are configured dynamically based on domain
	configure: (domain: string): Partial<OAuthProviderConfig> => {
		// Validate domain safety (SSRF protection, private IPs, etc.)
		const hostname = validateDomainSafety(domain, 'Auth0');

		// Validate against Auth0 domain allowlist
		const ALLOWED_AUTH0_DOMAINS = ['.auth0.com', '.us.auth0.com', '.eu.auth0.com', '.au.auth0.com', '.jp.auth0.com'];
		validateDomainAllowlist(hostname, ALLOWED_AUTH0_DOMAINS, 'Auth0');

		return {
			authorizationUrl: `https://${hostname}/authorize`,
			tokenUrl: `https://${hostname}/oauth/token`,
			userInfoUrl: `https://${hostname}/userinfo`,
			jwksUri: `https://${hostname}/.well-known/jwks.json`,
			issuer: `https://${hostname}/`,
		};
	},
};
