/**
 * Auth0 OAuth Provider Preset
 *
 * Configuration for Auth0 OAuth 2.0 authentication.
 * Requires domain configuration.
 */

import type { OAuthProviderConfig } from '../../types.ts';

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
		if (!domain) {
			throw new Error('Auth0 provider requires domain configuration');
		}

		// Ensure domain doesn't include protocol or trailing slash
		const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');

		return {
			authorizationUrl: `https://${cleanDomain}/authorize`,
			tokenUrl: `https://${cleanDomain}/oauth/token`,
			userInfoUrl: `https://${cleanDomain}/userinfo`,
			jwksUri: `https://${cleanDomain}/.well-known/jwks.json`,
			issuer: `https://${cleanDomain}/`,
		};
	},
};
