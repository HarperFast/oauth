/**
 * Google OAuth Provider Configuration
 *
 * Supports OpenID Connect (OIDC) with ID tokens
 */

import type { OAuthProviderConfig } from '../../types.ts';

export const GoogleProvider: OAuthProviderConfig = {
	provider: 'google',
	clientId: '', // Will be overridden by config
	clientSecret: '', // Will be overridden by config
	authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
	tokenUrl: 'https://oauth2.googleapis.com/token',
	userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
	jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
	issuer: 'https://accounts.google.com',
	scope: 'openid profile email',
	usernameClaim: 'email',
	emailClaim: 'email',
	nameClaim: 'name',
	// Google includes user info in ID token, prefer that
	preferIdToken: true,
	// Additional Google-specific parameters
	additionalParams: {
		access_type: 'offline', // Request refresh token
		prompt: 'consent', // Force consent to get refresh token
	},
};
