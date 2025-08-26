/**
 * Generic OAuth Provider Configuration
 *
 * Base configuration for custom OAuth 2.0 providers
 */

import type { OAuthProviderConfig } from '../../types.ts';

export const genericProvider: OAuthProviderConfig = {
	provider: 'generic',
	clientId: '', // Must be provided in config
	clientSecret: '', // Must be provided in config
	authorizationUrl: '', // Must be provided in config
	tokenUrl: '', // Must be provided in config
	userInfoUrl: '', // Must be provided in config
	scope: 'openid profile email',
	usernameClaim: 'email',
	emailClaim: 'email',
	nameClaim: 'name',
	defaultRole: 'user',
	postLoginRedirect: '/',
};
