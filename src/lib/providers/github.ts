/**
 * GitHub OAuth Provider Configuration
 *
 * Note: GitHub uses OAuth 2.0, not OIDC, so no ID tokens or JWKS
 */

import type { OAuthProviderConfig, GetUserInfoHelpers } from '../../types.ts';

export const GitHubProvider: OAuthProviderConfig = {
	provider: 'github',
	clientId: '', // Will be overridden by config
	clientSecret: '', // Will be overridden by config
	authorizationUrl: 'https://github.com/login/oauth/authorize',
	tokenUrl: 'https://github.com/login/oauth/access_token',
	userInfoUrl: 'https://api.github.com/user',
	// No JWKS - GitHub doesn't support OIDC
	jwksUri: null,
	issuer: null,
	scope: 'read:user user:email',
	usernameClaim: 'login',
	emailClaim: 'email',
	nameClaim: 'name',
	// Validate token every 15 minutes (GitHub tokens don't expire but can be revoked)
	tokenValidationInterval: 15 * 60 * 1000, // 15 minutes

	// GitHub-specific: validate token by making lightweight API call
	async validateToken(accessToken: string, logger?: any): Promise<boolean> {
		try {
			const response = await fetch('https://api.github.com/user', {
				method: 'HEAD', // HEAD request - no body, just status
				headers: {
					Authorization: `Bearer ${accessToken}`,
					Accept: 'application/json',
				},
			});
			const isValid = response.ok;
			if (!isValid) {
				logger?.debug?.(`GitHub token validation failed: ${response.status} ${response.statusText}`);
			}
			return isValid;
		} catch (error) {
			logger?.warn?.('GitHub token validation error:', (error as Error).message);
			return false; // Assume invalid on error
		}
	},

	// GitHub-specific: need to fetch email separately if not public
	async getUserInfo(accessToken: string, helpers: GetUserInfoHelpers): Promise<any> {
		// Get basic user info using the base getUserInfo method
		const userInfo = await helpers.getUserInfo(accessToken);

		// If email is not public, fetch from emails endpoint
		if (!userInfo.email) {
			try {
				const emailResponse = await fetch('https://api.github.com/user/emails', {
					headers: {
						Authorization: `Bearer ${accessToken}`,
						Accept: 'application/json',
					},
				});

				if (emailResponse.ok) {
					const emails = (await emailResponse.json()) as Array<{
						email: string;
						primary: boolean;
						verified: boolean;
					}>;
					const primaryEmail = emails.find((e) => e.primary);
					if (primaryEmail) {
						userInfo.email = primaryEmail.email;
						userInfo.email_verified = primaryEmail.verified;
					}
				}
			} catch (error) {
				// Email fetch failed, continue without it
				helpers.logger?.warn?.('Failed to fetch GitHub user emails:', (error as Error).message);
			}
		}

		return userInfo;
	},
};
