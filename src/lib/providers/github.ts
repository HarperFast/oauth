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
