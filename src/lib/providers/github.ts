/**
 * GitHub OAuth Provider Configuration
 *
 * Note: GitHub uses OAuth 2.0, not OIDC, so no ID tokens or JWKS
 */

import type { OAuthProviderConfig, GetUserInfoHelpers } from '../../types.ts';
import { ADAPTER_EMAIL_PROVENANCE } from '../emailProvenance.ts';

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
			logger?.warn?.('GitHub token validation error:', error instanceof Error ? error.message : String(error));
			return false; // Assume invalid on error
		}
	},

	// GitHub-specific: the /user payload omits the email unless it's public and
	// never carries verified status — always consult /user/emails so both
	// `email` and `email_verified` are dependable for hook consumers (#174)
	async getUserInfo(accessToken: string, helpers: GetUserInfoHelpers): Promise<any> {
		// Get basic user info using the base getUserInfo method
		const userInfo = await helpers.getUserInfo(accessToken);

		// Only a genuinely successful /user/emails fetch earns the trusted tag.
		// On any failure or non-OK response the provenance stays 'unauthenticated'.
		let emailFetchSucceeded = false;

		try {
			const emailResponse = await fetch('https://api.github.com/user/emails', {
				headers: {
					Authorization: `Bearer ${accessToken}`,
					Accept: 'application/json',
				},
				// Bounded so a stalled response can't hold the login callback open
				signal: AbortSignal.timeout(5000),
			});

			if (emailResponse.ok) {
				const emails = (await emailResponse.json()) as Array<{
					email: string;
					primary: boolean;
					verified: boolean;
				}>;
				if (userInfo.email) {
					// Public profile email: surface its verified status. No match →
					// leave email_verified unset (unknown), never guess.
					const match = emails.find((e) => e.email === userInfo.email);
					if (match) {
						userInfo.email_verified = match.verified;
						emailFetchSucceeded = true;
					}
				} else {
					const primaryEmail = emails.find((e) => e.primary);
					if (primaryEmail) {
						userInfo.email = primaryEmail.email;
						userInfo.email_verified = primaryEmail.verified;
						emailFetchSucceeded = true;
					}
				}
			} else {
				// The case operators actually hit when the user:email scope is missing
				helpers.logger?.warn?.(
					`GitHub /user/emails returned ${emailResponse.status} — email/email_verified unavailable (is the user:email scope granted?)`
				);
				// Drain the unread body so undici returns the socket to the pool
				// (same pattern as OAuthProvider's fetch error paths)
				await emailResponse.body?.cancel();
			}
		} catch (error) {
			// Email fetch failed — provenance not trusted
			helpers.logger?.warn?.(
				'Failed to fetch GitHub user emails:',
				error instanceof Error ? error.message : String(error)
			);
		}

		// 'github-authenticated' ONLY when the authenticated /user/emails fetch
		// succeeded AND the resolved email is verified. Both conditions are decided
		// here, in the code that performed the fetch, and asserted through the
		// ADAPTER_EMAIL_PROVENANCE Symbol — a remote body cannot carry a symbol key,
		// so the wrapper can trust it. Any failure, or an unverified email, leaves it
		// unauthenticated so the adoption gate denies it.
		const provenance =
			emailFetchSucceeded && userInfo.email_verified === true ? 'github-authenticated' : 'unauthenticated';
		// A userinfo endpoint that returns a null/primitive body leaves userInfo non-object;
		// nothing can be adopted from it, so return it as-is rather than defineProperty-ing.
		if (!userInfo || typeof userInfo !== 'object') {
			return userInfo;
		}
		// Non-enumerable so a spread — `{ ...adapterResult, email: attacker }` — does not
		// carry the assertion onto a substituted email; the wrapper reads it by key, which
		// works regardless of enumerability.
		Object.defineProperty(userInfo, ADAPTER_EMAIL_PROVENANCE, { value: provenance, enumerable: false });
		return userInfo;
	},
};
