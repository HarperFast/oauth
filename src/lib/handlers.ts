/**
 * OAuth Endpoint Handlers
 *
 * Handler functions for OAuth authentication endpoints
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Request, RequestTarget, Logger, IOAuthProvider, OAuthProviderConfig } from '../types.ts';

/**
 * Handle OAuth login initiation
 */
export async function handleLogin(
	request: Request,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	logger?: Logger
): Promise<any> {
	// Generate CSRF token with metadata
	const csrfToken = await provider.generateCSRFToken({
		originalUrl: request.headers?.referer || config.postLoginRedirect || '/oauth/test',
		sessionId: request.session?.id,
	});

	// Build authorization URL with CSRF token as state parameter
	const authUrl = provider.getAuthorizationUrl(csrfToken, config.redirectUri || '');

	logger?.info?.(`OAuth login initiated for session: ${request.session?.id}`);

	return {
		status: 302,
		headers: {
			Location: authUrl,
		},
	};
}

/**
 * Handle OAuth callback from provider
 */
export async function handleCallback(
	request: Request,
	target: RequestTarget,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	logger?: Logger
): Promise<any> {
	// Get query parameters from target
	const code = target.get?.('code');
	const state = target.get?.('state');
	const error = target.get?.('error');
	const errorDescription = target.get?.('error_description');

	// Handle OAuth errors from provider
	if (error) {
		logger?.error?.(`OAuth error: ${error} - ${errorDescription}`);
		// Redirect to original URL or fallback with error
		const fallbackUrl = config.postLoginRedirect || '/';
		const errorUrl = `${fallbackUrl}${fallbackUrl.includes('?') ? '&' : '?'}error=oauth_failed&reason=${encodeURIComponent(error)}`;
		return {
			status: 302,
			headers: {
				Location: errorUrl,
			},
		};
	}

	// Validate parameters
	if (!code || !state) {
		logger?.warn?.('Missing required OAuth callback parameters');
		const fallbackUrl = config.postLoginRedirect || '/';
		const errorUrl = `${fallbackUrl}${fallbackUrl.includes('?') ? '&' : '?'}error=invalid_request`;
		return {
			status: 302,
			headers: {
				Location: errorUrl,
			},
		};
	}

	// Verify CSRF token
	const tokenData = await provider.verifyCSRFToken(state);
	if (!tokenData) {
		logger?.warn?.('Invalid or expired CSRF token');
		// Redirect back to login with error parameter
		const providerKey = config.provider || 'oauth';
		const loginUrl = `/oauth/${providerKey}/login?error=session_expired`;
		return {
			status: 302,
			headers: {
				Location: loginUrl,
			},
		};
	}

	try {
		// Exchange code for tokens
		const tokenResponse = await provider.exchangeCodeForToken(code, config.redirectUri || '');

		// Verify ID token if present (OIDC flow)
		let idTokenClaims = null;
		if (tokenResponse.id_token) {
			try {
				idTokenClaims = provider.verifyIdToken ? await provider.verifyIdToken(tokenResponse.id_token) : null;
				logger?.info?.('ID token verified successfully');
			} catch (error) {
				// Log verification failure but continue with userinfo endpoint
				logger?.warn?.('ID token verification failed, falling back to userinfo endpoint:', (error as Error).message);
			}
		}

		// Get user info (will use ID token claims if available and verified)
		const userInfo = await provider.getUserInfo(tokenResponse.access_token, idTokenClaims);

		// Map to Harper user
		const user = provider.mapUserToHarper(userInfo);

		// Store in session if available
		if (request.session) {
			// Store user info in session
			if (typeof request.session.update === 'function') {
				await request.session.update({
					user: user.username, // Harper expects just the username string
					oauthUser: user, // Store full OAuth user object separately
					oauthToken: tokenResponse.access_token,
					oauthRefreshToken: tokenResponse.refresh_token,
				});
			} else {
				request.session.user = user.username;
				request.session.oauthUser = user;
				request.session.oauthToken = tokenResponse.access_token;
				if (tokenResponse.refresh_token) {
					request.session.oauthRefreshToken = tokenResponse.refresh_token;
				}
			}

			logger?.info?.(`OAuth login successful for user: ${user.username}`);
		} else {
			logger?.warn?.('No session available for OAuth user');
		}

		// Redirect to original URL or default
		return {
			status: 302,
			headers: {
				Location: tokenData.originalUrl || config.postLoginRedirect || '/oauth/test',
			},
		};
	} catch (error) {
		logger?.error?.('OAuth callback error:', error);
		return {
			status: 500,
			body: {
				error: 'Authentication failed',
				message: (error as Error).message,
			},
		};
	}
}

/**
 * Handle user logout
 */
export async function handleLogout(request: Request, logger?: Logger): Promise<any> {
	if (request.session) {
		if (typeof request.session.update === 'function') {
			await request.session.update({
				user: undefined,
				oauthUser: undefined,
				oauthToken: undefined,
				oauthRefreshToken: undefined,
			});
		} else {
			delete request.session.user;
			delete request.session.oauthUser;
			delete request.session.oauthToken;
			delete request.session.oauthRefreshToken;
		}
		logger?.info?.('User logged out');
	}

	return {
		status: 200,
		body: { message: 'Logged out successfully' },
	};
}

/**
 * Get current user info
 */
export async function handleUserInfo(request: Request): Promise<any> {
	// Add debug logging
	if (!request) {
		return {
			status: 500,
			body: { error: 'Request object not provided' },
		};
	}

	// Check for OAuth user in session first, then Harper user
	const oauthUser = request?.session?.oauthUser;
	const username = request?.user || request?.session?.user;

	if (!username && !oauthUser) {
		return {
			status: 401,
			body: {
				authenticated: false,
				message: 'Not authenticated',
			},
		};
	}

	// If we have OAuth user details, use those
	if (oauthUser) {
		return {
			status: 200,
			body: {
				authenticated: true,
				username: oauthUser.username,
				role: oauthUser.role,
				email: oauthUser.email,
				name: oauthUser.name,
				provider: oauthUser.provider,
			},
		};
	}

	// Fall back to Harper user - extract just the username string and role name
	const usernameString = typeof username === 'string' ? username : (username as any)?.username;
	const roleData = typeof username === 'object' ? (username as any)?.role : (request as any)?.user?.role;

	// Extract role name - Harper roles can be objects with id/name or just strings
	const roleName = typeof roleData === 'string' ? roleData : roleData?.id || roleData?.name || 'user';

	return {
		status: 200,
		body: {
			authenticated: true,
			username: usernameString,
			role: roleName,
			email: null,
			name: null,
			provider: 'harper',
		},
	};
}

/**
 * Refresh OAuth access token
 */
export async function handleRefresh(
	request: Request,
	provider: IOAuthProvider,
	_config: OAuthProviderConfig,
	logger?: Logger
): Promise<any> {
	// Get refresh token from session
	const refreshToken = request?.session?.oauthRefreshToken;

	if (!refreshToken) {
		return {
			status: 401,
			body: { error: 'No refresh token available' },
		};
	}

	try {
		// Refresh the access token
		if (!provider.refreshAccessToken) {
			return {
				status: 501,
				body: { error: 'Token refresh not supported by this provider' },
			};
		}

		const tokenResponse = await provider.refreshAccessToken(refreshToken);

		// Update session with new tokens
		if (request.session) {
			if (typeof request.session.update === 'function') {
				await request.session.update({
					oauthToken: tokenResponse.access_token,
					// Update refresh token if a new one was provided
					oauthRefreshToken: tokenResponse.refresh_token || refreshToken,
				});
			} else {
				request.session.oauthToken = tokenResponse.access_token;
				if (tokenResponse.refresh_token) {
					request.session.oauthRefreshToken = tokenResponse.refresh_token;
				}
			}

			logger?.info?.('OAuth token refreshed successfully');
		}

		return {
			status: 200,
			body: {
				message: 'Token refreshed successfully',
				expiresIn: tokenResponse.expires_in,
			},
		};
	} catch (error) {
		logger?.error?.('Token refresh failed:', error);
		return {
			status: 401,
			body: {
				error: 'Token refresh failed',
				message: (error as Error).message,
			},
		};
	}
}

/**
 * Serve OAuth test page
 */
export async function handleTestPage(logger?: Logger): Promise<any> {
	try {
		const __dirname = dirname(fileURLToPath(import.meta.url));
		const testHtml = await readFile(join(__dirname, '..', '..', 'assets', 'test.html'), 'utf8');

		return {
			status: 200,
			headers: {
				'Content-Type': 'text/html',
			},
			body: testHtml,
		};
	} catch (error) {
		logger?.error?.('Failed to load test page:', error);
		return {
			status: 500,
			body: { error: 'Failed to load test page' },
		};
	}
}
