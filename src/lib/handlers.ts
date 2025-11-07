/**
 * OAuth Endpoint Handlers
 *
 * Handler functions for OAuth authentication endpoints
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Request, RequestTarget, Logger, IOAuthProvider, OAuthProviderConfig } from '../types.ts';
import type { HookManager } from './hookManager.ts';

/**
 * Sanitize a redirect parameter to prevent open redirect attacks
 *
 * Takes a user-provided redirect URL and extracts only the path portion,
 * stripping any protocol, domain, or port information.
 *
 * Blocks dangerous protocols like javascript:, data:, vbscript:, and file:
 * to prevent XSS and other injection attacks.
 *
 * @param redirectParam - User-provided redirect URL (may be absolute, relative, or protocol-relative)
 * @returns Safe relative path (pathname + search + hash), or '/' if invalid
 *
 * @example
 * sanitizeRedirect('https://evil.com/phish')  // '/phish'
 * sanitizeRedirect('//evil.com/phish')        // '/phish'
 * sanitizeRedirect('/dashboard')              // '/dashboard'
 * sanitizeRedirect('javascript:alert(1)')     // '/'
 * sanitizeRedirect('invalid')                 // '/'
 */
export function sanitizeRedirect(redirectParam: string): string {
	try {
		const url = new URL(redirectParam, 'http://localhost');

		// Block dangerous protocols
		// These protocols can be used for XSS, file access, or other attacks
		const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
		if (dangerousProtocols.some((proto) => url.protocol === proto)) {
			return '/';
		}

		const sanitized = url.pathname + url.search + url.hash;

		// Additional validation: result must start with /
		if (!sanitized.startsWith('/')) {
			return '/';
		}

		return sanitized;
	} catch (error) {
		// Invalid URL - return safe default
		return '/';
	}
}

/**
 * Handle OAuth login initiation
 */
export async function handleLogin(
	request: Request,
	target: RequestTarget,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	logger?: Logger
): Promise<any> {
	// Determine redirect URL: query param > referer header > config default
	let redirectParam = target.get?.('redirect');

	// Sanitize redirect parameter to prevent open redirect attacks
	if (redirectParam) {
		redirectParam = sanitizeRedirect(redirectParam);
	}

	const originalUrl = redirectParam || request.headers?.referer || config.postLoginRedirect || '/';

	// Generate CSRF token with metadata
	const csrfToken = await provider.generateCSRFToken({
		originalUrl,
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
	hookManager: HookManager,
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

		// Call onLogin hook before storing session
		// This allows user provisioning plugins to create/update user records
		const hookData = await hookManager.callOnLogin(user, tokenResponse, request.session, request, config.provider);

		// Store in session if available
		if (request.session) {
			// Calculate token expiration and refresh thresholds
			const expiresIn = tokenResponse.expires_in || 3600; // Default 1 hour if not provided
			const now = Date.now();
			const expiresAt = now + expiresIn * 1000;
			const refreshThreshold = now + expiresIn * 800; // Refresh at 80% of lifetime

			// Prepare session data
			const sessionData: any = {
				user: hookData?.user || user.username, // Use hook's user if provided, otherwise OAuth username
				oauthUser: user, // Store full OAuth user object separately
				oauth: {
					provider: config.provider,
					accessToken: tokenResponse.access_token,
					refreshToken: tokenResponse.refresh_token,
					expiresAt,
					refreshThreshold,
					scope: tokenResponse.scope,
					tokenType: tokenResponse.token_type || 'Bearer',
					lastRefreshed: now,
				},
			};

			// Merge remaining hook data into session if provided (excluding 'user' since we already used it)
			if (hookData) {
				// eslint-disable-next-line @typescript-eslint/no-unused-vars, sonarjs/no-unused-vars
				const { user, ...remainingHookData } = hookData;
				Object.assign(sessionData, remainingHookData);
			}

			// Store user info and OAuth metadata in session
			if (typeof request.session.update === 'function') {
				await request.session.update(sessionData);
			} else {
				Object.assign(request.session, sessionData);
			}

			logger?.info?.(`OAuth login successful for user: ${user.username}, token expires in ${expiresIn}s`);
		} else {
			logger?.warn?.('No session available for OAuth user');
		}

		// Redirect to original URL or default
		return {
			status: 302,
			headers: {
				Location: tokenData.originalUrl || config.postLoginRedirect || '/',
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
 * Clear OAuth session data and log out the user
 * Shared function for explicit logout and automatic logout on token expiration
 *
 * Deletes the session record from the hdb_session table, completely removing it
 * rather than just clearing the user field. This ensures no orphaned sessions remain.
 */
export async function clearOAuthSession(session: any, logger?: Logger): Promise<void> {
	if (!session) return;

	// Delete the session record from the hdb_session table
	// This completely removes the session on logout, rather than just nulling the user field
	if (typeof session.delete === 'function') {
		await session.delete(session.id);
	} else {
		// Fallback for sessions without delete method - clear in-memory
		session.user = null;
		delete session.oauth;
		delete session.oauthUser;
	}

	logger?.info?.('OAuth session cleared');
}

/**
 * Handle user logout
 */
export async function handleLogout(request: Request, hookManager: HookManager, logger?: Logger): Promise<any> {
	// Call onLogout hook before clearing session
	await hookManager.callOnLogout(request.session, request);

	// Clear the OAuth session
	await clearOAuthSession(request.session, logger);

	return {
		status: 200,
		body: { message: 'Logged out successfully' },
	};
}

/**
 * Get current user info
 */
export async function handleUserInfo(request: Request, tokenRefreshed = false): Promise<any> {
	// Add debug logging
	if (!request) {
		return {
			status: 500,
			body: { error: 'Request object not provided' },
		};
	}

	// Check for OAuth user in session first, then Harper user
	const oauthUser = request?.session?.oauthUser;
	const oauthMetadata = request?.session?.oauth;
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
				// Include OAuth token status in debug mode
				oauth: oauthMetadata
					? {
							provider: oauthMetadata.provider,
							expiresAt: oauthMetadata.expiresAt,
							refreshThreshold: oauthMetadata.refreshThreshold,
							lastRefreshed: oauthMetadata.lastRefreshed,
							hasRefreshToken: !!oauthMetadata.refreshToken,
							tokenRefreshed,
						}
					: undefined,
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
 * Refresh OAuth access token (legacy handler - not used, replaced by automatic refresh)
 * Kept for backward compatibility
 */
export async function handleRefresh(
	request: Request,
	provider: IOAuthProvider,
	_config: OAuthProviderConfig,
	logger?: Logger
): Promise<any> {
	// Get refresh token from session
	const refreshToken = request?.session?.oauth?.refreshToken;

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
		if (request.session?.oauth) {
			const expiresIn = tokenResponse.expires_in || 3600;
			const now = Date.now();

			const updatedOAuth = {
				...request.session.oauth,
				accessToken: tokenResponse.access_token,
				refreshToken: tokenResponse.refresh_token || refreshToken,
				expiresAt: now + expiresIn * 1000,
				refreshThreshold: now + expiresIn * 800,
				lastRefreshed: now,
			};

			if (typeof request.session.update === 'function') {
				await request.session.update({
					oauth: updatedOAuth,
				});
			} else {
				request.session.oauth = updatedOAuth;
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
