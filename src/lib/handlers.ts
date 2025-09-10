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
 * Validate and sanitize redirect URL to prevent open redirect attacks
 */
function validateRedirectUrl(url: string | undefined, allowedDomains: string[] = []): string | null {
	if (!url) return null;
	
	try {
		const parsedUrl = new URL(url);
		
		// Only allow relative URLs (same origin) or explicitly allowed domains
		if (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') {
			// For absolute URLs, check if domain is in allowed list
			if (allowedDomains.length === 0) {
				// If no allowed domains specified, reject all absolute URLs for security
				return null;
			}
			
			const hostname = parsedUrl.hostname.toLowerCase();
			const isAllowed = allowedDomains.some(domain => {
				const allowedDomain = domain.toLowerCase();
				return hostname === allowedDomain || hostname.endsWith('.' + allowedDomain);
			});
			
			if (!isAllowed) {
				return null;
			}
		}
		
		// Return the normalized URL
		return parsedUrl.href;
	} catch (error) {
		// Invalid URL format
		return null;
	}
}


/**
 * Handle OAuth login initiation
 */
export async function handleLogin(
	request: Request,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	logger?: Logger
): Promise<any> {
	// Validate referer URL to prevent open redirect attacks
	const validatedReferer = validateRedirectUrl(
		request.headers?.referer,
		config.allowedRedirectDomains || []
	);
	
	// Log security rejections for monitoring
	if (request.headers?.referer && !validatedReferer) {
		logger?.warn?.(`Rejected potentially unsafe referer URL for security: ${request.headers.referer}`);
	}
	
	// Generate CSRF token with metadata
	const csrfToken = await provider.generateCSRFToken({
		originalUrl: validatedReferer || config.postLoginRedirect || '/oauth/test',
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
		const errorUrl = new URL(fallbackUrl, 'http://localhost'); // Base URL for relative paths
		errorUrl.searchParams.set('error', 'oauth_failed');
		errorUrl.searchParams.set('reason', error);
		return {
			status: 302,
			headers: {
				Location: errorUrl.pathname + errorUrl.search,
			},
		};
	}

	// Validate parameters
	if (!code || !state) {
		logger?.warn?.('Missing required OAuth callback parameters');
		const fallbackUrl = config.postLoginRedirect || '/';
		const errorUrl = new URL(fallbackUrl, 'http://localhost'); // Base URL for relative paths
		errorUrl.searchParams.set('error', 'invalid_request');
		return {
			status: 302,
			headers: {
				Location: errorUrl.pathname + errorUrl.search,
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
		// Process OAuth callback using provider (most providers use standard flow)
		const sessionData = await provider.processCallback(code, config.redirectUri || '');

		try {
			await request.session!.update!(sessionData);
			logger?.info?.(`OAuth login successful for user: ${sessionData.user}`);
		} catch (error) {
			logger?.error?.('Failed to create Harper session:', error);
			return {
				status: 500,
				body: {
					error: 'Session creation failed',
					message: 'Could not create authentication session'
				}
			};
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
	try {
		// Clear OAuth session data
		await request.session!.update!({
			user: undefined,
			authProvider: undefined,
			authProviderMetadata: undefined,
		} as any);
		
		logger?.info?.('User logged out successfully');
		
		return {
			status: 200,
			body: { message: 'Logged out successfully' },
		};
	} catch (error) {
		logger?.error?.('Failed to clear session:', error);
		return {
			status: 500,
			body: { 
				error: 'Logout failed',
				message: 'Could not clear session'
			}
		};
	}
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
	const session = request?.session as any;
	const username = request?.user || session?.user;
	const isOAuthUser = session?.authProvider === 'oauth';

	if (!username && !isOAuthUser) {
		return {
			status: 401,
			body: {
				authenticated: false,
				message: 'Not authenticated',
			},
		};
	}

	// If we have OAuth user details, use those
	if (isOAuthUser && session?.authProviderMetadata) {
		const metadata = session.authProviderMetadata;
		return {
			status: 200,
			body: {
				authenticated: true,
				username: session.user,
				role: 'user', // OAuth users get default role
				email: metadata.profile?.email || null,
				name: metadata.profile?.name || null,
				provider: 'oauth',
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
	// Get session data directly from request
	if (!(request.session as any)?.authProviderMetadata?.refreshToken) {
		return {
			status: 401,
			body: { error: 'No refresh token available' },
		};
	}

	const metadata = (request.session as any).authProviderMetadata;
	
	// Check if provider supports token refresh
	if (!provider.refreshTokensWithMetadata) {
		return {
			status: 501,
			body: { error: 'Token refresh not supported by this provider' },
		};
	}

	try {
		// Refresh the access token using provider method
		const newMetadata = await provider.refreshTokensWithMetadata(metadata.refreshToken, metadata);
		
		await request.session!.update!({
			authProviderMetadata: newMetadata
		} as any);

		logger?.info?.('OAuth token refreshed successfully via manual endpoint');

		return {
			status: 200,
			body: {
				message: 'Token refreshed successfully',
				expiresIn: Math.round((newMetadata.refreshAt - newMetadata.issuedAt) / 1000), // Convert back to seconds
				refreshedAt: newMetadata.issuedAt
			},
		};
	} catch (error) {
		logger?.error?.('Manual token refresh failed:', error);
		return {
			status: 500,
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
