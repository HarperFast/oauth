/**
 * OAuth Endpoint Handlers
 *
 * Handler functions for OAuth authentication endpoints
 */

import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RequestTarget } from 'harper';
import type { Request, Logger, IOAuthProvider, MCPAuthorizeState, MCPConfig, OAuthProviderConfig } from '../types.ts';
import { consentNonceMatches, readConsentNonce } from './mcp/consentBinding.ts';
import { handleMCPCallback } from './mcp/index.ts';
import { resolveIssuer } from './mcp/wellKnown.ts';
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
 * Build a safe error redirect URL
 *
 * Sanitizes the redirect path, then appends error query params using the URL API
 * so params are always placed before any hash fragment.
 */
function buildErrorRedirect(rawUrl: string, params: Record<string, string>): string {
	const safePath = sanitizeRedirect(rawUrl);
	const url = new URL(safePath, 'http://localhost');
	for (const [key, value] of Object.entries(params)) {
		url.searchParams.set(key, value);
	}
	return url.pathname + url.search + url.hash;
}

/**
 * Handle OAuth login initiation
 */
export async function handleLogin(
	request: Request,
	target: RequestTarget,
	provider: IOAuthProvider,
	config: OAuthProviderConfig,
	providerName: string,
	logger?: Logger
): Promise<any> {
	// Determine redirect URL: query param > referer header > config default
	let redirectParam = target.get?.('redirect');

	// Sanitize redirect parameter to prevent open redirect attacks
	if (redirectParam) {
		redirectParam = sanitizeRedirect(redirectParam);
	}

	const referer = request.headers?.referer ? sanitizeRedirect(request.headers.referer) : undefined;
	const originalUrl = redirectParam || referer || config.postLoginRedirect || '/';

	// Generate CSRF token with metadata
	// Bind token to provider to prevent cross-provider CSRF attacks
	const csrfToken = await provider.generateCSRFToken({
		originalUrl,
		sessionId: request.session?.id,
		providerName, // Bind state token to this provider
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
	providerName: string,
	opts?: { mcpConfig?: MCPConfig; logger?: Logger }
): Promise<any> {
	const { mcpConfig, logger } = opts ?? {};
	// Get query parameters from target
	const code = target.get?.('code');
	const state = target.get?.('state');
	const error = target.get?.('error');
	const errorDescription = target.get?.('error_description');

	// Helper: build an MCP-aware error redirect to the MCP client's redirect_uri.
	// Only used in MCP branches — the human path keeps its existing
	// buildErrorRedirect shape (error code only, optionally with reason) to
	// avoid changing observable behavior on the human OAuth flow.
	// RFC 9207: include `iss` on all authorization responses, including errors.
	const mcpErrorRedirect = (mcp: MCPAuthorizeState, errorCode: string, description: string) => {
		const url = new URL(mcp.redirectUri);
		url.searchParams.set('error', errorCode);
		url.searchParams.set('error_description', description);
		if (mcp.clientState) url.searchParams.set('state', mcp.clientState);
		url.searchParams.set('iss', resolveIssuer(request as any, mcpConfig ?? {}));
		return { status: 302, headers: { Location: url.toString() } };
	};

	// Validate state presence — we use it both to route errors (via mcp
	// payload, when present) AND to defend against CSRF.
	if (!state) {
		// Without state, we can't be in an MCP flow (MCP always sets state).
		// Preserve the legacy human-OAuth error UX: if the IdP sent an error,
		// echo it to postLoginRedirect with the original reason. Otherwise,
		// generic invalid_request.
		if (error) {
			logger?.error?.(`OAuth error (no state): ${error} - ${errorDescription}`);
			const errorUrl = buildErrorRedirect(config.postLoginRedirect || '/', {
				error: 'oauth_failed',
				reason: error,
			});
			return { status: 302, headers: { Location: errorUrl } };
		}
		logger?.warn?.('Missing state parameter in OAuth callback');
		const errorUrl = buildErrorRedirect(config.postLoginRedirect || '/', { error: 'invalid_request' });
		return { status: 302, headers: { Location: errorUrl } };
	}

	// Verify CSRF token FIRST — before checking the upstream error param.
	// This is what lets MCP-initiated errors route back to the MCP client's
	// redirect_uri instead of the Harper app's default path. The token is
	// single-use; consuming it on error is fine because OAuth callbacks
	// aren't retried with the same state.
	const tokenData = await provider.verifyCSRFToken(state);
	if (!tokenData) {
		logger?.warn?.('Invalid or expired CSRF token');
		// We can't know if this was an MCP flow (state didn't decode), so
		// fall back to a generic redirect — same behavior as pre-fix.
		const loginUrl = `/oauth/${providerName}/login?error=session_expired`;
		return { status: 302, headers: { Location: loginUrl } };
	}

	// Token purpose enforcement: a CIMD confirm token (minted for POST
	// /oauth/mcp/confirm) also carries `mcp` + `providerName` and would
	// otherwise be accepted here as upstream state — letting a malicious
	// client skip the consent interstitial entirely by feeding its confirm
	// token to the IdP as `state`. Treat it exactly like an invalid token
	// (same generic response; nothing in a mis-purposed token is trusted,
	// including its mcp redirect_uri).
	if (tokenData._confirm) {
		logger?.warn?.('CIMD confirm token presented as upstream OAuth state; rejecting');
		const loginUrl = `/oauth/${providerName}/login?error=session_expired`;
		return { status: 302, headers: { Location: loginUrl } };
	}

	const mcpState = tokenData.mcp as MCPAuthorizeState | undefined;

	// Verify state token was issued for THIS provider (prevents cross-provider attacks).
	if (tokenData.providerName !== providerName) {
		logger?.warn?.(
			`State token provider mismatch: token issued for '${tokenData.providerName}', callback for '${providerName}'`
		);
		if (mcpState) {
			return mcpErrorRedirect(mcpState, 'invalid_request', 'cross-provider state mismatch');
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'auth_failed',
			reason: 'csrf',
		});
		return { status: 302, headers: { Location: errorUrl } };
	}

	// Now that we know the flow context, handle upstream IdP errors.
	if (error) {
		logger?.error?.(`OAuth error: ${error} - ${errorDescription}`);
		if (mcpState) {
			return mcpErrorRedirect(mcpState, error, errorDescription || error);
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'oauth_failed',
			reason: error,
		});
		return { status: 302, headers: { Location: errorUrl } };
	}

	// Validate code presence — needed regardless of flow.
	if (!code) {
		logger?.warn?.('Missing authorization code in OAuth callback');
		if (mcpState) {
			return mcpErrorRedirect(mcpState, 'invalid_request', 'Missing authorization code');
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'invalid_request',
		});
		return { status: 302, headers: { Location: errorUrl } };
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
				logger?.warn?.(
					'ID token verification failed, falling back to userinfo endpoint:',
					error instanceof Error ? error.message : String(error)
				);
			}
		}

		// Get user info (will use ID token claims if available and verified)
		const userInfo = await provider.getUserInfo(tokenResponse.access_token, idTokenClaims);

		// Map to Harper user
		const user = provider.mapUserToHarper(userInfo);

		// Call onLogin hook before storing session
		// This allows user provisioning plugins to create/update user records
		// Pass providerName (registry key) not config.provider (provider type) for multi-tenant support
		const hookData = await hookManager.callOnLogin(user, tokenResponse, request.session, request, providerName);

		// MCP branch: if the CSRF state was minted by /oauth/mcp/authorize, the
		// upstream callback's job is to mint an MCP authorization code, NOT to
		// create a Harper session. Independent lifecycle per #86 resolved
		// decision. The upstream IdP token never reaches the MCP client.
		// Pass the onLogin-mapped username so the issued auth code (and the
		// JWT exchanged for it in Stage 4) is bound to the correct identity.
		if (mcpState) {
			// CIMD browser binding: the callback must arrive in the same browser
			// that approved the consent interstitial (SameSite=Lax sends the
			// nonce cookie on the top-level redirect from the IdP). Without this
			// check an attacker could self-approve the interstitial and hand the
			// victim the upstream IdP URL. Absent hash = DCR flow (no interstitial).
			if (mcpState.browserNonceHash && !consentNonceMatches(readConsentNonce(request), mcpState.browserNonceHash)) {
				logger?.warn?.(`MCP callback: consent browser binding mismatch for client=${mcpState.clientId}`);
				return mcpErrorRedirect(
					mcpState,
					'access_denied',
					'Authorization must complete in the browser that approved it'
				);
			}
			const userIdentifier = hookData?.user ?? user.username;
			return handleMCPCallback(request, mcpState, userIdentifier, mcpConfig ?? {}, logger);
		}

		// Store in session if available
		if (request.session) {
			// Calculate token expiration and refresh thresholds
			// For providers that don't return expires_in (like GitHub), tokens don't expire
			// so we don't set expiration/refresh thresholds to avoid premature session cleanup
			const now = Date.now();
			let expiresAt: number | undefined;
			let refreshThreshold: number | undefined;

			if (tokenResponse.expires_in) {
				// Token has expiration - calculate thresholds
				const expiresIn = tokenResponse.expires_in;
				expiresAt = now + expiresIn * 1000;
				refreshThreshold = now + expiresIn * 800; // Refresh at 80% of lifetime
			}
			// else: No expires_in means token doesn't expire (e.g., GitHub)
			// Leave expiresAt and refreshThreshold undefined so middleware doesn't try to refresh

			// Prepare session data
			const sessionData: any = {
				user: hookData?.user || user.username, // Use hook's user if provided, otherwise OAuth username
				oauthUser: user, // Store full OAuth user object separately
				oauth: {
					provider: providerName, // Config key (backwards compatible - e.g., 'my-custom-github', 'production-okta')
					providerConfigId: providerName, // Config key/ID (clearer naming for new code)
					providerType: config.provider, // Provider type (e.g., 'github', 'okta')
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

			logger?.info?.(
				`OAuth login successful for user: ${user.username}${tokenResponse.expires_in ? `, token expires in ${tokenResponse.expires_in}s` : ', token does not expire'}`
			);
		} else {
			logger?.warn?.('No session available for OAuth user');
		}

		// Redirect to original URL or default (sanitize to prevent open redirect)
		return {
			status: 302,
			headers: {
				Location: sanitizeRedirect(tokenData.originalUrl || config.postLoginRedirect || '/'),
			},
		};
	} catch (error) {
		logger?.error?.('OAuth callback error:', error);
		// Use a safe, generic reason code — details are in the server log
		const message = error instanceof Error ? error.message : String(error);
		let reason = 'unknown';
		if (message.startsWith('Token exchange failed')) reason = 'token_exchange';
		else if (message.includes('claim')) reason = 'user_mapping';
		else if (message.includes('user info') || message.includes('userinfo')) reason = 'user_info';
		else if (message.includes('hook') || message.includes('onLogin')) reason = 'login_hook';
		if (mcpState) {
			return mcpErrorRedirect(mcpState, 'server_error', reason);
		}
		const errorUrl = buildErrorRedirect(tokenData.originalUrl || config.postLoginRedirect || '/', {
			error: 'auth_failed',
			reason,
		});
		return { status: 302, headers: { Location: errorUrl } };
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
							providerConfigId: oauthMetadata.providerConfigId,
							providerType: oauthMetadata.providerType,
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
