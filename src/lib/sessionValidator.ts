/**
 * OAuth Session Validation and Token Refresh
 *
 * Handles automatic validation and refresh of OAuth tokens in sessions
 */

import type { Request, IOAuthProvider, Logger, OAuthSessionMetadata } from '../types.ts';
import { clearOAuthSession } from './handlers.ts';
import type { HookManager } from './hookManager.ts';

export interface SessionValidationResult {
	/** Whether the session has valid OAuth data */
	valid: boolean;
	/** Whether tokens were refreshed during validation */
	refreshed?: boolean;
	/** Error message if validation failed */
	error?: string;
}

/**
 * Validate OAuth session and refresh tokens if needed
 *
 * This function checks if OAuth tokens in the session are expired or approaching
 * expiration, and automatically refreshes them if possible.
 *
 * Token refresh strategy:
 * - If token is expired (past expiresAt), refresh immediately
 * - If token is approaching expiration (past refreshThreshold = 80% of lifetime), refresh proactively
 * - If no refresh token available and token is expired, clear OAuth session data
 *
 * @param request - Harper request object with session
 * @param provider - OAuth provider instance for token refresh
 * @param logger - Optional logger for debugging
 * @param hookManager - Optional hook manager for calling onTokenRefresh hook
 * @returns Validation result indicating if session is valid and if refresh occurred
 */
export async function validateAndRefreshSession(
	request: Request,
	provider: IOAuthProvider,
	logger?: Logger,
	hookManager?: HookManager
): Promise<SessionValidationResult> {
	const session = request.session;

	// No session available
	if (!session) {
		return { valid: false, error: 'No session available' };
	}

	// Check for OAuth metadata in session
	const oauthMetadata = session.oauth as OAuthSessionMetadata | undefined;

	if (!oauthMetadata) {
		// No OAuth data in session - not an OAuth session
		return { valid: false, error: 'No OAuth data in session' };
	}

	// Validate required fields
	if (!oauthMetadata.accessToken) {
		logger?.warn?.('OAuth session missing access token, logging out');
		await clearOAuthSession(session, logger);
		return { valid: false, error: 'OAuth session missing access token' };
	}

	const now = Date.now();
	const isExpired = oauthMetadata.expiresAt ? now >= oauthMetadata.expiresAt : false;
	const needsRefresh = oauthMetadata.refreshThreshold ? now >= oauthMetadata.refreshThreshold : false;

	// Token is still valid and doesn't need refresh
	if (!isExpired && !needsRefresh) {
		return { valid: true, refreshed: false };
	}

	// Token needs refresh - check if refresh token is available
	if (!oauthMetadata.refreshToken) {
		if (isExpired) {
			logger?.warn?.('OAuth token expired and no refresh token available, logging out');
			await clearOAuthSession(session, logger);
			return { valid: false, error: 'Token expired and no refresh token available' };
		}
		// Token approaching expiration but no refresh token - still valid for now
		return { valid: true, refreshed: false };
	}

	// Attempt to refresh the token
	logger?.debug?.(
		isExpired
			? 'OAuth token expired, attempting refresh...'
			: 'OAuth token approaching expiration (80% lifetime), refreshing proactively...'
	);

	try {
		// Check if provider supports token refresh
		if (!provider.refreshAccessToken) {
			logger?.warn?.('OAuth provider does not support token refresh');
			if (isExpired) {
				await clearOAuthSession(session, logger);
				return { valid: false, error: 'Token expired and provider does not support refresh' };
			}
			return { valid: true, refreshed: false };
		}

		// Perform token refresh
		const tokenResponse = await provider.refreshAccessToken(oauthMetadata.refreshToken);

		// Calculate new expiration times
		const expiresIn = tokenResponse.expires_in || 3600; // Default 1 hour
		const newExpiresAt = now + expiresIn * 1000;
		const newRefreshThreshold = now + expiresIn * 800; // Refresh at 80% of lifetime

		// Update session with new tokens and metadata
		const updatedMetadata: OAuthSessionMetadata = {
			...oauthMetadata,
			accessToken: tokenResponse.access_token,
			refreshToken: tokenResponse.refresh_token || oauthMetadata.refreshToken, // Keep existing if not provided
			expiresAt: newExpiresAt,
			refreshThreshold: newRefreshThreshold,
			scope: tokenResponse.scope || oauthMetadata.scope,
			tokenType: tokenResponse.token_type || oauthMetadata.tokenType,
			lastRefreshed: now,
		};

		// Update session
		session.oauth = updatedMetadata;
		if (typeof session.update === 'function') {
			await session.update(session);
		}

		logger?.info?.('OAuth token refreshed successfully');

		// Call onTokenRefresh hook
		if (hookManager) {
			await hookManager.callOnTokenRefresh(session, true, request);
		}

		return { valid: true, refreshed: true };
	} catch (error) {
		logger?.error?.('OAuth token refresh failed:', (error as Error).message);

		// If token was expired and refresh failed, log out
		if (isExpired) {
			await clearOAuthSession(session, logger);
			return { valid: false, error: `Token refresh failed: ${(error as Error).message}` };
		}

		// Token not yet expired, allow continued use
		return { valid: true, refreshed: false };
	}
}

/**
 * Check if a session has valid OAuth authentication
 * Does not refresh tokens, only checks validity
 */
export function hasValidOAuthSession(request: Request): boolean {
	const session = request.session;
	if (!session) return false;

	const oauthMetadata = session.oauth as OAuthSessionMetadata | undefined;
	if (!oauthMetadata || !oauthMetadata.accessToken) return false;

	// Check if token is expired - return true if valid, false if expired
	return !(oauthMetadata.expiresAt && Date.now() >= oauthMetadata.expiresAt);
}
