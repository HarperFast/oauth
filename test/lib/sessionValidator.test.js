/**
 * Session Validator Tests
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateAndRefreshSession, hasValidOAuthSession } from '../../dist/lib/sessionValidator.js';

/**
 * Create a mock OAuth provider
 */
function createMockProvider(overrides = {}) {
	return {
		config: {
			provider: 'google',
			...overrides.config,
		},
		refreshAccessToken: async (refreshToken) => {
			if (overrides.refreshAccessToken) {
				return overrides.refreshAccessToken(refreshToken);
			}
			return {
				access_token: 'new_access_token',
				refresh_token: 'new_refresh_token',
				expires_in: 3600,
				token_type: 'Bearer',
				scope: 'openid profile email',
			};
		},
		...overrides,
	};
}

/**
 * Create a mock session that simulates HarperDB session behavior
 */
function createMockSession(overrides = {}) {
	const session = {
		user: 'test@example.com',
		oauthUser: {
			username: 'test@example.com',
			email: 'test@example.com',
			name: 'Test User',
			role: 'user',
		},
		oauth: {
			provider: 'google',
			accessToken: 'old_access_token',
			refreshToken: 'old_refresh_token',
			expiresAt: Date.now() + 3600000, // 1 hour from now
			refreshThreshold: Date.now() + 2880000, // 48 minutes from now (80%)
			scope: 'openid profile email',
			tokenType: 'Bearer',
			lastRefreshed: Date.now() - 1000,
		},
		...overrides,
		// Simulate HarperDB session.update() which REPLACES entire session
		update: async function (data) {
			// HarperDB's session.update() accepts the session object itself
			// In production, it serializes and replaces the entire session
			// For testing, we need to handle when data === this (same object reference)
			if (data === this) {
				// Session is updating itself - this is the correct usage
				// No-op since the session already has all the current values
				return;
			}

			// Legacy path: when passed a plain object (old API usage)
			// Clear all existing properties
			const keys = Object.keys(this);
			for (const key of keys) {
				if (key !== 'update') {
					delete this[key];
				}
			}
			// Set new properties
			Object.assign(this, data);
		},
	};

	return session;
}

// ============================================================================
// Basic Validation Tests
// ============================================================================

// Session Validation - Basic
test('should return invalid for missing session', async () => {
	const provider = createMockProvider();
	const result = await validateAndRefreshSession({ session: null }, provider);

	assert.strictEqual(result.valid, false);
	assert.strictEqual(result.error, 'No session available');
});

test('should return invalid for session without oauth data', async () => {
	const provider = createMockProvider();
	const session = { user: 'test' };
	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, false);
	assert.strictEqual(result.error, 'No OAuth data in session');
});

test('should return invalid for session without access token', async () => {
	const provider = createMockProvider();
	const session = { user: 'test', oauth: { provider: 'google' } };
	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, false);
	assert.strictEqual(result.error, 'OAuth session missing access token');
});

test('should return valid for valid session', async () => {
	const provider = createMockProvider();
	const session = createMockSession();
	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
});

// ============================================================================
// Token Refresh Tests - BUG REPRODUCTION
// ============================================================================

// Token Refresh - Session Field Preservation
test('should preserve provider field during token refresh', async () => {
	const provider = createMockProvider();
	const session = createMockSession({
		oauth: {
			provider: 'google',
			providerConfigId: 'google',
			providerType: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() - 1000, // Already expired
			refreshThreshold: Date.now() - 1000,
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, true);

	// BUG: This assertion will FAIL before the fix!
	// The provider field gets lost during session.update()
	assert.strictEqual(session.oauth.provider, 'google', 'provider field should be preserved after token refresh');
	assert.strictEqual(
		session.oauth.providerConfigId,
		'google',
		'providerConfigId field should be preserved after token refresh'
	);
	assert.strictEqual(
		session.oauth.providerType,
		'google',
		'providerType field should be preserved after token refresh'
	);
});

test('should preserve custom session fields from hooks during refresh', async () => {
	const provider = createMockProvider();
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() - 1000, // Already expired
			refreshThreshold: Date.now() - 1000,
		},
		// Custom fields added by onLogin hook
		customField: 'custom_value',
		anotherField: { nested: 'data' },
		permissions: ['read', 'write'],
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, true);

	// BUG: These assertions will FAIL before the fix!
	// Custom fields get lost during session.update()
	assert.strictEqual(session.customField, 'custom_value', 'custom field should be preserved');
	assert.deepStrictEqual(session.anotherField, { nested: 'data' }, 'nested custom field should be preserved');
	assert.deepStrictEqual(session.permissions, ['read', 'write'], 'array field should be preserved');
});

test('should refresh token when approaching expiration (80% threshold)', async () => {
	const provider = createMockProvider();
	const now = Date.now();
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: now + 600000, // 10 minutes from now
			refreshThreshold: now - 1000, // Past the 80% threshold
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, true);
	assert.strictEqual(session.oauth.accessToken, 'new_access_token');
	assert.strictEqual(session.oauth.provider, 'google', 'provider should be preserved');
});

test('should update token metadata correctly', async () => {
	const provider = createMockProvider();
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() - 1000,
			refreshThreshold: Date.now() - 1000,
			scope: 'old_scope',
		},
	});

	const beforeRefresh = Date.now();
	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, true);
	assert.strictEqual(session.oauth.accessToken, 'new_access_token');
	assert.strictEqual(session.oauth.refreshToken, 'new_refresh_token');
	assert.strictEqual(session.oauth.scope, 'openid profile email');
	assert.strictEqual(session.oauth.tokenType, 'Bearer');
	assert.ok(session.oauth.expiresAt > beforeRefresh);
	assert.ok(session.oauth.refreshThreshold > beforeRefresh);
	assert.ok(session.oauth.lastRefreshed >= beforeRefresh);
});

// ============================================================================
// Token Refresh - Error Handling
// ============================================================================

// Token Refresh - Error Handling
test('should logout when token expired and no refresh token', async () => {
	const provider = createMockProvider();
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: undefined, // No refresh token
			expiresAt: Date.now() - 1000, // Expired
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, false);
	assert.strictEqual(result.error, 'Token expired and no refresh token available');
	// Session should be cleared
	assert.strictEqual(session.oauth, undefined);
});

test('should handle refresh failure for expired token', async () => {
	const provider = createMockProvider({
		refreshAccessToken: async () => {
			throw new Error('Refresh failed');
		},
	});
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() - 1000, // Expired
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, false);
	assert.ok(result.error.includes('Token refresh failed'));
	// Session should be cleared after failed refresh of expired token
	assert.strictEqual(session.oauth, undefined);
});

test('should not logout when refresh fails for non-expired token', async () => {
	const provider = createMockProvider({
		refreshAccessToken: async () => {
			throw new Error('Refresh failed');
		},
	});
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() + 600000, // Not expired yet
			refreshThreshold: Date.now() - 1000, // But past refresh threshold
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	// Should remain valid even though refresh failed
	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
	// Session should NOT be cleared
	assert.ok(session.oauth);
	assert.strictEqual(session.oauth.provider, 'google');
});

test('should handle provider without refresh support', async () => {
	const provider = createMockProvider({
		refreshAccessToken: undefined, // No refresh support
	});
	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() - 1000, // Expired
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, false);
	assert.strictEqual(result.error, 'Token expired and provider does not support refresh');
});

// ============================================================================
// Hook Integration Tests
// ============================================================================

// Token Refresh - Hook Integration
test('should call onTokenRefresh hook after successful refresh', async () => {
	const provider = createMockProvider();
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'old_token',
			refreshToken: 'old_refresh',
			expiresAt: Date.now() - 1000,
		},
	});

	let hookCalled = false;
	let hookSession;
	let hookRefreshed;
	const hookManager = {
		callOnTokenRefresh: async (sess, refreshed) => {
			hookCalled = true;
			hookSession = sess;
			hookRefreshed = refreshed;
		},
	};

	const result = await validateAndRefreshSession({ session }, provider, undefined, hookManager);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, true);
	assert.strictEqual(hookCalled, true);
	assert.strictEqual(hookRefreshed, true);

	// BUG: This will FAIL before the fix!
	// Hook receives session with provider: undefined
	assert.strictEqual(hookSession.oauth?.provider, 'google', 'hook should receive session with provider field intact');
});

// ============================================================================
// Periodic Token Validation Tests (GitHub-style non-expiring tokens)
// ============================================================================

// Token Validation - Periodic Validation for Non-Expiring Tokens
test('should perform periodic validation for non-expiring tokens', async () => {
	let validationCalled = false;
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				validationCalled = true;
				return true; // Token is valid
			},
			tokenValidationInterval: 1000, // 1 second for testing
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'github_token',
			refreshToken: undefined, // GitHub doesn't provide refresh tokens
			// No expiresAt or refreshThreshold - GitHub-style token
			lastValidated: Date.now() - 2000, // 2 seconds ago, past interval
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
	assert.strictEqual(validationCalled, true, 'validateToken should have been called');
	assert.ok(session.oauth.lastValidated > Date.now() - 100, 'lastValidated timestamp should be updated');
});

test('should skip validation when interval has not passed', async () => {
	let validationCalled = false;
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				validationCalled = true;
				return true;
			},
			tokenValidationInterval: 60000, // 1 minute
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'github_token',
			refreshToken: undefined,
			lastValidated: Date.now() - 5000, // Only 5 seconds ago
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
	assert.strictEqual(validationCalled, false, 'validateToken should NOT be called yet');
});

test('should use lastRefreshed if lastValidated is not set', async () => {
	let validationCalled = false;
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				validationCalled = true;
				return true;
			},
			tokenValidationInterval: 1000,
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'github_token',
			refreshToken: undefined,
			lastRefreshed: Date.now() - 2000, // 2 seconds ago
			// No lastValidated field
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(validationCalled, true, 'Should use lastRefreshed as fallback');
});

test('should validate immediately if never validated before', async () => {
	let validationCalled = false;
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				validationCalled = true;
				return true;
			},
			tokenValidationInterval: 60000,
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'github_token',
			refreshToken: undefined,
			// No lastValidated or lastRefreshed - brand new token
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(validationCalled, true, 'Should validate immediately on first check');
});

test('should logout when periodic validation fails (token revoked)', async () => {
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				return false; // Token has been revoked
			},
			tokenValidationInterval: 1000,
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'revoked_token',
			refreshToken: undefined,
			lastValidated: Date.now() - 2000,
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, false);
	assert.strictEqual(result.error, 'Token validation failed - token may have been revoked');
	assert.strictEqual(session.oauth, undefined, 'Session should be cleared after validation failure');
});

test('should handle validation errors gracefully (network issues)', async () => {
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				throw new Error('Network error: ECONNREFUSED');
			},
			tokenValidationInterval: 1000,
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'token',
			refreshToken: undefined,
			lastValidated: Date.now() - 2000,
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	// Should remain valid despite validation error (could be temporary network issue)
	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
	assert.ok(session.oauth, 'Session should NOT be cleared on validation error');
	assert.strictEqual(session.oauth.accessToken, 'token', 'Token should remain unchanged');
});

test('should use default validation interval when not specified', async () => {
	let validationCalled = false;
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				validationCalled = true;
				return true;
			},
			// No tokenValidationInterval specified - should default to 15 minutes
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'github_token',
			refreshToken: undefined,
			lastValidated: Date.now() - 16 * 60 * 1000, // 16 minutes ago, past default 15min
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(validationCalled, true, 'Should use default 15 minute interval');
});

test('should not validate tokens with expiration (Google-style)', async () => {
	let validationCalled = false;
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: async () => {
				validationCalled = true;
				return true;
			},
			tokenValidationInterval: 1000,
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'google_token',
			refreshToken: 'refresh_token',
			expiresAt: Date.now() + 3600000, // Has expiration - not GitHub-style
			lastValidated: Date.now() - 2000,
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
	assert.strictEqual(
		validationCalled,
		false,
		'Should NOT validate tokens that have expiration (use refresh flow instead)'
	);
});

test('should not validate when validateToken function is not provided', async () => {
	const provider = createMockProvider({
		config: {
			...createMockProvider().config,
			validateToken: undefined, // No validation function provided
		},
	});

	const session = createMockSession({
		oauth: {
			provider: 'some-provider',
			accessToken: 'token',
			refreshToken: undefined,
			// No expiration
			lastValidated: Date.now() - 100000, // Very old
		},
	});

	const result = await validateAndRefreshSession({ session }, provider);

	assert.strictEqual(result.valid, true);
	assert.strictEqual(result.refreshed, false);
	// Should just pass through without attempting validation
});

// ============================================================================
// hasValidOAuthSession Tests
// ============================================================================

// hasValidOAuthSession
test('should return false for missing session', () => {
	const result = hasValidOAuthSession({ session: null });
	assert.strictEqual(result, false);
});

test('should return false for session without oauth data', () => {
	const result = hasValidOAuthSession({ session: { user: 'test' } });
	assert.strictEqual(result, false);
});

test('should return false for expired token', () => {
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'token',
			expiresAt: Date.now() - 1000, // Expired
		},
	});
	const result = hasValidOAuthSession({ session });
	assert.strictEqual(result, false);
});

test('should return true for valid token', () => {
	const session = createMockSession({
		oauth: {
			provider: 'google',
			accessToken: 'token',
			expiresAt: Date.now() + 3600000, // Valid
		},
	});
	const result = hasValidOAuthSession({ session });
	assert.strictEqual(result, true);
});

test('should return true for token without expiration', () => {
	const session = createMockSession({
		oauth: {
			provider: 'github',
			accessToken: 'token',
			// No expiresAt - GitHub-style non-expiring token
		},
	});
	const result = hasValidOAuthSession({ session });
	assert.strictEqual(result, true);
});
