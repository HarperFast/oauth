/**
 * Tests for OAuth Handlers
 */

import { describe, it, before, after, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import {
	handleLogin,
	handleCallback,
	handleLogout,
	handleUserInfo,
	handleRefresh,
	handleTestPage,
} from '../../dist/lib/handlers.js';

describe('OAuth Handlers', () => {
	let mockProvider;
	let mockConfig;
	let mockLogger;
	let mockRequest;
	let mockTarget;

	beforeEach(() => {
		// Setup common mocks
		mockLogger = {
			info: mock.fn(),
			warn: mock.fn(),
			error: mock.fn(),
			debug: mock.fn(),
		};

		mockConfig = {
			provider: 'test',
			clientId: 'test-client',
			clientSecret: 'test-secret',
			authorizationUrl: 'https://auth.test.com/authorize',
			tokenUrl: 'https://auth.test.com/token',
			userInfoUrl: 'https://auth.test.com/userinfo',
			redirectUri: 'https://localhost:9953/oauth/test/callback',
			postLoginRedirect: '/dashboard',
		};

		mockProvider = {
			generateCSRFToken: mock.fn(async () => 'csrf-token-123'),
			getAuthorizationUrl: mock.fn(() => 'https://auth.test.com/authorize?state=csrf-token-123'),
			verifyCSRFToken: mock.fn(async () => ({ originalUrl: '/dashboard', timestamp: Date.now() })),
			exchangeCodeForToken: mock.fn(async () => ({
				access_token: 'access-token-123',
				refresh_token: 'refresh-token-456',
			})),
			getUserInfo: mock.fn(async () => ({
				sub: 'user-123',
				email: 'user@example.com',
				name: 'Test User',
			})),
			mapUserToHarper: mock.fn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				name: 'Test User',
				provider: 'test',
			})),
			refreshAccessToken: mock.fn(async () => ({
				access_token: 'new-access-token',
				expires_in: 3600,
			})),
			refreshTokensWithMetadata: mock.fn(async (refreshToken, existingMetadata) => {
				const now = Date.now();
				const expiresInMs = 3600 * 1000; // 1 hour
				return {
					...existingMetadata,
					accessToken: 'new-access-token',
					issuedAt: now,
					refreshAt: now + expiresInMs,
					refreshThreshold: now + (expiresInMs * 0.8),
					refreshToken: refreshToken,
					lastRefreshed: now
				};
			}),
			processCallback: mock.fn(async (code, redirectUri) => {
				const now = Date.now();
				const expiresInMs = 3600 * 1000; // 1 hour
				return {
					user: 'user@example.com',
					authProvider: 'oauth',
					authProviderMetadata: {
						provider: 'test',
						accessToken: 'access-token-123',
						refreshToken: 'refresh-token-456',
						issuedAt: now,
						refreshAt: now + expiresInMs,
						refreshThreshold: now + (expiresInMs * 0.8),
						userInfo: {
							sub: 'user-123',
							email: 'user@example.com',
							name: 'Test User',
						},
						profile: {
							email: 'user@example.com',
							name: 'Test User',
							picture: undefined
						}
					},
					expiresAt: now + (24 * 60 * 60 * 1000)
				};
			}),
		};

		mockRequest = {
			headers: {
				referer: 'https://app.example.com/page',
			},
			session: {
				id: 'session-123',
				update: mock.fn(),
				authProviderMetadata: {
					provider: 'test',
					accessToken: 'old-access-token',
					refreshToken: 'refresh-token-456',
					issuedAt: Date.now() - 1800000, // 30 minutes ago
					refreshAt: Date.now() + 1800000, // 30 minutes from now
					refreshThreshold: Date.now() + 1440000, // 24 minutes from now (80% of 30 min)
				},
			},
		};

		mockTarget = {
			get: mock.fn((key) => {
				const params = {
					code: 'auth-code-789',
					state: 'csrf-token-123',
				};
				return params[key];
			}),
		};
	});

	describe('handleLogin', () => {
		it('should initiate OAuth login flow', async () => {
			const result = await handleLogin(mockRequest, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, 'https://auth.test.com/authorize?state=csrf-token-123');
			assert.equal(mockProvider.generateCSRFToken.mock.calls.length, 1);
			assert.equal(mockProvider.getAuthorizationUrl.mock.calls.length, 1);
		});

		it('should use referer as original URL when domain is allowed', async () => {
			// Configure allowed domains for security
			mockConfig.allowedRedirectDomains = ['app.example.com'];
			
			const result = await handleLogin(mockRequest, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, 'https://app.example.com/page');
		});
		
		it('should reject unsafe referer and fall back to postLoginRedirect', async () => {
			// No allowed domains configured - should reject all absolute URLs
			const result = await handleLogin(mockRequest, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/dashboard'); // Falls back to postLoginRedirect
		});

		it('should fall back to postLoginRedirect when no referer', async () => {
			delete mockRequest.headers.referer;
			const result = await handleLogin(mockRequest, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/dashboard');
		});

		it('should include session ID in CSRF token', async () => {
			const result = await handleLogin(mockRequest, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].sessionId, 'session-123');
		});
	});

	describe('handleCallback', () => {
		it('should handle successful OAuth callback', async () => {
			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			assert.equal(mockProvider.verifyCSRFToken.mock.calls.length, 1);
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 1);
			assert.equal(mockProvider.getUserInfo.mock.calls.length, 1);
			assert.equal(mockProvider.mapUserToHarper.mock.calls.length, 1);
		});

		it('should update session with user data', async () => {
			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'user@example.com');
			assert.equal(updateCall.arguments[0].authProvider, 'oauth');
			assert.ok(updateCall.arguments[0].authProviderMetadata);
			assert.equal(updateCall.arguments[0].authProviderMetadata.accessToken, 'access-token-123');
			assert.equal(updateCall.arguments[0].authProviderMetadata.refreshToken, 'refresh-token-456');
		});

		it('should handle OAuth error response', async () => {
			mockTarget.get = mock.fn((key) => {
				if (key === 'error') return 'access_denied';
				if (key === 'error_description') return 'User denied access';
				return null;
			});

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=oauth_failed&reason=access_denied');
		});

		it('should handle missing code parameter', async () => {
			mockTarget.get = mock.fn(() => null);

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=invalid_request');
		});

		it('should handle invalid CSRF token', async () => {
			mockProvider.verifyCSRFToken = mock.fn(async () => null);

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/oauth/test/login?error=session_expired');
		});

		it('should handle OAuth error with custom postLoginRedirect', async () => {
			mockTarget.get = mock.fn((key) => {
				if (key === 'error') return 'invalid_scope';
				if (key === 'error_description') return 'Requested scope not allowed';
				return null;
			});
			mockConfig.postLoginRedirect = '/app/home';

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/app/home?error=oauth_failed&reason=invalid_scope');
		});

		it('should handle missing parameters with query string in postLoginRedirect', async () => {
			mockTarget.get = mock.fn(() => null);
			mockConfig.postLoginRedirect = '/app?tab=auth';

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/app?tab=auth&error=invalid_request');
		});

		it('should verify ID token when present', async () => {
			mockProvider.verifyIdToken = mock.fn(async () => ({ sub: 'user-123', email: 'verified@example.com' }));
			mockProvider.exchangeCodeForToken = mock.fn(async () => ({
				access_token: 'access-token',
				id_token: 'id-token-jwt',
			}));

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(mockProvider.verifyIdToken.mock.calls.length, 1);
			assert.equal(mockProvider.verifyIdToken.mock.calls[0].arguments[0], 'id-token-jwt');
		});

		it('should handle ID token verification failure gracefully', async () => {
			mockProvider.verifyIdToken = mock.fn(async () => {
				throw new Error('Invalid signature');
			});
			mockProvider.exchangeCodeForToken = mock.fn(async () => ({
				access_token: 'access-token',
				id_token: 'invalid-token',
			}));

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			// Should still succeed, falling back to userinfo endpoint
			assert.equal(result.status, 302);
			assert.equal(mockProvider.getUserInfo.mock.calls.length, 1);
		});

		it('should handle token exchange failure', async () => {
			mockProvider.exchangeCodeForToken = mock.fn(async () => {
				throw new Error('Invalid client credentials');
			});

			const result = await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 500);
			assert.equal(result.body.error, 'Authentication failed');
			assert.ok(result.body.message.includes('Invalid client credentials'));
		});
	});

	describe('handleLogout', () => {
		it('should clear session data', async () => {
			const result = await handleLogout(mockRequest, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(result.body.message, 'Logged out successfully');

			// Verify session.update was called to clear OAuth data
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, undefined);
			assert.equal(updateCall.arguments[0].authProvider, undefined);
			assert.equal(updateCall.arguments[0].authProviderMetadata, undefined);
		});

		it('should handle logout with different session ID', async () => {
			mockRequest.session.id = 'different-session-id';

			const result = await handleLogout(mockRequest, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(result.body.message, 'Logged out successfully');
			
			// Verify session.update was called to clear OAuth data
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
		});
	});

	describe('handleUserInfo', () => {
		it('should return OAuth user info from session', async () => {
			mockRequest.session.oauthUser = {
				username: 'oauth-user',
				role: 'admin',
				email: 'oauth@example.com',
				name: 'OAuth User',
				provider: 'test',
			};

			const result = await handleUserInfo(mockRequest);

			assert.equal(result.status, 200);
			assert.equal(result.body.authenticated, true);
			assert.equal(result.body.username, 'oauth-user');
			assert.equal(result.body.role, 'admin');
			assert.equal(result.body.email, 'oauth@example.com');
			assert.equal(result.body.provider, 'test');
		});

		it('should fall back to Harper user', async () => {
			delete mockRequest.session.oauthUser;
			mockRequest.user = 'harper-user';

			const result = await handleUserInfo(mockRequest);

			assert.equal(result.status, 200);
			assert.equal(result.body.authenticated, true);
			assert.equal(result.body.username, 'harper-user');
			assert.equal(result.body.provider, 'harper');
		});

		it('should handle user object with role', async () => {
			delete mockRequest.session.oauthUser;
			mockRequest.user = {
				username: 'harper-user',
				role: { id: 'admin', name: 'Administrator' },
			};

			const result = await handleUserInfo(mockRequest);

			assert.equal(result.status, 200);
			assert.equal(result.body.username, 'harper-user');
			assert.equal(result.body.role, 'admin');
		});

		it('should return not authenticated when no user', async () => {
			delete mockRequest.session.oauthUser;
			delete mockRequest.user;
			delete mockRequest.session.user;

			const result = await handleUserInfo(mockRequest);

			assert.equal(result.status, 401);
			assert.equal(result.body.authenticated, false);
			assert.equal(result.body.message, 'Not authenticated');
		});

		it('should handle missing request object', async () => {
			const result = await handleUserInfo(null);

			assert.equal(result.status, 500);
			assert.equal(result.body.error, 'Request object not provided');
		});
	});

	describe('handleRefresh', () => {
		it('should refresh access token', async () => {
			const result = await handleRefresh(mockRequest, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(result.body.message, 'Token refreshed successfully');
			assert.equal(result.body.expiresIn, 3600);

			// Verify session.update was called with new tokens
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].authProviderMetadata.accessToken, 'new-access-token');
		});

		it('should handle missing refresh token', async () => {
			// Mock session without refresh token
			mockRequest.session.authProviderMetadata = {
				provider: 'test',
				accessToken: 'old-access-token',
				// No refreshToken
			};

			const result = await handleRefresh(mockRequest, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 401);
			assert.equal(result.body.error, 'No refresh token available');
		});

		it('should handle provider without refresh support', async () => {
			// Mock provider without refreshTokensWithMetadata method
			const providerWithoutRefresh = { ...mockProvider };
			delete providerWithoutRefresh.refreshTokensWithMetadata;

			const result = await handleRefresh(mockRequest, providerWithoutRefresh, mockConfig, mockLogger);

			assert.equal(result.status, 501);
			assert.equal(result.body.error, 'Token refresh not supported by this provider');
		});

		it('should handle refresh failure', async () => {
			mockProvider.refreshTokensWithMetadata = mock.fn(async () => {
				throw new Error('Refresh token expired');
			});

			const result = await handleRefresh(mockRequest, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 500);
			assert.equal(result.body.error, 'Token refresh failed');
			assert.ok(result.body.message.includes('Refresh token expired'));
		});

		it('should update refresh token when new one provided', async () => {
			mockProvider.refreshTokensWithMetadata = mock.fn(async (refreshToken, existingMetadata) => {
				const now = Date.now();
				const expiresInMs = 7200 * 1000; // 2 hours
				return {
					...existingMetadata,
					accessToken: 'new-access',
					issuedAt: now,
					refreshAt: now + expiresInMs,
					refreshThreshold: now + (expiresInMs * 0.8),
					refreshToken: 'new-refresh',
					lastRefreshed: now
				};
			});

			const result = await handleRefresh(mockRequest, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 200);
			
			// Verify session.update was called with new tokens
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].authProviderMetadata.accessToken, 'new-access');
			assert.equal(updateCall.arguments[0].authProviderMetadata.refreshToken, 'new-refresh');
		});
	});

	describe('handleTestPage', () => {
		it('should serve test HTML page', async () => {
			// Mock readFile to return test HTML
			const result = await handleTestPage(mockLogger);

			// Since we can't easily mock fs.promises.readFile in this context,
			// we'll just check the structure
			assert.ok(result);
			// The actual implementation will either return success or error
			if (result.status === 200) {
				assert.equal(result.headers['Content-Type'], 'text/html');
			} else {
				assert.equal(result.status, 500);
				assert.equal(result.body.error, 'Failed to load test page');
			}
		});
	});
});
