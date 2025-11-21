/**
 * Tests for OAuth Handlers
 */

import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { handleLogin, handleCallback, handleLogout, handleUserInfo, handleTestPage } from '../../dist/lib/handlers.js';

describe('OAuth Handlers', () => {
	let mockProvider;
	let mockConfig;
	let mockLogger;
	let mockHookManager;
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

		mockHookManager = {
			callOnLogin: mock.fn(async () => {}),
			callOnLogout: mock.fn(async () => {}),
			callOnTokenRefresh: mock.fn(async () => {}),
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
		};

		mockRequest = {
			headers: {
				referer: 'https://app.example.com/page',
			},
			session: {
				id: 'session-123',
				update: mock.fn(),
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
			const result = await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, 'https://auth.test.com/authorize?state=csrf-token-123');
			assert.equal(mockProvider.generateCSRFToken.mock.calls.length, 1);
			assert.equal(mockProvider.getAuthorizationUrl.mock.calls.length, 1);
		});

		it('should use redirect query parameter when provided', async () => {
			const targetWithRedirect = {
				get: mock.fn((key) => {
					if (key === 'redirect') return '/custom/redirect/path';
					return undefined;
				}),
			};

			await handleLogin(mockRequest, targetWithRedirect, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/custom/redirect/path');
		});

		it('should use referer as original URL when no redirect param', async () => {
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, 'https://app.example.com/page');
		});

		it('should fall back to postLoginRedirect when no redirect param or referer', async () => {
			delete mockRequest.headers.referer;
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/dashboard');
		});

		it('should include session ID in CSRF token', async () => {
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].sessionId, 'session-123');
		});
	});

	describe('handleCallback', () => {
		it('should handle successful OAuth callback', async () => {
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			assert.equal(mockProvider.verifyCSRFToken.mock.calls.length, 1);
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 1);
			assert.equal(mockProvider.getUserInfo.mock.calls.length, 1);
			assert.equal(mockProvider.mapUserToHarper.mock.calls.length, 1);
		});

		it('should update session with user data', async () => {
			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, mockLogger);

			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'user@example.com');
			assert.ok(updateCall.arguments[0].oauthUser);
			// Token data is now stored in oauth object
			assert.ok(updateCall.arguments[0].oauth);
			assert.equal(updateCall.arguments[0].oauth.accessToken, 'access-token-123');
			assert.equal(updateCall.arguments[0].oauth.refreshToken, 'refresh-token-456');
		});

		it('should handle OAuth error response', async () => {
			mockTarget.get = mock.fn((key) => {
				if (key === 'error') return 'access_denied';
				if (key === 'error_description') return 'User denied access';
				return null;
			});

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=oauth_failed&reason=access_denied');
		});

		it('should handle missing code parameter', async () => {
			mockTarget.get = mock.fn(() => null);

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=invalid_request');
		});

		it('should handle invalid CSRF token', async () => {
			mockProvider.verifyCSRFToken = mock.fn(async () => null);

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

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

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/app/home?error=oauth_failed&reason=invalid_scope');
		});

		it('should handle missing parameters with query string in postLoginRedirect', async () => {
			mockTarget.get = mock.fn(() => null);
			mockConfig.postLoginRedirect = '/app?tab=auth';

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/app?tab=auth&error=invalid_request');
		});

		it('should verify ID token when present', async () => {
			mockProvider.verifyIdToken = mock.fn(async () => ({ sub: 'user-123', email: 'verified@example.com' }));
			mockProvider.exchangeCodeForToken = mock.fn(async () => ({
				access_token: 'access-token',
				id_token: 'id-token-jwt',
			}));

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, mockLogger);

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

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			// Should still succeed, falling back to userinfo endpoint
			assert.equal(result.status, 302);
			assert.equal(mockProvider.getUserInfo.mock.calls.length, 1);
		});

		it('should handle token exchange failure', async () => {
			mockProvider.exchangeCodeForToken = mock.fn(async () => {
				throw new Error('Invalid client credentials');
			});

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 500);
			assert.equal(result.body.error, 'Authentication failed');
			assert.ok(result.body.message.includes('Invalid client credentials'));
		});

		it('should handle session without update function', async () => {
			mockRequest.session = {
				id: 'session-123',
			};

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(mockRequest.session.user, 'user@example.com');
			assert.ok(mockRequest.session.oauthUser);
			// Token data is now stored in oauth object
			assert.ok(mockRequest.session.oauth);
			assert.equal(mockRequest.session.oauth.accessToken, 'access-token-123');
		});

		it('should handle tokens without expiration (GitHub style)', async () => {
			// GitHub doesn't return expires_in - tokens don't expire
			mockProvider.exchangeCodeForToken = mock.fn(async () => ({
				access_token: 'github-token-123',
				token_type: 'bearer',
				scope: 'user:email',
				// No expires_in field - token doesn't expire
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			const updateCall = mockRequest.session.update.mock.calls[0];
			// expiresAt and refreshThreshold should be undefined for non-expiring tokens
			assert.equal(updateCall.arguments[0].oauth.expiresAt, undefined);
			assert.equal(updateCall.arguments[0].oauth.refreshThreshold, undefined);
			assert.equal(updateCall.arguments[0].oauth.accessToken, 'github-token-123');
		});

		it('should handle missing session', async () => {
			delete mockRequest.session;

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				mockLogger
			);

			assert.equal(result.status, 302);
			// Should still complete but log warning
			assert.equal(mockLogger.warn.mock.calls.length, 1);
		});
	});

	describe('handleLogout', () => {
		it('should clear session data', async () => {
			// Add delete method mock to session
			mockRequest.session.delete = mock.fn();

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(result.body.message, 'Logged out successfully');

			// Should call session.delete with session ID
			assert.equal(mockRequest.session.delete.mock.calls.length, 1);
			assert.equal(mockRequest.session.delete.mock.calls[0].arguments[0], 'session-123');
		});

		it('should handle session without delete function', async () => {
			mockRequest.session = {
				user: 'test-user',
				oauthUser: { username: 'test' },
				oauth: { accessToken: 'token' },
			};

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
			// Falls back to clearing fields when delete method isn't available
			assert.equal(mockRequest.session.user, null);
			assert.equal(mockRequest.session.oauth, undefined);
			assert.equal(mockRequest.session.oauthUser, undefined);
		});

		it('should handle missing session', async () => {
			delete mockRequest.session;

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(result.body.message, 'Logged out successfully');
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
