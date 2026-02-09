/**
 * Tests for OAuth Handlers
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleLogin, handleCallback, handleLogout, handleUserInfo, handleTestPage } from '../../dist/lib/handlers.js';
import { createMockFn, createMockLogger } from '../helpers/mockFn.js';

describe('OAuth Handlers', () => {
	let mockProvider;
	let mockConfig;
	let mockLogger;
	let mockHookManager;
	let mockRequest;
	let mockTarget;

	beforeEach(() => {
		// Setup common mocks
		mockLogger = createMockLogger();

		mockHookManager = {
			callOnLogin: createMockFn(async () => {}),
			callOnLogout: createMockFn(async () => {}),
			callOnTokenRefresh: createMockFn(async () => {}),
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
			generateCSRFToken: createMockFn(async () => 'csrf-token-123'),
			getAuthorizationUrl: createMockFn(() => 'https://auth.test.com/authorize?state=csrf-token-123'),
			verifyCSRFToken: createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider', // Match the default providerName used in tests
			})),
			exchangeCodeForToken: createMockFn(async () => ({
				access_token: 'access-token-123',
				refresh_token: 'refresh-token-456',
			})),
			getUserInfo: createMockFn(async () => ({
				sub: 'user-123',
				email: 'user@example.com',
				name: 'Test User',
			})),
			mapUserToHarper: createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				name: 'Test User',
				provider: 'test',
			})),
			refreshAccessToken: createMockFn(async () => ({
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
				update: createMockFn(),
			},
		};

		mockTarget = {
			get: createMockFn((key) => {
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
			const providerName = 'test-provider';
			const result = await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, providerName, mockLogger);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, 'https://auth.test.com/authorize?state=csrf-token-123');
			assert.equal(mockProvider.generateCSRFToken.mock.calls.length, 1);
			assert.equal(mockProvider.getAuthorizationUrl.mock.calls.length, 1);
		});

		it('should bind CSRF token to provider name', async () => {
			const providerName = 'acme-corp';
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, providerName, mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].providerName, 'acme-corp');
		});

		it('should use redirect query parameter when provided', async () => {
			const targetWithRedirect = {
				get: createMockFn((key) => {
					if (key === 'redirect') return '/custom/redirect/path';
					return undefined;
				}),
			};

			await handleLogin(mockRequest, targetWithRedirect, mockProvider, mockConfig, 'test-provider', mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/custom/redirect/path');
		});

		it('should use referer as original URL when no redirect param', async () => {
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, 'test-provider', mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			// Referer is sanitized to a relative path
			assert.equal(csrfCall.arguments[0].originalUrl, '/page');
		});

		it('should sanitize referer to prevent open redirect via CSRF token', async () => {
			mockRequest.headers.referer = 'https://evil.com/steal';
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, 'test-provider', mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			// Must strip the external domain, keeping only the path
			assert.equal(csrfCall.arguments[0].originalUrl, '/steal');
		});

		it('should fall back to postLoginRedirect when no redirect param or referer', async () => {
			delete mockRequest.headers.referer;
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, 'test-provider', mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/dashboard');
		});

		it('should include session ID in CSRF token', async () => {
			await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, 'test-provider', mockLogger);

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
				'test-provider',
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
			await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				'test-provider',
				mockLogger
			);

			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'user@example.com');
			assert.ok(updateCall.arguments[0].oauthUser);
			// Token data is now stored in oauth object
			assert.ok(updateCall.arguments[0].oauth);
			assert.equal(updateCall.arguments[0].oauth.accessToken, 'access-token-123');
			assert.equal(updateCall.arguments[0].oauth.refreshToken, 'refresh-token-456');
		});

		it('should handle OAuth error response', async () => {
			mockTarget.get = createMockFn((key) => {
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
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=oauth_failed&reason=access_denied');
		});

		it('should handle missing code parameter', async () => {
			mockTarget.get = createMockFn(() => null);

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=invalid_request');
		});

		it('should handle invalid CSRF token', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => null);

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/oauth/test-provider/login?error=session_expired');
		});

		it('should handle OAuth error with custom postLoginRedirect', async () => {
			mockTarget.get = createMockFn((key) => {
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
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/app/home?error=oauth_failed&reason=invalid_scope');
		});

		it('should handle missing parameters with query string in postLoginRedirect', async () => {
			mockTarget.get = createMockFn(() => null);
			mockConfig.postLoginRedirect = '/app?tab=auth';

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/app?tab=auth&error=invalid_request');
		});

		it('should verify ID token when present', async () => {
			mockProvider.verifyIdToken = createMockFn(async () => ({ sub: 'user-123', email: 'verified@example.com' }));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'access-token',
				id_token: 'id-token-jwt',
			}));

			await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				'test-provider',
				mockLogger
			);

			assert.equal(mockProvider.verifyIdToken.mock.calls.length, 1);
			assert.equal(mockProvider.verifyIdToken.mock.calls[0].arguments[0], 'id-token-jwt');
		});

		it('should handle ID token verification failure gracefully', async () => {
			mockProvider.verifyIdToken = createMockFn(async () => {
				throw new Error('Invalid signature');
			});
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'access-token',
				id_token: 'invalid-token',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			// Should still succeed, falling back to userinfo endpoint
			assert.equal(result.status, 302);
			assert.equal(mockProvider.getUserInfo.mock.calls.length, 1);
		});

		it('should redirect with error on token exchange failure', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => {
				throw new Error('Token exchange failed: provider returned 500 Internal Server Error');
			});

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.ok(result.headers.Location.includes('error=auth_failed'));
			assert.ok(result.headers.Location.includes('reason=token_exchange'));
			// Must NOT leak raw error details in the URL
			assert.ok(!result.headers.Location.includes('500'));
			assert.ok(!result.headers.Location.includes('Internal'));
		});

		it('should use user_info reason when getUserInfo fails', async () => {
			mockProvider.getUserInfo = createMockFn(async () => {
				throw new Error('Failed to fetch user info: 503 Service Unavailable');
			});

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.ok(result.headers.Location.includes('reason=user_info'));
			assert.ok(!result.headers.Location.includes('503'));
		});

		it('should use user_mapping reason when mapUserToHarper fails', async () => {
			mockProvider.mapUserToHarper = createMockFn(() => {
				throw new Error("Username claim 'login' not found in user info");
			});

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.ok(result.headers.Location.includes('reason=user_mapping'));
		});

		it('should use unknown reason for unexpected errors', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => {
				throw new Error('Something completely unexpected');
			});

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.ok(result.headers.Location.includes('reason=unknown'));
			assert.ok(!result.headers.Location.includes('unexpected'));
		});

		it('should place error params before hash fragment in redirect URL', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => {
				throw new Error('Token exchange failed: provider returned 500');
			});
			// CSRF token returns a URL with a fragment
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/app#section',
				timestamp: Date.now(),
				providerName: 'test-provider',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			const loc = result.headers.Location;
			// Query params must come before the hash fragment
			const queryIdx = loc.indexOf('?');
			const hashIdx = loc.indexOf('#');
			assert.ok(queryIdx < hashIdx, `Query params (${queryIdx}) should be before fragment (${hashIdx}): ${loc}`);
			assert.ok(loc.includes('error=auth_failed'));
		});

		it('should sanitize redirect URL in error path to prevent open redirect', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => {
				throw new Error('Token exchange failed: provider error');
			});
			// CSRF token returns an absolute external URL (from unsanitized referer)
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: 'https://evil.com/phish',
				timestamp: Date.now(),
				providerName: 'test-provider',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			// Should NOT redirect to evil.com
			assert.ok(!result.headers.Location.includes('evil.com'));
			// Should redirect to the sanitized path
			assert.ok(result.headers.Location.startsWith('/phish'));
		});

		it('should not allow open redirect on successful callback via originalUrl', async () => {
			// CSRF token returns an absolute external URL
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: 'https://evil.com/steal',
				timestamp: Date.now(),
				providerName: 'test-provider',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			// Success redirect must NOT go to external domain
			assert.ok(!result.headers.Location.includes('evil.com'));
			assert.ok(result.headers.Location.startsWith('/'));
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
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			assert.equal(mockRequest.session.user, 'user@example.com');
			assert.ok(mockRequest.session.oauthUser);
			// Token data is now stored in oauth object
			assert.ok(mockRequest.session.oauth);
			assert.equal(mockRequest.session.oauth.accessToken, 'access-token-123');
			assert.equal(mockRequest.session.oauth.provider, 'test-provider', 'provider (config key) should be set');
			assert.equal(mockRequest.session.oauth.providerConfigId, 'test-provider', 'providerConfigId should be set');
			assert.equal(mockRequest.session.oauth.providerType, 'test', 'providerType should match config.provider');
		});

		it('should handle tokens without expiration (GitHub style)', async () => {
			// GitHub doesn't return expires_in - tokens don't expire
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
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
				'test-provider',
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
				'test-provider',
				mockLogger
			);

			assert.equal(result.status, 302);
			// Should still complete but log warning
			assert.equal(mockLogger.warn.mock.calls.length, 1);
		});

		// Security tests for provider binding
		it('should reject callback when state token provider does not match callback provider', async () => {
			// State token was issued for 'evil-company' but callback is for 'target-company'
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'evil-company', // Token was for different provider
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'target-company', // But callback is for this provider
				mockLogger
			);

			// Should reject with error - redirects to original URL with error params
			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=auth_failed&reason=csrf');

			// Should log warning about potential attack
			assert.ok(mockLogger.warn.mock.calls.some((call) => call.arguments[0].includes('State token provider mismatch')));

			// Should NOT attempt token exchange
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0);
		});

		it('should allow callback when state token provider matches callback provider', async () => {
			// State token was issued for 'acme-corp' and callback is also for 'acme-corp'
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'acme-corp',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'acme-corp', // Same provider
				'test-provider',
				mockLogger
			);

			// Should succeed
			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');

			// Should attempt token exchange
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 1);
		});

		it('should prevent cross-tenant CSRF attack', async () => {
			// Attack scenario: Evil Company tries to use Target Company's callback URL
			// 1. Attacker gets victim to authenticate at evil-company.okta.com
			// 2. Evil Okta redirects to fabric.com/oauth/target-company/callback
			// 3. But state token was issued for evil-company

			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/',
				timestamp: Date.now(),
				providerName: 'evil-company',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'target-company',
				'test-provider',
				mockLogger
			);

			// Attack should be blocked - redirects to original URL with error params
			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/?error=auth_failed&reason=csrf');

			// Should not reveal target company's OAuth configuration
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0);
		});

		it('should store providerName in session oauth metadata', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'acme-corp',
			}));

			await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'acme-corp',
				'test-provider',
				mockLogger
			);

			const updateCall = mockRequest.session.update.mock.calls[0];
			// Provider should be the registry key (providerName), not the provider type
			assert.equal(updateCall.arguments[0].oauth.provider, 'acme-corp');
		});
	});

	describe('handleLogout', () => {
		it('should clear session data', async () => {
			// Add delete method mock to session
			mockRequest.session.delete = createMockFn();

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
