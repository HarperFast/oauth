/**
 * Tests for OAuth Handlers
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
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
			redirectUri: 'http://localhost:9926/oauth/test/callback',
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
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			assert.equal(mockProvider.verifyCSRFToken.mock.calls.length, 1);
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 1);
			assert.equal(mockProvider.getUserInfo.mock.calls.length, 1);
			assert.equal(mockProvider.mapUserToHarper.mock.calls.length, 1);
		});

		it('should update session with user data', async () => {
			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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
				{ logger: mockLogger }
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

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'acme-corp', {
				logger: mockLogger,
			});

			const updateCall = mockRequest.session.update.mock.calls[0];
			// Provider should be the registry key (providerName), not the provider type
			assert.equal(updateCall.arguments[0].oauth.provider, 'acme-corp');
		});
	});

	describe('handleCallback — onLogin outcome gating (#174)', () => {
		const callback = () =>
			handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

		it('denied without redirect → standard error redirect, no session', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'denied' }));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=access_denied&reason=denied');
			assert.equal(mockRequest.session.update.mock.calls.length, 0, 'no session must be created');
		});

		it('denied with error → error string surfaced as reason', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'denied', error: 'not_provisioned' }));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=access_denied&reason=not_provisioned');
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('denied with relative redirect → 302 to it, no session', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'denied', redirect: '/access-denied' }));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/access-denied');
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('hook-provided absolute http(s) redirect passes through (trusted app code)', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({
				status: 'needs_confirmation',
				redirect: 'https://accounts.example.com/finish-setup',
			}));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, 'https://accounts.example.com/finish-setup');
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('hook-provided javascript: redirect is neutralized', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({
				status: 'denied',
				redirect: 'javascript:alert(1)',
			}));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/');
		});

		it('needs_confirmation with redirect → 302 to it, no session', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({
				status: 'needs_confirmation',
				redirect: '/onboarding',
			}));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/onboarding');
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('needs_confirmation missing redirect (JS hook bug) → error redirect fallback', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'needs_confirmation' }));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=access_denied&reason=confirmation_required');
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('status ok is stripped from session data, user honored', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'ok', user: 'internal-42', extra: 'kept' }));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			const sessionData = mockRequest.session.update.mock.calls[0].arguments[0];
			assert.equal(sessionData.user, 'internal-42');
			assert.equal(sessionData.extra, 'kept');
			assert.equal(sessionData.status, undefined, "flow-control 'ok' must not leak into the session");
		});

		it('unknown status value keeps legacy enrich behavior (merged, login proceeds) and warns', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'active', user: 'internal-42' }));

			const result = await callback();

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			const sessionData = mockRequest.session.update.mock.calls[0].arguments[0];
			assert.equal(sessionData.user, 'internal-42');
			assert.equal(sessionData.status, 'active', 'non-outcome status values are session data as before');
			assert.ok(
				mockLogger.warn.mock.calls.some((call) => call.arguments[0].includes("unrecognized status 'active'")),
				'a typo-guard warning must be logged'
			);
		});

		it('status ok does not warn', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'ok', user: 'internal-42' }));

			await callback();

			assert.ok(
				!mockLogger.warn.mock.calls.some((call) => String(call.arguments[0]).includes('unrecognized status')),
				'recognized statuses must not warn'
			);
		});
	});

	describe('handleCallback — MCP branch', () => {
		let originalDatabases;
		let storedAuthCodes;
		// Import lazily so the dist symbol load doesn't happen at file parse.
		let resetMCPAuthCodesTableCache;

		const MCP_STATE = {
			clientId: 'mcp-client-1',
			resource: 'https://app.example.com/mcp',
			codeChallenge: 'fake-challenge-32-chars-or-longer',
			codeChallengeMethod: 'S256',
			redirectUri: 'https://mcp-client.example.com/cb',
			scope: 'mcp:read',
			clientState: 'mcp-state-xyz',
		};

		const MCP_CONFIG = {
			issuer: 'https://as.example.com',
			enabled: true,
		};

		beforeEach(async () => {
			({ resetMCPAuthCodesTableCache } = await import('../../dist/lib/mcp/authCodeStore.js'));
			resetMCPAuthCodesTableCache();
			originalDatabases = global.databases;
			storedAuthCodes = new Map();
			global.databases = {
				oauth: {
					mcp_auth_codes: {
						get: async (id) => storedAuthCodes.get(id) ?? null,
						put: async (record) => {
							storedAuthCodes.set(record.code, record);
						},
						delete: async (id) => storedAuthCodes.delete(id),
					},
				},
			};
			// Replace verifyCSRFToken to return MCP state by default for this block.
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				timestamp: Date.now(),
				providerName: 'test-provider',
				mcp: { ...MCP_STATE },
			}));
		});

		// Restore global.databases in afterEach so a failing assertion mid-test
		// doesn't pollute later tests in this describe block.
		afterEach(() => {
			global.databases = originalDatabases;
		});

		it('on success, mints auth code and redirects to MCP client redirect_uri', async () => {
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			const url = new URL(result.headers.Location);
			assert.equal(url.origin + url.pathname, MCP_STATE.redirectUri);
			assert.ok(url.searchParams.get('code'));
			assert.equal(url.searchParams.get('state'), MCP_STATE.clientState);
			assert.equal(storedAuthCodes.size, 1);
		});

		it('includes iss on success redirect (RFC 9207, handler-level)', async () => {
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			const url = new URL(result.headers.Location);
			assert.equal(url.searchParams.get('iss'), MCP_CONFIG.issuer, 'iss must equal the configured issuer on success');
		});

		it('includes iss on error redirect (RFC 9207, handler-level mcpErrorRedirect)', async () => {
			mockTarget.get = createMockFn((key) => {
				const params = {
					state: 'csrf-token-123',
					error: 'access_denied',
					error_description: 'User denied authorization',
				};
				return params[key];
			});
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			const url = new URL(result.headers.Location);
			assert.equal(url.searchParams.get('iss'), MCP_CONFIG.issuer, 'iss must appear on MCP error redirects');
		});

		it('binds the auth code to onLogin-mapped user (hookData.user wins over OAuth username)', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ user: 'internal-user-id-42' }));
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			const [record] = storedAuthCodes.values();
			assert.equal(record.user, 'internal-user-id-42');
		});

		it('onLogin denied → access_denied to MCP client, no auth code minted (#174)', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({ status: 'denied', error: 'not_provisioned' }));
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			const url = new URL(result.headers.Location);
			assert.equal(url.origin + url.pathname, MCP_STATE.redirectUri);
			assert.equal(url.searchParams.get('error'), 'access_denied');
			assert.equal(url.searchParams.get('error_description'), 'not_provisioned');
			assert.equal(url.searchParams.get('state'), MCP_STATE.clientState);
			assert.ok(url.searchParams.get('iss'), 'iss required on MCP error redirects (RFC 9207)');
			assert.equal(storedAuthCodes.size, 0, 'no auth code must be minted');
		});

		it('onLogin needs_confirmation → access_denied to MCP client (interactive step not possible) (#174)', async () => {
			mockHookManager.callOnLogin = createMockFn(async () => ({
				status: 'needs_confirmation',
				redirect: '/onboarding',
			}));
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			const url = new URL(result.headers.Location);
			assert.equal(
				url.origin + url.pathname,
				MCP_STATE.redirectUri,
				'must fail cleanly to the MCP client, not follow the interactive redirect'
			);
			assert.equal(url.searchParams.get('error'), 'access_denied');
			assert.equal(storedAuthCodes.size, 0);
		});

		it('routes upstream IdP error to MCP client redirect_uri (not Harper postLoginRedirect)', async () => {
			mockTarget.get = createMockFn((key) => {
				const params = {
					state: 'csrf-token-123',
					error: 'access_denied',
					error_description: 'User denied authorization',
				};
				return params[key];
			});
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			const url = new URL(result.headers.Location);
			assert.equal(url.origin + url.pathname, MCP_STATE.redirectUri);
			assert.equal(url.searchParams.get('error'), 'access_denied');
			assert.equal(url.searchParams.get('state'), MCP_STATE.clientState);
		});

		it('routes cross-provider state mismatch to MCP redirect_uri', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				timestamp: Date.now(),
				providerName: 'other-provider', // mismatch
				mcp: { ...MCP_STATE },
			}));
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			const url = new URL(result.headers.Location);
			assert.equal(url.origin + url.pathname, MCP_STATE.redirectUri);
			assert.equal(url.searchParams.get('error'), 'invalid_request');
		});

		it('does NOT include upstream IdP token in MCP redirect URL', async () => {
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			const location = result.headers.Location;
			for (const banned of ['access_token', 'refresh_token', 'id_token', 'token_type', 'access-token-123']) {
				assert.ok(!location.includes(banned), `${banned} must not appear in MCP redirect URL`);
			}
		});

		it('does NOT create a Harper session on the MCP branch (independent lifecycle)', async () => {
			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				mcpConfig: MCP_CONFIG,
				logger: mockLogger,
			});
			// session.update must not have been called for the MCP branch
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('onLogin fires for MCP-initiated auth (bridged authorize/callback flow)', async () => {
			// Regression guard: the onLogin hook must fire on the MCP branch exactly
			// as it does on the human-session branch — it runs before the branch
			// decision so user-provisioning hooks work for MCP users too.
			const onLoginMock = createMockFn(async () => ({}));
			const trackingHookManager = {
				...mockHookManager,
				callOnLogin: onLoginMock,
			};

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, trackingHookManager, 'test-provider', {
				mcpConfig: MCP_CONFIG,
				logger: mockLogger,
			});

			assert.equal(onLoginMock.mock.calls.length, 1, 'callOnLogin fired exactly once on the MCP path');
			// The hook receives the mapped Harper user, the upstream token response, the session, the request, and the provider name.
			const [oauthUser, tokenResponse, , , providerName] = onLoginMock.mock.calls[0].arguments;
			assert.ok(oauthUser.username, 'user object forwarded to onLogin');
			assert.ok(tokenResponse, 'token response forwarded to onLogin');
			assert.equal(providerName, 'test-provider');
		});

		it('rejects a CIMD confirm token presented as upstream state (token purpose enforcement)', async () => {
			// Attack: feed the interstitial's confirm_token to the IdP as `state`;
			// it carries providerName + mcp and would otherwise mint an auth code
			// without /confirm ever running.
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				timestamp: Date.now(),
				providerName: 'test-provider',
				mcp: { ...MCP_STATE },
				_confirm: true,
			}));
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ mcpConfig: MCP_CONFIG, logger: mockLogger }
			);
			assert.equal(result.status, 302);
			assert.match(result.headers.Location, /error=session_expired/, 'treated exactly like an invalid token');
			assert.ok(!result.headers.Location.includes('code='), 'no auth code minted');
			assert.equal(storedAuthCodes.size, 0, 'no auth code persisted');
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0, 'upstream code never exchanged');
		});

		describe('CIMD consent browser binding', () => {
			const NONCE = 'callback-consent-nonce';
			const FLOW_ID = 'cbflow';
			let hashConsentNonce, buildConsentCookie, cookieHeader;

			beforeEach(async () => {
				({ hashConsentNonce, buildConsentCookie } = await import('../../dist/lib/mcp/consentBinding.js'));
				// The per-flow Set-Cookie value minus its attributes → a Cookie header pair.
				cookieHeader = buildConsentCookie(FLOW_ID, NONCE).split(';')[0];
				mockProvider.verifyCSRFToken = createMockFn(async () => ({
					timestamp: Date.now(),
					providerName: 'test-provider',
					mcp: { ...MCP_STATE, browserNonceHash: hashConsentNonce(NONCE), consentFlowId: FLOW_ID },
				}));
			});

			it('completes when the callback arrives with the consent cookie', async () => {
				mockRequest.headers.cookie = cookieHeader;
				const result = await handleCallback(
					mockRequest,
					mockTarget,
					mockProvider,
					mockConfig,
					mockHookManager,
					'test-provider',
					{ mcpConfig: MCP_CONFIG, logger: mockLogger }
				);
				assert.equal(result.status, 302);
				const url = new URL(result.headers.Location);
				assert.ok(url.searchParams.get('code'), 'auth code minted for the bound browser');
			});

			it('rejects when the consent cookie is missing — victim browser never approved', async () => {
				// Attack: the malicious client self-approves the interstitial, then
				// sends the victim the upstream IdP URL. The victim's browser has no
				// (or a different) consent cookie, so no code may be minted.
				delete mockRequest.headers.cookie;
				const result = await handleCallback(
					mockRequest,
					mockTarget,
					mockProvider,
					mockConfig,
					mockHookManager,
					'test-provider',
					{ mcpConfig: MCP_CONFIG, logger: mockLogger }
				);
				assert.equal(result.status, 302);
				const url = new URL(result.headers.Location);
				assert.equal(url.origin + url.pathname, MCP_STATE.redirectUri, 'error routed to the client redirect_uri');
				assert.equal(url.searchParams.get('error'), 'access_denied');
				assert.equal(url.searchParams.get('code'), null, 'no auth code issued');
				assert.equal(storedAuthCodes.size, 0);
			});

			it('rejects when the consent cookie does not match the bound hash', async () => {
				mockRequest.headers.cookie = buildConsentCookie(FLOW_ID, 'some-other-browser-nonce').split(';')[0];
				const result = await handleCallback(
					mockRequest,
					mockTarget,
					mockProvider,
					mockConfig,
					mockHookManager,
					'test-provider',
					{ mcpConfig: MCP_CONFIG, logger: mockLogger }
				);
				const url = new URL(result.headers.Location);
				assert.equal(url.searchParams.get('error'), 'access_denied');
				assert.equal(storedAuthCodes.size, 0);
			});

			it('DCR flows (no browserNonceHash) are unaffected', async () => {
				mockProvider.verifyCSRFToken = createMockFn(async () => ({
					timestamp: Date.now(),
					providerName: 'test-provider',
					mcp: { ...MCP_STATE },
				}));
				delete mockRequest.headers.cookie;
				const result = await handleCallback(
					mockRequest,
					mockTarget,
					mockProvider,
					mockConfig,
					mockHookManager,
					'test-provider',
					{ mcpConfig: MCP_CONFIG, logger: mockLogger }
				);
				const url = new URL(result.headers.Location);
				assert.ok(url.searchParams.get('code'), 'DCR callback mints a code without a consent cookie');
			});
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
	describe('handleCallback — state↔session binding (#181)', () => {
		it('rejects a callback processed in a different session than the one that initiated', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider',
				sessionId: 'attacker-session-999',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard?error=auth_failed&reason=csrf');
			// Rejected before any upstream call or session write.
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('allows a callback in the same session that initiated the flow', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider',
				sessionId: 'session-123',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 1);
		});

		it('tolerates state tokens without a sessionId (pre-binding tokens)', async () => {
			// The default mock tokenData carries no sessionId — enforcement is
			// conditional on presence so in-flight logins across a deploy survive.
			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
		});

		it('rejects a foreign-session MCP callback with an MCP error redirect', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				timestamp: Date.now(),
				providerName: 'test-provider',
				sessionId: 'attacker-session-999',
				mcp: {
					clientId: 'mcp-client-1',
					redirectUri: 'https://mcp-client.example.com/cb',
					clientState: 'mcp-state-xyz',
				},
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.ok(result.headers.Location.startsWith('https://mcp-client.example.com/cb'));
			assert.ok(result.headers.Location.includes('error=access_denied'));
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0);
		});
	});
});
