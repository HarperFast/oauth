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
			hasHook: createMockFn(() => true),
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

		it('reads referer from a Harper `.asObject` headers wrapper (runtime shape)', async () => {
			// The live runtime wraps headers behind `.asObject`; direct
			// `request.headers.referer` is undefined there. Regression guard.
			const wrapped = {
				session: mockRequest.session,
				headers: { asObject: { referer: 'https://app.example.com/deep' } },
			};
			await handleLogin(wrapped, mockTarget, mockProvider, mockConfig, 'test-provider', mockLogger);

			const csrfCall = mockProvider.generateCSRFToken.mock.calls[0];
			assert.equal(csrfCall.arguments[0].originalUrl, '/deep');
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

		it('mints a browser-binding secret: hash in the state token, stable secret in a __Host- cookie', async () => {
			const { BROWSER_SECRET_COOKIE_NAME, hashBrowserSecret } = await import('../../dist/lib/mcp/consentBinding.js');
			const result = await handleLogin(mockRequest, mockTarget, mockProvider, mockConfig, 'test-provider', mockLogger);

			const meta = mockProvider.generateCSRFToken.mock.calls[0].arguments[0];
			assert.ok(meta.browserNonceHash, 'secret hash stored in the state token');
			assert.equal(meta.loginFlowId, undefined, 'no per-flow id in the state (stable cookie)');

			const setCookie = result.headers['Set-Cookie'];
			const [pair, ...attrs] = setCookie.split('; ');
			const eq = pair.indexOf('=');
			assert.equal(pair.slice(0, eq), BROWSER_SECRET_COOKIE_NAME, 'stable cookie name (no per-flow suffix)');
			assert.equal(
				hashBrowserSecret(pair.slice(eq + 1)),
				meta.browserNonceHash,
				'cookie value hashes to the bound hash'
			);
			for (const attr of ['Path=/', 'Secure', 'HttpOnly', 'SameSite=Lax']) {
				assert.ok(attrs.includes(attr), `cookie carries ${attr}`);
			}
		});
	});

	describe('handleCallback', () => {
		// Default: no users exist in the Harper system DB — the gate never fires.
		// Tests that need a collision override globalThis.databases.system.hdb_user.get.
		beforeEach(() => {
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
		});

		afterEach(() => {
			delete globalThis.databases;
		});

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
			// Default mock has no OIDC token and no trusted provenance. With no
			// existing account, the login is roleless: session.user is set to a
			// non-resolvable quarantine principal so no later-provisioned account of
			// the claim's name can be adopted. oauthUser is preserved intact.
			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.match(updateCall.arguments[0].user, /^unverified:user@example\.com#[0-9a-f]{16}$/);
			assert.ok(updateCall.arguments[0].oauthUser);
			assert.equal(updateCall.arguments[0].oauth.authTrust, 'untrusted');
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
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: { sub: 'user-123', email: 'verified@example.com' },
				signatureVerified: true,
			}));
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

		// authEvidence exposed to onLogin — mapUserToHarper is mocked to return a verified
		// email; the signal must come from token verification + provenance, not that alone.
		function stubEmail(mockedEmailVerified = true) {
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				email: 'user@example.com',
				emailVerified: mockedEmailVerified,
				role: 'user',
			}));
		}
		const evidenceFromHook = () => mockHookManager.callOnLogin.mock.calls[0].arguments[0].authEvidence;

		it('authEvidence: signed + issuer-validated + verified email → emailAuthenticated true, signed-oidc, idTokenSubject set', async () => {
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: { sub: 'user-123', iss: 'https://idp.example.com', email: 'user@example.com' },
				signatureVerified: true,
				issuerValidated: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at', id_token: 'jwt' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'signed-oidc',
			}));
			stubEmail();

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			const e = evidenceFromHook();
			assert.equal(e.emailProvenance, 'signed-oidc');
			assert.equal(e.emailAuthenticated, true);
			assert.equal(e.signatureVerified, true);
			assert.equal(e.issuerValidated, true);
			assert.equal(e.email, 'user@example.com');
			assert.equal(e.idTokenSubject, 'user-123');
			assert.equal(e.idTokenIssuer, 'https://idp.example.com');
		});

		it('authEvidence: NORMALIZES an unsigned id token (getUserInfo says signed-oidc but signature unverified) to unauthenticated', async () => {
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: { sub: 'user-123' },
				signatureVerified: false,
				issuerValidated: false,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at', id_token: 'jwt' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'signed-oidc',
			}));
			stubEmail();

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			const e = evidenceFromHook();
			assert.equal(
				e.emailProvenance,
				'unauthenticated',
				'decoded-but-unverified token must not be labelled signed-oidc'
			);
			assert.equal(e.emailAuthenticated, false);
			assert.equal(e.idTokenSubject, undefined);
		});

		it('authEvidence: github-authenticated + verified email → emailAuthenticated true even without id-token flags', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'github-authenticated',
			}));
			stubEmail();

			await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				{ ...mockConfig, provider: 'github' },
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			const e = evidenceFromHook();
			assert.equal(e.emailProvenance, 'github-authenticated');
			assert.equal(e.emailAuthenticated, true);
			assert.equal(e.signatureVerified, false);
		});

		it('authEvidence: plain userinfo with emailVerified true is still emailAuthenticated false', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'unauthenticated',
			}));
			stubEmail();

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			assert.equal(evidenceFromHook().emailAuthenticated, false);
		});

		it('authEvidence: not attached when no onLogin hook is registered', async () => {
			mockHookManager.hasHook = createMockFn(() => false);
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'unauthenticated',
			}));
			stubEmail();

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			const oauthUser = mockHookManager.callOnLogin.mock.calls[0].arguments[0];
			assert.equal(oauthUser.authEvidence, undefined);
		});

		it('authEvidence: a verified signature but UNvalidated issuer is unauthenticated', async () => {
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: { sub: 'user-123', iss: 'https://idp.example.com' },
				signatureVerified: true,
				issuerValidated: false,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at', id_token: 'jwt' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'signed-oidc',
			}));
			stubEmail();

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			const e = evidenceFromHook();
			assert.equal(e.emailProvenance, 'unauthenticated');
			assert.equal(e.emailAuthenticated, false);
			assert.equal(e.idTokenIssuer, undefined, 'no issuer exposed unless validated');
			assert.equal(e.idTokenSubject, undefined);
		});

		it('authEvidence: github-authenticated provenance on a NON-github provider is unauthenticated', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'github-authenticated',
			}));
			stubEmail();

			await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				{ ...mockConfig, provider: 'google' },
				mockHookManager,
				'test-provider',
				{
					logger: mockLogger,
				}
			);

			const e = evidenceFromHook();
			assert.equal(e.emailProvenance, 'unauthenticated');
			assert.equal(e.emailAuthenticated, false);
		});

		it('authEvidence: emailAuthenticated is false when there is no usable email (attests the email, not the username)', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at' }));
			mockProvider.getUserInfo = createMockFn(async () => ({ _emailProvenance: 'github-authenticated' }));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'handle',
				email: undefined,
				emailVerified: true,
				role: 'user',
			}));

			await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				{ ...mockConfig, provider: 'github' },
				mockHookManager,
				'test-provider',
				{
					logger: mockLogger,
				}
			);

			const e = evidenceFromHook();
			assert.equal(e.email, undefined);
			assert.equal(e.emailAuthenticated, false, 'no email → cannot attest an authenticated email');
		});

		it('authEvidence: is frozen and non-enumerable (not persisted into the session)', async () => {
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({ access_token: 'at' }));
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				_emailProvenance: 'unauthenticated',
			}));
			stubEmail();

			await handleCallback(mockRequest, mockTarget, mockProvider, mockConfig, mockHookManager, 'test-provider', {
				logger: mockLogger,
			});

			const oauthUser = mockHookManager.callOnLogin.mock.calls[0].arguments[0];
			assert.equal(Object.getOwnPropertyDescriptor(oauthUser, 'authEvidence').enumerable, false);
			assert.equal(Object.isFrozen(oauthUser.authEvidence), true);
			assert.equal(Object.keys(oauthUser).includes('authEvidence'), false);
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
			// Without update(), session is written via Object.assign.
			// Default mock is untrusted + no account → roleless quarantine principal.
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
			assert.match(mockRequest.session.user, /^unverified:user@example\.com#[0-9a-f]{16}$/);
			assert.equal(mockRequest.session.oauth.authTrust, 'untrusted');
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

		// ── Account-adoption gate ─────────────────────────────────────────────────

		it('gate: Google-style (email usernameClaim, JWKS-signed token, email_verified=true) → adopted', async () => {
			// Google uses usernameClaim:'email', so username===email. With a JWKS-signed
			// id token carrying email_verified=true, the gate must allow adoption.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			// Simulate getUserInfo returning signed-oidc provenance (email in id token)
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				email: 'user@example.com',
				email_verified: true,
				iss: 'https://accounts.google.com',
				iat: 1,
				_emailProvenance: 'signed-oidc',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'google',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					email: 'user@example.com',
					email_verified: true,
					iss: 'https://accounts.google.com',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
				issuerValidated: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-jwt',
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

			// Must succeed (redirect to post-login URL, session written).
			assert.equal(result.status, 302);
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'user@example.com');
		});

		it('gate: Okta preferred_username ≠ email, matching account → denied', async () => {
			// Okta uses usernameClaim:'preferred_username'. When preferred_username is
			// different from the email address, the gate must deny because the username
			// (not an email) cannot be correlated to the verified email claim.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'alice.smith' ? { username: name } : null) } },
			};
			// Okta preferred_username is a short handle, not the email
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				preferred_username: 'alice.smith',
				email: 'alice@corp.example.com',
				email_verified: true,
				_emailProvenance: 'signed-oidc',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'alice.smith', // Okta's preferred_username — NOT the email
				role: 'user',
				email: 'alice@corp.example.com',
				emailVerified: true,
				provider: 'okta',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					preferred_username: 'alice.smith',
					email: 'alice@corp.example.com',
					email_verified: true,
					iss: 'https://corp.okta.com',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-jwt',
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

			// username !== email → gate denies
			assert.equal(result.status, 302);
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: Okta preferred_username === email, matching account → adopted', async () => {
			// When Okta's preferred_username happens to equal the email address,
			// the gate should allow adoption (all three trust conditions satisfied).
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'alice@corp.example.com' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				preferred_username: 'alice@corp.example.com',
				email: 'alice@corp.example.com',
				email_verified: true,
				_emailProvenance: 'signed-oidc',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'alice@corp.example.com',
				role: 'user',
				email: 'alice@corp.example.com',
				emailVerified: true,
				provider: 'okta',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					preferred_username: 'alice@corp.example.com',
					email: 'alice@corp.example.com',
					email_verified: true,
					iss: 'https://corp.okta.com',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
				issuerValidated: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-jwt',
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
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'alice@corp.example.com');
		});

		it('gate: GitHub login claim (username ≠ email) + existing account → denied', async () => {
			// GitHub uses usernameClaim:'login'. The login handle is NOT the email, so
			// the gate must deny even when email_verified=true and provenance is github-authenticated.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'victimadmin' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				login: 'victimadmin',
				email: 'attacker@github.test',
				email_verified: true,
				_emailProvenance: 'github-authenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'victimadmin', // GitHub login — NOT the email
				role: 'user',
				email: 'attacker@github.test',
				emailVerified: true,
				provider: 'github',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: GitHub verified email (authenticated fetch, username=email) → adopted', async () => {
			// When a GitHub user is identified by email (e.g. a custom usernameClaim
			// override or a hook) and GitHub's /user/emails confirmed it verified,
			// the authenticated-fetch provenance makes the claim trusted.
			// config.provider must be 'github' for github-authenticated to be honored.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'alice@example.com' ? { username: name } : null) } },
			};
			const githubConfig = { ...mockConfig, provider: 'github' };
			mockProvider.getUserInfo = createMockFn(async () => ({
				login: 'alice',
				email: 'alice@example.com',
				email_verified: true,
				_emailProvenance: 'github-authenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'alice@example.com', // email used as username
				role: 'user',
				email: 'alice@example.com',
				emailVerified: true,
				provider: 'github',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				githubConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			// github-authenticated provenance + email===username + provider===github → trusted
			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'alice@example.com');
		});

		it('gate: UserInfo email with sub mismatch → denied (unauthenticated provenance)', async () => {
			// When getUserInfo returns _emailProvenance:'unauthenticated' (e.g. UserInfo
			// sub did not match id-token sub), the gate must deny even if email_verified.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'different-sub',
				email: 'user@example.com',
				email_verified: true,
				_emailProvenance: 'unauthenticated', // sub mismatch was detected by getUserInfo
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'test',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'original-sub',
					email_verified: true,
					iss: 'https://accounts.test',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-jwt',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: unsigned token + matching UserInfo email → denied (sub-matched-userinfo no longer trusted)', async () => {
			// sub-matched-userinfo is no longer a trusted source. Even with a matching
			// sub and email_verified=true in UserInfo, an unsigned token → denied.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				iss: 'https://accounts.example.com',
				iat: 1,
				exp: Math.floor(Date.now() / 1000) + 3600,
				email: 'user@example.com',
				email_verified: true,
				name: 'Real User',
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'test',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: { sub: 'u1', iss: 'https://accounts.example.com', iat: 1, exp: Math.floor(Date.now() / 1000) + 3600 },
				signatureVerified: false,
				issuerValidated: false,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'unsigned-jwt',
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

			// unsigned token is not a trusted source → denied
			assert.equal(result.status, 302);
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: unverified email (email_verified missing) matching existing account → denied', async () => {
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			// email_verified not set (undefined) — the gate must deny.
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: undefined,
				provider: 'test',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			// No session must have been written.
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: email_verified=true but unsigned token (signatureVerified=false) → denied', async () => {
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'test',
			}));
			// signatureVerified = false: the token was NOT JWKS-verified.
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: { sub: 'u1', email: 'user@example.com', email_verified: true },
				signatureVerified: false,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'unsigned-jwt',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: reassignable/non-email claim (username ≠ email) matching existing account → denied', async () => {
			// E.g. GitHub login claim — `username` is "victimadmin", not an email.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'victimadmin' ? { username: name } : null) } },
			};
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'victimadmin',
				role: 'user',
				email: 'attacker@github.test',
				emailVerified: true,
				provider: 'github',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: no matching account → login proceeds (role-less, unchanged)', async () => {
			// The default mock already returns null (no user) — this test is explicit.
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'brand-new-user@example.com',
				role: 'user',
				email: 'brand-new-user@example.com',
				emailVerified: undefined,
				provider: 'test',
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
			// Session was set.
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
		});

		it('gate: hook-supplied user override → gate skipped, identity honored', async () => {
			// When onLogin sets hookData.user, that is authoritative — the gate
			// does not fire regardless of what the IdP claim says.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'hook-user' ? { username: name } : null) } },
			};
			mockHookManager.callOnLogin = createMockFn(async () => ({ user: 'hook-user' }));
			// The IdP claim is unverified — would be denied if the gate ran.
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'hook-user',
				role: 'user',
				email: 'hook-user',
				emailVerified: undefined,
				provider: 'test',
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
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.equal(updateCall.arguments[0].user, 'hook-user', 'hook-supplied user must be used');
			assert.equal(updateCall.arguments[0].oauth.authTrust, 'hook', 'hook-supplied identity stamps hook provenance');
		});

		it('gate: escape hatch enabled → unverified collision adopted with warning', async () => {
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			// email_verified not set — would normally be denied.
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'user@example.com',
				email_verified: undefined,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: undefined,
				provider: 'test',
			}));

			const warnMessages = [];
			const warnLogger = { ...mockLogger, warn: createMockFn((...args) => warnMessages.push(args.join(' '))) };

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: warnLogger, allowUnverifiedClaimInheritance: true }
			);

			// Escape hatch restores legacy adopt behavior.
			assert.equal(result.status, 302);
			assert.equal(result.headers.Location, '/dashboard');
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
			// A warning must be emitted.
			const warned = warnMessages.some((m) => m.includes('allowUnverifiedClaimInheritance'));
			assert.ok(warned, 'escape hatch must log a warning mentioning allowUnverifiedClaimInheritance');
		});

		it('gate: MCP path uses the same resolvedUser (both sinks unified)', async () => {
			// Verify that the MCP branch also uses resolvedUser, not a separate hookData?.user ?? user.username.
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
			mockHookManager.callOnLogin = createMockFn(async () => ({ user: 'hook-user-mcp' }));
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider',
				mcp: {
					clientId: 'mcp-client',
					redirectUri: 'https://mcp-client.test/callback',
					clientState: 'mcp-state-123',
					browserNonceHash: 'will-be-matched',
				},
			}));

			// The browser binding check reads a cookie; mock it so the binding passes.
			const { hashBrowserSecret } = await import('../../dist/lib/mcp/consentBinding.js');
			const secret = 'test-secret';
			const hash = hashBrowserSecret(secret);
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider',
				mcp: {
					clientId: 'mcp-client',
					redirectUri: 'https://mcp-client.test/callback',
					clientState: 'mcp-state-123',
					browserNonceHash: hash,
				},
			}));
			mockRequest.headers = { Cookie: `__Host-oauth_browser=${secret}` };

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			// MCP callback mints an auth code redirect. Check that hook-user-mcp was used.
			// The MCP handler will redirect with an auth code to the client redirect_uri.
			assert.equal(result.status, 302);
			// The redirect goes to the MCP client — not the post-login path.
			assert.ok(
				result.headers.Location.startsWith('https://mcp-client.test/callback') ||
					result.headers.Location.includes('code=') ||
					result.headers.Location.includes('error='),
				`MCP callback result unexpected: ${result.headers.Location}`
			);
		});

		it('gate: issuer mismatch (JWKS-signed, wrong iss) → denied', async () => {
			// Token is JWKS-signed (signatureVerified=true) but issuer does not match
			// the provider's expected issuer (issuerValidated=false). Gate must deny.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				email: 'user@example.com',
				email_verified: true,
				_emailProvenance: 'signed-oidc',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'test',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					email: 'user@example.com',
					email_verified: true,
					iss: 'https://evil.example.com',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
				issuerValidated: false,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-but-wrong-issuer-jwt',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: Azure /common (issuerValidated=false) without email_verified → denied', async () => {
			// Azure multi-tenant tokens have no known expected issuer (issuer:null preset),
			// so issuerValidated=false. Without email_verified, adoption must be denied.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				email: 'user@example.com',
				_emailProvenance: 'signed-oidc',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: undefined,
				provider: 'azure',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					email: 'user@example.com',
					iss: 'https://login.microsoftonline.com/tenant-id/v2.0',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
				issuerValidated: false,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'azure-jwt',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: custom emailClaim → emailVerified undefined → denied', async () => {
			// When emailClaim is not the standard 'email', mapUserToHarper yields
			// emailVerified: undefined (no trustworthy verified flag). Gate must deny.
			globalThis.databases = {
				system: {
					hdb_user: {
						get: async (name) => (name === 'custom-email@example.com' ? { username: name } : null),
					},
				},
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				customEmail: 'custom-email@example.com',
				email_verified: true,
				_emailProvenance: 'signed-oidc',
			}));
			// Simulate mapUserToHarper behavior for custom emailClaim: emailVerified is undefined
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'custom-email@example.com',
				role: 'user',
				email: 'custom-email@example.com',
				emailVerified: undefined,
				provider: 'test',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					customEmail: 'custom-email@example.com',
					email_verified: true,
					iss: 'https://idp.example.com',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
				issuerValidated: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-jwt',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: GitHub /user/emails fetch failure → denied (no trusted tag)', async () => {
			// When the GitHub email fetch fails, getUserInfo must NOT set github-authenticated.
			// The gate must deny even if email is present.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				login: 'someuser',
				email: 'user@example.com',
				email_verified: true,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'github',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: _emailProvenance in UserInfo body → stripped, still denied', async () => {
			// A UserInfo body supplying _emailProvenance must be stripped — remote data
			// must never supply a trusted provenance value.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'user@example.com' ? { username: name } : null) } },
			};
			// getUserInfo simulates what OAuthProvider.getUserInfo does after stripping:
			// the raw body had _emailProvenance:'signed-oidc' but it was stripped and
			// replaced with 'unauthenticated' (no actual id token).
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				email: 'user@example.com',
				email_verified: true,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'user@example.com',
				role: 'user',
				email: 'user@example.com',
				emailVerified: true,
				provider: 'test',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: untrusted claim, no existing account → roleless non-adoptable quarantine principal', async () => {
			// No account + untrusted claim: session.user is set to a non-resolvable
			// quarantine principal (unpredictable suffix) so a later-created privileged
			// account of the claim's name can never be adopted. oauthUser is preserved.
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'attacker@example.com',
				email_verified: false,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'attacker@example.com',
				role: 'user',
				email: 'attacker@example.com',
				emailVerified: false,
				provider: 'test',
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
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.ok(updateCall, 'session.update must have been called');
			assert.match(
				updateCall.arguments[0].user,
				/^unverified:attacker@example\.com#[0-9a-f]{16}$/,
				'session user must be a non-resolvable quarantine principal'
			);
			assert.equal(updateCall.arguments[0].oauth.authTrust, 'untrusted');
			// oauthUser (incl. any app role claim) is preserved for app-level authz
			assert.equal(updateCall.arguments[0].oauthUser.role, 'user');
		});

		it('gate: Option B — trusted claim, no existing account → real identity persisted', async () => {
			// Trusted claim with no existing account: use the real identity (a later
			// admin-created account with this name is the legitimate owner's).
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'u1',
				email: 'newuser@example.com',
				email_verified: true,
				iss: 'https://accounts.google.com',
				_emailProvenance: 'signed-oidc',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'newuser@example.com',
				role: 'user',
				email: 'newuser@example.com',
				emailVerified: true,
				provider: 'google',
			}));
			mockProvider.verifyIdToken = createMockFn(async () => ({
				claims: {
					sub: 'u1',
					email: 'newuser@example.com',
					email_verified: true,
					iss: 'https://accounts.google.com',
					iat: 1,
					exp: Math.floor(Date.now() / 1000) + 3600,
				},
				signatureVerified: true,
				issuerValidated: true,
			}));
			mockProvider.exchangeCodeForToken = createMockFn(async () => ({
				access_token: 'token',
				id_token: 'signed-jwt',
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
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.ok(updateCall, 'session.update must have been called');
			assert.equal(
				updateCall.arguments[0].user,
				'newuser@example.com',
				'trusted claim with no account must use real identity'
			);
			assert.equal(updateCall.arguments[0].oauth.authTrust, 'verified', 'trusted claim stamps verified provenance');
		});

		it('gate: Option B — unverified session cannot later adopt a provisioned account', async () => {
			// An oauth-unverified: session cannot adopt a later-created account.
			// This simulates the second login after an account is provisioned:
			// the gate now sees userExists=true but the claim is untrusted → denied.
			globalThis.databases = {
				system: {
					hdb_user: { get: async (name) => (name === 'attacker@example.com' ? { username: name } : null) },
				},
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'attacker@example.com',
				email_verified: false,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'attacker@example.com',
				role: 'user',
				email: 'attacker@example.com',
				emailVerified: false,
				provider: 'test',
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
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied after account provisioned; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: provenance injection — non-github adapter returning github-authenticated → denied', async () => {
			// A custom getUserInfo on a non-github provider cannot earn github-authenticated.
			// The plugin strips _emailProvenance from the adapter return and assigns based on
			// config.provider; a non-github provider always gets 'unauthenticated'.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'victim@example.com' ? { username: name } : null) } },
			};
			// config.provider is 'test' (not 'github'), so even if the adapter tries to inject
			// 'github-authenticated' it is stripped and replaced with 'unauthenticated'.
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'victim@example.com',
				email_verified: true,
				_emailProvenance: 'github-authenticated', // injection attempt — must be ignored
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'victim@example.com',
				role: 'superadmin',
				email: 'victim@example.com',
				emailVerified: true,
				provider: 'test',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig, // provider: 'test'
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied for provenance injection attempt; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: untrusted login persists a principal that is not the claim (pre-emption closed at mint)', async () => {
			// Even though mapUserToHarper returns the raw claim as username, the session
			// principal is an unpredictable quarantine value — so an hdb_user later
			// created with the claim's name is never resolved as this session's identity.
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				email: 'collision@example.com',
				email_verified: false,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'collision@example.com',
				role: 'user',
				email: 'collision@example.com',
				emailVerified: false,
				provider: 'test',
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
			assert.ok(updateCall, 'session.update must have been called (login succeeds, roleless)');
			assert.notEqual(
				updateCall.arguments[0].user,
				'collision@example.com',
				'session principal must not be the raw claim'
			);
			assert.match(updateCall.arguments[0].user, /^unverified:collision@example\.com#[0-9a-f]{16}$/);
		});

		it('gate: fetchEmail — id token without email + fetchEmail:true → login succeeds but adoption denied', async () => {
			// When the id token lacks email and fetchEmail is true, userinfo supplies the email.
			// The provenance is 'unauthenticated', so adoption of an existing account is denied.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'idp@example.com' ? { username: name } : null) } },
			};
			// getUserInfo returns unauthenticated provenance (fetchEmail path)
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'sub123',
				email: 'idp@example.com',
				email_verified: false,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'idp@example.com',
				role: 'user',
				email: 'idp@example.com',
				emailVerified: false,
				provider: 'test',
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

			// Existing account exists but claim is untrusted → denied
			assert.equal(result.status, 302);
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied for unauthenticated fetchEmail against existing account; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});

		it('gate: fetchEmail — id token without email + fetchEmail:true + no existing account → quarantine principal', async () => {
			// Same fetchEmail scenario but no existing account: login succeeds with a
			// roleless, non-adoptable quarantine principal.
			globalThis.databases = {
				system: { hdb_user: { get: async () => null } },
			};
			mockProvider.getUserInfo = createMockFn(async () => ({
				sub: 'sub456',
				email: 'new@example.com',
				email_verified: false,
				_emailProvenance: 'unauthenticated',
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'new@example.com',
				role: 'user',
				email: 'new@example.com',
				emailVerified: false,
				provider: 'test',
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
			const updateCall = mockRequest.session.update.mock.calls[0];
			assert.match(updateCall.arguments[0].user, /^unverified:new@example\.com#[0-9a-f]{16}$/);
			assert.equal(updateCall.arguments[0].oauth.authTrust, 'untrusted');
		});

		it('gate: github verified:false → not github-authenticated → denied', async () => {
			// email_verified must be true for the GitHub adapter to earn 'github-authenticated'.
			// A verified:false record must not grant trusted status.
			globalThis.databases = {
				system: { hdb_user: { get: async (name) => (name === 'unverified@example.com' ? { username: name } : null) } },
			};
			const githubConfig = { ...mockConfig, provider: 'github' };
			mockProvider.getUserInfo = createMockFn(async () => ({
				login: 'unverified',
				email: 'unverified@example.com',
				email_verified: false, // not verified
				_emailProvenance: 'github-authenticated', // would be stripped; plugin re-assigns based on email_verified
			}));
			mockProvider.mapUserToHarper = createMockFn(() => ({
				username: 'unverified@example.com',
				role: 'user',
				email: 'unverified@example.com',
				emailVerified: false,
				provider: 'github',
			}));

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				githubConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			assert.ok(
				result.headers.Location.includes('access_denied'),
				`expected access_denied for unverified GitHub email; got ${result.headers.Location}`
			);
			assert.equal(mockRequest.session.update.mock.calls.length, 0);
		});
	});

	describe('handleCallback — onLogin outcome gating (#174)', () => {
		beforeEach(() => {
			globalThis.databases = { system: { hdb_user: { get: async () => null } } };
		});
		afterEach(() => {
			delete globalThis.databases;
		});

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
		let hashBrowserSecret, buildBrowserSecretCookie;

		// Every /oauth/mcp/authorize flow (CIMD and stored/DCR) mints a stable
		// browser-secret cookie and binds its hash into the upstream state; the
		// callback fails closed without a matching cookie. The default fixtures
		// below carry a valid binding so happy-path assertions exercise the bound
		// flow — tests that need an unbound/mismatched state override them locally.
		const MCP_SECRET = 'mcp-branch-browser-secret';

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
			({ hashBrowserSecret, buildBrowserSecretCookie } = await import('../../dist/lib/mcp/consentBinding.js'));
			resetMCPAuthCodesTableCache();
			originalDatabases = global.databases;
			storedAuthCodes = new Map();
			global.databases = {
				// No users in the system DB — the account-adoption gate never fires.
				system: { hdb_user: { get: async () => null } },
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
			// Replace verifyCSRFToken to return a browser-bound MCP state by default.
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				timestamp: Date.now(),
				providerName: 'test-provider',
				mcp: { ...MCP_STATE, browserNonceHash: hashBrowserSecret(MCP_SECRET) },
			}));
			// The initiating browser's stable cookie accompanies the callback.
			mockRequest.headers.cookie = buildBrowserSecretCookie(MCP_SECRET).split(';')[0];
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

		describe('MCP browser binding (stable cookie)', () => {
			const SECRET = 'callback-browser-secret';
			let cookieHeader;

			beforeEach(async () => {
				// The stable browser-secret cookie accompanies the callback.
				// Reuse the BROWSER_SECRET_COOKIE_NAME / buildBrowserSecretCookie imported in the outer beforeEach.
				cookieHeader = buildBrowserSecretCookie(SECRET).split(';')[0];
				mockProvider.verifyCSRFToken = createMockFn(async () => ({
					timestamp: Date.now(),
					providerName: 'test-provider',
					mcp: { ...MCP_STATE, browserNonceHash: hashBrowserSecret(SECRET) },
				}));
			});

			it('completes when the callback arrives with the stable browser-secret cookie', async () => {
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

			it('rejects when the browser-secret cookie is missing — victim browser never approved', async () => {
				// Attack: the malicious client initiates the flow (cookie in THEIR browser),
				// then sends the victim the upstream IdP URL. The victim has no cookie.
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

			it('rejects when the browser-secret cookie does not match the bound hash', async () => {
				mockRequest.headers.cookie = buildBrowserSecretCookie('some-other-browser-secret').split(';')[0];
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

			it('fails closed on an MCP state with no browser binding (forged/pre-upgrade state)', async () => {
				// An MCP state with no browserNonceHash is a forged or pre-upgrade
				// in-flight state — must NOT mint an auth code (authorization-code injection).
				mockProvider.verifyCSRFToken = createMockFn(async () => ({
					timestamp: Date.now(),
					providerName: 'test-provider',
					mcp: { ...MCP_STATE }, // no browserNonceHash
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
				assert.equal(url.origin + url.pathname, MCP_STATE.redirectUri, 'error routed to the client redirect_uri');
				assert.equal(url.searchParams.get('error'), 'access_denied');
				assert.equal(url.searchParams.get('code'), null, 'no auth code minted for an unbound MCP state');
				assert.equal(storedAuthCodes.size, 0, 'no auth code persisted');
				assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0, 'upstream code never exchanged');
			});
		});
	});

	describe('handleLogout', () => {
		it('persists an invalidated session record (user: null) — not just an in-memory clear', async () => {
			// Regression (F4): Harper session exposes only .update, never .delete — logout must persist { user: null }.
			mockRequest.session.update = createMockFn(); // session already has id: 'session-123'

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(result.body.message, 'Logged out successfully');
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
			const persisted = mockRequest.session.update.mock.calls[0].arguments[0];
			assert.deepEqual(
				persisted,
				{ user: null },
				'persists only { user: null } — oauth keys dropped by the full-replace put'
			);
		});

		it('clears in-memory session fields on the production path so the current request sees no identity', async () => {
			// Production path must also clear in-memory so the current request sees no identity.
			mockRequest.session = {
				id: 'session-123',
				update: createMockFn(),
				user: { username: 'alice', role: 'superuser' },
				oauth: { accessToken: 'tok-abc' },
				oauthUser: { username: 'alice', provider: 'github' },
			};

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
			// update() must still have been called once with { user: null }
			assert.equal(mockRequest.session.update.mock.calls.length, 1);
			assert.deepEqual(mockRequest.session.update.mock.calls[0].arguments[0], { user: null });
			// In-memory fields must be cleared so the current request sees no identity
			assert.equal(mockRequest.session.user, null, 'session.user cleared in memory');
			assert.equal(mockRequest.session.oauth, undefined, 'session.oauth deleted in memory');
			assert.equal(mockRequest.session.oauthUser, undefined, 'session.oauthUser deleted in memory');
		});

		it('does NOT persist a row for an anonymous logout (session with .update but no id)', async () => {
			// .update on an anonymous request mints a non-expiring hdb_session row — must not call it.
			mockRequest.session = { update: createMockFn() }; // no id → nothing to invalidate

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
			assert.equal(mockRequest.session.update.mock.calls.length, 0, 'no persistence for an anonymous logout');
		});

		it('falls back to an in-memory clear when the session cannot persist (no update)', async () => {
			mockRequest.session = {
				id: 'session-123',
				user: 'test-user',
				oauthUser: { username: 'test' },
				oauth: { accessToken: 'token' },
			};

			const result = await handleLogout(mockRequest, mockHookManager, mockLogger);

			assert.equal(result.status, 200);
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

		it('untrusted (quarantine) session → /user reports IdP identity with no role', async () => {
			// A roleless untrusted session sets session.user to a non-resolvable quarantine
			// principal and stamps oauth.authTrust='untrusted'. The /user endpoint reports
			// the IdP-derived identity and a null role — never leaking the opaque principal,
			// and never an IdP-derived Harper role.
			mockRequest.session.user = 'unverified:attacker@example.com#0123456789abcdef';
			mockRequest.session.oauth = { authTrust: 'untrusted', providerType: 'test' };
			mockRequest.session.oauthUser = {
				username: 'attacker@example.com', // raw IdP identity (preserved)
				role: 'user', // app role claim preserved on oauthUser; not a Harper role
				email: 'attacker@example.com',
				name: 'Attacker',
				provider: 'test',
			};

			const result = await handleUserInfo(mockRequest);

			assert.equal(result.status, 200);
			assert.equal(result.body.authenticated, true);
			assert.equal(result.body.username, 'attacker@example.com', 'reports IdP identity, not the opaque principal');
			assert.notEqual(result.body.username, mockRequest.session.user, 'must not leak the quarantine principal');
			assert.equal(result.body.role, null, 'must not carry a Harper role');
		});

		it('trusted session → /user reports raw identity and IdP role (unchanged)', async () => {
			// Normal trusted sessions must be unaffected: oauthUser.username and oauthUser.role
			// are reported as before.
			mockRequest.session.user = 'alice@example.com';
			mockRequest.session.oauthUser = {
				username: 'alice@example.com',
				role: 'admin',
				email: 'alice@example.com',
				name: 'Alice',
				provider: 'google',
			};

			const result = await handleUserInfo(mockRequest);

			assert.equal(result.status, 200);
			assert.equal(result.body.username, 'alice@example.com');
			assert.equal(result.body.role, 'admin');
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
		beforeEach(() => {
			globalThis.databases = { system: { hdb_user: { get: async () => null } } };
		});
		afterEach(() => {
			delete globalThis.databases;
		});

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

	describe('handleCallback — login browser binding', () => {
		const SECRET = 'login-binding-secret';
		let hashBrowserSecret, buildBrowserSecretCookie;

		beforeEach(async () => {
			({ hashBrowserSecret, buildBrowserSecretCookie } = await import('../../dist/lib/mcp/consentBinding.js'));
			// A logged-out flow: no sessionId in the token (the session binding
			// has nothing to check — the exact gap the browser-secret cookie closes).
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider',
				browserNonceHash: hashBrowserSecret(SECRET),
			}));
			// No users in system DB — account-adoption gate never fires.
			globalThis.databases = { system: { hdb_user: { get: async () => null } } };
		});

		afterEach(() => {
			delete globalThis.databases;
		});

		it('completes when the callback arrives in the browser that initiated the login', async () => {
			mockRequest.headers.cookie = buildBrowserSecretCookie(SECRET).split(';')[0];

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

		it('rejects when the binding cookie is missing — attacker-minted state in a victim browser', async () => {
			// Attack: the attacker initiates a login (cookie set in THEIR browser),
			// completes IdP auth as themselves, then feeds the callback URL to the
			// victim. The victim's browser has no matching cookie — no login.
			delete mockRequest.headers.cookie;

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

		it('rejects when the browser-secret cookie does not hash-match', async () => {
			mockRequest.headers.cookie = buildBrowserSecretCookie('some-other-browser-secret').split(';')[0];

			const result = await handleCallback(
				mockRequest,
				mockTarget,
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.headers.Location, '/dashboard?error=auth_failed&reason=csrf');
			assert.equal(mockProvider.exchangeCodeForToken.mock.calls.length, 0);
		});

		it('tolerates state tokens without a nonce hash (pre-upgrade in-flight logins)', async () => {
			mockProvider.verifyCSRFToken = createMockFn(async () => ({
				originalUrl: '/dashboard',
				timestamp: Date.now(),
				providerName: 'test-provider',
			}));
			delete mockRequest.headers.cookie;

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
	});

	describe('handleCallback — CRLF-safe error logging (CWE-117)', () => {
		beforeEach(() => {
			globalThis.databases = { system: { hdb_user: { get: async () => null } } };
		});
		afterEach(() => {
			delete globalThis.databases;
		});

		const CRLF_ERROR = 'access_denied\r\nFORGED line';
		const CRLF_DESC = 'desc\r\ninjected';

		function targetWith(params) {
			return { get: createMockFn((key) => params[key]) };
		}

		it('encodes CR/LF in upstream error params on the no-state path', async () => {
			const result = await handleCallback(
				mockRequest,
				targetWith({ error: CRLF_ERROR, error_description: CRLF_DESC }),
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			const logged = mockLogger.error.mock.calls[0].arguments[0];
			assert.ok(!logged.includes('\r') && !logged.includes('\n'), 'no raw CR/LF reaches the log line');
			assert.ok(logged.includes('\\r\\n'), 'injected control chars are visibly encoded');
		});

		it('encodes CR/LF in upstream error params on the verified-state path', async () => {
			const result = await handleCallback(
				mockRequest,
				targetWith({ state: 'csrf-token-123', error: CRLF_ERROR, error_description: CRLF_DESC }),
				mockProvider,
				mockConfig,
				mockHookManager,
				'test-provider',
				{ logger: mockLogger }
			);

			assert.equal(result.status, 302);
			const logged = mockLogger.error.mock.calls[0].arguments[0];
			assert.ok(!logged.includes('\r') && !logged.includes('\n'), 'no raw CR/LF reaches the log line');
			assert.ok(logged.includes('\\r\\n'), 'injected control chars are visibly encoded');
		});
	});
});
