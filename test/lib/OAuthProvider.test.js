/**
 * Tests for OAuthProvider
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import jwksRsa from 'jwks-rsa';
import { OAuthProvider } from '../../dist/lib/OAuthProvider.js';
import { GitHubProvider } from '../../dist/lib/providers/github.js';
import { AzureADProvider } from '../../dist/lib/providers/azure.js';
import { resetCSRFTableCache } from '../../dist/lib/CSRFTokenManager.js';
import { startIssuerDiscovery, awaitDiscoveredIssuer, _clearDiscoveryCache } from '../../dist/lib/discovery.js';
import { _setFetch, _setDnsLookup } from '../../dist/lib/mcp/cimd.js';

describe('OAuthProvider', () => {
	let provider;
	let originalDatabases;
	let mockTableInstance;
	let storedTokens;

	const mockConfig = {
		provider: 'test',
		clientId: 'test-client-id',
		clientSecret: 'test-client-secret',
		authorizationUrl: 'https://auth.example.com/authorize',
		tokenUrl: 'https://auth.example.com/token',
		userInfoUrl: 'https://auth.example.com/userinfo',
		redirectUri: 'http://localhost:9926/oauth/test/callback',
		scope: 'openid profile email',
		usernameClaim: 'email',
		defaultRole: 'user',
	};

	const mockLogger = {
		info: () => {},
		warn: () => {},
		error: () => {},
		debug: () => {},
	};

	before(() => {
		// Save original global.databases if it exists
		originalDatabases = global.databases;
	});

	after(() => {
		// Restore original global.databases
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		// Reset CSRFTokenManager's module-level table cache so each test
		// picks up this iteration's mockTableInstance. Without this, Bun
		// (which shares module state across tests in a single process)
		// keeps the first iteration's table reference and writes go to
		// a stale storedTokens Map. Node hides this by running each file
		// in a separate process.
		resetCSRFTableCache();

		// Initialize token storage
		storedTokens = new Map();

		// Create mock table instance
		mockTableInstance = {
			get: async (id) => storedTokens.get(id) || null,
			put: async (record) => {
				storedTokens.set(record.token_id, record);
			},
			delete: async (id) => {
				storedTokens.delete(id);
			},
		};

		// Mock the global databases object
		global.databases = {
			oauth: {
				csrf_tokens: mockTableInstance,
			},
		};
	});

	describe('Initialization', () => {
		it('should create provider with valid config', () => {
			assert.doesNotThrow(() => {
				provider = new OAuthProvider(mockConfig, mockLogger);
			});
			assert.equal(provider.config.clientId, 'test-client-id');
		});

		it('should throw with missing required fields', () => {
			const invalidConfig = { ...mockConfig };
			delete invalidConfig.clientId;

			assert.throws(
				() => {
					new OAuthProvider(invalidConfig, mockLogger);
				},
				{
					message: /missing required fields.*clientId/i,
				}
			);
		});

		it('should throw with multiple missing fields', () => {
			const invalidConfig = {
				provider: 'test',
			};

			assert.throws(
				() => {
					new OAuthProvider(invalidConfig, mockLogger);
				},
				{
					message: /missing required fields.*clientId.*clientSecret/i,
				}
			);
		});
	});

	describe('Authorization URL Generation', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should generate authorization URL with required parameters', () => {
			const state = 'random-state-123';
			const url = provider.getAuthorizationUrl(state, mockConfig.redirectUri);

			assert.ok(url.startsWith(mockConfig.authorizationUrl));
			assert.ok(url.includes('client_id=test-client-id'));
			assert.ok(url.includes('state=random-state-123'));
			assert.ok(url.includes('response_type=code'));
			assert.ok(url.includes('redirect_uri='));
			assert.ok(url.includes('scope=openid'));
		});

		it('should handle authorization URL with existing query params', () => {
			const configWithQuery = {
				...mockConfig,
				authorizationUrl: 'https://auth.example.com/authorize?tenant=123',
			};
			provider = new OAuthProvider(configWithQuery, mockLogger);

			const url = provider.getAuthorizationUrl('state', 'https://callback');
			assert.ok(url.includes('tenant=123'));
			assert.ok(url.includes('client_id='));
		});
	});

	describe('User Mapping', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should map user info to Harper user', () => {
			const userInfo = {
				sub: '123456',
				email: 'user@example.com',
				name: 'Test User',
				picture: 'https://example.com/avatar.jpg',
			};

			const harperUser = provider.mapUserToHarper(userInfo);

			assert.equal(harperUser.username, 'user@example.com');
			assert.equal(harperUser.email, 'user@example.com');
			assert.equal(harperUser.name, 'Test User');
			assert.equal(harperUser.role, 'user');
			assert.equal(harperUser.provider, 'test');
		});

		it('should normalize email_verified into emailVerified (#174 follow-up)', () => {
			const base = { sub: '1', email: 'user@example.com' };

			assert.equal(provider.mapUserToHarper({ ...base, email_verified: true }).emailVerified, true);
			assert.equal(provider.mapUserToHarper({ ...base, email_verified: false }).emailVerified, false);
			// Absent or non-boolean claims must stay undefined — consumers gate on === true
			assert.equal(provider.mapUserToHarper(base).emailVerified, undefined);
			assert.equal(provider.mapUserToHarper({ ...base, email_verified: 'true' }).emailVerified, undefined);
			// Raw claim still reachable for consumers that need the provider's exact value
			assert.equal(
				provider.mapUserToHarper({ ...base, email_verified: 'true' }).metadata.oauthClaims.email_verified,
				'true'
			);
		});

		it('should use custom username claim', () => {
			const customConfig = {
				...mockConfig,
				usernameClaim: 'sub',
			};
			provider = new OAuthProvider(customConfig, mockLogger);

			const userInfo = {
				sub: 'user-123',
				email: 'user@example.com',
			};

			const harperUser = provider.mapUserToHarper(userInfo);
			assert.equal(harperUser.username, 'user-123');
		});

		it('should handle nested username claim', () => {
			const customConfig = {
				...mockConfig,
				usernameClaim: 'profile.username',
			};
			provider = new OAuthProvider(customConfig, mockLogger);

			const userInfo = {
				profile: {
					username: 'nested-user',
				},
				email: 'user@example.com',
			};

			const harperUser = provider.mapUserToHarper(userInfo);
			assert.equal(harperUser.username, 'nested-user');
		});

		it('should use default role when not in claims', () => {
			const userInfo = {
				email: 'user@example.com',
			};

			const harperUser = provider.mapUserToHarper(userInfo);
			assert.equal(harperUser.role, 'user');
		});

		it('should extract role from claims', () => {
			const configWithRole = {
				...mockConfig,
				roleClaim: 'role',
			};
			provider = new OAuthProvider(configWithRole, mockLogger);

			const userInfo = {
				email: 'admin@example.com',
				role: 'admin',
			};

			const harperUser = provider.mapUserToHarper(userInfo);
			assert.equal(harperUser.role, 'admin');
		});
	});

	describe('CSRF Token Management', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should generate unique CSRF tokens', async () => {
			const token1 = await provider.generateCSRFToken({ url: '/page1' });
			const token2 = await provider.generateCSRFToken({ url: '/page2' });

			assert.notEqual(token1, token2);
			assert.equal(token1.length, 64); // 32 bytes hex = 64 chars
			assert.equal(token2.length, 64);
		});

		it('should store metadata with token', async () => {
			const metadata = {
				originalUrl: '/dashboard',
				sessionId: 'session-123',
			};

			const token = await provider.generateCSRFToken(metadata);

			// Verify token was stored in mock table
			assert.ok(token);
			assert.equal(typeof token, 'string');
			assert.equal(storedTokens.size, 1);

			const storedRecord = storedTokens.get(token);
			assert.ok(storedRecord);
			assert.ok(storedRecord.data);
			// created_at is Harper-managed (@createdTime), not hand-written.
			assert.equal(storedRecord.created_at, undefined);
		});

		it('should verify and consume valid token', async () => {
			const metadata = { originalUrl: '/test' };
			const token = await provider.generateCSRFToken(metadata);

			const verified = await provider.verifyCSRFToken(token);
			assert.ok(verified);
			assert.equal(verified.originalUrl, '/test');
			assert.ok(verified.timestamp);

			// Token should be consumed (one-time use)
			const secondVerify = await provider.verifyCSRFToken(token);
			assert.equal(secondVerify, null);
		});

		it('should reject invalid token', async () => {
			const result = await provider.verifyCSRFToken('invalid-token');
			assert.equal(result, null);
		});
	});

	describe('Token Exchange', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should exchange code for token with correct parameters', async () => {
			// Mock fetch for token exchange
			const originalFetch = global.fetch;
			let capturedRequest;

			global.fetch = async (url, options) => {
				capturedRequest = { url, options };
				return {
					ok: true,
					headers: {
						get: (name) => (name === 'content-type' ? 'application/json' : null),
					},
					json: async () => ({
						access_token: 'access-123',
						token_type: 'Bearer',
						expires_in: 3600,
						refresh_token: 'refresh-456',
					}),
				};
			};

			try {
				const result = await provider.exchangeCodeForToken('auth-code-789', 'https://callback');

				assert.equal(capturedRequest.url, mockConfig.tokenUrl);
				assert.equal(capturedRequest.options.method, 'POST');
				assert.ok(capturedRequest.options.body.includes('code=auth-code-789'));
				assert.ok(capturedRequest.options.body.includes('client_id=test-client-id'));
				assert.ok(capturedRequest.options.body.includes('client_secret=test-client-secret'));

				assert.equal(result.access_token, 'access-123');
				assert.equal(result.refresh_token, 'refresh-456');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should handle form-encoded token response', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: true,
				headers: {
					get: () => 'application/x-www-form-urlencoded',
				},
				text: async () => 'access_token=github-token&token_type=bearer&scope=user',
			});

			try {
				const result = await provider.exchangeCodeForToken('code', 'https://callback');
				assert.equal(result.access_token, 'github-token');
				assert.equal(result.token_type, 'bearer');
				assert.equal(result.scope, 'user');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should throw with sanitized message on token exchange failure', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 401,
				statusText: 'Unauthorized',
				headers: { get: () => null },
			});

			try {
				await assert.rejects(async () => await provider.exchangeCodeForToken('code', 'https://callback'), {
					message: /Token exchange failed.*401 Unauthorized/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should extract error_description from JSON error response', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 400,
				statusText: 'Bad Request',
				headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
				json: async () => ({
					error: 'invalid_client',
					error_description: 'The client credentials are invalid',
				}),
			});

			try {
				await assert.rejects(async () => await provider.exchangeCodeForToken('code', 'https://callback'), {
					message: /Token exchange failed.*The client credentials are invalid/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should not leak HTML error pages in token exchange errors', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 500,
				statusText: 'Internal Server Error',
				headers: { get: (h) => (h === 'content-type' ? 'text/html' : null) },
			});

			try {
				await assert.rejects(async () => await provider.exchangeCodeForToken('code', 'https://callback'), {
					message: /Token exchange failed.*500 Internal Server Error/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should drain response body on non-JSON error to prevent socket leak', async () => {
			const originalFetch = global.fetch;
			let bodyCancelled = false;

			global.fetch = async () => ({
				ok: false,
				status: 500,
				statusText: 'Internal Server Error',
				headers: { get: (h) => (h === 'content-type' ? 'text/html' : null) },
				body: {
					cancel: async () => {
						bodyCancelled = true;
					},
				},
			});

			try {
				await assert.rejects(async () => await provider.exchangeCodeForToken('code', 'https://callback'), {
					message: /Token exchange failed/,
				});
				assert.ok(bodyCancelled, 'response.body.cancel() should have been called');
			} finally {
				global.fetch = originalFetch;
			}
		});
	});

	describe('JSON Parse Safety', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should fall back to status when JSON parse fails in token exchange', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 502,
				statusText: 'Bad Gateway',
				headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
				json: async () => {
					throw new SyntaxError('Unexpected end of JSON input');
				},
			});

			try {
				await assert.rejects(async () => await provider.exchangeCodeForToken('code', 'https://callback'), {
					message: /Token exchange failed.*502 Bad Gateway/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should fall back to status when JSON parse fails in token refresh', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 502,
				statusText: 'Bad Gateway',
				headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
				json: async () => {
					throw new SyntaxError('Unexpected end of JSON input');
				},
			});

			try {
				await assert.rejects(async () => await provider.refreshAccessToken('bad-token'), {
					message: /Token refresh failed.*502 Bad Gateway/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});
	});

	describe('User Info Fetching', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should fetch user info with access token', async () => {
			const originalFetch = global.fetch;

			global.fetch = async (url, options) => {
				assert.equal(url, mockConfig.userInfoUrl);
				assert.equal(options.headers.Authorization, 'Bearer test-token');

				return {
					ok: true,
					json: async () => ({
						sub: '123',
						email: 'user@example.com',
						name: 'Test User',
					}),
				};
			};

			try {
				const userInfo = await provider.getUserInfo('test-token');
				assert.equal(userInfo.email, 'user@example.com');
				assert.equal(userInfo.name, 'Test User');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should use ID token claims when available', async () => {
			const idTokenClaims = {
				sub: '123',
				email: 'id-token@example.com',
				name: 'ID Token User',
			};

			const userInfo = await provider.getUserInfo('token', idTokenClaims);
			assert.equal(userInfo.email, 'id-token@example.com');
			assert.equal(userInfo.name, 'ID Token User');
		});

		it('fetchEmail fallback: a fetched email does not inherit the id token email_verified', async () => {
			const fetchProvider = new OAuthProvider({ ...mockConfig, fetchEmail: true });
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({ sub: '123', email: 'victim@example.com', email_verified: false }),
			});
			try {
				// id token has no email but claims email_verified: true — it must not attach to
				// the fetched (userinfo) address.
				const userInfo = await fetchProvider.getUserInfo('token', {
					sub: '123',
					email: null,
					email_verified: true,
				});
				assert.equal(userInfo.email, 'victim@example.com', 'fetched address wins');
				assert.equal(userInfo.email_verified, false, 'fetched address keeps its own (false) flag');
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should call custom getUserInfo function', async () => {
			const customConfig = {
				...mockConfig,
				getUserInfo: async function (accessToken, helpers) {
					assert.equal(accessToken, 'custom-token');
					assert.ok(helpers.getUserInfo);
					assert.ok(helpers.logger);
					return {
						email: 'custom@example.com',
						custom: true,
					};
				},
			};

			provider = new OAuthProvider(customConfig, mockLogger);
			const userInfo = await provider.getUserInfo('custom-token');
			assert.equal(userInfo.email, 'custom@example.com');
			assert.equal(userInfo.custom, true);
		});

		it('provenance injection: non-github adapter returning github-authenticated → unauthenticated', async () => {
			// A custom adapter on a non-github provider cannot earn 'github-authenticated'.
			// The plugin strips the adapter's _emailProvenance and assigns based on config.provider.
			const nonGithubConfig = {
				...mockConfig,
				provider: 'custom-oidc',
				getUserInfo: async () => ({
					email: 'victim@example.com',
					email_verified: true,
					_emailProvenance: 'github-authenticated', // injection attempt
				}),
			};
			provider = new OAuthProvider(nonGithubConfig, mockLogger);
			const userInfo = await provider.getUserInfo('token');
			assert.equal(
				userInfo._emailProvenance,
				'unauthenticated',
				'non-github adapter must not earn github-authenticated'
			);
		});

		it('provenance injection: non-github adapter returning signed-oidc → unauthenticated', async () => {
			// A custom adapter cannot earn 'signed-oidc' either — that is only assigned
			// by the plugin on the verified id-token path, never read from adapter output.
			const nonGithubConfig = {
				...mockConfig,
				provider: 'custom-oidc',
				getUserInfo: async () => ({
					email: 'victim@example.com',
					email_verified: true,
					_emailProvenance: 'signed-oidc', // injection attempt
				}),
			};
			provider = new OAuthProvider(nonGithubConfig, mockLogger);
			const userInfo = await provider.getUserInfo('token');
			assert.equal(userInfo._emailProvenance, 'unauthenticated', 'adapter cannot earn signed-oidc');
		});

		it('provenance: a custom getUserInfo labelled provider:github cannot earn github-authenticated', async () => {
			// The trusted stamp comes only from the built-in adapter's authenticated fetch,
			// asserted through the provenance Symbol. A custom adapter that returns
			// email_verified:true without a fetch cannot set the Symbol, so it must not
			// earn github-authenticated.
			const githubConfig = {
				...mockConfig,
				provider: 'github',
				getUserInfo: async () => ({
					email: 'alice@example.com',
					email_verified: true,
				}),
			};
			provider = new OAuthProvider(githubConfig, mockLogger);
			const userInfo = await provider.getUserInfo('token');
			assert.equal(
				userInfo._emailProvenance,
				'unauthenticated',
				'only the built-in GitHub adapter may earn github-authenticated'
			);
		});

		it('provenance: the built-in GitHub adapter with a verified email → github-authenticated', async () => {
			const originalFetch = global.fetch;
			global.fetch = async (url) => {
				if (String(url).includes('api.github.com/user/emails')) {
					return { ok: true, json: async () => [{ email: 'alice@example.com', primary: true, verified: true }] };
				}
				return { ok: true, json: async () => ({ email: 'alice@example.com' }) };
			};
			try {
				provider = new OAuthProvider(
					{ ...mockConfig, provider: 'github', getUserInfo: GitHubProvider.getUserInfo },
					mockLogger
				);
				const userInfo = await provider.getUserInfo('token');
				assert.equal(userInfo._emailProvenance, 'github-authenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('provenance: the built-in GitHub adapter with an unverified email → unauthenticated', async () => {
			const originalFetch = global.fetch;
			global.fetch = async (url) => {
				if (String(url).includes('api.github.com/user/emails')) {
					return { ok: true, json: async () => [{ email: 'alice@example.com', primary: true, verified: false }] };
				}
				return { ok: true, json: async () => ({ email: 'alice@example.com' }) };
			};
			try {
				provider = new OAuthProvider(
					{ ...mockConfig, provider: 'github', getUserInfo: GitHubProvider.getUserInfo },
					mockLogger
				);
				const userInfo = await provider.getUserInfo('token');
				assert.equal(
					userInfo._emailProvenance,
					'unauthenticated',
					'an unverified GitHub email must not earn github-authenticated'
				);
			} finally {
				global.fetch = originalFetch;
			}
		});
	});

	describe('Token Refresh', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should refresh access token with correct parameters', async () => {
			const originalFetch = global.fetch;
			let capturedRequest;

			global.fetch = async (url, options) => {
				capturedRequest = { url, options };
				return {
					ok: true,
					headers: {
						get: (name) => (name === 'content-type' ? 'application/json' : null),
					},
					json: async () => ({
						access_token: 'new-access-token',
						token_type: 'Bearer',
						expires_in: 3600,
						refresh_token: 'new-refresh-token',
						scope: 'openid profile email',
					}),
				};
			};

			try {
				const result = await provider.refreshAccessToken('old-refresh-token');

				assert.equal(capturedRequest.url, mockConfig.tokenUrl);
				assert.equal(capturedRequest.options.method, 'POST');
				assert.ok(capturedRequest.options.body.includes('grant_type=refresh_token'));
				assert.ok(capturedRequest.options.body.includes('refresh_token=old-refresh-token'));
				assert.ok(capturedRequest.options.body.includes('client_id=test-client-id'));
				assert.ok(capturedRequest.options.body.includes('client_secret=test-client-secret'));

				assert.equal(result.access_token, 'new-access-token');
				assert.equal(result.refresh_token, 'new-refresh-token');
				assert.equal(result.expires_in, 3600);
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should handle form-encoded refresh token response', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: true,
				headers: {
					get: () => 'application/x-www-form-urlencoded',
				},
				text: async () => 'access_token=refreshed-token&token_type=bearer&expires_in=7200',
			});

			try {
				const result = await provider.refreshAccessToken('refresh-token');
				assert.equal(result.access_token, 'refreshed-token');
				assert.equal(result.token_type, 'bearer');
				assert.equal(result.expires_in, '7200');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should throw with sanitized message on HTTP error during token refresh', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 400,
				statusText: 'Bad Request',
				headers: { get: () => null },
			});

			try {
				await assert.rejects(async () => await provider.refreshAccessToken('bad-token'), {
					message: /Token refresh failed.*400 Bad Request/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should drain response body on error to prevent socket leak', async () => {
			const originalFetch = global.fetch;
			let bodyCancelled = false;

			global.fetch = async () => ({
				ok: false,
				status: 502,
				statusText: 'Bad Gateway',
				headers: { get: () => null },
				body: {
					cancel: async () => {
						bodyCancelled = true;
					},
				},
			});

			try {
				await assert.rejects(async () => await provider.refreshAccessToken('bad-token'), {
					message: /Token refresh failed/,
				});
				assert.ok(bodyCancelled, 'response.body.cancel() should have been called');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should extract error_description from JSON error during token refresh', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				status: 400,
				statusText: 'Bad Request',
				headers: { get: (h) => (h === 'content-type' ? 'application/json' : null) },
				json: async () => ({
					error: 'invalid_grant',
					error_description: 'The refresh token is invalid',
				}),
			});

			try {
				await assert.rejects(async () => await provider.refreshAccessToken('bad-token'), {
					message: /Token refresh failed.*The refresh token is invalid/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should handle HTTP 200 with error object (GitHub-style)', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: true,
				headers: {
					get: () => 'application/json',
				},
				json: async () => ({
					error: 'bad_refresh_token',
					error_description: 'The refresh token passed is incorrect or expired.',
					error_uri: 'https://docs.github.com/apps',
				}),
			});

			try {
				await assert.rejects(async () => await provider.refreshAccessToken('expired-token'), {
					message: /Token refresh failed.*incorrect or expired/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should handle HTTP 200 with error object without description', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: true,
				headers: {
					get: () => 'application/json',
				},
				json: async () => ({
					error: 'invalid_token',
				}),
			});

			try {
				await assert.rejects(async () => await provider.refreshAccessToken('token'), {
					message: /Token refresh failed.*invalid_token/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should include scope in refresh request when configured', async () => {
			const configWithScope = {
				...mockConfig,
				scope: 'read write admin',
			};
			provider = new OAuthProvider(configWithScope, mockLogger);

			const originalFetch = global.fetch;
			let capturedRequest;

			global.fetch = async (url, options) => {
				capturedRequest = { url, options };
				return {
					ok: true,
					headers: {
						get: () => 'application/json',
					},
					json: async () => ({
						access_token: 'new-token',
						token_type: 'Bearer',
						expires_in: 3600,
					}),
				};
			};

			try {
				await provider.refreshAccessToken('refresh-token');
				assert.ok(capturedRequest.options.body.includes('scope=read+write+admin'));
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should throw when refresh token is missing', async () => {
			await assert.rejects(async () => await provider.refreshAccessToken(''), {
				message: /Refresh token is required/i,
			});
		});
	});

	describe('getUserInfo with ID Token Claims', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should prefer ID token claims when available', async () => {
			const idTokenClaims = {
				sub: 'id-token-sub',
				email: 'idtoken@example.com',
				name: 'ID Token User',
			};

			const userInfo = await provider.getUserInfo('access-token', idTokenClaims);
			assert.equal(userInfo.email, 'idtoken@example.com');
			assert.equal(userInfo.name, 'ID Token User');
		});

		it('should set _emailProvenance signed-oidc when email is in the id token and the signature was verified', async () => {
			const idTokenClaims = {
				sub: 'u1',
				email: 'user@example.com',
				email_verified: true,
			};

			const userInfo = await provider.getUserInfo('access-token', idTokenClaims, true);
			assert.equal(userInfo._emailProvenance, 'signed-oidc');
		});

		it('must NOT set _emailProvenance signed-oidc on the no-JWKS fallback (signatureVerified false) (#231 §5d)', async () => {
			// verifyIdToken's no-JWKS fallback returns signatureVerified: false — the
			// claims are decoded, not cryptographically verified. getUserInfo must not
			// label them 'signed-oidc' just because idTokenClaims is present.
			const idTokenClaims = {
				sub: 'u1',
				email: 'user@example.com',
				email_verified: true,
			};

			const userInfo = await provider.getUserInfo('access-token', idTokenClaims, false);
			assert.equal(userInfo._emailProvenance, 'unauthenticated');
		});

		it('defaults to NOT signed-oidc when idTokenSignatureVerified is omitted (safe default)', async () => {
			const idTokenClaims = {
				sub: 'u1',
				email: 'user@example.com',
				email_verified: true,
			};

			const userInfo = await provider.getUserInfo('access-token', idTokenClaims);
			assert.equal(userInfo._emailProvenance, 'unauthenticated');
		});

		it('should set _emailProvenance unauthenticated when no id token', async () => {
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({ sub: 'u1', email: 'user@example.com' }),
			});
			try {
				const userInfo = await provider.getUserInfo('access-token', null);
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should fetch userinfo email when ID token lacks email and fetchEmail is true (unauthenticated)', async () => {
			// When the id token lacks email and fetchEmail is configured, userinfo
			// is fetched to resolve the email so the login can succeed. Provenance is tagged
			// 'unauthenticated' (the email is not signed), so adoption of an existing account
			// is denied. Signed identity fields (iss, sub) come from the id token only.
			let fetchCalled = false;
			const originalFetch = global.fetch;
			global.fetch = async () => {
				fetchCalled = true;
				return { ok: true, json: async () => ({ sub: '123', email: 'fetched@example.com', name: 'Fetched User' }) };
			};

			const configWithFetchEmail = {
				...mockConfig,
				fetchEmail: true,
			};
			provider = new OAuthProvider(configWithFetchEmail, mockLogger);

			try {
				const idTokenClaimsNoEmail = {
					sub: '123',
					iss: 'https://issuer.example.com',
					name: 'User Without Email',
				};

				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(
					fetchCalled,
					true,
					'fetchUserInfo must be called when id token lacks email and fetchEmail is true'
				);
				assert.equal(userInfo.email, 'fetched@example.com', 'email must come from userinfo');
				assert.equal(userInfo.sub, '123', 'sub must come from id token (not userinfo)');
				assert.equal(userInfo.iss, 'https://issuer.example.com', 'iss must come from id token (not userinfo)');
				assert.equal(userInfo.name, 'User Without Email', 'id token name takes precedence when both present');
				assert.equal(userInfo._emailProvenance, 'unauthenticated', 'fetchEmail path is always unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('discards UserInfo whose sub does not match the id-token sub on the fetchEmail path (OIDC Core 5.3.2/5.3.4, #231 §5a)', async () => {
			// A UserInfo response describing a different subject than the id token
			// must never contribute fields (email, name, role claims, ...) to this
			// login. Only the id-token's own claims are used.
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({
					sub: 'attacker-sub',
					email: 'attacker@example.com',
					name: 'Attacker Name',
				}),
			});

			const configWithFetchEmail = {
				...mockConfig,
				fetchEmail: true,
			};
			provider = new OAuthProvider(configWithFetchEmail, mockLogger);

			try {
				const idTokenClaimsNoEmail = {
					sub: 'victim-sub',
					iss: 'https://issuer.example.com',
					name: 'Victim Name',
				};

				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo.sub, 'victim-sub', 'sub must stay the id token subject');
				assert.equal(userInfo.email, undefined, "the mismatched subject's email must not be merged in");
				assert.equal(userInfo.name, 'Victim Name', "the mismatched subject's name must not override the id token's");
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('discards UserInfo that omits sub entirely on the fetchEmail path (OIDC Core 5.3.2 requires sub)', async () => {
			// A UserInfo response with no `sub` at all is non-conformant and gets no
			// benefit of the doubt — treated the same as a mismatch, not skipped.
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({ email: 'attacker@example.com', name: 'Attacker Name' }),
			});

			const configWithFetchEmail = {
				...mockConfig,
				fetchEmail: true,
			};
			provider = new OAuthProvider(configWithFetchEmail, mockLogger);

			try {
				const idTokenClaimsNoEmail = { sub: 'victim-sub', iss: 'https://issuer.example.com', name: 'Victim Name' };
				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo.email, undefined, "a sub-less userinfo's email must not be merged in");
				assert.equal(userInfo.name, 'Victim Name');
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('allows UserInfo whose sub matches the id-token sub on the fetchEmail path', async () => {
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({
					sub: 'same-sub',
					email: 'user@example.com',
				}),
			});

			const configWithFetchEmail = {
				...mockConfig,
				fetchEmail: true,
			};
			provider = new OAuthProvider(configWithFetchEmail, mockLogger);

			try {
				const idTokenClaimsNoEmail = { sub: 'same-sub', iss: 'https://issuer.example.com' };
				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo.email, 'user@example.com', 'a matching sub still merges the fetched email');
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('Azure/Graph UserInfo (id, no sub) with matching oid is correlated and usable via emailClaim/usernameClaim', async () => {
			// Microsoft Graph's /v1.0/me is not an OIDC UserInfo endpoint: it returns
			// `id` (the directory object ID), never `sub`. Azure's id token carries
			// the same value as `oid`, so this alternate pairing must be accepted —
			// using the REAL Azure preset (provider: 'azure', userInfoUrl pointing at
			// graph.microsoft.com) so the gate is exercised as configured in practice.
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({
					id: 'aaaa-oid-1234',
					mail: 'alice@contoso.example',
					userPrincipalName: 'alice@contoso.onmicrosoft.com',
				}),
			});

			const azureConfig = {
				...AzureADProvider,
				clientId: 'c',
				clientSecret: 's',
				redirectUri: 'http://localhost:9926/oauth/azure/callback',
				fetchEmail: true,
				emailClaim: 'mail',
				usernameClaim: 'userPrincipalName',
			};
			provider = new OAuthProvider(azureConfig, mockLogger);

			try {
				const idTokenClaimsNoEmail = {
					sub: 'azure-sub-1',
					oid: 'aaaa-oid-1234',
					iss: 'https://login.microsoftonline.com/common/v2.0',
				};
				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo._emailProvenance, 'unauthenticated', 'fetchEmail path is always unauthenticated');
				assert.equal(userInfo.mail, 'alice@contoso.example', 'Graph field is usable via emailClaim');
				assert.equal(
					userInfo.userPrincipalName,
					'alice@contoso.onmicrosoft.com',
					'Graph field is usable via usernameClaim'
				);
				const mapped = provider.mapUserToHarper(userInfo);
				assert.equal(mapped.username, 'alice@contoso.onmicrosoft.com');
				assert.equal(mapped.email, 'alice@contoso.example');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('Azure/Graph UserInfo with a MISMATCHED oid is rejected', async () => {
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({ id: 'attacker-oid', mail: 'attacker@contoso.example' }),
			});

			const azureConfig = {
				...AzureADProvider,
				clientId: 'c',
				clientSecret: 's',
				redirectUri: 'http://localhost:9926/oauth/azure/callback',
				fetchEmail: true,
			};
			provider = new OAuthProvider(azureConfig, mockLogger);

			try {
				const idTokenClaimsNoEmail = {
					sub: 'azure-sub-1',
					oid: 'victim-oid',
					iss: 'https://login.microsoftonline.com/common/v2.0',
				};
				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo.mail, undefined, "the mismatched oid's Graph fields must not be merged in");
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('Graph id/oid correlation also works via userInfoUrl host alone (generic provider pointed at graph.microsoft.com)', async () => {
			// isAzureGraphUserInfo() has two arms: provider === 'azure', and the
			// userInfoUrl host. This exercises the host arm specifically (no
			// provider: 'azure'/'microsoft'), which is what makes the correlation
			// work for the 'microsoft' alias (providers/index.ts) and for a custom
			// provider config that points userInfoUrl at Graph without declaring
			// provider: 'azure'.
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({ id: 'aaaa-oid-1234', mail: 'alice@contoso.example' }),
			});

			const graphHostConfig = {
				...mockConfig,
				provider: 'generic',
				userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
				fetchEmail: true,
			};
			provider = new OAuthProvider(graphHostConfig, mockLogger);

			try {
				const idTokenClaimsNoEmail = {
					sub: 'azure-sub-1',
					oid: 'aaaa-oid-1234',
					iss: 'https://login.microsoftonline.com/common/v2.0',
				};
				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo.mail, 'alice@contoso.example', 'host-only match correlates via oid/id');
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('the id/oid pairing is rejected for a non-Azure, non-Graph provider (no alternate pairing outside Azure/Graph)', async () => {
			// Same Graph-shaped response (id, no sub) and a matching oid claim, but
			// on a plain generic provider whose userInfoUrl is not graph.microsoft.com
			// — the alternate pairing must not apply here.
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({ id: 'aaaa-oid-1234', mail: 'alice@contoso.example' }),
			});

			const genericConfig = { ...mockConfig, fetchEmail: true };
			provider = new OAuthProvider(genericConfig, mockLogger);

			try {
				const idTokenClaimsNoEmail = { sub: 'some-sub', oid: 'aaaa-oid-1234', iss: 'https://issuer.example.com' };
				const userInfo = await provider.getUserInfo('access-token', idTokenClaimsNoEmail);
				assert.equal(userInfo.mail, undefined, 'id/oid pairing must not correlate outside Azure/Graph');
				assert.equal(userInfo._emailProvenance, 'unauthenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should return signed-oidc with id token claims intact (no UserInfo merge)', async () => {
			// Confirms the idTokenClaims path is a simple passthrough with signed-oidc tag.
			// No UserInfo fetch happens regardless of fetchEmail.
			const configWithFetchEmail = {
				...mockConfig,
				fetchEmail: true,
			};
			provider = new OAuthProvider(configWithFetchEmail, mockLogger);

			const idTokenClaims = {
				sub: 'u1',
				iss: 'https://real.issuer.example.com',
				email: 'user@example.com',
				email_verified: true,
				name: 'Real User',
			};

			const userInfo = await provider.getUserInfo('access-token', idTokenClaims, true);
			assert.equal(userInfo.iss, 'https://real.issuer.example.com');
			assert.equal(userInfo.sub, 'u1');
			assert.equal(userInfo.email, 'user@example.com');
			assert.equal(userInfo.email_verified, true);
			assert.equal(userInfo._emailProvenance, 'signed-oidc');
		});
	});

	describe('fetchUserInfo', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should throw on HTTP error response', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				statusText: 'Unauthorized',
			});

			try {
				await assert.rejects(async () => await provider.fetchUserInfo('invalid-token'), {
					message: /Failed to fetch user info.*Unauthorized/i,
				});
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('should strip _emailProvenance from raw UserInfo response', async () => {
			// Remote data must never supply a trusted provenance value. fetchUserInfo
			// strips _emailProvenance so an attacker-controlled UserInfo body cannot
			// inject a trusted provenance tag.
			const originalFetch = global.fetch;
			global.fetch = async () => ({
				ok: true,
				json: async () => ({
					sub: 'u1',
					email: 'user@example.com',
					_emailProvenance: 'signed-oidc', // injected by attacker
				}),
			});
			try {
				const result = await provider.fetchUserInfo('access-token');
				assert.equal('_emailProvenance' in result, false, '_emailProvenance must be stripped');
				assert.equal(result.email, 'user@example.com');
			} finally {
				global.fetch = originalFetch;
			}
		});
	});

	describe('mapUserToHarper', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should throw when username claim is missing', () => {
			const userInfoNoEmail = {
				sub: '123',
				name: 'User',
			};

			assert.throws(
				() => {
					provider.mapUserToHarper(userInfoNoEmail);
				},
				{
					message: /Username claim 'email' not found/i,
				}
			);
		});

		it('should handle different provider user ID fields', () => {
			const userInfoWithId = {
				email: 'user@example.com',
				id: 'provider-id-123',
			};

			const harperUser = provider.mapUserToHarper(userInfoWithId);
			assert.equal(harperUser.providerUserId, 'provider-id-123');
		});

		it('should handle user_id field', () => {
			const userInfoWithUserId = {
				email: 'user@example.com',
				user_id: 'user-id-456',
			};

			const harperUser = provider.mapUserToHarper(userInfoWithUserId);
			assert.equal(harperUser.providerUserId, 'user-id-456');
		});

		it('should include metadata with OAuth claims', () => {
			const userInfo = {
				email: 'user@example.com',
				sub: '123',
				custom_field: 'custom_value',
			};

			const harperUser = provider.mapUserToHarper(userInfo);
			assert.ok(harperUser.metadata);
			assert.equal(harperUser.metadata.oauthProvider, 'test');
			assert.deepEqual(harperUser.metadata.oauthClaims, userInfo);
		});

		it('should read email from config.emailClaim when set', () => {
			const configWithEmailClaim = {
				...mockConfig,
				emailClaim: 'upn', // Azure uses 'upn' or similar custom claim
			};
			const providerWithEmailClaim = new OAuthProvider(configWithEmailClaim, mockLogger);

			const userInfo = {
				email: 'user@example.com',
				upn: 'azure-user@corp.onmicrosoft.com',
				sub: '123',
			};

			const harperUser = providerWithEmailClaim.mapUserToHarper(userInfo);
			assert.equal(
				harperUser.email,
				'azure-user@corp.onmicrosoft.com',
				'emailClaim must override the default email field'
			);
		});

		it('should set emailVerified undefined when emailClaim is not the standard email claim', () => {
			// email_verified only attests the standard 'email' claim. When emailClaim is
			// a custom field, there is no trustworthy paired verified flag, so emailVerified
			// must be undefined to prevent the adoption gate from passing.
			const configWithEmailClaim = {
				...mockConfig,
				emailClaim: 'upn',
			};
			const providerWithEmailClaim = new OAuthProvider(configWithEmailClaim, mockLogger);

			const userInfo = {
				upn: 'azure-user@corp.onmicrosoft.com',
				email: 'user@example.com',
				email_verified: true,
				sub: '123',
			};

			const harperUser = providerWithEmailClaim.mapUserToHarper(userInfo);
			assert.equal(
				harperUser.emailVerified,
				undefined,
				'emailVerified must be undefined when emailClaim is not standard email'
			);
		});

		it('should fall back to email field when emailClaim is not set', () => {
			const userInfo = {
				email: 'user@example.com',
				sub: '123',
			};

			const harperUser = provider.mapUserToHarper(userInfo);
			assert.equal(harperUser.email, 'user@example.com');
		});
	});

	describe('ID Token Verification', () => {
		beforeEach(() => {
			provider = new OAuthProvider(mockConfig, mockLogger);
		});

		it('should throw on invalid ID token format', async () => {
			await assert.rejects(async () => await provider.verifyIdToken('invalid.token'), {
				message: /Invalid ID token format/i,
			});
		});

		it('no-JWKS path: token without exp is rejected (cannot be trusted)', async () => {
			// A JWT missing exp passes jwt.verify's expiry check (no exp = no expiry check),
			// but must still be rejected because an untimed token cannot be safely trusted.
			const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
			const payload = Buffer.from(
				JSON.stringify({
					sub: '123',
					aud: mockConfig.clientId,
					iat: Math.floor(Date.now() / 1000),
					// exp intentionally absent
				})
			).toString('base64url');
			const fakeToken = `${header}.${payload}.fake-signature`;

			// On the no-JWKS path, verifyIdTokenClaims is called. It requires exp.
			await assert.rejects(async () => await provider.verifyIdToken(fakeToken), { message: /expired|exp/i });
		});

		it('should warn when JWKS is not configured', async () => {
			let warnCalled = false;
			const loggerWithWarn = {
				...mockLogger,
				warn: (msg) => {
					if (msg.includes('verifying claims only')) {
						warnCalled = true;
					}
				},
			};

			provider = new OAuthProvider(mockConfig, loggerWithWarn);

			// Create a simple JWT token (not signed, just for testing claims verification)
			const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
			const payload = Buffer.from(
				JSON.stringify({
					sub: '123',
					aud: mockConfig.clientId,
					exp: Math.floor(Date.now() / 1000) + 3600, // Valid for 1 hour
					iat: Math.floor(Date.now() / 1000),
				})
			).toString('base64url');
			const fakeToken = `${header}.${payload}.fake-signature`;

			try {
				await provider.verifyIdToken(fakeToken);
				assert.ok(warnCalled, 'Should warn when JWKS not configured');
			} catch {
				// Expected to potentially fail, but should have warned
				assert.ok(warnCalled, 'Should warn when JWKS not configured');
			}
		});
	});

	describe('ID Token Verification with a real JWKS signature + OIDC discovery (#264)', () => {
		// jwks-rsa supports an injected `fetcher`, so these tests exercise real
		// RS256 signature verification (jwt.verify against a real key pair)
		// without any network I/O — the same approach `OAuthProvider`'s own
		// `initializeJwksClient` would use in production, just with the
		// fetcher substituted for a real jwks_uri the way the account-adoption
		// gate's own test fixtures substitute a real local server. The
		// private `jwksClient` field is overwritten after construction, the
		// same way this file already reaches into other private fields.
		let keyPair;
		const KID = 'test-key-1';

		before(() => {
			keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
		});

		beforeEach(() => {
			_clearDiscoveryCache();
			_setDnsLookup(async () => [{ address: '93.184.216.34', family: 4 }]);
		});
		afterEach(() => {
			_setFetch(null);
			_setDnsLookup(null);
		});

		function publicJwk() {
			const jwk = keyPair.publicKey.export({ format: 'jwk' });
			return { ...jwk, kid: KID, alg: 'RS256', use: 'sig' };
		}

		function attachRealJwksClient(provider, keys = [publicJwk()]) {
			provider['jwksClient'] = jwksRsa({
				jwksUri: 'https://idp.example.com/jwks', // never actually fetched — see `fetcher`
				fetcher: async () => ({ keys }),
				cache: true,
			});
		}

		function sign(claims, { kid = KID, key = keyPair.privateKey } = {}) {
			return jwt.sign(claims, key, { algorithm: 'RS256', keyid: kid });
		}

		function jsonResponse(body, status = 200) {
			const bytes = Buffer.from(JSON.stringify(body));
			return {
				ok: status >= 200 && status < 300,
				status,
				headers: new Map([['content-type', 'application/json']]),
				body: {
					getReader: () => {
						let sent = false;
						return {
							read: async () => {
								if (!sent) {
									sent = true;
									return { done: false, value: bytes };
								}
								return { done: true, value: undefined };
							},
							cancel: () => {},
						};
					},
				},
			};
		}

		describe('generic OIDC discovery (non-Azure)', () => {
			const discoveryConfig = {
				provider: 'generic',
				clientId: 'test-client-id',
				clientSecret: 'test-client-secret',
				authorizationUrl: 'https://idp.example.com/authorize',
				tokenUrl: 'https://idp.example.com/token',
				userInfoUrl: 'https://idp.example.com/userinfo',
				jwksUri: 'https://idp.example.com/jwks',
				redirectUri: 'https://app.test.com/oauth',
				issuer: undefined,
			};
			const WELL_KNOWN = 'https://idp.example.com/.well-known/openid-configuration';

			function discoveryDoc() {
				return {
					issuer: 'https://idp.example.com',
					authorization_endpoint: discoveryConfig.authorizationUrl,
					token_endpoint: discoveryConfig.tokenUrl,
					jwks_uri: discoveryConfig.jwksUri,
				};
			}

			it('a signature-verified token is upgraded to issuerValidated once discovery resolves', async () => {
				_setFetch(async () => jsonResponse(discoveryDoc()));
				startIssuerDiscovery(
					discoveryConfig.authorizationUrl,
					discoveryConfig.jwksUri,
					discoveryConfig.tokenUrl,
					'custom-idp'
				);

				const p = new OAuthProvider({ ...discoveryConfig }, mockLogger);
				attachRealJwksClient(p);

				const now = Math.floor(Date.now() / 1000);
				const token = sign({ iss: 'https://idp.example.com', sub: 'user-1', aud: discoveryConfig.clientId, iat: now, exp: now + 3600 });

				const result = await p.verifyIdToken(token);
				assert.equal(result.signatureVerified, true);
				assert.equal(result.issuerValidated, true);
				assert.equal(p.config.issuer, 'https://idp.example.com', 'the discovered issuer is cached onto config');
			});

			it('a forged/invalid-signature token never consumes the bounded first-login discovery wait', async () => {
				// A fetch that resolves after a short, real delay so there is a
				// genuine pending window the bogus call could (incorrectly) consume.
				_setFetch(async () => {
					await new Promise((resolve) => setTimeout(resolve, 30));
					return jsonResponse(discoveryDoc());
				});
				startIssuerDiscovery(
					discoveryConfig.authorizationUrl,
					discoveryConfig.jwksUri,
					discoveryConfig.tokenUrl,
					'custom-idp'
				);

				const p = new OAuthProvider({ ...discoveryConfig }, mockLogger);
				attachRealJwksClient(p);

				const now = Math.floor(Date.now() / 1000);
				const otherKeyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
				const forgedToken = sign(
					{ iss: 'https://idp.example.com', sub: 'attacker', aud: discoveryConfig.clientId, iat: now, exp: now + 3600 },
					{ key: otherKeyPair.privateKey } // signed with a key NOT in the JWKS response
				);

				await assert.rejects(() => p.verifyIdToken(forgedToken));

				// A genuinely valid token right after it must still be the one that
				// gets to wait — proving the forged call above never consumed the slot.
				const validToken = sign({ iss: 'https://idp.example.com', sub: 'user-1', aud: discoveryConfig.clientId, iat: now, exp: now + 3600 });
				const result = await p.verifyIdToken(validToken);
				assert.equal(result.signatureVerified, true);
				assert.equal(result.issuerValidated, true, 'the valid call was still the first caller and got upgraded');
			});

			it('audience is still enforced on the discovery-eligible branch (shared verification options, not a parallel check)', async () => {
				_setFetch(async () => jsonResponse(discoveryDoc()));
				startIssuerDiscovery(
					discoveryConfig.authorizationUrl,
					discoveryConfig.jwksUri,
					discoveryConfig.tokenUrl,
					'custom-idp'
				);

				const p = new OAuthProvider({ ...discoveryConfig }, mockLogger);
				attachRealJwksClient(p);

				const now = Math.floor(Date.now() / 1000);
				const wrongAudienceToken = sign({
					iss: 'https://idp.example.com',
					sub: 'user-1',
					aud: 'some-other-client-id',
					iat: now,
					exp: now + 3600,
				});

				await assert.rejects(() => p.verifyIdToken(wrongAudienceToken), /audience/i);
			});

			it('a genuinely concurrent second login does not wait, even if discovery resolves moments later', async () => {
				let resolveFetch;
				_setFetch(
					() =>
						new Promise((resolve) => {
							resolveFetch = () => resolve(jsonResponse(discoveryDoc()));
						})
				);
				startIssuerDiscovery(
					discoveryConfig.authorizationUrl,
					discoveryConfig.jwksUri,
					discoveryConfig.tokenUrl,
					'custom-idp'
				);

				const p = new OAuthProvider({ ...discoveryConfig }, mockLogger);
				attachRealJwksClient(p);

				const now = Math.floor(Date.now() / 1000);
				const tokenA = sign({ iss: 'https://idp.example.com', sub: 'user-a', aud: discoveryConfig.clientId, iat: now, exp: now + 3600 });
				const tokenB = sign({ iss: 'https://idp.example.com', sub: 'user-b', aud: discoveryConfig.clientId, iat: now, exp: now + 3600 });

				const firstCall = p.verifyIdToken(tokenA);
				await new Promise((resolve) => setTimeout(resolve, 5)); // let the first call claim the await slot
				const secondResult = await p.verifyIdToken(tokenB);
				assert.equal(secondResult.issuerValidated, false, 'a concurrent second login does not wait');

				resolveFetch();
				const firstResult = await firstCall;
				assert.equal(firstResult.issuerValidated, true, 'the first login is upgraded once discovery resolves');
			});
		});

		describe('Azure alias authority pinned to a single tenant (collapses into the ordinary configured-issuer path)', () => {
			const GUID = '12345678-1234-1234-1234-123456789012';

			it('constructing OAuthProvider directly (bypassing buildProviderConfig, like TenantManager) still resolves the safe tenant-specific binding', () => {
				const handBuiltConfig = {
					provider: 'azure',
					clientId: 'c',
					clientSecret: 's',
					authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
					tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
					userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
					jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
					issuer: `https://login.microsoftonline.com/${GUID}/v2.0`,
					redirectUri: 'https://app.test.com/oauth',
				};

				const p = new OAuthProvider(handBuiltConfig, mockLogger);
				assert.equal(p.config.jwksUri, `https://login.microsoftonline.com/${GUID}/discovery/v2.0/keys`);
				assert.equal(p.config.issuer, `https://login.microsoftonline.com/${GUID}/v2.0`);
			});

			it('constructing OAuthProvider directly with an array pin on an alias still throws', () => {
				const handBuiltConfig = {
					provider: 'azure',
					clientId: 'c',
					clientSecret: 's',
					authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
					tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
					userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
					jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
					issuer: [`https://login.microsoftonline.com/${GUID}/v2.0`, 'https://login.microsoftonline.com/other/v2.0'],
					redirectUri: 'https://app.test.com/oauth',
				};

				assert.throws(() => new OAuthProvider(handBuiltConfig, mockLogger), /array/);
			});

			it('a token matching the pinned tenant verifies through the ordinary issuer-configured path', async () => {
				const handBuiltConfig = {
					provider: 'azure',
					clientId: 'c',
					clientSecret: 's',
					authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
					tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
					userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
					jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
					issuer: `https://login.microsoftonline.com/${GUID}/v2.0`,
					redirectUri: 'https://app.test.com/oauth',
				};
				const p = new OAuthProvider(handBuiltConfig, mockLogger);
				attachRealJwksClient(p);

				const now = Math.floor(Date.now() / 1000);
				const token = sign({
					iss: `https://login.microsoftonline.com/${GUID}/v2.0`,
					sub: 'user-1',
					tid: GUID,
					aud: 'c',
					iat: now,
					exp: now + 3600,
				});

				const result = await p.verifyIdToken(token);
				assert.equal(result.signatureVerified, true);
				assert.equal(result.issuerValidated, true);
			});

			it('a token claiming a different tenant than the pin is refused (not adoption-eligible)', async () => {
				const otherGuid = '87654321-4321-4321-4321-210987654321';
				const handBuiltConfig = {
					provider: 'azure',
					clientId: 'c',
					clientSecret: 's',
					authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
					tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
					userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
					jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
					issuer: `https://login.microsoftonline.com/${GUID}/v2.0`,
					redirectUri: 'https://app.test.com/oauth',
				};
				const p = new OAuthProvider(handBuiltConfig, mockLogger);
				attachRealJwksClient(p);

				const now = Math.floor(Date.now() / 1000);
				const token = sign({
					iss: `https://login.microsoftonline.com/${otherGuid}/v2.0`,
					sub: 'attacker',
					tid: otherGuid,
					aud: 'c',
					iat: now,
					exp: now + 3600,
				});

				await assert.rejects(() => p.verifyIdToken(token), /issuer/i);
			});
		});
	});
});
