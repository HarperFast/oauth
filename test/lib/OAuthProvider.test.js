/**
 * Tests for OAuthProvider
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { OAuthProvider } from '../../dist/lib/OAuthProvider.js';

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
		redirectUri: 'https://localhost:9953/oauth/test/callback',
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
			assert.ok(storedRecord.created_at);
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

		it('should throw on token exchange failure', async () => {
			const originalFetch = global.fetch;

			global.fetch = async () => ({
				ok: false,
				text: async () => 'Invalid client credentials',
			});

			try {
				await assert.rejects(async () => await provider.exchangeCodeForToken('code', 'https://callback'), {
					message: /Token exchange failed.*Invalid client credentials/i,
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
	});
});
