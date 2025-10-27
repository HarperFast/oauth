/**
 * Tests for OAuth Resource
 */

import { describe, it, beforeEach, mock } from 'node:test';
import assert from 'node:assert/strict';

// Mock Harper's Resource class for testing
global.Resource = class {
	constructor() {}
	static loadAsInstance = true;
};

import { createOAuthResource } from '../../dist/lib/resource.js';

describe('OAuth Resource', () => {
	let mockProviders;
	let mockLogger;
	let mockHookManager;

	beforeEach(() => {
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

		mockProviders = {
			github: {
				provider: {
					generateCSRFToken: mock.fn(),
					getAuthorizationUrl: mock.fn(),
				},
				config: {
					provider: 'github',
					clientId: 'github-client',
				},
			},
			google: {
				provider: {
					generateCSRFToken: mock.fn(),
					getAuthorizationUrl: mock.fn(),
				},
				config: {
					provider: 'google',
					clientId: 'google-client',
				},
			},
		};
	});

	describe('createOAuthResource', () => {
		describe('Debug Mode OFF (Production)', () => {
			let resource;

			beforeEach(() => {
				resource = createOAuthResource(mockProviders, false, mockHookManager, mockLogger);
			});

			it('should return 404 for root path', async () => {
				const result = await resource.get('', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should return 404 for provider info', async () => {
				const result = await resource.get('github', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should return 404 for test endpoint', async () => {
				const result = await resource.get('test', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should return 404 for provider test endpoint', async () => {
				const result = await resource.get('github/test', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should return 404 for user endpoint', async () => {
				const result = await resource.get('github/user', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should return 404 for refresh endpoint', async () => {
				const result = await resource.get('github/refresh', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should allow login endpoint', async () => {
				const result = await resource.get('github/login', {
					headers: {},
					session: { id: 'test' },
				});
				// Should not return 404
				assert.notEqual(result.status, 404);
			});

			it('should allow callback endpoint', async () => {
				const target = {
					id: 'github/callback',
					get: () => 'test-code',
				};
				const result = await resource.get(target, {
					session: { id: 'test' },
				});
				// The actual callback will fail without proper setup, but it shouldn't be 404
				assert.notEqual(result.status, 404);
			});

			it('should handle unknown provider', async () => {
				const result = await resource.get('unknown/login', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Provider not found');
				assert.deepEqual(result.body.available, ['github', 'google']);
			});
		});

		describe('Debug Mode ON', () => {
			let resource;

			beforeEach(() => {
				resource = createOAuthResource(mockProviders, true, mockHookManager, mockLogger);
			});

			it('should show provider list at root', async () => {
				const result = await resource.get('', {});
				assert.equal(result.message, 'OAuth providers');
				assert.ok(Array.isArray(result.providers));
				assert.equal(result.providers.length, 2);
				assert.equal(result.providers[0].name, 'github');
				assert.ok(result.providers[0].endpoints);
			});

			it('should show provider info', async () => {
				const result = await resource.get('github', {});
				assert.equal(result.message, 'OAuth provider: github');
				assert.equal(result.configured, true);
				assert.ok(result.endpoints);
				assert.ok(result.endpoints.login);
				assert.ok(result.endpoints.callback);
				assert.ok(result.endpoints.test);
			});

			it('should allow test endpoint', async () => {
				const result = await resource.get('test', {});
				// Test page might fail to load in test env, but shouldn't be 404
				if (result.status === 404) {
					assert.fail('Test endpoint should be available in debug mode');
				}
			});

			it('should allow provider test endpoint', async () => {
				const result = await resource.get('github/test', {});
				// Test page might fail to load in test env, but shouldn't be 404
				if (result.status === 404) {
					assert.fail('Provider test endpoint should be available in debug mode');
				}
			});

			it('should allow user endpoint', async () => {
				const result = await resource.get('github/user', { session: {} });
				// Will return 401 without user, but not 404
				assert.notEqual(result.status, 404);
			});

			it('should allow refresh endpoint', async () => {
				const result = await resource.get('github/refresh', { session: {} });
				// Will return 401 without refresh token, but not 404
				assert.notEqual(result.status, 404);
			});

			it('should still show available providers for unknown provider', async () => {
				const result = await resource.get('unknown/login', {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Provider not found');
				assert.deepEqual(result.body.available, ['github', 'google']);
			});
		});

		describe('Request Target Handling', () => {
			let resource;

			beforeEach(() => {
				resource = createOAuthResource(mockProviders, false, mockHookManager, mockLogger);
			});

			it('should handle string target', async () => {
				const result = await resource.get('github/login', {
					headers: {},
					session: { id: 'test' },
				});
				assert.ok(result);
			});

			it('should handle object target with id', async () => {
				const target = {
					id: 'github/login',
					pathname: null,
				};
				const result = await resource.get(target, {
					headers: {},
					session: { id: 'test' },
				});
				assert.ok(result);
			});

			it('should handle object target with pathname', async () => {
				const target = {
					id: null,
					pathname: 'github/login',
				};
				const result = await resource.get(target, {
					headers: {},
					session: { id: 'test' },
				});
				assert.ok(result);
			});

			it('should handle target with query params for callback', async () => {
				const target = {
					id: 'github/callback',
					get: mock.fn((key) => {
						if (key === 'code') return 'auth-code';
						if (key === 'state') return 'csrf-token';
						return null;
					}),
				};

				// Add verifyCSRFToken method to mock provider
				mockProviders.github.provider.verifyCSRFToken = mock.fn(async () => null);

				const result = await resource.get(target, {
					session: { id: 'test' },
				});
				// Callback will fail without proper setup but should be called
				assert.ok(result);
			});
		});

		describe('POST Requests', () => {
			let resource;

			beforeEach(() => {
				resource = createOAuthResource(mockProviders, false, mockHookManager, mockLogger);
			});

			it('should handle logout POST request', async () => {
				const request = {
					session: {
						user: 'test-user',
						update: mock.fn(),
					},
				};
				const result = await resource.post('logout', {}, request);
				assert.equal(result.status, 200);
				assert.equal(result.body.message, 'Logged out successfully');
			});

			it('should reject non-logout POST requests', async () => {
				const result = await resource.post('github/login', {}, {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});

			it('should handle other POST endpoints', async () => {
				const result = await resource.post('github/something', {}, {});
				assert.equal(result.status, 404);
				assert.equal(result.body.error, 'Not found');
			});
		});
	});

	describe('Resource Creation', () => {
		it('should create resource with providers', () => {
			const resource = createOAuthResource(mockProviders, false, mockHookManager, mockLogger);
			assert.ok(resource);
			assert.equal(typeof resource.get, 'function');
			assert.equal(typeof resource.post, 'function');
		});

		it('should create different instances with different configs', () => {
			const resource1 = createOAuthResource(mockProviders, false, mockHookManager, mockLogger);
			const resource2 = createOAuthResource(mockProviders, true, mockHookManager, mockLogger);
			// Each resource is a new object
			assert.notEqual(resource1, resource2);
		});
	});
});
