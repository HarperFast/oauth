/**
 * Tests for OAuthResource Response Builders
 * Tests static methods that build various response objects
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';

// Mock Harper's Resource class
global.Resource = class {
	static loadAsInstance = false;
};

import { OAuthResource } from '../../dist/lib/resource.js';

describe('OAuthResource - Response Builders', () => {
	afterEach(() => {
		OAuthResource.reset();
	});

	describe('buildProviderListResponse()', () => {
		it('should build response with empty providers', () => {
			const providers = {};
			const response = OAuthResource.buildProviderListResponse(providers);

			assert.equal(response.message, 'OAuth providers');
			assert.equal(response.logout, 'POST /oauth/logout');
			assert.ok(Array.isArray(response.providers));
			assert.equal(response.providers.length, 0);
		});

		it('should build response with single provider', () => {
			const providers = {
				github: {
					config: {
						provider: 'github',
						clientId: 'test-id',
					},
				},
			};
			const response = OAuthResource.buildProviderListResponse(providers);

			assert.equal(response.providers.length, 1);
			assert.equal(response.providers[0].name, 'github');
			assert.equal(response.providers[0].provider, 'github');
			assert.ok(response.providers[0].endpoints);
			assert.equal(response.providers[0].endpoints.login, '/oauth/github/login');
			assert.equal(response.providers[0].endpoints.callback, '/oauth/github/callback');
			assert.equal(response.providers[0].endpoints.user, '/oauth/github/user');
			assert.equal(response.providers[0].endpoints.refresh, '/oauth/github/refresh');
			assert.equal(response.providers[0].endpoints.test, '/oauth/github/test');
		});

		it('should build response with multiple providers', () => {
			const providers = {
				github: {
					config: {
						provider: 'github',
					},
				},
				google: {
					config: {
						provider: 'google',
					},
				},
				azure: {
					config: {
						provider: 'azure',
					},
				},
			};
			const response = OAuthResource.buildProviderListResponse(providers);

			assert.equal(response.providers.length, 3);
			const providerNames = response.providers.map((p) => p.name);
			assert.ok(providerNames.includes('github'));
			assert.ok(providerNames.includes('google'));
			assert.ok(providerNames.includes('azure'));
		});

		it('should include correct endpoint paths for each provider', () => {
			const providers = {
				'custom-provider': {
					config: {
						provider: 'custom',
					},
				},
			};
			const response = OAuthResource.buildProviderListResponse(providers);

			const endpoints = response.providers[0].endpoints;
			assert.equal(endpoints.login, '/oauth/custom-provider/login');
			assert.equal(endpoints.callback, '/oauth/custom-provider/callback');
			assert.equal(endpoints.user, '/oauth/custom-provider/user');
			assert.equal(endpoints.refresh, '/oauth/custom-provider/refresh');
			assert.equal(endpoints.test, '/oauth/custom-provider/test');
		});
	});

	describe('buildProviderInfoResponse()', () => {
		it('should return 404 for non-existent provider', () => {
			const providers = {
				github: { config: { provider: 'github' } },
			};
			const response = OAuthResource.buildProviderInfoResponse('google', providers);

			assert.equal(response.status, 404);
			assert.equal(response.body.error, 'Provider not found');
			assert.deepEqual(response.body.available, ['github']);
		});

		it('should build info response for existing provider', () => {
			const providers = {
				github: {
					config: {
						provider: 'github',
						clientId: 'test-id',
					},
				},
			};
			const response = OAuthResource.buildProviderInfoResponse('github', providers);

			assert.equal(response.message, 'OAuth provider: github');
			assert.equal(response.provider, 'github');
			assert.equal(response.configured, true);
			assert.equal(response.logout, 'POST /oauth/logout');
			assert.ok(response.endpoints);
		});

		it('should include correct endpoints', () => {
			const providers = {
				google: {
					config: {
						provider: 'google',
					},
				},
			};
			const response = OAuthResource.buildProviderInfoResponse('google', providers);

			assert.equal(response.endpoints.login, '/oauth/google/login');
			assert.equal(response.endpoints.callback, '/oauth/google/callback');
			assert.equal(response.endpoints.user, '/oauth/google/user');
			assert.equal(response.endpoints.refresh, '/oauth/google/refresh');
			assert.equal(response.endpoints.test, '/oauth/google/test');
		});

		it('should list available providers when provider not found', () => {
			const providers = {
				github: { config: { provider: 'github' } },
				google: { config: { provider: 'google' } },
				azure: { config: { provider: 'azure' } },
			};
			const response = OAuthResource.buildProviderInfoResponse('invalid', providers);

			assert.equal(response.status, 404);
			assert.equal(response.body.available.length, 3);
			assert.ok(response.body.available.includes('github'));
			assert.ok(response.body.available.includes('google'));
			assert.ok(response.body.available.includes('azure'));
		});
	});

	describe('buildTokenStatusResponse()', () => {
		it('should return 401 when no session', () => {
			const request = {};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 401);
			assert.equal(response.body.error, 'No OAuth session');
			assert.ok(response.body.message.includes('log in again'));
		});

		it('should return 401 when session has no oauth data', () => {
			const request = {
				session: {
					user: 'testuser',
				},
			};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 401);
			assert.equal(response.body.error, 'No OAuth session');
		});

		it('should return 401 when oauth data has no accessToken', () => {
			const request = {
				session: {
					user: 'testuser',
					oauth: {
						provider: 'github',
						// Missing accessToken
					},
				},
			};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 401);
			assert.equal(response.body.error, 'No OAuth session');
		});

		it('should return 200 with token status when valid session', () => {
			const now = Date.now();
			const request = {
				session: {
					user: 'testuser',
					oauth: {
						provider: 'github',
						accessToken: 'test-token',
						expiresAt: now + 3600000,
						lastRefreshed: now - 1000,
					},
				},
			};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 200);
			assert.equal(response.body.message, 'Token is valid');
			assert.equal(response.body.provider, 'github');
			assert.equal(response.body.expiresAt, now + 3600000);
			assert.equal(response.body.lastRefreshed, now - 1000);
		});

		it('should handle session with minimal oauth data', () => {
			const request = {
				session: {
					oauth: {
						accessToken: 'token',
						provider: 'google',
					},
				},
			};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 200);
			assert.equal(response.body.provider, 'google');
			assert.equal(response.body.expiresAt, undefined);
			assert.equal(response.body.lastRefreshed, undefined);
		});

		it('should handle empty string accessToken as invalid', () => {
			const request = {
				session: {
					oauth: {
						accessToken: '',
						provider: 'github',
					},
				},
			};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 401);
		});

		it('should handle null accessToken as invalid', () => {
			const request = {
				session: {
					oauth: {
						accessToken: null,
						provider: 'github',
					},
				},
			};
			const response = OAuthResource.buildTokenStatusResponse(request);

			assert.equal(response.status, 401);
		});
	});

	describe('Response Consistency', () => {
		it('should return same structure for repeated calls', () => {
			const providers = {
				github: { config: { provider: 'github' } },
			};

			const response1 = OAuthResource.buildProviderListResponse(providers);
			const response2 = OAuthResource.buildProviderListResponse(providers);

			assert.deepEqual(response1, response2);
		});

		it('should not mutate input providers object', () => {
			const providers = {
				github: { config: { provider: 'github' } },
			};
			const originalProviders = JSON.parse(JSON.stringify(providers));

			OAuthResource.buildProviderListResponse(providers);
			OAuthResource.buildProviderInfoResponse('github', providers);

			assert.deepEqual(providers, originalProviders);
		});

		it('should handle undefined session properties gracefully', () => {
			const request = {
				session: {
					oauth: {
						accessToken: 'token',
					},
				},
			};

			const response = OAuthResource.buildTokenStatusResponse(request);
			assert.equal(response.status, 200);
			// Should not throw when provider, expiresAt, etc. are undefined
		});
	});
});
