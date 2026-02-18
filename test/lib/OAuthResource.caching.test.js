/**
 * Tests for OAuthResource dynamic provider caching via DynamicProviderCache
 * Verifies that dynamically resolved providers are cached or not based on config
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMockFn, createMockLogger } from '../helpers/mockFn.js';

import { OAuthResource } from '../../dist/lib/resource.js';
import { DynamicProviderCache } from '../../dist/lib/dynamicProviderCache.js';

describe('OAuthResource - cacheDynamicProviders', () => {
	let originalDatabases;
	let mockLogger;

	before(() => {
		originalDatabases = global.databases;
	});

	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		mockLogger = createMockLogger();

		// Mock databases for CSRF token manager
		global.databases = {
			oauth: {
				csrf_tokens: {
					get: async () => null,
					put: async () => {},
					delete: async () => {},
				},
			},
		};
	});

	afterEach(() => {
		OAuthResource.reset();
	});

	describe('configure()', () => {
		it('should default dynamicProviderCache to null when not provided', () => {
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger);
			assert.equal(OAuthResource.dynamicProviderCache, null);
		});

		it('should store DynamicProviderCache instance', () => {
			const cache = new DynamicProviderCache(false);
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger, cache);
			assert.equal(OAuthResource.dynamicProviderCache, cache);
		});

		it('should accept TTL-based cache', () => {
			const cache = new DynamicProviderCache(60);
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger, cache);
			assert.equal(OAuthResource.dynamicProviderCache, cache);
		});
	});

	describe('reset()', () => {
		it('should reset dynamicProviderCache to null', () => {
			const cache = new DynamicProviderCache(60);
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger, cache);
			assert.equal(OAuthResource.dynamicProviderCache, cache);

			OAuthResource.reset();
			assert.equal(OAuthResource.dynamicProviderCache, null);
		});
	});

	describe('dynamic provider resolution caching', () => {
		const hookConfig = {
			provider: 'github',
			clientId: 'test-client',
			clientSecret: 'test-secret',
			authorizationUrl: 'https://github.com/login/oauth/authorize',
			tokenUrl: 'https://github.com/login/oauth/access_token',
			userInfoUrl: 'https://api.github.com/user',
			scope: 'user:email',
			usernameClaim: 'login',
		};

		it('should cache resolved provider when cache is enabled (true)', async () => {
			const callResolveProvider = createMockFn(async () => hookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(true);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const mockRequest = {
				session: { id: 'session-123' },
				headers: {},
			};

			const resource = new OAuthResource();
			resource.getContext = () => mockRequest;
			const target = { id: 'dynamic-provider/login', get: () => null };

			// First call - should resolve via hook and redirect to OAuth provider
			const result = await resource.get(target);
			assert.equal(result.status, 302, 'Should redirect to OAuth provider');
			assert.equal(callResolveProvider.mock.calls.length, 1);

			// Provider should be cached in dynamic cache (not in static providers)
			assert.ok(cache.get('dynamic-provider'), 'Provider should be cached in dynamic cache');

			// Second call - should use cache, not call hook again
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 1, 'Hook should not be called again for cached provider');
		});

		it('should NOT cache resolved provider when cache is disabled (false)', async () => {
			const callResolveProvider = createMockFn(async () => hookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(false);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const mockRequest = {
				session: { id: 'session-123' },
				headers: {},
			};

			const resource = new OAuthResource();
			resource.getContext = () => mockRequest;
			const target = { id: 'dynamic-provider/login', get: () => null };

			// First call - should resolve via hook
			const result = await resource.get(target);
			assert.equal(result.status, 302, 'Should redirect to OAuth provider');
			assert.equal(callResolveProvider.mock.calls.length, 1);

			// Provider should NOT be cached
			assert.equal(cache.get('dynamic-provider'), undefined, 'Provider should not be cached');
			assert.equal(OAuthResource.providers['dynamic-provider'], undefined, 'Provider should not be in static registry');

			// Second call - should call hook again (not cached)
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 2, 'Hook should be called again for uncached provider');
		});

		it('should cache with TTL and expire after timeout', async () => {
			const callResolveProvider = createMockFn(async () => hookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(30);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const mockRequest = {
				session: { id: 'session-123' },
				headers: {},
			};

			const resource = new OAuthResource();
			resource.getContext = () => mockRequest;
			const target = { id: 'dynamic-provider/login', get: () => null };

			// First call - resolves via hook
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 1);

			// Second call - uses cache
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 1, 'Should use cache within TTL');

			// Advance time past TTL
			const realNow = Date.now;
			Date.now = () => realNow() + 31_000;
			try {
				// Third call - cache expired, should call hook again
				await resource.get(target);
				assert.equal(callResolveProvider.mock.calls.length, 2, 'Hook should be called again after TTL expires');
			} finally {
				Date.now = realNow;
			}
		});
	});
});
