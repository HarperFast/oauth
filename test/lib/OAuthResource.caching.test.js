/**
 * Tests for OAuthResource cacheDynamicProviders flag
 * Verifies that dynamically resolved providers are cached or not based on config
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMockFn, createMockLogger } from '../helpers/mockFn.js';

import { OAuthResource } from '../../dist/lib/resource.js';

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
		it('should default cacheDynamicProviders to true', () => {
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger);
			assert.equal(OAuthResource.cacheDynamicProviders, true);
		});

		it('should set cacheDynamicProviders to false when specified', () => {
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger, false);
			assert.equal(OAuthResource.cacheDynamicProviders, false);
		});

		it('should set cacheDynamicProviders to true when specified', () => {
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger, true);
			assert.equal(OAuthResource.cacheDynamicProviders, true);
		});
	});

	describe('reset()', () => {
		it('should reset cacheDynamicProviders to true', () => {
			OAuthResource.configure({}, false, { hasHook: () => false }, {}, mockLogger, false);
			assert.equal(OAuthResource.cacheDynamicProviders, false);

			OAuthResource.reset();
			assert.equal(OAuthResource.cacheDynamicProviders, true);
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

		it('should cache resolved provider when cacheDynamicProviders is true', async () => {
			const callResolveProvider = createMockFn(async () => hookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			// Use login action (not debug-only) so debug mode doesn't matter
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, true);

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

			// Provider should be cached in registry
			assert.ok(OAuthResource.providers['dynamic-provider'], 'Provider should be cached in registry');

			// Second call - should use cache, not call hook again
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 1, 'Hook should not be called again for cached provider');
		});

		it('should NOT cache resolved provider when cacheDynamicProviders is false', async () => {
			const callResolveProvider = createMockFn(async () => hookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, false);

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
			assert.equal(OAuthResource.providers['dynamic-provider'], undefined, 'Provider should not be in registry');

			// Second call - should call hook again (not cached)
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 2, 'Hook should be called again for uncached provider');
		});
	});
});
