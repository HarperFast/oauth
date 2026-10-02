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
			redirectUri: 'https://app.test.com/oauth',
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

	describe('dynamic resolution — invalid Azure issuer pin (#264/#271)', () => {
		const badAzureHookConfig = {
			provider: 'azure',
			clientId: 'c',
			clientSecret: 's',
			// A stale pin that doesn't name the configured tenant — buildProviderConfig throws AzureIssuerBindingError.
			tenantId: '12345678-1234-1234-1234-123456789012',
			issuer: 'https://login.microsoftonline.com/87654321-4321-4321-4321-210987654321/v2.0',
			redirectUri: 'https://app.test.com/oauth',
		};

		it('returns 500 and does not cache a provider, naming the real cause in the log', async () => {
			const callResolveProvider = createMockFn(async () => badAzureHookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(true);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const resource = new OAuthResource();
			resource.getContext = () => ({ session: { id: 'session-123' }, headers: {} });
			const target = { id: 'bad-azure-tenant/login', get: () => null };

			const result = await resource.get(target);
			assert.equal(result.status, 500);
			assert.equal(cache.get('bad-azure-tenant'), undefined, 'no provider is cached for a failed resolution');
			assert.ok(
				mockLogger.error.mock.calls.some((call) =>
					call.arguments.some(
						(arg) =>
							typeof arg === 'string' && arg.includes('invalid Azure issuer pin') && arg.includes('different tenant')
					)
				),
				'the log names the real cause, not a generic "Error resolving provider"'
			);
		});

		it('does not re-run the resolve hook for the same provider within the cooldown — short-circuits to the same 500', async () => {
			const callResolveProvider = createMockFn(async () => badAzureHookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(true);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const resource = new OAuthResource();
			resource.getContext = () => ({ session: { id: 'session-123' }, headers: {} });
			const target = { id: 'bad-azure-tenant/login', get: () => null };

			const first = await resource.get(target);
			assert.equal(first.status, 500);
			assert.equal(callResolveProvider.mock.calls.length, 1);

			const second = await resource.get(target);
			assert.equal(second.status, 500);
			assert.equal(
				callResolveProvider.mock.calls.length,
				1,
				'the hook must not be re-run while the failure is cooling down'
			);
		});

		it('re-runs the resolve hook once the cooldown elapses', async () => {
			const callResolveProvider = createMockFn(async () => badAzureHookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(true);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const resource = new OAuthResource();
			resource.getContext = () => ({ session: { id: 'session-123' }, headers: {} });
			const target = { id: 'bad-azure-tenant/login', get: () => null };

			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 1);

			const realNow = Date.now;
			Date.now = () => realNow() + 31_000;
			try {
				await resource.get(target);
				assert.equal(callResolveProvider.mock.calls.length, 2, 'the hook runs again once the 30s cooldown elapses');
			} finally {
				Date.now = realNow;
			}
		});
	});

	describe('dynamic resolution — Azure tenant-mismatch warning reaches the log, deduped (#271 follow-up)', () => {
		const mismatchedAzureHookConfig = {
			provider: 'azure',
			clientId: 'c',
			clientSecret: 's',
			// authorizationUrl names the shared 'common' alias; jwksUri names one real
			// tenant. Unpinned, buildProviderConfig derives the tenant-exclusive
			// issuer (the safe direction) but also warns about the mismatch — this
			// only reaches the log at all once a logger is passed through.
			authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
			jwksUri: 'https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/discovery/v2.0/keys',
			redirectUri: 'https://app.test.com/oauth',
		};

		it('passes the logger through so the mismatch warning fires for a dynamically-resolved provider', async () => {
			const callResolveProvider = createMockFn(async () => mismatchedAzureHookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			const cache = new DynamicProviderCache(true);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const resource = new OAuthResource();
			resource.getContext = () => ({ session: { id: 'session-123' }, headers: {} });
			const target = { id: 'mismatched-azure/login', get: () => null };

			const result = await resource.get(target);
			assert.equal(result.status, 302, 'the mismatch is advisory only — the provider still resolves');
			assert.ok(
				mockLogger.warn.mock.calls.some((call) =>
					call.arguments.some((arg) => typeof arg === 'string' && arg.includes('mismatched-azure'))
				),
				'the warning reaches the log now that resource.ts passes the logger to buildProviderConfig'
			);
		});

		it('does not repeat the same warning on every request — dedup survives even with caching disabled', async () => {
			const callResolveProvider = createMockFn(async () => mismatchedAzureHookConfig);
			const mockHookManager = {
				hasHook: (name) => name === 'onResolveProvider',
				callResolveProvider,
			};

			// Cache disabled: every request re-runs the hook and rebuilds the
			// config, which is exactly the "every request" case the dedup exists
			// to stop from flooding the log.
			const cache = new DynamicProviderCache(false);
			OAuthResource.configure({}, false, mockHookManager, {}, mockLogger, cache);

			const resource = new OAuthResource();
			resource.getContext = () => ({ session: { id: 'session-123' }, headers: {} });
			const target = { id: 'mismatched-azure/login', get: () => null };

			await resource.get(target);
			await resource.get(target);
			await resource.get(target);
			assert.equal(callResolveProvider.mock.calls.length, 3, 'the hook does re-run every request (cache disabled)');

			const matchingWarnings = mockLogger.warn.mock.calls.filter((call) =>
				call.arguments.some((arg) => typeof arg === 'string' && arg.includes('mismatched-azure'))
			);
			assert.equal(matchingWarnings.length, 1, 'the warning logs once, not once per request');
		});
	});
});
