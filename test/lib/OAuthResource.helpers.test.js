/**
 * Tests for OAuthResource Helper Methods
 * Tests static methods extracted for testability
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

// Note: Bun uses test/bun-preload.js to mock the harperdb module
// Node.js will load the real harperdb module, which may trigger async
// native module loading that continues after tests complete. This is harmless.

import { OAuthResource } from '../../dist/lib/resource.js';

describe('OAuthResource - Helper Methods', () => {
	afterEach(() => {
		// Reset configuration after each test
		OAuthResource.reset();
	});

	describe('parseRoute()', () => {
		it('should parse route with provider and action', () => {
			const target = { id: 'github/login', pathname: 'github/login' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, 'github');
			assert.equal(route.action, 'login');
			assert.equal(route.path, 'github/login');
		});

		it('should parse route with provider only', () => {
			const target = { id: 'github', pathname: 'github' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, 'github');
			assert.equal(route.action, '');
			assert.equal(route.path, 'github');
		});

		it('should parse empty route', () => {
			const target = { id: '', pathname: '' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, '');
			assert.equal(route.action, '');
			assert.equal(route.path, '');
		});

		it('should parse route with extra path segments', () => {
			const target = { id: 'github/callback/extra', pathname: 'github/callback/extra' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, 'github');
			assert.equal(route.action, 'callback');
			assert.equal(route.path, 'github/callback/extra');
		});

		it('should handle null/undefined id and pathname', () => {
			const target = { id: null, pathname: undefined };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, '');
			assert.equal(route.action, '');
			assert.equal(route.path, '');
		});

		it('should prefer id over pathname', () => {
			const target = { id: 'github/login', pathname: 'google/callback' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, 'github');
			assert.equal(route.action, 'login');
		});

		it('should handle numeric id', () => {
			const target = { id: 123, pathname: '' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.path, '123');
		});

		it('should filter out empty path segments', () => {
			const target = { id: '/github//login/', pathname: '' };
			const route = OAuthResource.parseRoute(target);

			assert.equal(route.providerName, 'github');
			assert.equal(route.action, 'login');
		});
	});

	describe('isDebugOnlyRoute()', () => {
		it('should identify root path as debug-only', () => {
			const route = { providerName: '', action: '', path: '' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), true);
		});

		it('should identify /test as debug-only', () => {
			const route = { providerName: 'test', action: '', path: 'test' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), true);
		});

		it('should identify provider/test as debug-only', () => {
			const route = { providerName: 'github', action: 'test', path: 'github/test' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), true);
		});

		it('should identify provider/user as debug-only', () => {
			const route = { providerName: 'github', action: 'user', path: 'github/user' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), true);
		});

		it('should identify provider/refresh as debug-only', () => {
			const route = { providerName: 'github', action: 'refresh', path: 'github/refresh' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), true);
		});

		it('should identify provider info (no action) as debug-only', () => {
			const route = { providerName: 'github', action: '', path: 'github' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), true);
		});

		it('should NOT identify provider/login as debug-only', () => {
			const route = { providerName: 'github', action: 'login', path: 'github/login' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), false);
		});

		it('should NOT identify provider/callback as debug-only', () => {
			const route = { providerName: 'github', action: 'callback', path: 'github/callback' };
			assert.equal(OAuthResource.isDebugOnlyRoute(route), false);
		});
	});

	describe('notFoundResponse()', () => {
		it('should return 404 status', () => {
			const response = OAuthResource.notFoundResponse();
			assert.equal(response.status, 404);
		});

		it('should return error message', () => {
			const response = OAuthResource.notFoundResponse();
			assert.equal(response.body.error, 'Not found');
		});

		it('should return consistent response object', () => {
			const response1 = OAuthResource.notFoundResponse();
			const response2 = OAuthResource.notFoundResponse();
			assert.deepEqual(response1, response2);
		});
	});

	describe('configure() and reset()', () => {
		it('should configure all properties', () => {
			const mockProviders = { github: { config: { provider: 'github' } } };
			const mockHookManager = { callOnLogin: () => {} };
			const mockLogger = { info: () => {} };

			OAuthResource.configure(mockProviders, true, mockHookManager, mockLogger);

			assert.equal(OAuthResource.providers, mockProviders);
			assert.equal(OAuthResource.debugMode, true);
			assert.equal(OAuthResource.hookManager, mockHookManager);
			assert.equal(OAuthResource.logger, mockLogger);
		});

		it('should allow configuration without logger', () => {
			const mockProviders = { github: { config: { provider: 'github' } } };
			const mockHookManager = { callOnLogin: () => {} };

			OAuthResource.configure(mockProviders, false, mockHookManager);

			assert.equal(OAuthResource.providers, mockProviders);
			assert.equal(OAuthResource.debugMode, false);
			assert.equal(OAuthResource.hookManager, mockHookManager);
			assert.equal(OAuthResource.logger, undefined);
		});

		it('should reset all properties to defaults', () => {
			const mockProviders = { github: { config: { provider: 'github' } } };
			const mockHookManager = { callOnLogin: () => {} };
			const mockLogger = { info: () => {} };

			OAuthResource.configure(mockProviders, true, mockHookManager, mockLogger);
			OAuthResource.reset();

			assert.deepEqual(OAuthResource.providers, {});
			assert.equal(OAuthResource.debugMode, false);
			assert.equal(OAuthResource.hookManager, null);
			assert.equal(OAuthResource.logger, undefined);
		});

		it('should allow reconfiguration', () => {
			const providers1 = { github: { config: { provider: 'github' } } };
			const providers2 = { google: { config: { provider: 'google' } } };
			const mockHookManager = { callOnLogin: () => {} };

			OAuthResource.configure(providers1, true, mockHookManager);
			assert.equal(Object.keys(OAuthResource.providers).length, 1);

			OAuthResource.configure(providers2, false, mockHookManager);
			assert.equal(Object.keys(OAuthResource.providers).length, 1);
			assert.ok(OAuthResource.providers.google);
			assert.equal(OAuthResource.debugMode, false);
		});
	});

	describe('getHookManager() and getProviders()', () => {
		beforeEach(() => {
			OAuthResource.reset();
		});

		it('should return null hookManager when not configured', () => {
			assert.equal(OAuthResource.getHookManager(), null);
		});

		it('should return empty providers when not configured', () => {
			assert.deepEqual(OAuthResource.getProviders(), {});
		});

		it('should return configured hookManager', () => {
			const mockHookManager = { callOnLogin: () => {} };
			const mockProviders = {};
			OAuthResource.configure(mockProviders, false, mockHookManager);

			assert.equal(OAuthResource.getHookManager(), mockHookManager);
		});

		it('should return configured providers', () => {
			const mockProviders = {
				github: { config: { provider: 'github' } },
				google: { config: { provider: 'google' } },
			};
			const mockHookManager = { callOnLogin: () => {} };
			OAuthResource.configure(mockProviders, false, mockHookManager);

			const providers = OAuthResource.getProviders();
			assert.equal(Object.keys(providers).length, 2);
			assert.ok(providers.github);
			assert.ok(providers.google);
		});
	});
});
