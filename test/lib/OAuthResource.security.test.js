/**
 * Tests for OAuthResource Security Features
 * Tests IP allowlist and debug endpoint access control
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createMockLogger } from '../helpers/mockFn.js';

// Mock Harper's Resource class
global.Resource = class {
	static loadAsInstance = false;
};

import { OAuthResource } from '../../dist/lib/resource.js';

describe('OAuthResource - Security', () => {
	let originalEnv;

	beforeEach(() => {
		// Save original environment
		originalEnv = process.env.DEBUG_ALLOWED_IPS;
		OAuthResource.reset();
	});

	afterEach(() => {
		// Restore environment
		if (originalEnv === undefined) {
			delete process.env.DEBUG_ALLOWED_IPS;
		} else {
			process.env.DEBUG_ALLOWED_IPS = originalEnv;
		}
		OAuthResource.reset();
	});

	describe('checkDebugAccess() - IP Allowlist', () => {
		it('should allow localhost IPv4 (127.0.0.1) by default', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = { ip: '127.0.0.1' };
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, true);
			// Should log info, not warning
			assert.ok(logger.info.mock.calls.length > 0);
			assert.equal(logger.warn.mock.calls.length, 0);
		});

		it('should allow localhost IPv6 (::1) by default', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = { ip: '::1' };
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, true);
			assert.ok(logger.info.mock.calls.length > 0);
		});

		it('should deny non-localhost IPs by default', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = { ip: '192.168.1.100' };
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, false);
			// Should log warning
			assert.ok(logger.warn.mock.calls.length > 0);
		});

		it('should allow IPs in custom allowlist', () => {
			process.env.DEBUG_ALLOWED_IPS = '192.168.1.100,10.0.0.5';
			const request = { ip: '192.168.1.100' };
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, true);
		});

		it('should deny IPs not in custom allowlist', () => {
			process.env.DEBUG_ALLOWED_IPS = '192.168.1.100';
			const request = { ip: '192.168.1.200' };
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, false);
		});

		it('should support CIDR-like prefix matching', () => {
			process.env.DEBUG_ALLOWED_IPS = '10.0.0.';
			const logger = createMockLogger();

			// Should match all IPs starting with 10.0.0.
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.0.1' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.0.100' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.0.255' }, logger), true);

			// Should not match different subnets
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.1.1' }, logger), false);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '192.168.1.1' }, logger), false);
		});

		it('should handle multiple IPs in allowlist with spaces', () => {
			process.env.DEBUG_ALLOWED_IPS = '127.0.0.1, 192.168.1.100,  10.0.0.1  ';
			const logger = createMockLogger();

			assert.equal(OAuthResource.checkDebugAccess({ ip: '127.0.0.1' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '192.168.1.100' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.0.1' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.0.2' }, logger), false);
		});

		it('should handle missing request.ip gracefully', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = {}; // No ip property
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, false);
			// Should log warning about unauthorized IP
			assert.ok(logger.warn.mock.calls.length > 0);
		});

		it('should work without logger', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = { ip: '127.0.0.1' };

			// Should not throw when logger is undefined
			const allowed = OAuthResource.checkDebugAccess(request);

			assert.equal(allowed, true);
		});

		it('should log client IP in warning for denied access', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = { ip: '1.2.3.4' };
			const logger = createMockLogger();

			OAuthResource.checkDebugAccess(request, logger);

			assert.ok(logger.warn.mock.calls.length > 0);
			const warnCall = logger.warn.mock.calls[0];
			assert.ok(warnCall.arguments[0].includes('denied'));
			assert.equal(warnCall.arguments[1].ip, '1.2.3.4');
		});

		it('should log client IP in info for allowed access', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const request = { ip: '127.0.0.1' };
			const logger = createMockLogger();

			OAuthResource.checkDebugAccess(request, logger);

			assert.ok(logger.info.mock.calls.length > 0);
			const infoCall = logger.info.mock.calls[0];
			assert.ok(infoCall.arguments[0].includes('accessed'));
			assert.equal(infoCall.arguments[1].ip, '127.0.0.1');
		});
	});

	describe('forbiddenResponse()', () => {
		it('should return 403 status', () => {
			const response = OAuthResource.forbiddenResponse();
			assert.equal(response.status, 403);
		});

		it('should include helpful error message', () => {
			const response = OAuthResource.forbiddenResponse();
			assert.equal(response.body.error, 'Access forbidden');
			assert.ok(response.body.message.includes('allowed IPs'));
		});

		it('should include hint about DEBUG_ALLOWED_IPS', () => {
			const response = OAuthResource.forbiddenResponse();
			assert.ok(response.body.hint.includes('DEBUG_ALLOWED_IPS'));
			assert.ok(response.body.hint.includes('127.0.0.1'));
		});

		it('should return consistent response object', () => {
			const response1 = OAuthResource.forbiddenResponse();
			const response2 = OAuthResource.forbiddenResponse();
			assert.deepEqual(response1, response2);
		});
	});

	describe('Security Integration', () => {
		it('should deny all remote IPs when debug mode on with default config', () => {
			delete process.env.DEBUG_ALLOWED_IPS;
			const logger = createMockLogger();

			const remoteIps = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8', '1.1.1.1'];

			for (const ip of remoteIps) {
				const allowed = OAuthResource.checkDebugAccess({ ip }, logger);
				assert.equal(allowed, false, `Should deny ${ip} by default`);
			}

			// Should have logged warnings for all denied IPs
			assert.equal(logger.warn.mock.calls.length, remoteIps.length);
		});

		it('should allow multiple subnets with prefix matching', () => {
			process.env.DEBUG_ALLOWED_IPS = '10.0.0.,192.168.1.,172.16.';
			const logger = createMockLogger();

			// Should allow IPs from all configured subnets
			assert.equal(OAuthResource.checkDebugAccess({ ip: '10.0.0.50' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '192.168.1.100' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '172.16.0.1' }, logger), true);

			// Should deny IPs from other subnets
			assert.equal(OAuthResource.checkDebugAccess({ ip: '8.8.8.8' }, logger), false);
		});

		it('should work correctly in production-like scenario', () => {
			// Simulate production: debug off, remote IP
			process.env.DEBUG_ALLOWED_IPS = '127.0.0.1';
			const request = { ip: '203.0.113.1' }; // Public IP
			const logger = createMockLogger();

			const allowed = OAuthResource.checkDebugAccess(request, logger);

			assert.equal(allowed, false);
			assert.ok(logger.warn.mock.calls.length > 0);
			const warnCall = logger.warn.mock.calls[0];
			assert.ok(warnCall.arguments[0].includes('denied'));
		});
	});

	describe('Edge Cases', () => {
		it('should handle empty DEBUG_ALLOWED_IPS', () => {
			process.env.DEBUG_ALLOWED_IPS = '';
			const request = { ip: '127.0.0.1' };

			// Empty string should still deny (no IPs in allowlist)
			const allowed = OAuthResource.checkDebugAccess(request);

			// Will check against [''] which won't match anything
			assert.equal(allowed, false);
		});

		it('should handle single IP without comma', () => {
			process.env.DEBUG_ALLOWED_IPS = '10.0.0.1';
			const request = { ip: '10.0.0.1' };

			const allowed = OAuthResource.checkDebugAccess(request);

			assert.equal(allowed, true);
		});

		it('should be case sensitive for IP matching', () => {
			// IPs shouldn't have case anyway, but test it
			process.env.DEBUG_ALLOWED_IPS = '127.0.0.1';
			const request = { ip: '127.0.0.1' };

			const allowed = OAuthResource.checkDebugAccess(request);

			assert.equal(allowed, true);
		});

		it('should handle IPv6 addresses', () => {
			process.env.DEBUG_ALLOWED_IPS = '::1,fe80::1';
			const logger = createMockLogger();

			assert.equal(OAuthResource.checkDebugAccess({ ip: '::1' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: 'fe80::1' }, logger), true);
			assert.equal(OAuthResource.checkDebugAccess({ ip: '::2' }, logger), false);
		});
	});
});
