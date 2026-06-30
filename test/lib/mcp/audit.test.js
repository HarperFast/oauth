/**
 * Tests for the MCP audit channel (emitMCPAuditEvent).
 *
 * Verifies:
 *  - oauth.mcp.token.issued fires with the correct payload shape
 *  - oauth.mcp.token.refreshed fires with the correct payload shape
 *  - No token material (access_token, refresh_token strings) appears in the emitted payload
 *  - The logger is called with info level (not error/warn/debug)
 *  - Emission does not throw
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// harper-mock stubs `logger` as a plain object with noop methods; we need to
// intercept the call. The mock is loaded by the --import flag, so we can
// import 'harper' and swap out the `info` method to spy on it.
import { logger as harperMockLogger } from 'harper';

// Import the function under test from the dist (built) output.
import { emitMCPAuditEvent } from '../../../dist/lib/mcp/audit.js';

const BASE_PAYLOAD = {
	event: /** @type {const} */ ('oauth.mcp.token.issued'),
	client_id: 'client-abc',
	sub: 'alice@example.com',
	aud: 'https://app.example.com/mcp',
	scope: 'mcp:read',
	jti: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
	timestamp: '2024-01-01T00:00:00.000Z',
};

describe('emitMCPAuditEvent', () => {
	let infoCalls;
	let originalInfo;

	beforeEach(() => {
		infoCalls = [];
		originalInfo = harperMockLogger.info;
		harperMockLogger.info = (...args) => infoCalls.push(args);
	});

	// Restore after each test so other tests in the suite see the original mock.
	// node:test doesn't provide afterEach for individual describe-level cleanup
	// from the outside, so we do it inline within each test.

	it('emits oauth.mcp.token.issued with the correct payload shape', () => {
		emitMCPAuditEvent(BASE_PAYLOAD);
		harperMockLogger.info = originalInfo;

		assert.equal(infoCalls.length, 1, 'exactly one info log emitted');
		const logged = infoCalls[0][0];
		assert.ok(typeof logged === 'string', 'logged argument is a string');
		const parsed = JSON.parse(logged.replace(/^MCP audit: /, ''));
		assert.equal(parsed.event, 'oauth.mcp.token.issued');
		assert.equal(parsed.client_id, BASE_PAYLOAD.client_id);
		assert.equal(parsed.sub, BASE_PAYLOAD.sub);
		assert.equal(parsed.aud, BASE_PAYLOAD.aud);
		assert.equal(parsed.scope, BASE_PAYLOAD.scope);
		assert.equal(parsed.jti, BASE_PAYLOAD.jti);
		assert.ok(parsed.timestamp, 'timestamp present');
	});

	it('emits oauth.mcp.token.refreshed with the correct payload shape', () => {
		const payload = { ...BASE_PAYLOAD, event: /** @type {const} */ ('oauth.mcp.token.refreshed') };
		emitMCPAuditEvent(payload);
		harperMockLogger.info = originalInfo;

		assert.equal(infoCalls.length, 1);
		const parsed = JSON.parse(infoCalls[0][0].replace(/^MCP audit: /, ''));
		assert.equal(parsed.event, 'oauth.mcp.token.refreshed');
		assert.equal(parsed.client_id, payload.client_id);
		assert.equal(parsed.sub, payload.sub);
		assert.equal(parsed.aud, payload.aud);
		assert.equal(parsed.jti, payload.jti);
	});

	it('never includes token strings in the emitted payload', () => {
		// Verify no token-shaped keys appear in what was logged.
		// emitMCPAuditEvent signature doesn't accept token strings — but confirm
		// no field sneaks through that looks like an actual credential.
		emitMCPAuditEvent(BASE_PAYLOAD);
		harperMockLogger.info = originalInfo;

		const logged = infoCalls[0][0];
		const BANNED_KEYS = ['access_token', 'refresh_token', 'id_token', 'client_secret'];
		for (const key of BANNED_KEYS) {
			assert.ok(!logged.includes(`"${key}"`), `"${key}" must not appear in audit log`);
		}
	});

	it('emits with a timestamp in ISO-8601 UTC format', () => {
		const payload = { ...BASE_PAYLOAD, timestamp: new Date().toISOString() };
		emitMCPAuditEvent(payload);
		harperMockLogger.info = originalInfo;

		const parsed = JSON.parse(infoCalls[0][0].replace(/^MCP audit: /, ''));
		assert.ok(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$/.test(parsed.timestamp), 'timestamp is ISO-8601 UTC');
	});

	it('does not throw when the logger is suppressed (info is undefined)', () => {
		// Simulate the logger being at a higher level so info is undefined (no-op).
		harperMockLogger.info = undefined;
		assert.doesNotThrow(() => emitMCPAuditEvent(BASE_PAYLOAD), 'emitMCPAuditEvent must not throw');
		harperMockLogger.info = originalInfo;
	});

	it('emits without scope when scope is undefined', () => {
		const { scope, ...noScope } = BASE_PAYLOAD;
		void scope;
		emitMCPAuditEvent(noScope);
		harperMockLogger.info = originalInfo;

		const parsed = JSON.parse(infoCalls[0][0].replace(/^MCP audit: /, ''));
		assert.equal(parsed.scope, undefined);
	});
});
