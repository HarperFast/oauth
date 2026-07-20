/**
 * Tests for the MCP POST dispatcher (src/lib/mcp/index.ts:handleMCPPost).
 *
 * Covers the deny paths and action routing that handleRegister-direct tests
 * intentionally skip: the master mcpConfig.enabled gate, the action map, and
 * the unknown-action fallthrough.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleMCPGet, handleMCPPost } from '../../../dist/lib/mcp/index.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';

const VALID_BODY = {
	redirect_uris: ['https://app.example.com/cb'],
	client_name: 'Test MCP Client',
};

function makeRequest(headers = {}) {
	return { headers };
}

describe('handleMCPPost (dispatcher)', () => {
	let originalDatabases;
	let storedRecords;

	before(() => {
		originalDatabases = global.databases;
	});

	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		resetMCPClientsTableCache();
		storedRecords = new Map();
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: {
					get: async (id) => storedRecords.get(id) || null,
					put: async (record) => {
						storedRecords.set(record.client_id, record);
					},
					delete: async (id) => {
						storedRecords.delete(id);
					},
				},
			},
		};
	});

	describe('master enable gate', () => {
		it('returns 404 when mcpConfig is undefined and never persists', async () => {
			const response = await handleMCPPost('register', makeRequest(), VALID_BODY, undefined);
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0, 'protected action must not run on deny path');
		});

		it('returns 404 when mcpConfig.enabled is false', async () => {
			const response = await handleMCPPost('register', makeRequest(), VALID_BODY, { enabled: false });
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});

		it('returns 404 when mcpConfig.enabled is undefined', async () => {
			const response = await handleMCPPost('register', makeRequest(), VALID_BODY, { dynamicClientRegistration: {} });
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});

		it('proceeds when mcpConfig.enabled is true', async () => {
			const response = await handleMCPPost('register', makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: {},
			});
			assert.equal(response.status, 201);
			assert.equal(storedRecords.size, 1);
		});
	});

	describe('action routing', () => {
		it('dispatches `register` to handleRegister', async () => {
			const response = await handleMCPPost('register', makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: {},
			});
			assert.equal(response.status, 201);
			assert.ok(response.body.client_id, 'register response carries an issued client_id');
		});

		it('returns 404 for an unknown action even when MCP is enabled', async () => {
			const response = await handleMCPPost('not-a-thing', makeRequest(), VALID_BODY, { enabled: true });
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});

		it('returns 404 for an empty action', async () => {
			const response = await handleMCPPost('', makeRequest(), VALID_BODY, { enabled: true });
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});
	});

	describe('layered deny: DCR sub-gate', () => {
		it('returns 404 when MCP is enabled but DCR is explicitly disabled', async () => {
			// The master gate passes (mcp.enabled=true) but handleRegister's own
			// gate (dynamicClientRegistration.enabled=false) trips. Either deny
			// path is acceptable — the contract is no registration happens.
			const response = await handleMCPPost('register', makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: { enabled: false },
			});
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});
	});
});

describe('handleMCPGet (dispatcher)', () => {
	function makeTarget(params = {}) {
		return {
			get(name) {
				return Object.prototype.hasOwnProperty.call(params, name) ? params[name] : undefined;
			},
		};
	}

	it('returns 404 when MCP is disabled', async () => {
		const response = await handleMCPGet('authorize', makeRequest(), makeTarget(), undefined, {});
		assert.equal(response.status, 404);
	});

	it('returns 404 for an unknown action', async () => {
		const response = await handleMCPGet('not-a-thing', makeRequest(), makeTarget(), { enabled: true }, {});
		assert.equal(response.status, 404);
	});

	it('dispatches authorize through handleAuthorize (verified via 400 invalid_request on empty query)', async () => {
		// handleAuthorize will hit phase-1 client_id validation; getting that 400
		// confirms the dispatcher routed us into authorize rather than the
		// catch-all 404.
		const response = await handleMCPGet('authorize', makeRequest(), makeTarget(), { enabled: true }, {});
		assert.equal(response.status, 400);
		assert.equal(response.body.error, 'invalid_request');
	});
});
