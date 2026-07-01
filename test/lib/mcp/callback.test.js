/**
 * Tests for the MCP callback branch (handleMCPCallback).
 *
 * Verifies it mints an authorization code, persists the binding fields,
 * redirects to the client's redirect_uri with `code` + echoed `state` + RFC 9207 `iss`,
 * and never leaks upstream-provider token material in the response.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleMCPCallback } from '../../../dist/lib/mcp/callback.js';
import { resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';

const SAMPLE_MCP_STATE = {
	clientId: 'client-abc',
	resource: 'https://app.example.com/mcp',
	codeChallenge: 'fake-challenge-32-chars-or-longer',
	codeChallengeMethod: 'S256',
	redirectUri: 'https://mcp-client.example.com/cb',
	scope: 'mcp:read',
	clientState: 'mcp-client-state',
};

const SAMPLE_USER_ID = 'alice@example.com';

const SAMPLE_MCP_CONFIG = {
	issuer: 'https://as.example.com',
	enabled: true,
};

// Minimal request stub — handleMCPCallback delegates issuer resolution to
// resolveIssuer(request, mcpConfig); with a configured issuer the request
// fields are not consulted.
const SAMPLE_REQUEST = { protocol: 'https', host: 'app.example.com', headers: { host: 'app.example.com' } };

describe('handleMCPCallback', () => {
	let originalDatabases;
	let storedRecords;
	let mockTable;

	before(() => {
		originalDatabases = global.databases;
	});

	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		resetMCPAuthCodesTableCache();
		storedRecords = new Map();
		mockTable = {
			get: async (id) => storedRecords.get(id) ?? null,
			put: async (record) => {
				storedRecords.set(record.code, record);
			},
			delete: async (id) => storedRecords.delete(id),
		};
		global.databases = {
			oauth: {
				mcp_auth_codes: mockTable,
			},
		};
	});

	it('mints an auth code and persists the binding fields', async () => {
		const response = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		assert.equal(response.status, 302);
		assert.equal(storedRecords.size, 1);
		const [record] = storedRecords.values();
		assert.ok(record.code);
		assert.equal(record.client_id, SAMPLE_MCP_STATE.clientId);
		assert.equal(record.user, SAMPLE_USER_ID);
		assert.equal(record.resource, SAMPLE_MCP_STATE.resource);
		assert.equal(record.code_challenge, SAMPLE_MCP_STATE.codeChallenge);
		assert.equal(record.code_challenge_method, SAMPLE_MCP_STATE.codeChallengeMethod);
		assert.equal(record.redirect_uri, SAMPLE_MCP_STATE.redirectUri);
		assert.equal(record.scope, SAMPLE_MCP_STATE.scope);
		assert.equal(typeof record.created_at, 'number');
	});

	it('redirects to the client redirect_uri with code and echoed state', async () => {
		const response = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		const url = new URL(response.headers.Location);
		assert.equal(url.origin + url.pathname, SAMPLE_MCP_STATE.redirectUri);
		assert.ok(url.searchParams.get('code'));
		assert.equal(url.searchParams.get('state'), SAMPLE_MCP_STATE.clientState);
	});

	it('includes iss on the success redirect (RFC 9207)', async () => {
		const response = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		const url = new URL(response.headers.Location);
		assert.equal(url.searchParams.get('iss'), SAMPLE_MCP_CONFIG.issuer, 'iss must equal the configured issuer');
	});

	it('derives iss from the request when issuer is not configured', async () => {
		const configWithoutIssuer = { enabled: true };
		const response = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, configWithoutIssuer);
		const url = new URL(response.headers.Location);
		assert.equal(url.searchParams.get('iss'), 'https://app.example.com', 'iss must derive from request scheme+host');
	});

	it('omits state when the MCP client did not send one', async () => {
		const { clientState, ...stateWithoutClientState } = SAMPLE_MCP_STATE;
		void clientState;
		const response = await handleMCPCallback(
			SAMPLE_REQUEST,
			stateWithoutClientState,
			SAMPLE_USER_ID,
			SAMPLE_MCP_CONFIG
		);
		const url = new URL(response.headers.Location);
		assert.equal(url.searchParams.has('state'), false);
		assert.ok(url.searchParams.get('code'));
		// iss is always present regardless of state
		assert.ok(url.searchParams.get('iss'));
	});

	it('generates a fresh code per invocation (no reuse across requests)', async () => {
		const a = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		const b = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		const codeA = new URL(a.headers.Location).searchParams.get('code');
		const codeB = new URL(b.headers.Location).searchParams.get('code');
		assert.notEqual(codeA, codeB);
		assert.equal(storedRecords.size, 2);
	});

	it('redirects with error when persistence fails (does not throw)', async () => {
		mockTable.put = async () => {
			throw new Error('db write failure');
		};
		const response = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		assert.equal(response.status, 302);
		const url = new URL(response.headers.Location);
		assert.equal(url.origin + url.pathname, SAMPLE_MCP_STATE.redirectUri);
		assert.equal(url.searchParams.get('error'), 'server_error');
		assert.equal(url.searchParams.get('state'), SAMPLE_MCP_STATE.clientState);
		// RFC 9207: iss must appear on error redirects too
		assert.equal(url.searchParams.get('iss'), SAMPLE_MCP_CONFIG.issuer);
	});

	it('never includes upstream provider token in the redirect URL', async () => {
		// `handleMCPCallback` signature doesn't take a token — that's the guard.
		// But assert no field on the response references known token-ish names.
		const response = await handleMCPCallback(SAMPLE_REQUEST, SAMPLE_MCP_STATE, SAMPLE_USER_ID, SAMPLE_MCP_CONFIG);
		const location = response.headers.Location;
		for (const banned of ['access_token', 'refresh_token', 'id_token', 'token_type']) {
			assert.ok(!location.includes(banned), `${banned} must not appear in MCP redirect URL`);
		}
	});
});
