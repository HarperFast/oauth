/**
 * Tests for MCPAuthCodeStore
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { MCPAuthCodeStore, resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';

function asTrackedObject(plain) {
	return new Proxy(plain, {
		ownKeys() {
			return [];
		},
		getOwnPropertyDescriptor() {
			return undefined;
		},
	});
}

describe('MCPAuthCodeStore', () => {
	let store;
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
		store = new MCPAuthCodeStore();
		storedRecords = new Map();
		mockTable = {
			get: async (id) => {
				const raw = storedRecords.get(id);
				return raw ? asTrackedObject(raw) : null;
			},
			put: async (record) => {
				storedRecords.set(record.code, record);
			},
			delete: async (id) => {
				storedRecords.delete(id);
			},
		};
		global.databases = {
			oauth: {
				mcp_auth_codes: mockTable,
			},
		};
	});

	const sampleRecord = {
		code: 'sample-code-abc',
		client_id: 'client-123',
		user: 'alice@example.com',
		resource: 'https://app.example.com/mcp',
		code_challenge: 'fake-challenge',
		code_challenge_method: 'S256',
		redirect_uri: 'https://mcp-client.example.com/cb',
		scope: 'mcp:read',
		created_at: 1700000000,
	};

	it('persists and retrieves a code, preserving scalar fields through tracked-object Proxy', async () => {
		await store.set(sampleRecord);

		const retrieved = await store.get(sampleRecord.code);
		assert.ok(retrieved, 'record retrieved');
		assert.equal(retrieved.code, sampleRecord.code);
		assert.equal(retrieved.client_id, sampleRecord.client_id);
		assert.equal(retrieved.user, sampleRecord.user);
		assert.equal(retrieved.resource, sampleRecord.resource);
		assert.equal(retrieved.code_challenge, sampleRecord.code_challenge);
		assert.equal(retrieved.code_challenge_method, sampleRecord.code_challenge_method);
		assert.equal(retrieved.redirect_uri, sampleRecord.redirect_uri);
		assert.equal(retrieved.scope, sampleRecord.scope);
		assert.equal(retrieved.created_at, sampleRecord.created_at);
	});

	it('returns null for an unknown code', async () => {
		assert.equal(await store.get('not-real'), null);
	});

	it('deletes a code (single-use semantics enforced by /token in Stage 4)', async () => {
		await store.set(sampleRecord);
		assert.equal(storedRecords.size, 1);
		await store.delete(sampleRecord.code);
		assert.equal(storedRecords.size, 0);
	});

	it('returns null when the underlying get throws', async () => {
		mockTable.get = async () => {
			throw new Error('db failure');
		};
		assert.equal(await store.get('whatever'), null);
	});

	it('propagates set() errors so callers can fail the request', async () => {
		mockTable.put = async () => {
			throw new Error('db write failure');
		};
		await assert.rejects(() => store.set(sampleRecord));
	});

	it('records without a scope decode as scope=undefined', async () => {
		const { scope, ...withoutScope } = sampleRecord;
		void scope;
		await store.set(withoutScope);
		const retrieved = await store.get(sampleRecord.code);
		assert.equal(retrieved.scope, undefined);
	});
});
