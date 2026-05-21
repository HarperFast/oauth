/**
 * Tests for MCPClientStore
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { MCPClientStore, resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';

describe('MCPClientStore', () => {
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
		resetMCPClientsTableCache();
		store = new MCPClientStore();
		storedRecords = new Map();
		mockTable = {
			get: async (id) => storedRecords.get(id) || null,
			put: async (record) => {
				storedRecords.set(record.client_id, record);
			},
			delete: async (id) => {
				storedRecords.delete(id);
			},
		};
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: mockTable,
			},
		};
	});

	describe('CRUD', () => {
		it('stores and retrieves a client, JSON-encoding array fields on write', async () => {
			const record = {
				client_id: 'abc-123',
				client_id_issued_at: 1700000000,
				redirect_uris: ['https://example.com/cb', 'https://example.com/cb2'],
				client_name: 'Test Client',
				grant_types: ['authorization_code', 'refresh_token'],
				response_types: ['code'],
				token_endpoint_auth_method: 'none',
				application_type: 'web',
			};

			await store.set(record);

			const stored = storedRecords.get('abc-123');
			assert.ok(stored, 'record was persisted');
			// Array fields stored as JSON strings
			assert.equal(typeof stored.redirect_uris, 'string');
			assert.deepEqual(JSON.parse(stored.redirect_uris), record.redirect_uris);
			assert.equal(typeof stored.grant_types, 'string');
			// Scalar fields stored as-is
			assert.equal(stored.client_name, 'Test Client');

			const retrieved = await store.get('abc-123');
			assert.ok(retrieved);
			assert.equal(retrieved.client_id, 'abc-123');
			assert.deepEqual(retrieved.redirect_uris, record.redirect_uris);
			assert.deepEqual(retrieved.grant_types, record.grant_types);
		});

		it('returns null for unknown client_id', async () => {
			const result = await store.get('does-not-exist');
			assert.equal(result, null);
		});

		it('deletes a client', async () => {
			await store.set({
				client_id: 'to-delete',
				client_id_issued_at: 1700000000,
				redirect_uris: ['https://example.com/cb'],
			});
			assert.equal(storedRecords.size, 1);

			await store.delete('to-delete');
			assert.equal(storedRecords.size, 0);
		});

		it('handles malformed array JSON gracefully (returns undefined for that field)', async () => {
			// Simulate corrupted record stored outside our encoder
			storedRecords.set('corrupted', {
				client_id: 'corrupted',
				client_id_issued_at: 1700000000,
				redirect_uris: 'not-json-{',
			});

			const retrieved = await store.get('corrupted');
			assert.ok(retrieved);
			assert.equal(retrieved.client_id, 'corrupted');
			assert.equal(retrieved.redirect_uris, undefined);
		});

		it('omits array fields that were undefined on the record', async () => {
			await store.set({
				client_id: 'minimal',
				client_id_issued_at: 1700000000,
				redirect_uris: ['https://example.com/cb'],
				// contacts, grant_types, response_types intentionally omitted
			});

			const stored = storedRecords.get('minimal');
			assert.equal(stored.contacts, undefined);
			assert.equal(stored.grant_types, undefined);
		});

		it('returns null when the underlying get call throws', async () => {
			mockTable.get = async () => {
				throw new Error('db read failure');
			};
			const result = await store.get('whatever');
			assert.equal(result, null);
		});

		it('propagates errors on set() so callers can fail registration with 500', async () => {
			mockTable.put = async () => {
				throw new Error('db write failure');
			};
			await assert.rejects(() =>
				store.set({
					client_id: 'will-fail',
					client_id_issued_at: 1700000000,
					redirect_uris: ['https://example.com/cb'],
				})
			);
		});
	});
});
