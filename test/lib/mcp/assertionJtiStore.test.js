/**
 * Tests for MCPAssertionJtiStore (client-assertion replay guard)
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	MCPAssertionJtiStore,
	jtiKey,
	resetMCPAssertionJtisTableCache,
} from '../../../dist/lib/mcp/assertionJtiStore.js';

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

describe('MCPAssertionJtiStore', () => {
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
		resetMCPAssertionJtisTableCache();
		store = new MCPAssertionJtiStore();
		storedRecords = new Map();
		mockTable = {
			get: async (id) => {
				const raw = storedRecords.get(id);
				return raw ? asTrackedObject(raw) : null;
			},
			put: async (record) => {
				storedRecords.set(record.id, record);
			},
		};
		global.databases = {
			oauth: {
				mcp_assertion_jtis: mockTable,
			},
		};
	});

	it('returns true on first sighting and persists the hashed key', async () => {
		const ok = await store.checkAndRecord('client-1', 'jti-abc');
		assert.equal(ok, true);
		assert.equal(storedRecords.size, 1);
		const stored = storedRecords.get(jtiKey('client-1', 'jti-abc'));
		assert.ok(stored, 'record stored under sha256(client_id, jti)');
		assert.equal(stored.client_id, 'client-1');
		// created_at is Harper-assigned via @createdTime — the app must NOT hand-write it.
		assert.equal(stored.created_at, undefined);
	});

	it('returns false on a replayed jti (tracked-object Proxy read path)', async () => {
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), true);
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), false);
		assert.equal(storedRecords.size, 1, 'replay does not write a second record');
	});

	it('treats ANY truthy stored record as a replay, even a malformed one without id', async () => {
		storedRecords.set(jtiKey('client-1', 'jti-abc'), {});
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), false);
	});

	it('scopes replay per client: the same jti from another client is fresh', async () => {
		assert.equal(await store.checkAndRecord('client-1', 'shared-jti'), true);
		assert.equal(await store.checkAndRecord('client-2', 'shared-jti'), true);
		assert.equal(storedRecords.size, 2);
	});

	it('keys cannot collide via delimiter stuffing', () => {
		// ("a", "b\nc") must not collide with ("a\nb", "c").
		assert.notEqual(jtiKey('a', 'b\nc'), jtiKey('a\nb', 'c'));
		assert.match(jtiKey('a', 'b'), /^[0-9a-f]{64}$/);
	});

	it('propagates read errors (fail closed — never "could not check, assume fresh")', async () => {
		mockTable.get = async () => {
			throw new Error('db read failure');
		};
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /db read failure/);
	});

	it('propagates write errors so the grant refuses issuance', async () => {
		mockTable.put = async () => {
			throw new Error('db write failure');
		};
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /db write failure/);
	});

	it('throws a descriptive error when the table is missing', async () => {
		global.databases = { oauth: {} };
		resetMCPAssertionJtisTableCache();
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /mcp_assertion_jtis/);
	});
});
