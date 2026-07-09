/**
 * Tests for MCPAssertionJtiStore (client-assertion replay guard)
 *
 * The guard uses Table.create() — insert-if-absent, 409 on an existing
 * record — so the mock implements that contract. NOTE: the mock's create is
 * synchronous-atomic, which matches Harper's SEQUENTIAL semantics; real
 * Harper currently enforces the existence check pre-staging only, so
 * concurrent in-flight creates can all report success (harper#1745). The
 * concurrency test below pins only the properties that hold under both
 * semantics: at least one winner, and rejection once a create has settled.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	MCPAssertionJtiStore,
	jtiKey,
	resetMCPAssertionJtisTableCache,
} from '../../../dist/lib/mcp/assertionJtiStore.js';

function conflictError() {
	const error = new Error('Record already exists');
	error.statusCode = 409;
	return error;
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
			create: async (record) => {
				if (storedRecords.has(record.id)) throw conflictError();
				storedRecords.set(record.id, record);
			},
		};
		global.databases = {
			oauth: {
				mcp_assertion_jtis: mockTable,
			},
		};
	});

	it('returns true on first sighting and persists under the hashed key', async () => {
		const ok = await store.checkAndRecord('client-1', 'jti-abc');
		assert.equal(ok, true);
		assert.equal(storedRecords.size, 1);
		const stored = storedRecords.get(jtiKey('client-1', 'jti-abc'));
		assert.ok(stored, 'record stored under sha256(len:client_id:jti)');
		assert.equal(stored.client_id, 'client-1');
		// created_at is Harper-assigned via @createdTime — the app must NOT hand-write it.
		assert.equal(stored.created_at, undefined);
	});

	it('returns false on a replayed jti (create 409 → replay)', async () => {
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), true);
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), false);
		assert.equal(storedRecords.size, 1, 'replay does not write a second record');
	});

	it('treats ANY pre-existing record as a replay, even a malformed one', async () => {
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

	it('propagates non-409 storage errors (fail closed — never "could not check, assume fresh")', async () => {
		mockTable.create = async () => {
			throw new Error('db write failure');
		};
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /db write failure/);
	});

	it('propagates a non-409 ClientError rather than treating it as a replay', async () => {
		mockTable.create = async () => {
			const error = new Error('table overloaded');
			error.statusCode = 503;
			throw error;
		};
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /table overloaded/);
	});

	it('concurrent presentations: at least one wins, and replay is rejected once settled', async () => {
		// Pins the SAFE properties that hold under both current-Harper
		// (pre-staging check only; in-flight duplicates may all succeed —
		// harper#1745) and per-node-atomic semantics (exactly one winner).
		// The mock serializes, so it yields exactly one winner; on real Harper
		// the winner count may exceed 1 for in-flight overlap, which is the
		// documented residual risk in the module header.
		const results = await Promise.all(Array.from({ length: 8 }, () => store.checkAndRecord('client-1', 'burst-jti')));
		const winners = results.filter(Boolean).length;
		assert.ok(winners >= 1, 'at least one presentation must win');
		assert.equal(storedRecords.size, 1, 'exactly one record persisted');
		// After any create has settled, every later presentation is a replay.
		assert.equal(await store.checkAndRecord('client-1', 'burst-jti'), false);
	});

	it('throws a descriptive error when the table is missing', async () => {
		global.databases = { oauth: {} };
		resetMCPAssertionJtisTableCache();
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /mcp_assertion_jtis/);
	});
});
