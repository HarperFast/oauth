/**
 * Tests for MCPAssertionJtiStore (client-assertion replay guard)
 *
 * The guard adds 1 to a row's `uses` with Table.patch() and accepts only the
 * presentation that reads back 1, so the mock implements patch the way Harper
 * applies it at commit: the `add` operation lands on the row as then stored.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	MCPAssertionJtiStore,
	jtiKey,
	resetMCPAssertionJtisTableCache,
	replayRetentionExpiresAt,
	REPLAY_RETENTION_MARGIN_SECONDS,
} from '../../../dist/lib/mcp/assertionJtiStore.js';

/** Harper's patch: plain fields replace, `{ __op__: 'add' }` adds to the stored number (missing counts as 0). */
function applyPatch(stored, update) {
	const next = { ...stored };
	for (const [name, value] of Object.entries(update)) {
		next[name] = value?.__op__ === 'add' ? (Number(next[name]) || 0) + value.value : value;
	}
	return next;
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
			get: async (id) => storedRecords.get(id) ?? null,
			patch: async (id, update) => {
				storedRecords.set(id, applyPatch(storedRecords.get(id), update));
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
		assert.equal(stored.uses, 1);
		// created_at is Harper-assigned via @createdTime — the app must NOT hand-write it.
		assert.equal(stored.created_at, undefined);
	});

	it('returns false on a replayed jti', async () => {
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), true);
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), false);
		assert.equal(storedRecords.size, 1, 'replay does not write a second record');
	});

	it('treats ANY pre-existing record as a replay, including one without uses (an earlier version wrote it)', async () => {
		storedRecords.set(jtiKey('client-1', 'jti-abc'), {});
		assert.equal(await store.checkAndRecord('client-1', 'jti-abc'), false);
		storedRecords.set(jtiKey('client-1', 'jti-old'), { id: 'x', client_id: 'client-1', expires_at: 1 });
		assert.equal(await store.checkAndRecord('client-1', 'jti-old'), false);
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

	it('propagates storage errors (fail closed — never "could not check, assume fresh")', async () => {
		mockTable.patch = async () => {
			throw new Error('db write failure');
		};
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /db write failure/);
		mockTable.get = async () => {
			throw new Error('db read failure');
		};
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /db read failure/);
	});

	it('refuses a concurrent presentation that passed the existence check but incremented second', async () => {
		// Both presentations find no row; the first increment commits and reads
		// back 1 before the second increment lands.
		let releaseSecond;
		const secondMayCommit = new Promise((resolve) => (releaseSecond = resolve));
		let patches = 0;
		const realPatch = mockTable.patch;
		mockTable.patch = async (id, update) => {
			if (++patches === 2) await secondMayCommit;
			return realPatch(id, update);
		};
		const first = store.checkAndRecord('client-1', 'race-jti');
		const second = store.checkAndRecord('client-1', 'race-jti');
		assert.equal(await first, true);
		releaseSecond();
		assert.equal(await second, false, 'the second increment reads back 2');
		assert.equal(storedRecords.get(jtiKey('client-1', 'race-jti')).uses, 2);
	});

	it('concurrent presentations: at most one is accepted, and a later one is refused', async () => {
		const results = await Promise.all(Array.from({ length: 8 }, () => store.checkAndRecord('client-1', 'burst-jti')));
		assert.ok(results.filter(Boolean).length <= 1, 'at most one presentation is accepted');
		assert.equal(storedRecords.size, 1, 'exactly one record persisted');
		assert.equal(await store.checkAndRecord('client-1', 'burst-jti'), false);
	});

	it('throws a descriptive error when the table is missing', async () => {
		global.databases = { oauth: {} };
		resetMCPAssertionJtisTableCache();
		await assert.rejects(() => store.checkAndRecord('client-1', 'jti-abc'), /mcp_assertion_jtis/);
	});
});

describe('MCPAssertionJtiStore — explicit per-record retention', () => {
	let originalDatabases;
	let rows;
	let clockMs;
	let lastPatch;

	// The verifier's clock tolerance (clientAssertion.ts default).
	const CLOCK_TOLERANCE_SECONDS = 5;

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		resetMCPAssertionJtisTableCache();
		rows = new Map();
		clockMs = Date.now();
		lastPatch = undefined;
		// A table that honours per-record expiry the way Harper does on read in
		// the worst case: a row is gone as soon as its expiresAt has passed.
		global.databases = {
			oauth: {
				mcp_assertion_jtis: {
					get: async (id) => {
						const row = rows.get(id);
						if (row && row.expiresAt <= clockMs) rows.delete(id);
						return rows.get(id)?.record ?? null;
					},
					patch: async (id, update, context) => {
						lastPatch = { update, context };
						rows.set(id, {
							record: applyPatch(rows.get(id)?.record, update),
							expiresAt: context?.expiresAt ?? clockMs + 120_000,
						});
					},
				},
			},
		};
	});

	it('writes the expiry into the patch context and mirrors it in expires_at', async () => {
		const exp = Math.floor(Date.now() / 1000) + 300;
		assert.equal(await new MCPAssertionJtiStore().checkAndRecord('client-1', 'jti-1', exp), true);
		const expected = (exp + REPLAY_RETENTION_MARGIN_SECONDS) * 1000;
		assert.equal(lastPatch.context.expiresAt, expected);
		assert.equal(lastPatch.update.expires_at, expected);
	});

	it('rejects a replay at the expiry boundary while the assertion is still acceptable', async () => {
		const store = new MCPAssertionJtiStore();
		const exp = Math.floor(Date.now() / 1000) + 300; // an interactive assertion's maximum window
		assert.equal(await store.checkAndRecord('client-1', 'jti-edge', exp), true);
		// The verifier still accepts this assertion until exp + tolerance.
		clockMs = (exp + CLOCK_TOLERANCE_SECONDS) * 1000 - 1;
		assert.equal(await store.checkAndRecord('client-1', 'jti-edge', exp), false, 'replay still inside the window');
		// Only once the assertion can no longer be accepted may the row lapse,
		// freeing the jti for a later assertion.
		clockMs = (exp + REPLAY_RETENTION_MARGIN_SECONDS) * 1000 + 1;
		const laterExp = Math.floor(clockMs / 1000) + 60;
		assert.equal(await store.checkAndRecord('client-1', 'jti-edge', laterExp), true);
	});

	it('retention follows each assertion exp, so a window change after writing cannot shorten it', () => {
		const nowMs = Date.parse('2026-09-30T00:00:00Z');
		const now = nowMs / 1000;
		// Written under a 60 s window, then under a 300 s window: each row covers
		// its own assertion's acceptance (exp + tolerance) regardless of the
		// setting in force when it is checked later.
		for (const exp of [now + 60, now + 300, now + 305]) {
			const expiresAt = replayRetentionExpiresAt(exp, nowMs);
			assert.ok(expiresAt > (exp + CLOCK_TOLERANCE_SECONDS) * 1000, `exp ${exp - now}s covered`);
		}
		// A fixed 120 s table expiry would not cover a 300 s assertion.
		assert.ok(nowMs + 120_000 < (now + 300 + CLOCK_TOLERANCE_SECONDS) * 1000);
	});

	it('falls back to now + 120 s when no usable exp is supplied', () => {
		const nowMs = Date.parse('2026-09-30T00:00:00Z');
		assert.equal(replayRetentionExpiresAt(undefined, nowMs), nowMs + 120_000);
		assert.equal(replayRetentionExpiresAt(Number.NaN, nowMs), nowMs + 120_000);
		// An exp already in the past still retains from now.
		assert.equal(replayRetentionExpiresAt(nowMs / 1000 - 10, nowMs), nowMs + REPLAY_RETENTION_MARGIN_SECONDS * 1000);
	});
});
