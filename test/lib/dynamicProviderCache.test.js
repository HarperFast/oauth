/**
 * Tests for DynamicProviderCache
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DynamicProviderCache } from '../../dist/lib/dynamicProviderCache.js';

/** Helper to create a mock ProviderRegistryEntry */
function mockEntry(name) {
	return {
		provider: { config: { provider: name } },
		config: { provider: name, clientId: `${name}-id`, clientSecret: `${name}-secret` },
	};
}

/** Helper to advance time by overriding Date.now */
function advanceTime(ms) {
	const real = Date.now;
	const future = real() + ms;
	Date.now = () => future;
	return () => {
		Date.now = real;
	};
}

describe('DynamicProviderCache', () => {
	describe('constructor TTL parsing', () => {
		it('defaults to cache forever (true)', () => {
			const cache = new DynamicProviderCache();
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);
			assert.strictEqual(cache.get('okta-org1'), entry);
		});

		it('true caches forever', () => {
			const cache = new DynamicProviderCache(true);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);

			// Even after a large time advance, entry should still be there
			const restore = advanceTime(999_999_999);
			try {
				assert.strictEqual(cache.get('okta-org1'), entry);
			} finally {
				restore();
			}
		});

		it('false never caches', () => {
			const cache = new DynamicProviderCache(false);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);
			assert.strictEqual(cache.get('okta-org1'), undefined);
			assert.strictEqual(cache.size, 0);
		});

		it('number sets TTL in seconds', () => {
			const cache = new DynamicProviderCache(60);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);

			// Within TTL — should return entry
			const restore30 = advanceTime(30_000);
			try {
				assert.strictEqual(cache.get('okta-org1'), entry);
			} finally {
				restore30();
			}

			// Beyond TTL — should evict and return undefined
			const restore61 = advanceTime(61_000);
			try {
				assert.strictEqual(cache.get('okta-org1'), undefined);
			} finally {
				restore61();
			}
		});

		it('zero TTL behaves like false', () => {
			const cache = new DynamicProviderCache(0);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);
			assert.strictEqual(cache.get('okta-org1'), undefined);
		});

		it('negative TTL behaves like false', () => {
			const cache = new DynamicProviderCache(-10);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);
			assert.strictEqual(cache.get('okta-org1'), undefined);
		});
	});

	describe('get/set', () => {
		let cache;

		beforeEach(() => {
			cache = new DynamicProviderCache(60);
		});

		it('returns undefined for unknown keys', () => {
			assert.strictEqual(cache.get('nonexistent'), undefined);
		});

		it('stores and retrieves entries', () => {
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);
			assert.strictEqual(cache.get('okta-org1'), entry);
		});

		it('stores multiple entries independently', () => {
			const entry1 = mockEntry('okta');
			const entry2 = mockEntry('azure');
			cache.set('okta-org1', entry1);
			cache.set('azure-org2', entry2);
			assert.strictEqual(cache.get('okta-org1'), entry1);
			assert.strictEqual(cache.get('azure-org2'), entry2);
			assert.strictEqual(cache.size, 2);
		});

		it('overwrites existing entry with new timestamp', () => {
			const entry1 = mockEntry('okta');
			const entry2 = mockEntry('okta-updated');
			cache.set('okta-org1', entry1);

			// Advance 50s (within TTL), then overwrite
			const restore = advanceTime(50_000);
			try {
				cache.set('okta-org1', entry2);
			} finally {
				restore();
			}

			// Advance 55s from original set (5s from overwrite) — should still be valid
			const restore55 = advanceTime(55_000);
			try {
				assert.strictEqual(cache.get('okta-org1'), entry2);
			} finally {
				restore55();
			}
		});
	});

	describe('TTL expiration', () => {
		it('evicts entry on get after TTL expires', () => {
			const cache = new DynamicProviderCache(30);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);
			assert.strictEqual(cache.size, 1);

			const restore = advanceTime(31_000);
			try {
				assert.strictEqual(cache.get('okta-org1'), undefined);
				// Entry should be removed from the map (lazy eviction)
				assert.strictEqual(cache.size, 0);
			} finally {
				restore();
			}
		});

		it('returns entry at exact TTL boundary', () => {
			const cache = new DynamicProviderCache(60);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);

			// At exactly 60s — Date.now() - cachedAt === ttlMs, should still be valid (not >)
			const restore = advanceTime(60_000);
			try {
				assert.strictEqual(cache.get('okta-org1'), entry);
			} finally {
				restore();
			}
		});

		it('expires entry just past TTL boundary', () => {
			const cache = new DynamicProviderCache(60);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);

			const restore = advanceTime(60_001);
			try {
				assert.strictEqual(cache.get('okta-org1'), undefined);
			} finally {
				restore();
			}
		});
	});

	describe('clear', () => {
		it('removes all entries', () => {
			const cache = new DynamicProviderCache(60);
			cache.set('a', mockEntry('a'));
			cache.set('b', mockEntry('b'));
			cache.set('c', mockEntry('c'));
			assert.strictEqual(cache.size, 3);

			cache.clear();
			assert.strictEqual(cache.size, 0);
			assert.strictEqual(cache.get('a'), undefined);
			assert.strictEqual(cache.get('b'), undefined);
		});
	});

	describe('updateTTL', () => {
		it('changes TTL for subsequent lookups', () => {
			const cache = new DynamicProviderCache(60);
			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);

			// Shorten TTL to 10s
			cache.updateTTL(10);

			// At 15s — entry should be expired under new TTL
			const restore = advanceTime(15_000);
			try {
				assert.strictEqual(cache.get('okta-org1'), undefined);
			} finally {
				restore();
			}
		});

		it('switching to false clears cache immediately', () => {
			const cache = new DynamicProviderCache(60);
			cache.set('a', mockEntry('a'));
			cache.set('b', mockEntry('b'));
			assert.strictEqual(cache.size, 2);

			cache.updateTTL(false);
			assert.strictEqual(cache.size, 0);
			// New sets should also be no-ops
			cache.set('c', mockEntry('c'));
			assert.strictEqual(cache.size, 0);
		});

		it('switching from false to number enables caching', () => {
			const cache = new DynamicProviderCache(false);
			cache.set('a', mockEntry('a'));
			assert.strictEqual(cache.get('a'), undefined);

			cache.updateTTL(30);
			const entry = mockEntry('b');
			cache.set('b', entry);
			assert.strictEqual(cache.get('b'), entry);
		});

		it('switching to true caches forever', () => {
			const cache = new DynamicProviderCache(10);
			cache.updateTTL(true);

			const entry = mockEntry('okta');
			cache.set('okta-org1', entry);

			const restore = advanceTime(999_999_999);
			try {
				assert.strictEqual(cache.get('okta-org1'), entry);
			} finally {
				restore();
			}
		});
	});

	describe('size', () => {
		it('returns 0 for empty cache', () => {
			const cache = new DynamicProviderCache(60);
			assert.strictEqual(cache.size, 0);
		});

		it('reflects number of stored entries', () => {
			const cache = new DynamicProviderCache(60);
			cache.set('a', mockEntry('a'));
			assert.strictEqual(cache.size, 1);
			cache.set('b', mockEntry('b'));
			assert.strictEqual(cache.size, 2);
		});

		it('does not count expired entries until accessed', () => {
			const cache = new DynamicProviderCache(10);
			cache.set('a', mockEntry('a'));
			assert.strictEqual(cache.size, 1);

			const restore = advanceTime(15_000);
			try {
				// size still 1 (lazy eviction)
				assert.strictEqual(cache.size, 1);
				// accessing evicts it
				cache.get('a');
				assert.strictEqual(cache.size, 0);
			} finally {
				restore();
			}
		});
	});
});
