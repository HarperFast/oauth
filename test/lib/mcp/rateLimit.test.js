/**
 * Tests for the per-node token-bucket rate limiter (#163).
 * The clock is injected — no test sleeps.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRateLimiter } from '../../../dist/lib/mcp/rateLimit.js';

function makeClock(startMs = 0) {
	let t = startMs;
	return { now: () => t, advance: (ms) => (t += ms) };
}

describe('createRateLimiter', () => {
	it('admits up to capacity, then blocks with seconds until one token refills', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 2, refillPerMinute: 60, now: clock.now });
		assert.equal(limiter.tryTake('k').allowed, true);
		assert.equal(limiter.tryTake('k').allowed, true);
		const blocked = limiter.tryTake('k');
		assert.equal(blocked.allowed, false);
		assert.equal(blocked.retryAfterSeconds, 1); // 60/min = one token per second
	});

	it('refills continuously with elapsed time', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 60, now: clock.now });
		assert.equal(limiter.tryTake('k').allowed, true);
		assert.equal(limiter.tryTake('k').allowed, false);
		clock.advance(500); // half a token — still blocked
		assert.equal(limiter.tryTake('k').allowed, false);
		clock.advance(500); // a full token has refilled
		assert.equal(limiter.tryTake('k').allowed, true);
	});

	it('caps refill at capacity — idle time never accrues an unbounded burst', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 2, refillPerMinute: 60, now: clock.now });
		limiter.tryTake('k');
		clock.advance(3_600_000); // an hour idle
		assert.equal(limiter.tryTake('k').allowed, true);
		assert.equal(limiter.tryTake('k').allowed, true);
		assert.equal(limiter.tryTake('k').allowed, false, 'burst is bounded by capacity, not elapsed time');
	});

	it('isolates keys — a drained key does not starve another', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 1, now: clock.now });
		assert.equal(limiter.tryTake('noisy').allowed, true);
		assert.equal(limiter.tryTake('noisy').allowed, false);
		assert.equal(limiter.tryTake('quiet').allowed, true);
	});

	it('LRU-bounds the key space — a unique-key flood evicts the oldest bucket', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 1, maxKeys: 2, now: clock.now });
		assert.equal(limiter.tryTake('a').allowed, true);
		assert.equal(limiter.tryTake('a').allowed, false); // 'a' drained
		limiter.tryTake('b');
		limiter.tryTake('c'); // map at maxKeys → evicts 'a' (least recently used)
		assert.equal(limiter.tryTake('a').allowed, true, 'an evicted key returns with a fresh bucket');
	});

	it('retryAfterSeconds reflects the deficit at slow refill rates', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 2, now: clock.now });
		limiter.tryTake('k');
		const blocked = limiter.tryTake('k');
		assert.equal(blocked.allowed, false);
		assert.equal(blocked.retryAfterSeconds, 30); // 2/min = one token per 30 s
	});

	it('clamps a sub-1 capacity up to 1 so a slow rate still admits the first request', () => {
		const clock = makeClock();
		// rate 0.5/min → capacity would be 0.5, below the 1 token a take needs;
		// without the clamp this bucket could never admit anyone.
		const limiter = createRateLimiter({ capacity: 0.5, refillPerMinute: 0.5, now: clock.now });
		assert.equal(limiter.tryTake('k').allowed, true, 'first request admitted despite sub-1 rate');
		const blocked = limiter.tryTake('k');
		assert.equal(blocked.allowed, false);
		assert.equal(blocked.retryAfterSeconds, 120); // 0.5/min = one token per 120 s
		clock.advance(120_000);
		assert.equal(limiter.tryTake('k').allowed, true, 'refills at the configured slow rate');
	});

	it('bounds memory under a long, unique-key flood — keys are fingerprinted, LRU still evicts', () => {
		const clock = makeClock();
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 1, maxKeys: 3, now: clock.now });
		// Keys of arbitrary length must not grow the map beyond maxKeys, and each
		// distinct key still gets its own bucket (fingerprints don't collide).
		const long = (n) => `https://attacker.example.com/${'x'.repeat(4000)}/${n}`;
		for (let i = 0; i < 1000; i++) assert.equal(limiter.tryTake(long(i)).allowed, true);
		// The three most-recent keys retain state; older ones were evicted, so a
		// re-request of a recent drained key is still blocked (state survived).
		assert.equal(limiter.tryTake(long(999)).allowed, false, 'recent key keeps its drained bucket');
		assert.equal(limiter.tryTake(long(0)).allowed, true, 'long-evicted key returns fresh');
	});

	it('caps retryAfterSeconds at a sane upper bound for tiny rates', () => {
		const clock = makeClock();
		// 1e-5/min would compute a ~6,000,000 s wait; capped to the int32-second max.
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 0.00001, now: clock.now });
		limiter.tryTake('k');
		const blocked = limiter.tryTake('k');
		assert.equal(blocked.allowed, false);
		assert.equal(blocked.retryAfterSeconds, 2_147_483);
	});

	it('stays well-defined when constructed with a non-positive refill rate', () => {
		const clock = makeClock();
		// A 0 rate would divide-by-zero the retry-after math; the guard falls back
		// to capacity so the limiter still admits the burst and yields a finite wait.
		const limiter = createRateLimiter({ capacity: 3, refillPerMinute: 0, now: clock.now });
		assert.equal(limiter.tryTake('k').allowed, true);
		assert.equal(limiter.tryTake('k').allowed, true);
		assert.equal(limiter.tryTake('k').allowed, true);
		const blocked = limiter.tryTake('k');
		assert.equal(blocked.allowed, false);
		assert.ok(Number.isFinite(blocked.retryAfterSeconds) && blocked.retryAfterSeconds >= 1);
	});

	it('_reset drops all bucket state', () => {
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 1 });
		limiter.tryTake('k');
		assert.equal(limiter.tryTake('k').allowed, false);
		limiter._reset();
		assert.equal(limiter.tryTake('k').allowed, true);
	});
});
