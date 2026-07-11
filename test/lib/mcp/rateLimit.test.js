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

	it('_reset drops all bucket state', () => {
		const limiter = createRateLimiter({ capacity: 1, refillPerMinute: 1 });
		limiter.tryTake('k');
		assert.equal(limiter.tryTake('k').allowed, false);
		limiter._reset();
		assert.equal(limiter.tryTake('k').allowed, true);
	});
});
