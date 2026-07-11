/**
 * Per-node in-memory token-bucket rate limiter (#163).
 *
 * Deliberately PER-NODE, not replicated: Harper replication makes a shared
 * counter table a hot-write anti-pattern, and the surfaces this limits are
 * already bounded cross-node — the client_credentials grant by the assertion
 * replay guard and its ≤60s `exp` window, CIMD fetches by the concurrency
 * caps. A node-local bucket is the right defense-in-depth without turning
 * every token request into a replicated write.
 *
 * Buckets refill continuously (elapsed-time based — no interval timers), so a
 * limit of N/min admits a burst of up to N and then one request per 60/N
 * seconds. Keys may be ATTACKER-CHOSEN strings (client_ids, URLs), so: (1) the
 * key space is LRU-bounded — at `maxKeys` the least-recently-used bucket is
 * evicted (an evicted bucket forgets that key's spend history, acceptable
 * because eviction requires `maxKeys` distinct keys inside one window and the
 * global concurrency caps still bound aggregate work); and (2) the key is
 * stored as a fixed-size SHA-256 fingerprint, so a flood of long distinct keys
 * bounds map memory to `maxKeys` × a constant, not × the raw key length.
 */

import { createHash } from 'node:crypto';

type BucketState = { tokens: number; lastRefill: number };

export type RateLimitResult = { allowed: true } | { allowed: false; retryAfterSeconds: number };

export type RateLimiter = {
	tryTake(key: string): RateLimitResult;
	/** Drop all bucket state (for testing). @internal */
	_reset(): void;
};

const DEFAULT_MAX_KEYS = 10_000;

export function createRateLimiter(options: {
	/** Bucket capacity (maximum burst). */
	capacity: number;
	/** Continuous refill rate, tokens per minute. */
	refillPerMinute: number;
	/** LRU bound on distinct keys tracked. Default 10 000. */
	maxKeys?: number;
	/** Clock override (for testing). Default Date.now. */
	now?: () => number;
}): RateLimiter {
	// A token bucket takes 1 token per request, so a burst ceiling below 1 could
	// never admit anyone — clamp it up. The refill rate is left untouched, so a
	// sub-1/min limit still means "one request, then one per 60/rate seconds".
	const capacity = Math.max(1, options.capacity);
	const { refillPerMinute } = options;
	const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
	const now = options.now ?? Date.now;
	const buckets = new Map<string, BucketState>();

	return {
		tryTake(key: string): RateLimitResult {
			// Fixed-size fingerprint: the raw key may be an attacker-chosen URL of
			// arbitrary length, and it is retained in the map until evicted.
			const mapKey = createHash('sha256').update(key).digest('base64url');
			const at = now();
			let bucket = buckets.get(mapKey);
			if (bucket) {
				const elapsedMs = at - bucket.lastRefill;
				if (elapsedMs > 0) {
					bucket.tokens = Math.min(capacity, bucket.tokens + (elapsedMs / 60_000) * refillPerMinute);
					bucket.lastRefill = at;
				}
				// Delete now; the set below re-inserts so Map order tracks recency (LRU).
				buckets.delete(mapKey);
			} else {
				bucket = { tokens: capacity, lastRefill: at };
				if (buckets.size >= maxKeys) {
					const oldest = buckets.keys().next().value;
					if (oldest !== undefined) buckets.delete(oldest);
				}
			}
			let result: RateLimitResult;
			if (bucket.tokens >= 1) {
				bucket.tokens -= 1;
				result = { allowed: true };
			} else {
				const deficit = 1 - bucket.tokens;
				result = { allowed: false, retryAfterSeconds: Math.ceil((deficit * 60) / refillPerMinute) };
			}
			buckets.set(mapKey, bucket);
			return result;
		},
		_reset(): void {
			buckets.clear();
		},
	};
}
