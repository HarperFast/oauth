/**
 * TTL cache for dynamically-resolved OAuth providers.
 *
 * Sits between the static provider registry and the onResolveProvider hook so
 * the hook (a database lookup, decryption, etc.) doesn't run on every request.
 * It is in-memory and per-worker-thread, and freshness is controlled solely by
 * the TTL: an entry is re-resolved once it expires, so a config change (disabled
 * provider, rotated credentials, etc.) takes effect within one TTL window.
 *
 * There is intentionally no manual eviction API. A per-thread evict would clear
 * only one worker's copy, leaving the others stale — a partial, confusing state.
 * The uniform TTL is the single, predictable convergence mechanism; tune it (or
 * disable the cache) rather than reaching for invalidation.
 *
 * cacheDynamicProviders values:
 *   <number> — cache for N seconds (use a low value for fresher config)
 *   false    — never cache; call the hook every request. Prefer this if your
 *              onResolveProvider already caches at the lookup layer.
 *   true     — cache forever (no expiry); only safe if a resolved config never
 *              changes for the life of the process.
 *   (unset)  — DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS (bounded; see below)
 */

import type { ProviderRegistryEntry } from '../types.ts';

/**
 * Default TTL (seconds) when `cacheDynamicProviders` is not set. Bounded rather
 * than forever, so a changed backing config is picked up within the window with
 * no manual step.
 */
export const DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS = 300;

interface CacheEntry {
	entry: ProviderRegistryEntry;
	cachedAt: number;
}

export class DynamicProviderCache {
	private cache = new Map<string, CacheEntry>();
	private ttlMs: number;

	constructor(ttl: boolean | number = DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS) {
		this.ttlMs = DynamicProviderCache.parseTTL(ttl);
	}

	private static parseTTL(ttl: boolean | number): number {
		if (ttl === true) return Infinity;
		if (ttl === false || ttl <= 0) return 0;
		return ttl * 1000;
	}

	get(name: string): ProviderRegistryEntry | undefined {
		if (this.ttlMs === 0) return undefined;

		const cached = this.cache.get(name);
		if (!cached) return undefined;

		if (this.ttlMs !== Infinity && Date.now() - cached.cachedAt > this.ttlMs) {
			this.cache.delete(name);
			return undefined;
		}

		return cached.entry;
	}

	set(name: string, entry: ProviderRegistryEntry): void {
		if (this.ttlMs === 0) return;
		this.cache.set(name, { entry, cachedAt: Date.now() });
	}

	clear(): void {
		this.cache.clear();
	}

	updateTTL(ttl: boolean | number): void {
		this.ttlMs = DynamicProviderCache.parseTTL(ttl);
		if (this.ttlMs === 0) this.cache.clear();
	}

	get size(): number {
		return this.cache.size;
	}
}
