/**
 * TTL cache for dynamically-resolved OAuth providers.
 *
 * Sits between the static provider registry and the onResolveProvider hook
 * to avoid a database lookup on every request while still picking up
 * config changes within a bounded window.
 *
 * cacheDynamicProviders values:
 *   true     — cache forever (no eviction except explicit invalidate/clear)
 *   false    — never cache, always call hook
 *   <number> — cache for N seconds
 *   (unset)  — DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS (bounded)
 *
 * The cache is in-memory and per-worker-thread. A resolved provider therefore
 * only goes stale when its TTL elapses (each thread re-resolves on its own) or
 * when a consumer explicitly evicts it via `delete`/`clear`. Because an explicit
 * eviction reaches only the thread that runs it, the TTL is the cross-thread
 * convergence mechanism — keep it bounded so config changes (disable / delete /
 * credential rotation) take effect cluster-wide.
 */

import type { ProviderRegistryEntry } from '../types.ts';

/**
 * Default TTL (seconds) when `cacheDynamicProviders` is not set. Bounded rather
 * than infinite so a changed backing config is picked up within the window even
 * without an explicit invalidation. The previous default was `true` (forever),
 * which left disabled/rotated providers serving stale data until restart.
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

	/**
	 * Evict a single entry. Returns true if it was present. Use when the backing
	 * config for `name` changes so the next request re-resolves it via the hook.
	 */
	delete(name: string): boolean {
		return this.cache.delete(name);
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
