/**
 * TTL cache for dynamically-resolved OAuth providers.
 *
 * Sits between the static provider registry and the onResolveProvider hook
 * to avoid a database lookup on every request while still picking up
 * config changes within a bounded window.
 *
 * cacheDynamicProviders values:
 *   true     — cache forever (backward compatible default)
 *   false    — never cache, always call hook
 *   <number> — cache for N seconds
 */

import type { ProviderRegistryEntry } from '../types.ts';

interface CacheEntry {
	entry: ProviderRegistryEntry;
	cachedAt: number;
}

export class DynamicProviderCache {
	private cache = new Map<string, CacheEntry>();
	private ttlMs: number;

	constructor(ttl: boolean | number = true) {
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
