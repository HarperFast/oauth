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

import type { Logger, ProviderRegistryEntry } from '../types.ts';

/**
 * Default TTL (seconds) when `cacheDynamicProviders` is not set. Bounded rather
 * than forever, so a changed backing config is picked up within the window with
 * no manual step.
 */
export const DEFAULT_DYNAMIC_PROVIDER_CACHE_TTL_SECONDS = 300;

/**
 * Fixed, short cooldown for a dynamically-resolved provider's invalid Azure
 * issuer pin (HarperFast/oauth#264/#271) — independent of the success TTL
 * above, and not configurable: a config error should recover fast once
 * fixed, which the (often much longer, or infinite) success TTL is wrong
 * for. Without this, a bad pin re-runs the resolve hook and re-throws on
 * every single request for that provider until an operator notices.
 */
const AZURE_PIN_FAILURE_COOLDOWN_MS = 30_000;

interface CacheEntry {
	entry: ProviderRegistryEntry;
	cachedAt: number;
}

interface AzurePinFailure {
	message: string;
	failedAt: number;
}

export class DynamicProviderCache {
	private cache = new Map<string, CacheEntry>();
	private ttlMs: number;
	private azurePinFailures = new Map<string, AzurePinFailure>();
	private warnedOnce = new Set<string>();

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
		this.azurePinFailures.clear();
		this.warnedOnce.clear();
	}

	updateTTL(ttl: boolean | number): void {
		this.ttlMs = DynamicProviderCache.parseTTL(ttl);
		if (this.ttlMs === 0) this.cache.clear();
	}

	get size(): number {
		return this.cache.size;
	}

	/**
	 * Record a dynamically-resolved provider's `AzureIssuerBindingError` so
	 * {@link getAzurePinFailure} can short-circuit the resolve hook for
	 * `AZURE_PIN_FAILURE_COOLDOWN_MS` instead of re-running (and re-throwing)
	 * it on every request for `name` until the cooldown elapses.
	 */
	recordAzurePinFailure(name: string, message: string): void {
		this.azurePinFailures.set(name, { message, failedAt: Date.now() });
	}

	/** The still-cooling-down `AzureIssuerBindingError` message for `name`, or `undefined` if there isn't one or it has expired. */
	getAzurePinFailure(name: string): string | undefined {
		const failure = this.azurePinFailures.get(name);
		if (!failure) return undefined;
		if (Date.now() - failure.failedAt > AZURE_PIN_FAILURE_COOLDOWN_MS) {
			this.azurePinFailures.delete(name);
			return undefined;
		}
		return failure.message;
	}

	/** Clear any cooling-down Azure-pin failure for `name` — called on a successful resolution. */
	clearAzurePinFailure(name: string): void {
		this.azurePinFailures.delete(name);
	}

	/**
	 * True the first time `name`+`message` is seen, `false` every time after
	 * (until {@link clear} runs) — records the pair as seen either way. Used
	 * by {@link wrapLoggerForDynamicResolution} to stop an advisory warning
	 * from `buildProviderConfig` (e.g. the Azure tenant-mismatch warning)
	 * from repeating on every dynamic resolution of the same provider — which,
	 * with `cacheDynamicProviders: false` or a short TTL, can mean every
	 * single request. Independent of the success-cache TTL and the Azure-pin
	 * cooldown above: once warned, a provider stays quiet about that exact
	 * message for the life of this cache instance, not just one TTL window.
	 */
	private shouldWarnOnce(name: string, message: string): boolean {
		const key = `${name}\u0000${message}`;
		if (this.warnedOnce.has(key)) return false;
		this.warnedOnce.add(key);
		return true;
	}

	/**
	 * Wrap `logger` so `warn` calls for `providerName` made while building its
	 * config dynamically (`onResolveProvider`) are deduped via
	 * {@link shouldWarnOnce} — the first occurrence of each distinct message
	 * logs; later ones are silently dropped. `info`/`error`/`debug` pass
	 * through unchanged: those are either one-shot events (a successful
	 * resolution) or already covered by their own cooldown (`AzureIssuerBindingError`,
	 * via {@link recordAzurePinFailure}), not messages that repeat identically
	 * on every request.
	 */
	wrapLoggerForDynamicResolution(providerName: string, logger?: Logger): Logger | undefined {
		if (!logger) return logger;
		return {
			...logger,
			warn: (message: string, ...args: any[]) => {
				if (this.shouldWarnOnce(providerName, message)) logger.warn?.(message, ...args);
			},
		};
	}
}
