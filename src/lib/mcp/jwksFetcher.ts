/**
 * `jwks_uri` key fetching for interactive CIMD clients (private_key_jwt).
 *
 * Fetches a client's JWK Set with the same controls as the CIMD document
 * itself (`fetchPinnedBoundedJson`): every resolved address is validated and
 * the connection is pinned to it, no redirects are followed, and one deadline
 * plus a byte cap bound the exchange. On top of that:
 *
 * - Location policy is re-checked on every use (`jwksUriIssue`): https, the
 *   client ID's exact origin unless the operator allowlists another origin.
 *   Tightening the allowlist takes effect immediately, even for cached keys.
 * - Only key material is cached (see `publicKeySetFromDocument`), keyed by the
 *   (client_id, jwks_uri) pair — keys fetched for one client are never served
 *   to another, even when both name the same URL.
 * - Cache lifetime honours `Cache-Control` within [60 s, 3600 s], default
 *   300 s. Errors and invalid sets are never cached.
 * - Concurrent misses for one key share a single fetch; total in-flight
 *   fetches are capped; fetch attempts per (client, uri) are rate-limited.
 * - An unknown `kid` may trigger at most one refetch per (client, uri) per
 *   KID_MISS_REFETCH_INTERVAL_MS, so assertions carrying random `kid`s cannot
 *   drive fetches.
 *
 * Caches and limiters are per worker thread, like the CIMD document cache.
 */

import type { Logger, MCPClientIdMetadataDocumentsConfig } from '../../types.ts';
import {
	CimdClientError,
	DEFAULT_FETCH_TIMEOUT_MS,
	DEFAULT_MAX_DOCUMENT_BYTES,
	cacheTtlSeconds,
	fetchPinnedBoundedJson,
	toFinitePositive,
} from './cimd.ts';
import { jwksUriIssue, publicKeySetFromDocument } from './clientKeySet.ts';
import { createRateLimiter } from './rateLimit.ts';

const JWKS_CACHE_MIN_TTL_S = 60;
const JWKS_CACHE_MAX_TTL_S = 3_600;
const JWKS_CACHE_DEFAULT_TTL_S = 300;
const JWKS_CACHE_MAX_ENTRIES = 1_000;
/** Total concurrent JWKS fetches per worker; over the cap, requests fast-fail with 429. */
export const MAX_CONCURRENT_JWKS_FETCHES = 8;
/** Fetch attempts per (client, jwks_uri) per minute. */
export const JWKS_FETCH_ATTEMPTS_PER_MINUTE = 10;
/** Minimum spacing between unknown-kid refetches for one (client, jwks_uri). */
export const KID_MISS_REFETCH_INTERVAL_MS = 60_000;

type CacheEntry = { keys: Record<string, unknown>[]; expiresAt: number; fetchedAt: number };

const jwksCache = new Map<string, CacheEntry>();
const inFlight = new Map<string, Promise<Record<string, unknown>[]>>();
const fetchLimiter = createRateLimiter({
	capacity: JWKS_FETCH_ATTEMPTS_PER_MINUTE,
	refillPerMinute: JWKS_FETCH_ATTEMPTS_PER_MINUTE,
});

// --- Injected clock for testing ---
let _now: () => number = () => Date.now();
/** Replace the clock (tests only). @internal */
export function _setJwksNow(fn: (() => number) | null): void {
	_now = fn ?? (() => Date.now());
}
/** Clear the key cache, in-flight map and fetch limiter (tests only). @internal */
export function _clearJwksCache(): void {
	jwksCache.clear();
	inFlight.clear();
	fetchLimiter._reset();
}

/** Length-prefixed cache key: the component boundary is unambiguous for any client_id. */
function cacheKey(clientId: string, jwksUri: string): string {
	return `${clientId.length}:${clientId}|${jwksUri}`;
}

export interface GetClientJwksOptions {
	/** The caller saw an unknown `kid`: refetch once if the rate limit allows. */
	refetchForUnknownKid?: boolean;
}

/**
 * Return the verified public keys at `jwksUri` for `clientId`. Throws
 * `CimdClientError` on policy, fetch or validation failures (429-status
 * errors for capacity and rate limits) and a plain `Error` on transport
 * failures.
 */
export async function getClientJwks(
	clientId: string,
	jwksUri: string,
	cimdConfig: MCPClientIdMetadataDocumentsConfig | undefined,
	options: GetClientJwksOptions = {},
	logger?: Logger
): Promise<Record<string, unknown>[]> {
	const locationIssue = jwksUriIssue(jwksUri, clientId, cimdConfig?.privateKeyJwt?.jwksUriAllowedOrigins ?? []);
	if (locationIssue) {
		throw new CimdClientError('invalid_client', `client keys: ${locationIssue}`);
	}

	const key = cacheKey(clientId, jwksUri);
	const now = _now();
	const cached = jwksCache.get(key);
	if (cached && cached.expiresAt <= now) jwksCache.delete(key);
	const fresh = cached && cached.expiresAt > now ? cached : undefined;

	if (fresh) {
		const refetchAllowed = options.refetchForUnknownKid && now - fresh.fetchedAt >= KID_MISS_REFETCH_INTERVAL_MS;
		if (!refetchAllowed) {
			// LRU refresh: re-insert so eviction targets the least recently used.
			jwksCache.delete(key);
			jwksCache.set(key, fresh);
			return fresh.keys;
		}
	}

	const existing = inFlight.get(key);
	if (existing) return existing;
	// Total-concurrency bound: the in-flight map IS the counter (no await sits
	// between this check and the set below). Checked before the attempt limiter
	// so a capacity reject does not spend an attempt.
	if (inFlight.size >= MAX_CONCURRENT_JWKS_FETCHES) {
		throw new CimdClientError('temporarily_unavailable', 'client key fetch capacity reached; retry shortly', {
			statusCode: 429,
		});
	}
	const attempt = fetchLimiter.tryTake(key);
	if (!attempt.allowed) {
		logger?.warn?.(`JWKS: fetch rate limit reached for client ${JSON.stringify(clientId)}`);
		throw new CimdClientError('slow_down', 'client key fetch rate limit reached; retry shortly', {
			statusCode: 429,
			retryAfterSeconds: attempt.retryAfterSeconds,
		});
	}
	const pending = fetchAndCache(key, clientId, jwksUri, cimdConfig, logger).finally(() => inFlight.delete(key));
	inFlight.set(key, pending);
	return pending;
}

async function fetchAndCache(
	key: string,
	clientId: string,
	jwksUri: string,
	cimdConfig: MCPClientIdMetadataDocumentsConfig | undefined,
	logger?: Logger
): Promise<Record<string, unknown>[]> {
	try {
		const { body, cacheControl } = await fetchPinnedBoundedJson(jwksUri, {
			label: 'JWKS document',
			tag: 'JWKS',
			accept: 'application/jwk-set+json, application/json',
			contentTypes: ['application/jwk-set+json', 'application/json'],
			timeoutMs: toFinitePositive(cimdConfig?.fetchTimeoutMs, DEFAULT_FETCH_TIMEOUT_MS),
			maxBytes: toFinitePositive(cimdConfig?.maxDocumentBytes, DEFAULT_MAX_DOCUMENT_BYTES),
			logger,
		});
		let doc: unknown;
		try {
			doc = JSON.parse(body);
		} catch (error) {
			throw new CimdClientError('invalid_client', 'JWKS document is not valid JSON', { cause: error });
		}
		const keySet = publicKeySetFromDocument(doc);
		if ('error' in keySet) throw new CimdClientError('invalid_client', `JWKS document: ${keySet.error}`);

		if (jwksCache.size >= JWKS_CACHE_MAX_ENTRIES) {
			const oldest = jwksCache.keys().next().value;
			if (oldest !== undefined) jwksCache.delete(oldest);
		}
		const ttlSeconds = cacheTtlSeconds(
			cacheControl,
			JWKS_CACHE_MIN_TTL_S,
			JWKS_CACHE_MAX_TTL_S,
			JWKS_CACHE_DEFAULT_TTL_S
		);
		const now = _now();
		jwksCache.delete(key);
		jwksCache.set(key, { keys: keySet.keys, expiresAt: now + ttlSeconds * 1000, fetchedAt: now });
		logger?.info?.(
			`JWKS: fetched ${keySet.keys.length} key(s) for client ${JSON.stringify(clientId)} (cached for ${ttlSeconds}s)`
		);
		return keySet.keys;
	} catch (err) {
		// Never cache errors or invalid sets; the attempt limiter bounds repeats.
		if (err instanceof CimdClientError) {
			logger?.warn?.(`JWKS: rejected keys for client ${JSON.stringify(clientId)}: ${err.message}`);
		} else {
			logger?.error?.(
				`JWKS: fetch failed for client ${JSON.stringify(clientId)}: ${err instanceof Error ? err.message : String(err)}`
			);
		}
		throw err;
	}
}
