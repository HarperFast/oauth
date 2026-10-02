/**
 * OIDC Discovery 1.0 — deriving an ID-token issuer for a statically
 * configured, explicit-endpoint JWKS provider that has no usable `issuer`
 * (HarperFast/oauth#264). Presets (`domain`/`tenantId`) already derive an
 * issuer directly for the common shortcuts; this module covers the case
 * where an operator bypassed those shortcuts with explicit endpoints.
 *
 * Fetch safety: reuses `fetchPinnedBoundedJson` (pinned-connect, no-redirect,
 * size- and time-bounded) — no new fetch primitive. Opts out of its
 * private/loopback-address block (`allowPrivateAddresses`): the endpoints
 * discovered against here are operator-configured, not attacker-controlled,
 * the same trust level as `jwksUri` itself (which `jwks-rsa` fetches with no
 * SSRF gate at all) — unlike CIMD's own `client_id` input, which that block
 * exists for.
 *
 * Validation (per OIDC Discovery 1.0 §4.3 and #264's own design): a
 * candidate issuer is accepted only when its document's `issuer` equals the
 * exact URL prefix it was fetched from (root accepts the documented
 * trailing-slash exception), `authorization_endpoint` exactly equals the
 * configured `authorizationUrl`, `jwks_uri` exactly equals the configured
 * `jwksUri`, and `token_endpoint` exactly equals the configured `tokenUrl`
 * (required by OIDC Discovery for the authorization-code flow this plugin
 * uses — a document that omits it refuses too, never bypassing the check).
 * Every candidate is constructed from the configured `authorizationUrl`'s
 * own origin, so cross-origin is structurally impossible, not just checked.
 *
 * Performance/safety contract:
 * - Never blocks boot: `startIssuerDiscovery` is fire-and-forget, called only
 *   after a provider registry is *published* (see `src/index.ts`), never
 *   from config building.
 * - Never fetches per request: dynamic (`onResolveProvider`) providers only
 *   ever read the cache (`awaitDiscoveredIssuer`), keyed by the full
 *   validated tuple so they can share a result with a static provider that
 *   already resolved the same endpoints — never starting a fetch of their
 *   own.
 * - The first adoption-eligible login (one whose ID-token signature already
 *   verified — `OAuthProvider.verifyIdToken` awaits this only *after* that)
 *   awaits the in-flight attempt with a short, explicit bound
 *   (`DISCOVERY_LOGIN_AWAIT_BOUND_MS`); any other login during the same
 *   pending window does not wait, by #264's own design.
 * - Bounded everywhere: `MAX_DISCOVERY_PREFIXES` ancestor path-prefixes,
 *   `DISCOVERY_OVERALL_BUDGET_MS` total wall-clock per discovery attempt
 *   (checked only between fully-awaited fetches — never racing an
 *   outstanding one), `MAX_CONCURRENT_DISCOVERY_ATTEMPTS` in-flight at once.
 * - Cached for the process lifetime on success; a failure is retried at most
 *   once per `RETRY_COOLDOWN_MS`, and only from a fresh `startIssuerDiscovery`
 *   call (a live config reload) — never from the read path.
 * - Fully failure-contained: nothing in this module can produce an unhandled
 *   rejection or let a throwing logger escape a caller.
 */

import {
	fetchPinnedBoundedJson,
	CimdClientError,
	DEFAULT_FETCH_TIMEOUT_MS,
	DEFAULT_MAX_DOCUMENT_BYTES,
} from './mcp/cimd.ts';
import type { Logger } from '../types.ts';

/** Bound on a first adoption-eligible login awaiting an in-flight discovery attempt. */
export const DISCOVERY_LOGIN_AWAIT_BOUND_MS = 3_000;
/** Total wall-clock budget for one discovery attempt, across every candidate prefix. */
export const DISCOVERY_OVERALL_BUDGET_MS = 15_000;
/** Ancestor path-prefixes tried, longest first, before giving up. */
export const MAX_DISCOVERY_PREFIXES = 10;
/** Minimum spacing between a failed discovery attempt and the next one for the same key. */
export const RETRY_COOLDOWN_MS = 5 * 60_000;
/** Discovery attempts allowed in flight at once, across every provider. */
export const MAX_CONCURRENT_DISCOVERY_ATTEMPTS = 8;

/** Delay before retrying a fetch that only failed because CIMD's shared DNS-lookup permit (2, process-wide) was busy — never a "no document here" signal. */
export const CAPACITY_RETRY_DELAY_MS = 50;

// --- Injected timeouts for testing (mirrors cimd.ts's _setFetch/_setDnsLookup seams) ---
let _perFetchTimeoutMs = DEFAULT_FETCH_TIMEOUT_MS;
let _overallBudgetMs = DISCOVERY_OVERALL_BUDGET_MS;
let _retryCooldownMs = RETRY_COOLDOWN_MS;
let _capacityRetryDelayMs = CAPACITY_RETRY_DELAY_MS;

/** Override the per-fetch, overall-budget, retry-cooldown, and capacity-retry-delay timeouts (tests only); `null` restores the defaults. @internal */
export function _setDiscoveryTimeouts(
	overrides: {
		perFetchMs?: number;
		overallBudgetMs?: number;
		retryCooldownMs?: number;
		capacityRetryDelayMs?: number;
	} | null
): void {
	_perFetchTimeoutMs = overrides?.perFetchMs ?? DEFAULT_FETCH_TIMEOUT_MS;
	_overallBudgetMs = overrides?.overallBudgetMs ?? DISCOVERY_OVERALL_BUDGET_MS;
	_retryCooldownMs = overrides?.retryCooldownMs ?? RETRY_COOLDOWN_MS;
	_capacityRetryDelayMs = overrides?.capacityRetryDelayMs ?? CAPACITY_RETRY_DELAY_MS;
}

interface DiscoveryEntry {
	promise: Promise<string | null>;
	/** `undefined` while pending; the settled value (success or `null`) once known. */
	result?: string | null;
	/** Whether some login has already consumed the one bounded-await slot for this key. */
	awaited: boolean;
	settledAt?: number;
}

const discoveryCache = new Map<string, DiscoveryEntry>();
let activeDiscoveryAttempts = 0;
const discoveryQueue: Array<() => void> = [];

/** Key space is operator-configured endpoints, not request input — no eviction needed (unlike CIMD's attacker-keyed cache). */
function cacheKey(authorizationUrl: string, jwksUri: string, tokenUrl: string): string {
	return `${authorizationUrl}\n${jwksUri}\n${tokenUrl}`;
}

/** Clear all discovery state (tests only). @internal */
export function _clearDiscoveryCache(): void {
	discoveryCache.clear();
	activeDiscoveryAttempts = 0;
	discoveryQueue.length = 0;
}

/**
 * Ancestor path-prefixes of `pathname`, longest first, root last (`''`),
 * capped at `MAX_DISCOVERY_PREFIXES`. E.g. `/oauth2/id/v1/authorize` ->
 * `['/oauth2/id/v1', '/oauth2/id', '/oauth2', '']`.
 *
 * Root (`''`) is always included, even when capping: a `pathname` of `/`
 * itself has zero segments, so the drop-one-segment-at-a-time loop below
 * would otherwise never run at all and skip root entirely; a `pathname`
 * deeper than the cap would otherwise only ever try its longest prefixes
 * and never reach root, which is often exactly where a provider's discovery
 * document actually lives.
 */
function candidatePrefixes(pathname: string): string[] {
	const segments = pathname.split('/').filter(Boolean);
	if (segments.length === 0) return [''];
	const all: string[] = [];
	for (let drop = 1; drop <= segments.length; drop++) {
		const remaining = segments.slice(0, segments.length - drop);
		all.push(remaining.length === 0 ? '' : '/' + remaining.join('/'));
	}
	if (all.length <= MAX_DISCOVERY_PREFIXES) return all;
	return [...all.slice(0, MAX_DISCOVERY_PREFIXES - 1), all[all.length - 1]];
}

/** `true` only for CIMD's shared, process-wide DNS-lookup-permit rejection — never a real transport/validation failure. */
function isDnsCapacityRejection(error: unknown): boolean {
	return error instanceof CimdClientError && error.oauthError === 'temporarily_unavailable';
}

/**
 * Fetch one discovery document, deadlined at `deadlineAt` (an absolute
 * `Date.now()`-style timestamp — not a duration, so retries below share one
 * budget instead of each restarting a fresh per-fetch timeout). A DNS
 * capacity rejection (CIMD's `checkHostSsrf` shares a process-wide,
 * 2-permit DNS-lookup gate with every other CIMD/discovery caller; with
 * several discovery attempts started at once, the 3rd and later synchronously
 * see the permit already taken) retries the SAME fetch after a short delay
 * instead of being treated as "no document at this prefix" — that gate is a
 * transient capacity signal, not a result about this endpoint, so advancing
 * to the next (shorter) prefix on it would reach a wrong, and wrongly
 * CACHED, "not found" outcome purely from how many other discovery attempts
 * happened to start at the same moment. Returns `null` for every other
 * failure (transport, timeout, non-JSON, oversize, a genuinely exhausted
 * deadline) exactly as before.
 */
interface DiscoveryDocumentResult {
	doc: any | null;
	/** `true` only when the deadline ran out while every attempt was still hitting the DNS capacity gate — never a real negative result about this endpoint. */
	capacityExhausted: boolean;
}

async function fetchDiscoveryDocument(
	discoveryUrl: string,
	deadlineAt: number,
	logger?: Logger
): Promise<DiscoveryDocumentResult> {
	while (true) {
		const remaining = deadlineAt - Date.now();
		if (remaining <= 0) return { doc: null, capacityExhausted: false };
		try {
			const { body } = await fetchPinnedBoundedJson(discoveryUrl, {
				label: 'OIDC discovery document',
				tag: 'OIDC discovery',
				accept: 'application/json',
				contentTypes: ['application/json'],
				timeoutMs: Math.min(_perFetchTimeoutMs, remaining),
				maxBytes: DEFAULT_MAX_DOCUMENT_BYTES,
				logger,
				// `authorizationUrl`/`jwksUri` are operator-configured, not
				// attacker-controlled (unlike CIMD's own `client_id`) — the same
				// trust level as `jwksUri` itself, which `jwks-rsa` already fetches
				// with no SSRF gate at all. Blocking a private/loopback address here
				// would only break discovery for a self-hosted IdP on a private
				// network for no safety benefit over that already-ungated fetch.
				allowPrivateAddresses: true,
			});
			const doc = JSON.parse(body);
			return { doc: doc && typeof doc === 'object' && !Array.isArray(doc) ? doc : null, capacityExhausted: false };
		} catch (error) {
			if (isDnsCapacityRejection(error)) {
				if (remaining > _capacityRetryDelayMs) {
					await new Promise((resolve) => setTimeout(resolve, _capacityRetryDelayMs));
					continue;
				}
				return { doc: null, capacityExhausted: true };
			}
			return { doc: null, capacityExhausted: false }; // Transport, timeout, non-JSON, oversize, etc.
		}
	}
}

async function discoverIssuerUnsafe(
	authorizationUrl: string,
	jwksUri: string,
	tokenUrl: string,
	providerName: string,
	logger?: Logger
): Promise<string | null> {
	let url: URL;
	try {
		url = new URL(authorizationUrl);
	} catch {
		return null;
	}
	const startedAt = Date.now();
	const deadlineAt = startedAt + _overallBudgetMs;
	let lastMismatch: string | undefined;
	let lastCapacityExhausted = false;
	for (const prefix of candidatePrefixes(url.pathname)) {
		if (Date.now() >= deadlineAt) break;
		const issuerCandidates = prefix === '' ? [url.origin, `${url.origin}/`] : [`${url.origin}${prefix}`];
		const discoveryUrl =
			prefix === ''
				? `${url.origin}/.well-known/openid-configuration`
				: `${url.origin}${prefix}/.well-known/openid-configuration`;

		const { doc, capacityExhausted } = await fetchDiscoveryDocument(discoveryUrl, deadlineAt, logger);
		if (!doc) {
			lastCapacityExhausted = capacityExhausted;
			continue;
		}
		lastCapacityExhausted = false;

		if (!issuerCandidates.includes(doc.issuer)) {
			lastMismatch = `issuer ${JSON.stringify(doc.issuer)} does not match ${JSON.stringify(issuerCandidates[0])}`;
			continue;
		}
		if (doc.authorization_endpoint !== authorizationUrl) {
			lastMismatch = `authorization_endpoint ${JSON.stringify(doc.authorization_endpoint)} does not match the configured authorizationUrl ${JSON.stringify(authorizationUrl)}`;
			continue;
		}
		if (doc.jwks_uri !== jwksUri) {
			lastMismatch = `jwks_uri ${JSON.stringify(doc.jwks_uri)} does not match the configured jwksUri ${JSON.stringify(jwksUri)}`;
			continue;
		}
		// OIDC Discovery requires token_endpoint for the authorization-code flow
		// this plugin uses — an absent one is a non-compliant document, not a
		// safer bypass of the check, so it refuses the same as a mismatched one.
		if (doc.token_endpoint !== tokenUrl) {
			lastMismatch = `token_endpoint ${JSON.stringify(doc.token_endpoint)} does not match the configured tokenUrl ${JSON.stringify(tokenUrl)}`;
			continue;
		}

		try {
			logger?.info?.(
				`OIDC discovery for provider '${providerName}': issuer derived via discovery: ${doc.issuer} — add issuer: ${doc.issuer} to pin it.`
			);
		} catch {
			/* never let a throwing logger discard a successful result */
		}
		return doc.issuer;
	}

	try {
		const cause = lastCapacityExhausted
			? "the shared DNS-resolution capacity (CIMD's process-wide lookup permit) never freed up within the discovery budget — likely several discovery attempts starting at once; this will retry on the next reload"
			: (lastMismatch ?? 'no .well-known/openid-configuration document was found matching the configured endpoints');
		logger?.warn?.(
			`OIDC discovery failed for provider '${providerName}' at ${url.origin}: ${cause}. ` +
				`Set 'issuer' explicitly on provider '${providerName}' to your OIDC server's issuer URI.`
		);
	} catch {
		/* never let a throwing logger escape discovery */
	}
	return null;
}

/** Never rejects — any unexpected failure resolves to `null` after a best-effort, guarded log. */
async function discoverIssuer(
	authorizationUrl: string,
	jwksUri: string,
	tokenUrl: string,
	providerName: string,
	logger?: Logger
): Promise<string | null> {
	try {
		return await discoverIssuerUnsafe(authorizationUrl, jwksUri, tokenUrl, providerName, logger);
	} catch (error) {
		try {
			logger?.error?.(`OIDC discovery crashed for provider '${providerName}':`, error);
		} catch {
			/* never let a throwing logger escape discovery */
		}
		return null;
	}
}

function runQueued(): void {
	while (activeDiscoveryAttempts < MAX_CONCURRENT_DISCOVERY_ATTEMPTS && discoveryQueue.length > 0) {
		discoveryQueue.shift()!();
	}
}

/**
 * Start (or retry, after `RETRY_COOLDOWN_MS` since a prior failure) a
 * bounded, cached discovery attempt for one `(authorizationUrl, jwksUri,
 * tokenUrl)` tuple. Fire-and-forget: never throws, never blocks the caller.
 * Call only after the provider using these endpoints has been fully built
 * and published — never for a config that might still be discarded.
 */
export function startIssuerDiscovery(
	authorizationUrl: string,
	jwksUri: string,
	tokenUrl: string,
	providerName: string,
	logger?: Logger
): void {
	try {
		const key = cacheKey(authorizationUrl, jwksUri, tokenUrl);
		const existing = discoveryCache.get(key);
		if (existing) {
			const stale =
				existing.result === null &&
				existing.settledAt !== undefined &&
				Date.now() - existing.settledAt >= _retryCooldownMs;
			if (!stale) return;
		}

		try {
			logger?.debug?.(`OIDC discovery: starting for provider '${providerName}' at ${authorizationUrl}`);
		} catch {
			/* never let a throwing logger break discovery kickoff */
		}

		const run = (): Promise<string | null> => {
			activeDiscoveryAttempts++;
			return discoverIssuer(authorizationUrl, jwksUri, tokenUrl, providerName, logger).finally(() => {
				activeDiscoveryAttempts--;
				runQueued();
			});
		};
		const scheduled = new Promise<string | null>((resolve) => {
			const task = (): void => {
				run().then(resolve, () => resolve(null));
			};
			if (activeDiscoveryAttempts < MAX_CONCURRENT_DISCOVERY_ATTEMPTS) task();
			else discoveryQueue.push(task);
		});

		const entry: DiscoveryEntry = { promise: scheduled, awaited: false };
		scheduled.then(
			(value) => {
				entry.result = value;
				entry.settledAt = Date.now();
			},
			() => {
				entry.result = null;
				entry.settledAt = Date.now();
			}
		);
		discoveryCache.set(key, entry);
	} catch (error) {
		try {
			logger?.error?.(`OIDC discovery: failed to start for provider '${providerName}':`, error);
		} catch {
			/* swallow */
		}
	}
}

/**
 * Read (and, for the first caller only, bounded-await) the discovery result
 * for one `(authorizationUrl, jwksUri, tokenUrl)` tuple. Performs **zero**
 * network I/O itself — a cache miss (no static provider ever started
 * discovery for this exact tuple) returns `null` immediately, which is how a
 * dynamically-resolved provider reaches this function safely.
 */
export async function awaitDiscoveredIssuer(
	authorizationUrl: string,
	jwksUri: string,
	tokenUrl: string,
	logger?: Logger,
	boundMs: number = DISCOVERY_LOGIN_AWAIT_BOUND_MS
): Promise<string | null> {
	const key = cacheKey(authorizationUrl, jwksUri, tokenUrl);
	const entry = discoveryCache.get(key);
	if (!entry) {
		try {
			logger?.debug?.(
				`OIDC discovery: no cached result for ${authorizationUrl}; proceeding without a validated issuer for this login.`
			);
		} catch {
			/* never let a throwing logger break verification */
		}
		return null;
	}
	if (entry.result !== undefined) return entry.result;
	if (entry.awaited) return null;
	entry.awaited = true;
	return new Promise((resolve) => {
		const timer = setTimeout(() => resolve(null), boundMs);
		entry.promise.then((value) => {
			clearTimeout(timer);
			resolve(value);
		});
	});
}
