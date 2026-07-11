/**
 * Client ID Metadata Document (CIMD) resolution
 *
 * Implements the AS side of CIMD as specified in the MCP authorization spec
 * and draft-ietf-oauth-client-id-metadata-document-00. When a client_id is a
 * valid HTTPS URL with a non-root path, the AS fetches it as a JSON metadata
 * document (instead of doing a DCR lookup) and validates the result.
 *
 * SSRF guards:
 * - HTTPS only (lowercase-canonical scheme), non-root path required, no
 *   userinfo/fragment/query, no dot path segments (raw or percent-encoded).
 * - No IP-literal hosts in the URL (rejected before DNS).
 * - DNS gate: all resolved addresses are checked against the full IANA
 *   special-purpose registries. IPv4 rejects 0/8, 10/8, 100.64/10, 127/8,
 *   169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16,
 *   198.18/15, 198.51.100/24, 203.0.113/24, 224/4 (multicast), 240/4
 *   (reserved, incl. broadcast), and the AS112/AMT blocks.
 *   IPv6 fails closed to "global unicast (2000::/3) only", with v4-mapped and
 *   6to4/ISATAP transition forms classified by their embedded IPv4 address and
 *   the in-2000::/3 special-use prefixes (Teredo, ORCHID, documentation) also
 *   rejected.
 * - Pinned-connect: the fetch connects to the exact address the gate validated
 *   (custom `lookup`), while the hostname is kept for TLS SNI + certificate
 *   verification — so DNS rebinding between the gate and the connection cannot
 *   redirect the socket to an unvalidated address.
 * - `https.request` does not follow redirects, so a 3xx surfaces as a non-200
 *   and is rejected; only `200 OK` is accepted.
 * - 5 s deadline (configurable) covering DNS, connect, headers, AND body.
 * - Any rejection after headers (non-200, non-JSON, oversize) aborts the
 *   request, tearing down the pinned socket — a hostile endpoint can't hold
 *   connections open past the rejection.
 * - Concurrent DNS resolutions are globally bounded below libuv's default
 *   4-thread pool (getaddrinfo runs on that uncancellable pool and must not
 *   starve fs/crypto users), and TOTAL concurrent resolutions (DNS + connect
 *   + body) are separately bounded so unique client_ids can't fan out into
 *   unbounded outbound HTTPS work; over either bound, resolution
 *   fast-rejects. Concurrent resolutions of the same client_id are deduped
 *   to one fetch.
 * - 64 KB document size cap (configurable).
 * - `Accept: application/json` only; non-JSON responses rejected.
 * - Timeout/size config values are coerced to finite positive numbers;
 *   anything else (NaN, Infinity, non-numeric strings) falls back to the
 *   defaults rather than failing open.
 * - Rejections never echo the resolved address or DNS outcome to the caller
 *   (that would let unauthenticated clients probe the server's internal DNS
 *   view); details are logged server-side only.
 *
 * Caching:
 * - Per-process Map keyed by URL, LRU-bounded to 1000 entries (the key is
 *   attacker-chosen, so the cache must not grow unbounded).
 * - TTL: honor `Cache-Control: max-age` clamped to [60 s, 86400 s];
 *   default 3600 s when absent. `no-store`/`no-cache` are honored as the
 *   60 s floor rather than literally — the floor is deliberate DoS
 *   protection (an attacker's document must not be able to force a fetch
 *   per authorize request).
 * - Failures are NOT cached (the CIMD draft forbids caching error responses
 *   and invalid documents); repeated fetch attempts are instead rate-limited
 *   per client_id URL (fixed 10/min token bucket, #163) — legit clients hit
 *   the cache after their first success, so only failures repeat. Issuance
 *   itself is separately rate-limited at the client_credentials grant.
 * - Cached records are revalidated against the live redirect-host policy on
 *   every hit, so tightening `allowedRedirectUriHosts` takes effect
 *   immediately instead of after cache expiry (up to 24 h).
 *
 * Document shapes:
 * - Interactive (redirect-based) documents: `token_endpoint_auth_method:
 *   none` (public clients + PKCE), redirect_uris required.
 * - Headless client_credentials documents (#161): grant_types exactly
 *   ["client_credentials"], `token_endpoint_auth_method: private_key_jwt`,
 *   an inline public Ed25519 JWK Set (`jwks_uri` rejected — no second SSRF
 *   surface), NO redirect_uris/response_types — and only accepted when the
 *   operator has pinned `clientIdMetadataDocuments.allowedHosts` (hosting a
 *   reachable document must never suffice to mint tokens).
 */

import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';
import type { Logger, MCPClientIdMetadataDocumentsConfig, MCPClientRecord, MCPConfig } from '../../types.ts';
import { MCPClientStore } from './clientStore.ts';
import { createRateLimiter } from './rateLimit.ts';
import {
	validateGrantTypes,
	validateRedirectUri,
	validateResponseTypes,
	validateStringArray,
} from './clientValidator.ts';

const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_DOCUMENT_BYTES = 64 * 1024; // 64 KB
const CACHE_MIN_TTL_S = 60;
const CACHE_MAX_TTL_S = 86_400;
const CACHE_DEFAULT_TTL_S = 3_600;
const CACHE_MAX_ENTRIES = 1_000;

// Bound concurrent DNS resolutions: `dns.lookup` (getaddrinfo) runs on libuv's
// fixed thread pool and cannot be cancelled, so a flood of client_ids under
// blackholed DNS zones would otherwise pin every pool thread. The permit is
// held until the *underlying* lookup settles (not when the caller times out),
// which is what actually bounds pool occupancy. Kept below the default
// UV_THREADPOOL_SIZE (4) so CIMD lookups can never occupy the whole pool —
// fs/crypto/zlib share it; legit lookups settle in milliseconds, so the
// permit turns over fast.
const MAX_CONCURRENT_DNS = 2;
let activeDnsLookups = 0;

// Bound TOTAL concurrent CIMD resolutions (DNS + connect + body read): the DNS
// permit alone doesn't cap outbound HTTPS work — fast-resolving unique
// client_ids would otherwise fan out into unbounded concurrent fetches. The
// in-flight dedup map doubles as the counter (entries are removed on settle).
const MAX_CONCURRENT_RESOLUTIONS = 16;

type ResolvedAddress = { address: string; family: number };

type CacheEntry = { record: MCPClientRecord; expiresAt: number };

const cimdCache = new Map<string, CacheEntry>();

// Dedup concurrent resolutions of the same client_id so N parallel authorize
// requests for one uncached URL trigger a single fetch (thundering-herd guard).
const inFlightResolutions = new Map<string, Promise<MCPClientRecord | null>>();

// Per-URL fetch-attempt rate limit (#163) — fixed policy, no config knob:
// legit clients hit the cache after their first success (only failures
// repeat, and failures are never cached per the CIMD draft). Per-node
// semantics: see rateLimit.ts module header.
const CIMD_FETCH_ATTEMPTS_PER_MINUTE = 10;
const cimdFetchLimiter = createRateLimiter({
	capacity: CIMD_FETCH_ATTEMPTS_PER_MINUTE,
	refillPerMinute: CIMD_FETCH_ATTEMPTS_PER_MINUTE,
});

/**
 * Upper bound on a client_id length, shared by every entry point that uses a
 * caller-supplied client_id as a lookup or rate-limiter map key. Same
 * defense-in-depth family as the repo's 2048-char request-path cap.
 */
export const MAX_CLIENT_ID_LENGTH = 2048;

/**
 * Thrown when CIMD resolution fails due to a client-side issue (bad URL,
 * invalid document, unsupported auth method, allowedHosts policy).
 * Callers should surface this as the given `oauthError` with the `message`
 * as the `error_description`. Throttle rejections additionally carry a
 * `statusCode` (429) and `retryAfterSeconds` so callers can emit a proper
 * `Retry-After` instead of a misleading auth error.
 */
export class CimdClientError extends Error {
	readonly oauthError: string;
	readonly statusCode?: number;
	readonly retryAfterSeconds?: number;

	constructor(
		oauthError: string,
		message: string,
		options?: { cause?: unknown; statusCode?: number; retryAfterSeconds?: number }
	) {
		super(message, options);
		this.name = 'CimdClientError';
		this.oauthError = oauthError;
		this.statusCode = options?.statusCode;
		this.retryAfterSeconds = options?.retryAfterSeconds;
	}
}

// --- Injected dependencies for testing ---
export let _dnsLookup: (
	hostname: string,
	options: { all: true }
) => Promise<Array<{ address: string; family: number }>> = (hostname) => lookup(hostname, { all: true });

export function _setDnsLookup(
	fn: ((hostname: string, options: { all: true }) => Promise<Array<{ address: string; family: number }>>) | null
): void {
	_dnsLookup = fn ?? ((hostname) => lookup(hostname, { all: true }));
}

/**
 * Minimal response shape the resolver consumes. The production `_fetch`
 * (`pinnedHttpsFetch`) returns this; tests stub it directly.
 */
export type CimdResponse = {
	status: number;
	headers: { get(name: string): string | null };
	body: { getReader(): ReadableStreamDefaultReader<Uint8Array> } | null;
};

export type CimdFetchInit = {
	headers: Record<string, string>;
	signal: AbortSignal;
	/**
	 * Pre-validated addresses from the SSRF gate. The connection is PINNED to
	 * these (no re-resolution at connect time), which closes the DNS-rebinding
	 * TOCTOU: the socket connects to exactly the address that passed the gate,
	 * while the hostname is still used for TLS SNI and certificate validation.
	 */
	pinnedAddresses: ResolvedAddress[];
};

export type CimdFetch = (url: string, init: CimdFetchInit) => Promise<CimdResponse>;

/**
 * Fetch a CIMD document over HTTPS, pinning the TCP connection to a
 * pre-validated address via a custom `lookup`. `https.request` never follows
 * redirects, so a 3xx simply surfaces as a non-200 status (rejected upstream).
 */
function pinnedHttpsFetch(urlStr: string, init: CimdFetchInit): Promise<CimdResponse> {
	const url = new URL(urlStr);
	const pinned = init.pinnedAddresses;
	// The lookup ignores DNS and returns the already-validated address, so the
	// connect cannot race a rebind to a fresh (unvalidated) resolution.
	const lookup = (
		_host: string,
		options: { all?: boolean },
		callback: (err: Error | null, address?: any, family?: number) => void
	) => {
		if (options && options.all) return callback(null, pinned);
		callback(null, pinned[0].address, pinned[0].family);
	};
	return new Promise((resolve, reject) => {
		const req = httpsRequest(
			url,
			{ method: 'GET', headers: init.headers, servername: url.hostname, lookup: lookup as any, signal: init.signal },
			(res) => {
				resolve({
					status: res.statusCode ?? 0,
					headers: new Headers(res.headers as Record<string, string>),
					body: Readable.toWeb(res) as unknown as CimdResponse['body'],
				});
			}
		);
		req.on('error', reject);
		req.end();
	});
}

export let _fetch: CimdFetch = pinnedHttpsFetch;

export function _setFetch(fn: CimdFetch | null): void {
	_fetch = fn ?? pinnedHttpsFetch;
}

/** Clear the CIMD cache AND the per-URL fetch limiter (for testing) — tests
 * that loop many resolution attempts against one URL rely on the limiter
 * resetting alongside the cache. @internal */
export function _clearCimdCache(): void {
	cimdCache.clear();
	cimdFetchLimiter._reset();
}

// --- SSRF guard helpers ---

function isIpLiteral(hostname: string): boolean {
	// IPv6 literal: [...] (as returned by URL.hostname for IPv6 URLs)
	if (hostname.startsWith('[')) return true;
	// IPv4: four octets separated by dots
	return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

/**
 * IANA IPv4 special-purpose prefixes that must never be fetched (SSRF): every
 * non-global-unicast range from the IPv4 Special-Purpose Address Registry.
 * `[first-octet-quad, prefix-bits]`; checked as CIDRs against the address int.
 */
const IPV4_SPECIAL_USE: Array<[number, number, number, number, number]> = [
	[0, 0, 0, 0, 8], // "this network"
	[10, 0, 0, 0, 8], // private
	[100, 64, 0, 0, 10], // CGNAT / shared address space
	[127, 0, 0, 0, 8], // loopback
	[169, 254, 0, 0, 16], // link-local
	[172, 16, 0, 0, 12], // private
	[192, 0, 0, 0, 24], // IETF protocol assignments
	[192, 0, 2, 0, 24], // TEST-NET-1 (documentation)
	[192, 31, 196, 0, 24], // AS112-v4
	[192, 52, 193, 0, 24], // AMT
	[192, 88, 99, 0, 24], // 6to4 relay anycast (deprecated)
	[192, 168, 0, 0, 16], // private
	[192, 175, 48, 0, 24], // direct-delegation AS112
	[198, 18, 0, 0, 15], // benchmarking
	[198, 51, 100, 0, 24], // TEST-NET-2 (documentation)
	[203, 0, 113, 0, 24], // TEST-NET-3 (documentation)
	[224, 0, 0, 0, 4], // multicast
	[240, 0, 0, 0, 4], // reserved (incl. 255.255.255.255 broadcast)
];

function ipv4ToInt(a: number, b: number, c: number, d: number): number {
	return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

function isPrivateIpv4(address: string): boolean {
	const parts = address.split('.').map(Number);
	if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return true; // malformed → fail closed
	const [a, b, c, d] = parts;
	if (a >= 224) return true; // fast path — 224/4 + 240/4 are also table entries, so the table alone stays complete
	const ip = ipv4ToInt(a, b, c, d);
	for (const [wa, wb, wc, wd, bits] of IPV4_SPECIAL_USE) {
		const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
		if ((ip & mask) === (ipv4ToInt(wa, wb, wc, wd) & mask)) return true;
	}
	return false;
}

/**
 * Expand an IPv6 address into its 8 16-bit groups. Handles `::` compression,
 * a trailing embedded dotted-quad (v4-mapped/compat forms), and zone indexes.
 * Returns null when the address doesn't parse — callers treat that as
 * non-global (fail closed).
 */
function parseIpv6Groups(address: string): number[] | null {
	let addr = address;
	const zoneIdx = addr.indexOf('%');
	if (zoneIdx !== -1) addr = addr.slice(0, zoneIdx);
	addr = addr.toLowerCase();
	if (!addr) return null;

	// Convert a trailing dotted-quad into its two hex groups.
	if (addr.includes('.')) {
		const lastColon = addr.lastIndexOf(':');
		if (lastColon === -1) return null;
		const octets = addr
			.slice(lastColon + 1)
			.split('.')
			.map((o) => (/^\d{1,3}$/.test(o) ? parseInt(o, 10) : -1));
		if (octets.length !== 4 || octets.some((o) => o < 0 || o > 255)) return null;
		addr =
			addr.slice(0, lastColon + 1) +
			((octets[0] << 8) | octets[1]).toString(16) +
			':' +
			((octets[2] << 8) | octets[3]).toString(16);
	}

	const halves = addr.split('::');
	if (halves.length > 2) return null;
	const parseSide = (side: string): number[] | null => {
		if (side === '') return [];
		const out: number[] = [];
		for (const group of side.split(':')) {
			if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
			out.push(parseInt(group, 16));
		}
		return out;
	};

	if (halves.length === 2) {
		const left = parseSide(halves[0]);
		const right = parseSide(halves[1]);
		if (!left || !right || left.length + right.length > 7) return null;
		return [...left, ...new Array(8 - left.length - right.length).fill(0), ...right];
	}
	const groups = parseSide(addr);
	return groups && groups.length === 8 ? groups : null;
}

function ipv6ToBigInt(groups: number[]): bigint {
	let v = 0n;
	for (const g of groups) v = (v << 16n) | BigInt(g);
	return v;
}

/** Build a `[baseBigInt, prefixBits]` entry from a textual IPv6 prefix. */
function cidr6(prefix: string, bits: number): [bigint, number] {
	const groups = parseIpv6Groups(prefix);
	if (!groups) throw new Error(`invalid IPv6 prefix in special-use table: ${prefix}`);
	return [ipv6ToBigInt(groups), bits];
}

/**
 * IANA IPv6 special-purpose prefixes that fall *inside* global unicast
 * (2000::/3) and would otherwise pass the allow — documentation, benchmarking,
 * Teredo, ORCHID. Everything outside 2000::/3 (loopback, ULA, link-local,
 * multicast, NAT64, etc.) is already rejected by the global check below.
 */
const IPV6_SPECIAL_USE: Array<[bigint, number]> = [
	cidr6('2001:0000::', 32), // Teredo
	cidr6('2001:2::', 48), // benchmarking
	cidr6('2001:10::', 28), // ORCHID (deprecated)
	cidr6('2001:20::', 28), // ORCHIDv2
	cidr6('2001:db8::', 32), // documentation
	cidr6('3fff::', 20), // documentation
];

/**
 * Fail-closed IPv6 policy: only global unicast (2000::/3) is allowed, with
 * v4-mapped addresses (::ffff:a.b.c.d) classified by their embedded IPv4
 * address. Everything else — `::` unspecified, `::1` loopback in any textual
 * form, fc00::/7 ULA, fe80::/10 link-local, ff00::/8 multicast, NAT64,
 * reserved blocks, unparseable input — is treated as private.
 *
 * The IPv4-in-IPv6 transition forms sit *inside* 2000::/3 yet can target a
 * private IPv4, so they're decoded rather than blanket-allowed: 6to4
 * (2002::/16) and ISATAP embed a plaintext IPv4 (classified via
 * `isPrivateIpv4`). Special-use prefixes inside 2000::/3 (Teredo, ORCHID,
 * documentation, benchmarking) are rejected via `IPV6_SPECIAL_USE`.
 */
function isPrivateIpv6(address: string): boolean {
	const groups = parseIpv6Groups(address);
	if (!groups) return true;
	const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
	if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
		return isPrivateIpv4(`${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`);
	}
	// 6to4 (2002::/16) embeds an IPv4 address in groups 1 and 2
	if (g0 === 0x2002) {
		return isPrivateIpv4(`${g1 >> 8}.${g1 & 0xff}.${g2 >> 8}.${g2 & 0xff}`);
	}
	// ISATAP (interface identifier 0000:5efe:a.b.c.d or 0200:5efe:a.b.c.d)
	if ((g4 === 0x0000 || g4 === 0x0200) && g5 === 0x5efe) {
		return isPrivateIpv4(`${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`);
	}
	const ip = ipv6ToBigInt(groups);
	for (const [base, bits] of IPV6_SPECIAL_USE) {
		const mask = ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
		if ((ip & mask) === (base & mask)) return true;
	}
	return (g0 & 0xe000) !== 0x2000;
}

/**
 * Uniform client-facing message for every DNS-gate rejection. Deliberately
 * carries no detail: distinguishing "didn't resolve" from "resolved to a
 * private address" (or echoing the address) would let unauthenticated
 * callers probe the server's internal DNS view with guessed hostnames.
 * Details go to the server-side log only.
 */
const DNS_GATE_REJECTION = 'client_id metadata document host could not be resolved to a permitted address';

/**
 * Resolve `hostname` under a global concurrency permit. `dns.lookup` uses the
 * uncancellable libuv thread pool, so the permit is released only when the
 * *underlying* lookup settles — a caller that gives up early (deadline) does
 * NOT free a pool slot for a fresh lookup. When saturated we fast-reject
 * rather than queue unboundedly.
 */
async function boundedDnsLookup(hostname: string): Promise<ResolvedAddress[]> {
	if (activeDnsLookups >= MAX_CONCURRENT_DNS) {
		throw new CimdClientError('temporarily_unavailable', 'CIMD resolution capacity reached; retry shortly');
	}
	activeDnsLookups++;
	const raw = _dnsLookup(hostname, { all: true });
	// Release strictly on the RAW settle — not on the caller's (possibly earlier)
	// timeout — so concurrent getaddrinfo calls stay bounded by MAX_CONCURRENT_DNS.
	raw.then(
		() => activeDnsLookups--,
		() => activeDnsLookups--
	);
	return raw;
}

/**
 * DNS SSRF gate: resolves all addresses for `hostname`, rejects if any falls
 * outside the allowed (global unicast) ranges, and returns the validated set so
 * the caller can PIN the connection to it (closing the rebind TOCTOU).
 */
async function checkHostSsrf(hostname: string, logger?: Logger): Promise<ResolvedAddress[]> {
	let addresses: ResolvedAddress[];
	try {
		addresses = await boundedDnsLookup(hostname);
	} catch (error) {
		if (error instanceof CimdClientError) throw error; // capacity fast-reject
		logger?.warn?.(`CIMD: DNS resolution failed for host ${hostname}`);
		throw new CimdClientError('invalid_client', DNS_GATE_REJECTION, { cause: error });
	}
	if (addresses.length === 0) {
		logger?.warn?.(`CIMD: no addresses resolved for host ${hostname}`);
		throw new CimdClientError('invalid_client', DNS_GATE_REJECTION);
	}
	for (const { address, family } of addresses) {
		// Fail closed on any family the resolver reports other than 4/6 — an
		// unclassified address must never skip both range checks.
		const blocked = family === 4 ? isPrivateIpv4(address) : family === 6 ? isPrivateIpv6(address) : true;
		if (blocked) {
			logger?.warn?.(`CIMD: host ${hostname} resolves to a blocked address: ${address} (family ${family})`);
			throw new CimdClientError('invalid_client', DNS_GATE_REJECTION);
		}
	}
	return addresses;
}

// --- URL shape checks ---

/**
 * Return true when `clientId` contains a dot path segment (`/./` or `/../`),
 * raw or percent-encoded. Checked against the RAW string because WHATWG URL
 * parsing normalizes dot segments away before `URL.pathname` can see them —
 * `https://example.com/a/../client.json` must not alias
 * `https://example.com/client.json` when client_ids are compared as simple
 * strings (the CIMD draft prohibits dot path components).
 */
function hasDotPathSegments(clientId: string): boolean {
	const afterAuthority = clientId.slice('https://'.length);
	const pathStart = afterAuthority.indexOf('/');
	if (pathStart === -1) return false;
	let path = afterAuthority.slice(pathStart);
	const queryStart = path.search(/[?#]/);
	if (queryStart !== -1) path = path.slice(0, queryStart);
	const decoded = path.replace(/%2e/gi, '.');
	return /(^|\/)\.\.?(\/|$)/.test(decoded);
}

/**
 * Return true when `clientId` has the shape of a CIMD client_id:
 * - https scheme, written in canonical lowercase `https://` form (the
 *   document's client_id must string-match the URL exactly, so
 *   non-canonical scheme spellings can never validate anyway)
 * - Non-root path (pathname !== '' and pathname !== '/')
 * - No dot path segments, raw or percent-encoded
 * - No userinfo (username / password)
 * - No fragment
 * - No query string (the draft says SHOULD NOT; enforced here — a dynamic
 *   server could otherwise mint unlimited exact-match client_id aliases of
 *   one document by echoing query variants)
 * - Host is NOT an IP literal (IPv4 dotted-quad or IPv6 [bracket] form)
 *
 * This is a structural check only — no network I/O, no policy enforcement.
 * Policy checks (allowedHosts, SSRF gate) happen inside `resolveCimdClient`.
 */
export function isCimdClientId(clientId: string): boolean {
	if (!clientId.startsWith('https://')) return false;
	let url: URL;
	try {
		url = new URL(clientId);
	} catch {
		return false;
	}
	if (url.protocol !== 'https:') return false;
	if (url.pathname === '' || url.pathname === '/') return false;
	if (hasDotPathSegments(clientId)) return false;
	if (url.username || url.password) return false;
	if (url.hash) return false;
	if (url.search) return false;
	if (isIpLiteral(url.hostname)) return false;
	return true;
}

// --- Cache helpers ---

function parseCacheControlMaxAge(header: string | null): number {
	if (!header) return CACHE_DEFAULT_TTL_S;
	// `no-store`/`no-cache` are honored as the minimum TTL, not literally —
	// the floor is deliberate DoS protection (see module header).
	if (/\bno-store\b|\bno-cache\b/i.test(header)) return CACHE_MIN_TTL_S;
	const match = /\bmax-age\s*=\s*(\d+)/i.exec(header);
	if (!match) return CACHE_DEFAULT_TTL_S;
	const seconds = parseInt(match[1], 10);
	if (isNaN(seconds)) return CACHE_DEFAULT_TTL_S;
	return Math.max(CACHE_MIN_TTL_S, Math.min(CACHE_MAX_TTL_S, seconds));
}

/**
 * Coerce a config value to a finite positive number, falling back to
 * `fallback` otherwise. Config values can arrive as env-expanded strings, and
 * `NaN`/`Infinity` would silently disable the `>` comparisons the size and
 * time caps rely on — fail closed to the default instead.
 */
function toFinitePositive(value: unknown, fallback: number): number {
	const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
	return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Reject `promise` with `message` if `signal` aborts first (for operations
 * like `dns.lookup` that don't accept an AbortSignal themselves). */
function withAbort<T>(promise: Promise<T>, signal: AbortSignal, message: string): Promise<T> {
	if (signal.aborted) return Promise.reject(new Error(message));
	return new Promise((resolve, reject) => {
		const onAbort = () => reject(new Error(message));
		signal.addEventListener('abort', onAbort, { once: true });
		promise.then(
			(value) => {
				signal.removeEventListener('abort', onAbort);
				resolve(value);
			},
			(error) => {
				signal.removeEventListener('abort', onAbort);
				reject(error);
			}
		);
	});
}

// --- Document validation ---

function validateCimdDocument(
	doc: unknown,
	clientId: string,
	allowedRedirectUriHosts: string[] | undefined,
	allowedHostsConfigured: boolean
): MCPClientRecord {
	if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
		throw new CimdClientError('invalid_client', 'CIMD document must be a JSON object');
	}
	const d = doc as Record<string, unknown>;

	// client_id in document MUST exactly match the fetched URL.
	if (typeof d.client_id !== 'string' || d.client_id !== clientId) {
		throw new CimdClientError(
			'invalid_client',
			`CIMD document client_id (${JSON.stringify(d.client_id)}) does not match the request URL`
		);
	}

	// Required fields.
	if (typeof d.client_name !== 'string' || !d.client_name) {
		throw new CimdClientError('invalid_client', 'CIMD document missing required field: client_name');
	}

	// Optional array fields — validated before branching, because the
	// credentials branch below is selected on grant_types, which must be a
	// clean string array first.
	for (const [field, value] of Object.entries({
		contacts: d.contacts,
		grant_types: d.grant_types,
		response_types: d.response_types,
	})) {
		const err = validateStringArray(value, field);
		if (err) throw new CimdClientError('invalid_client', `CIMD document: ${err}`);
	}

	// client_credentials documents (headless agents, #161) have a distinct
	// shape: no redirect surface, private_key_jwt + an inline Ed25519 JWK Set.
	if (Array.isArray(d.grant_types) && (d.grant_types as string[]).includes('client_credentials')) {
		return validateCredentialsDocument(d, clientId, allowedHostsConfigured);
	}

	// --- Interactive (redirect-based) document shape ---
	if (!Array.isArray(d.redirect_uris) || d.redirect_uris.length === 0) {
		throw new CimdClientError('invalid_client', 'CIMD document missing required field: redirect_uris');
	}

	// Validate redirect_uris with the same structural rules AND the same
	// redirect-host policy as DCR (`dynamicClientRegistration.allowedRedirectUriHosts`).
	// Deliberately NOT `clientIdMetadataDocuments.allowedHosts` — that list governs
	// which hosts may SERVE metadata documents; a client's redirect targets are a
	// separate policy and need not share the document's host.
	for (const uri of d.redirect_uris) {
		const err = validateRedirectUri(uri, allowedRedirectUriHosts);
		if (err) throw new CimdClientError('invalid_client', `CIMD document: ${err}`);
	}

	// Grant types.
	const grantTypes: string[] = Array.isArray(d.grant_types)
		? (d.grant_types as string[])
		: ['authorization_code', 'refresh_token'];
	const grantErr = validateGrantTypes(grantTypes);
	if (grantErr) throw new CimdClientError('invalid_client', `CIMD document: ${grantErr}`);

	// Response types.
	const responseTypes: string[] = Array.isArray(d.response_types) ? (d.response_types as string[]) : ['code'];
	const responseErr = validateResponseTypes(responseTypes);
	if (responseErr) throw new CimdClientError('invalid_client', `CIMD document: ${responseErr}`);

	// token_endpoint_auth_method: interactive CIMD clients are public clients
	// ('none' + PKCE); 'private_key_jwt' exists only in the credentials shape.
	const authMethod = typeof d.token_endpoint_auth_method === 'string' ? d.token_endpoint_auth_method : 'none';
	if (authMethod !== 'none') {
		throw new CimdClientError(
			'invalid_client',
			`token_endpoint_auth_method '${authMethod}' is not supported for interactive CIMD clients; use 'none'`
		);
	}

	return {
		client_id: clientId,
		client_name: d.client_name as string,
		client_uri: typeof d.client_uri === 'string' ? d.client_uri : undefined,
		logo_uri: typeof d.logo_uri === 'string' ? d.logo_uri : undefined,
		scope: typeof d.scope === 'string' ? d.scope : undefined,
		contacts: Array.isArray(d.contacts) ? (d.contacts as string[]) : undefined,
		grant_types: grantTypes,
		response_types: responseTypes,
		token_endpoint_auth_method: authMethod,
		application_type: typeof d.application_type === 'string' ? d.application_type : 'web',
		software_id: typeof d.software_id === 'string' ? d.software_id : undefined,
		software_version: typeof d.software_version === 'string' ? d.software_version : undefined,
		redirect_uris: d.redirect_uris as string[],
		client_id_issued_at: 0, // CIMD records are not persisted; no issued-at timestamp.
		_cimd: true,
	};
}

/** Cap on registered assertion keys per client — bounds per-assertion verify
 * work and the jti-store keyspace a single document can claim. */
const MAX_CREDENTIALS_JWKS_KEYS = 8;

/**
 * Validate the client_credentials (headless agent) document shape (#161):
 * grant_types exactly ["client_credentials"], token_endpoint_auth_method
 * 'private_key_jwt', an inline JWK Set of 1..MAX_CREDENTIALS_JWKS_KEYS PUBLIC
 * Ed25519 keys, and no redirect surface — redirect_uris / response_types must
 * be ABSENT (RFC 7591 requires redirect_uris only for redirect-based grants,
 * and declaring one here would imply a flow this shape can never perform).
 * `jwks_uri` is rejected outright: the document itself is the hosted-key
 * story, and a second SSRF-fetch surface is not worth an indirection (#164).
 *
 * These documents only materialize when the operator has pinned
 * `clientIdMetadataDocuments.allowedHosts` — hosting a reachable document
 * must never suffice to mint tokens (#159 design update).
 */
function validateCredentialsDocument(
	d: Record<string, unknown>,
	clientId: string,
	allowedHostsConfigured: boolean
): MCPClientRecord {
	if (!allowedHostsConfigured) {
		throw new CimdClientError(
			'invalid_client',
			'client_credentials CIMD clients require the server to pin clientIdMetadataDocuments.allowedHosts'
		);
	}
	if ((d.grant_types as string[]).length !== 1) {
		throw new CimdClientError(
			'invalid_client',
			'CIMD document: client_credentials must not be combined with other grant types'
		);
	}
	if (d.redirect_uris !== undefined) {
		throw new CimdClientError(
			'invalid_client',
			'CIMD document: client_credentials clients must not declare redirect_uris'
		);
	}
	if (d.response_types !== undefined) {
		throw new CimdClientError(
			'invalid_client',
			'CIMD document: client_credentials clients must not declare response_types'
		);
	}
	if (d.token_endpoint_auth_method !== 'private_key_jwt') {
		throw new CimdClientError(
			'invalid_client',
			"CIMD document: client_credentials clients must use token_endpoint_auth_method 'private_key_jwt'"
		);
	}
	if (d.jwks_uri !== undefined) {
		throw new CimdClientError(
			'invalid_client',
			'CIMD document: jwks_uri is not supported; declare the public keys inline in jwks'
		);
	}
	const jwks = d.jwks;
	if (!jwks || typeof jwks !== 'object' || Array.isArray(jwks) || !Array.isArray((jwks as { keys?: unknown }).keys)) {
		throw new CimdClientError('invalid_client', 'CIMD document: client_credentials clients require a jwks JWK Set');
	}
	const keys = (jwks as { keys: unknown[] }).keys;
	if (keys.length === 0 || keys.length > MAX_CREDENTIALS_JWKS_KEYS) {
		throw new CimdClientError(
			'invalid_client',
			`CIMD document: jwks.keys must hold between 1 and ${MAX_CREDENTIALS_JWKS_KEYS} keys`
		);
	}
	// Beyond the security checks (public-only, Ed25519-only), enforce the shape
	// `selectKey` needs at verify time: verification fails CLOSED on missing or
	// duplicate kids anyway, but rejecting here surfaces a clear error when the
	// document is resolved instead of a confusing one on every assertion.
	const seenKids = new Set<string>();
	for (const key of keys) {
		if (!key || typeof key !== 'object' || Array.isArray(key)) {
			throw new CimdClientError('invalid_client', 'CIMD document: every jwks key must be a JWK object');
		}
		const k = key as Record<string, unknown>;
		if ('d' in k) {
			throw new CimdClientError(
				'invalid_client',
				'CIMD document: jwks must contain only PUBLIC keys (found private key material)'
			);
		}
		// Ed25519 public keys are exactly 32 bytes → 43 base64url chars; a precise
		// shape check keeps malformed keys out of the cache.
		if (k.kty !== 'OKP' || k.crv !== 'Ed25519' || typeof k.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(k.x)) {
			throw new CimdClientError('invalid_client', 'CIMD document: jwks keys must be public OKP/Ed25519 JWKs');
		}
		if (keys.length > 1 && k.kid === undefined) {
			throw new CimdClientError(
				'invalid_client',
				'CIMD document: jwks keys must each have a kid when multiple keys are present'
			);
		}
		if (k.kid !== undefined) {
			if (typeof k.kid !== 'string' || k.kid.length === 0) {
				throw new CimdClientError('invalid_client', 'CIMD document: jwks key kid must be a non-empty string');
			}
			if (seenKids.has(k.kid)) {
				throw new CimdClientError('invalid_client', 'CIMD document: jwks keys must have unique kid values');
			}
			seenKids.add(k.kid);
		}
	}

	return {
		client_id: clientId,
		client_name: d.client_name as string,
		client_uri: typeof d.client_uri === 'string' ? d.client_uri : undefined,
		logo_uri: typeof d.logo_uri === 'string' ? d.logo_uri : undefined,
		scope: typeof d.scope === 'string' ? d.scope : undefined,
		contacts: Array.isArray(d.contacts) ? (d.contacts as string[]) : undefined,
		grant_types: ['client_credentials'],
		token_endpoint_auth_method: 'private_key_jwt',
		software_id: typeof d.software_id === 'string' ? d.software_id : undefined,
		software_version: typeof d.software_version === 'string' ? d.software_version : undefined,
		jwks: { keys: keys as Record<string, unknown>[] },
		client_id_issued_at: 0, // CIMD records are not persisted; no issued-at timestamp.
		_cimd: true,
	};
}

// --- Core resolution ---

/**
 * Resolve a CIMD client_id by fetching and validating its metadata document.
 *
 * Returns a synthesized `MCPClientRecord` (with `_cimd: true`) on success.
 * Returns `null` when the URL's host is not in `allowedHosts` (treated as
 * "not found" — avoids leaking whether the host would be valid).
 * Throws `CimdClientError` for client-side validation failures (including
 * every DNS-gate rejection — see `DNS_GATE_REJECTION`).
 * Throws `Error` for server-side failures (network, timeout).
 *
 * Successful results are cached per URL per process (LRU-bounded); failures
 * are never cached (the CIMD draft forbids it).
 */
export async function resolveCimdClient(
	clientId: string,
	cimdConfig: MCPClientIdMetadataDocumentsConfig | undefined,
	allowedRedirectUriHosts?: string[],
	logger?: Logger
): Promise<MCPClientRecord | null> {
	// allowedHosts policy gate: when configured, only listed hosts are accepted.
	if (cimdConfig?.allowedHosts && cimdConfig.allowedHosts.length > 0) {
		let urlHost: string;
		try {
			urlHost = new URL(clientId).hostname;
		} catch {
			return null;
		}
		if (!cimdConfig.allowedHosts.includes(urlHost)) {
			// Return null (not found) rather than CimdClientError so we don't leak
			// the allowedHosts list to the client.
			logger?.debug?.(`CIMD: host ${urlHost} not in allowedHosts; treating as unknown client`);
			return null;
		}
	}

	// Cache lookup.
	const now = Date.now();
	const cached = cimdCache.get(clientId);
	if (cached) {
		if (cached.expiresAt <= now) {
			cimdCache.delete(clientId);
		} else {
			// Revalidate against the LIVE policies: a record cached under a looser
			// `allowedRedirectUriHosts` — or a credentials record cached while
			// `allowedHosts` was pinned — must not survive the operator tightening
			// or dropping the policy (cache TTL can be up to 24 h).
			if (
				cached.record.grant_types?.includes('client_credentials') &&
				!(cimdConfig?.allowedHosts && cimdConfig.allowedHosts.length > 0)
			) {
				cimdCache.delete(clientId);
				throw new CimdClientError(
					'invalid_client',
					'client_credentials CIMD clients require the server to pin clientIdMetadataDocuments.allowedHosts'
				);
			}
			for (const uri of cached.record.redirect_uris ?? []) {
				const policyErr = validateRedirectUri(uri, allowedRedirectUriHosts);
				if (policyErr) {
					cimdCache.delete(clientId);
					throw new CimdClientError('invalid_client', `CIMD document: ${policyErr}`);
				}
			}
			// LRU refresh: re-insert so eviction targets the least recently used.
			cimdCache.delete(clientId);
			cimdCache.set(clientId, cached);
			return cached.record;
		}
	}

	// Dedup concurrent resolutions of the same uncached client_id → single fetch.
	const existing = inFlightResolutions.get(clientId);
	if (existing) return existing;
	// Total-concurrency bound: the in-flight map IS the counter (no await sits
	// between this check and the set below, so the cap cannot be raced past).
	// Checked BEFORE the rate-limit take so a capacity reject doesn't spend a
	// token without a fetch (keeps "only actual fetch attempts consume" true).
	if (inFlightResolutions.size >= MAX_CONCURRENT_RESOLUTIONS) {
		throw new CimdClientError('temporarily_unavailable', 'CIMD resolution capacity reached; retry shortly', {
			statusCode: 429,
		});
	}
	// Per-URL fetch rate limit (#163): only actual fetch attempts consume —
	// cache hits returned above, dedup'd joiners, and capacity rejects never
	// reach this. Fixed policy (no knob): legit clients are served from the
	// cache after their first success; repeated attempts are the bad-document
	// amplification vector this closes.
	const rateLimit = cimdFetchLimiter.tryTake(clientId);
	if (!rateLimit.allowed) {
		logger?.warn?.(`CIMD: fetch rate limit reached for ${clientId}`);
		throw new CimdClientError('slow_down', 'CIMD resolution rate limit reached; retry shortly', {
			statusCode: 429,
			retryAfterSeconds: rateLimit.retryAfterSeconds,
		});
	}
	const pending = fetchAndValidateCimd(clientId, cimdConfig, allowedRedirectUriHosts, logger).finally(() =>
		inFlightResolutions.delete(clientId)
	);
	inFlightResolutions.set(clientId, pending);
	return pending;
}

/** Fetch + validate + cache a CIMD document (the deduped, network-bound half of
 * `resolveCimdClient`). */
async function fetchAndValidateCimd(
	clientId: string,
	cimdConfig: MCPClientIdMetadataDocumentsConfig | undefined,
	allowedRedirectUriHosts: string[] | undefined,
	logger?: Logger
): Promise<MCPClientRecord | null> {
	let record: MCPClientRecord;
	try {
		const parsedUrl = new URL(clientId);
		const fetchTimeout = toFinitePositive(cimdConfig?.fetchTimeoutMs, DEFAULT_FETCH_TIMEOUT_MS);
		const maxBytes = toFinitePositive(cimdConfig?.maxDocumentBytes, DEFAULT_MAX_DOCUMENT_BYTES);

		// One deadline across DNS gate, connect, headers, AND body read — a
		// hostile server must not be able to hold a connection open past the
		// timeout by trickling headers or body bytes.
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), fetchTimeout);

		let body: string;
		let cacheControlHeader: string | null = null;
		try {
			// SSRF gate: resolve + validate before connecting (raced against the
			// deadline; dns.lookup does not take an AbortSignal). The returned
			// addresses are PINNED into the fetch so the connection can't race a
			// rebind to a fresh, unvalidated resolution.
			const validatedAddresses = await withAbort(
				checkHostSsrf(parsedUrl.hostname, logger),
				controller.signal,
				'CIMD DNS lookup timed out'
			);

			const response = await _fetch(clientId, {
				headers: { Accept: 'application/json' },
				signal: controller.signal,
				pinnedAddresses: validatedAddresses,
			});

			// Only 200 is acceptable — the CIMD draft requires the document to be
			// served with 200 OK; a 404/500 with a JSON body is not a client.
			if (response.status !== 200) {
				throw new CimdClientError('invalid_client', `CIMD document fetch returned status ${response.status}`);
			}

			// Reject non-JSON content-type.
			const contentType = response.headers.get('content-type') ?? '';
			if (!contentType.includes('application/json')) {
				throw new CimdClientError('invalid_client', `CIMD document has non-JSON content-type: ${contentType}`);
			}

			cacheControlHeader = response.headers.get('cache-control');

			// Enforce size cap.
			const clHeader = response.headers.get('content-length');
			if (clHeader && parseInt(clHeader, 10) > maxBytes) {
				throw new CimdClientError(
					'invalid_client',
					`CIMD document content-length (${clHeader}) exceeds limit (${maxBytes})`
				);
			}

			// Read up to maxBytes (reader.read() rejects when the deadline aborts).
			const chunks: Uint8Array[] = [];
			let total = 0;
			const reader = response.body?.getReader();
			if (!reader) {
				throw new Error('CIMD fetch: response body is not readable');
			}
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (value) {
					total += value.length;
					if (total > maxBytes) {
						reader.cancel();
						throw new CimdClientError('invalid_client', `CIMD document exceeds size limit (${maxBytes} bytes)`);
					}
					chunks.push(value);
				}
			}
			body = Buffer.concat(chunks).toString('utf8');
		} catch (error) {
			// A rejection between headers and the full body read must tear down
			// the pinned socket — the deadline timer is cleared below, so nothing
			// else would ever abort a connection the server holds open.
			controller.abort();
			throw error;
		} finally {
			clearTimeout(timer);
		}

		let doc: unknown;
		try {
			doc = JSON.parse(body);
		} catch (error) {
			throw new CimdClientError('invalid_client', 'CIMD document is not valid JSON', { cause: error });
		}

		record = validateCimdDocument(
			doc,
			clientId,
			allowedRedirectUriHosts,
			!!(cimdConfig?.allowedHosts && cimdConfig.allowedHosts.length > 0)
		);

		// Positive cache, LRU-bounded (the key is attacker-chosen input).
		if (cimdCache.size >= CACHE_MAX_ENTRIES) {
			const oldest = cimdCache.keys().next().value;
			if (oldest !== undefined) cimdCache.delete(oldest);
		}
		const ttlSeconds = parseCacheControlMaxAge(cacheControlHeader);
		cimdCache.set(clientId, {
			record,
			expiresAt: Date.now() + ttlSeconds * 1000,
		});

		logger?.info?.(`CIMD: resolved client ${clientId} (cached for ${ttlSeconds}s)`);
		return record;
	} catch (err) {
		// Failures are never cached — the CIMD draft forbids caching error
		// responses and invalid documents. Amplification from repeated bad
		// requests is bounded by the per-URL fetch rate limit in
		// `resolveCimdClient` (#163) instead.
		if (err instanceof CimdClientError) {
			logger?.warn?.(`CIMD: rejected client ${clientId}: ${err.message}`);
			throw err;
		}
		logger?.error?.(`CIMD: fetch failed for ${clientId}: ${err instanceof Error ? err.message : String(err)}`);
		throw err;
	}
}

/**
 * Resolve a client by client_id:
 * - URL-shaped client_ids (isCimdClientId) → CIMD resolution.
 * - Everything else → DCR lookup via MCPClientStore.
 *
 * Returns `null` when the client is not found (either path).
 * Throws `CimdClientError` for CIMD validation failures.
 * Throws `Error` for server-side failures (DB or network).
 */
export async function resolveClient(
	clientId: string,
	mcpConfig: MCPConfig | undefined,
	logger?: Logger
): Promise<MCPClientRecord | null> {
	// An over-length client_id is never a real client — reject before it becomes
	// a CIMD fetch-limiter key or a store lookup (unknown-client null, no leak).
	if (clientId.length > MAX_CLIENT_ID_LENGTH) return null;
	const cimdConfig = mcpConfig?.clientIdMetadataDocuments;
	// CIMD is enabled by default when mcp.enabled; disabled only by explicit `enabled: false`.
	const cimdEnabled = cimdConfig?.enabled !== false;
	if (cimdEnabled && isCimdClientId(clientId)) {
		return resolveCimdClient(
			clientId,
			cimdConfig,
			mcpConfig?.dynamicClientRegistration?.allowedRedirectUriHosts,
			logger
		);
	}
	return new MCPClientStore(logger).get(clientId);
}
