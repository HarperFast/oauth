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
 *   userinfo/fragment, no dot path segments (raw or percent-encoded).
 * - No IP-literal hosts in the URL (rejected before DNS).
 * - DNS gate: all resolved addresses are checked against non-global ranges.
 *   IPv4 rejects 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12,
 *   192.168/16, 198.18/15, and 224/4+. IPv6 fails closed to "global unicast
 *   (2000::/3) only", with v4-mapped addresses classified by their embedded
 *   IPv4 address. DNS-rebinding is a noted residual risk (lookup-gate, not
 *   pinned-connect) — the fetched content is only trusted for exact URL
 *   identity, so the primary SSRF-reach risk is addressed by the DNS gate.
 * - `redirect: 'error'` — no following of 3xx responses.
 * - Only `200 OK` responses are accepted.
 * - 5 s deadline (configurable) covering DNS, connect, headers, AND body.
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
 *   and invalid documents); repeated fetches of bad documents are left to
 *   rate limiting (#163).
 * - Cached records are revalidated against the live redirect-host policy on
 *   every hit, so tightening `allowedRedirectUriHosts` takes effect
 *   immediately instead of after cache expiry (up to 24 h).
 *
 * Token auth method:
 * - Only `token_endpoint_auth_method: none` (public clients) is supported
 *   in v1. `private_key_jwt` will be activated by issue #159. Other values
 *   are rejected with a clear `invalid_client` error.
 *
 * #159 integration point:
 * - `jwks`, `jwks_uri`, and `token_endpoint_auth_method` are carried
 *   through on the resolved record so assertion verification (#159) can
 *   consume them without re-fetching.
 */

import { lookup } from 'node:dns/promises';
import type { Logger, MCPClientIdMetadataDocumentsConfig, MCPClientRecord, MCPConfig } from '../../types.ts';
import { MCPClientStore } from './clientStore.ts';
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

type CacheEntry = { record: MCPClientRecord; expiresAt: number };

const cimdCache = new Map<string, CacheEntry>();

/**
 * Thrown when CIMD resolution fails due to a client-side issue (bad URL,
 * invalid document, unsupported auth method, allowedHosts policy).
 * Callers should surface this as the given `oauthError` with the `message`
 * as the `error_description`.
 */
export class CimdClientError extends Error {
	readonly oauthError: string;

	constructor(oauthError: string, message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'CimdClientError';
		this.oauthError = oauthError;
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

export let _fetch: typeof globalThis.fetch = (...args) => globalThis.fetch(...args);

export function _setFetch(fn: typeof globalThis.fetch | null): void {
	_fetch = fn ?? ((...args) => globalThis.fetch(...args));
}

/** Clear the CIMD cache (for testing). @internal */
export function _clearCimdCache(): void {
	cimdCache.clear();
}

// --- SSRF guard helpers ---

function isIpLiteral(hostname: string): boolean {
	// IPv6 literal: [...] (as returned by URL.hostname for IPv6 URLs)
	if (hostname.startsWith('[')) return true;
	// IPv4: four octets separated by dots
	return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function isPrivateIpv4(address: string): boolean {
	const parts = address.split('.').map(Number);
	if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return true; // malformed → fail closed
	const [a, b] = parts;
	return (
		a === 0 || // 0.0.0.0/8 "this network" (0.0.0.0 routes to loopback on Linux)
		a === 127 || // 127.0.0.0/8 loopback
		a === 10 || // 10.0.0.0/8
		(a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT / shared address space
		(a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
		(a === 192 && b === 168) || // 192.168.0.0/16
		(a === 169 && b === 254) || // 169.254.0.0/16 link-local
		(a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 benchmarking
		a >= 224 // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + broadcast
	);
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

/**
 * Fail-closed IPv6 policy: only global unicast (2000::/3) is allowed, with
 * v4-mapped addresses (::ffff:a.b.c.d) classified by their embedded IPv4
 * address. Everything else — `::` unspecified, `::1` loopback in any textual
 * form, fc00::/7 ULA, fe80::/10 link-local, ff00::/8 multicast, reserved
 * blocks, unparseable input — is treated as private.
 */
function isPrivateIpv6(address: string): boolean {
	const groups = parseIpv6Groups(address);
	if (!groups) return true;
	const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
	if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
		return isPrivateIpv4(`${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`);
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
 * DNS SSRF gate: resolves all addresses for `hostname` and rejects if any
 * falls outside the allowed (global unicast) ranges.
 *
 * Note: this is a lookup-gate, not pinned-connect. DNS rebinding between the
 * gate check and the actual HTTP connection is a residual risk acknowledged in
 * the CIMD security considerations (#166). The primary SSRF-reach risk is
 * mitigated by this gate; connecting to an already-validated external address
 * that was then rebinded to private is a secondary, harder-to-exploit risk.
 */
async function checkHostSsrf(hostname: string, logger?: Logger): Promise<void> {
	let addresses: Array<{ address: string; family: number }>;
	try {
		addresses = await _dnsLookup(hostname, { all: true });
	} catch (error) {
		logger?.warn?.(`CIMD: DNS resolution failed for host ${hostname}`);
		throw new CimdClientError('invalid_client', DNS_GATE_REJECTION, { cause: error });
	}
	if (addresses.length === 0) {
		logger?.warn?.(`CIMD: no addresses resolved for host ${hostname}`);
		throw new CimdClientError('invalid_client', DNS_GATE_REJECTION);
	}
	for (const { address, family } of addresses) {
		if ((family === 4 && isPrivateIpv4(address)) || (family === 6 && isPrivateIpv6(address))) {
			logger?.warn?.(`CIMD: host ${hostname} resolves to a blocked address: ${address}`);
			throw new CimdClientError('invalid_client', DNS_GATE_REJECTION);
		}
	}
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
	allowedRedirectUriHosts: string[] | undefined
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

	// Optional array fields.
	for (const [field, value] of Object.entries({
		contacts: d.contacts,
		grant_types: d.grant_types,
		response_types: d.response_types,
	})) {
		const err = validateStringArray(value, field);
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

	// token_endpoint_auth_method: only 'none' supported in v1 for CIMD clients.
	const authMethod = typeof d.token_endpoint_auth_method === 'string' ? d.token_endpoint_auth_method : 'none';
	if (authMethod !== 'none') {
		throw new CimdClientError(
			'invalid_client',
			`token_endpoint_auth_method '${authMethod}' is not yet supported for CIMD clients (awaiting #159); use 'none'`
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
		// #159 integration: carry JWKS config through without activating private_key_jwt.
		jwks:
			d.jwks !== undefined && typeof d.jwks === 'object' && d.jwks !== null
				? (d.jwks as Record<string, unknown>)
				: undefined,
		jwks_uri: typeof d.jwks_uri === 'string' ? d.jwks_uri : undefined,
		redirect_uris: d.redirect_uris as string[],
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
			// Revalidate against the LIVE redirect-host policy: a record cached
			// under a looser `allowedRedirectUriHosts` must not survive the
			// operator tightening it (cache TTL can be up to 24 h).
			for (const uri of cached.record.redirect_uris) {
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

	// --- Fetch ---
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
			// SSRF gate: check DNS before connecting (raced against the deadline;
			// dns.lookup does not take an AbortSignal).
			await withAbort(checkHostSsrf(parsedUrl.hostname, logger), controller.signal, 'CIMD DNS lookup timed out');

			const response = await _fetch(clientId, {
				method: 'GET',
				headers: { Accept: 'application/json' },
				redirect: 'error',
				signal: controller.signal,
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
			body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
		} finally {
			clearTimeout(timer);
		}

		let doc: unknown;
		try {
			doc = JSON.parse(body);
		} catch (error) {
			throw new CimdClientError('invalid_client', 'CIMD document is not valid JSON', { cause: error });
		}

		record = validateCimdDocument(doc, clientId, allowedRedirectUriHosts);

		// Positive cache, LRU-bounded (the key is attacker-chosen input).
		if (cimdCache.size >= CACHE_MAX_ENTRIES) {
			const oldest = cimdCache.keys().next().value;
			if (oldest !== undefined) cimdCache.delete(oldest);
		}
		const ttlSeconds = parseCacheControlMaxAge(cacheControlHeader);
		cimdCache.set(clientId, {
			record,
			expiresAt: now + ttlSeconds * 1000,
		});

		logger?.info?.(`CIMD: resolved client ${clientId} (cached for ${ttlSeconds}s)`);
		return record;
	} catch (err) {
		// Failures are never cached — the CIMD draft forbids caching error
		// responses and invalid documents. Fetch amplification from repeated
		// bad requests is rate limiting's job (#163).
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
