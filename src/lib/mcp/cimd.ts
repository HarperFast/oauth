/**
 * Client ID Metadata Document (CIMD) resolution
 *
 * Implements the AS side of CIMD as specified in the MCP authorization spec
 * and draft-ietf-oauth-client-id-metadata-document-00. When a client_id is a
 * valid HTTPS URL with a non-root path, the AS fetches it as a JSON metadata
 * document (instead of doing a DCR lookup) and validates the result.
 *
 * SSRF guards:
 * - HTTPS only, non-root path required, no userinfo/fragment.
 * - No IP-literal hosts in the URL (rejected before DNS).
 * - DNS gate: all resolved addresses are checked against private/loopback
 *   ranges (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1,
 *   fc00::/7, fe80::/10, ::ffff:0/96). DNS-rebinding is a noted residual
 *   risk (lookup-gate, not pinned-connect) — the fetched content is only
 *   trusted for exact URL identity, so the primary SSRF-reach risk is
 *   addressed by the DNS gate.
 * - `redirect: 'error'` — no following of 3xx responses.
 * - 5 s fetch timeout (configurable).
 * - 64 KB document size cap (configurable).
 * - `Accept: application/json` only; non-JSON responses rejected.
 *
 * Caching:
 * - Per-process Map keyed by URL.
 * - TTL: honor `Cache-Control: max-age` clamped to [60 s, 86400 s];
 *   default 3600 s when absent.
 * - Negative-cache failures for 60 s to avoid hammering on bad documents.
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
const NEGATIVE_CACHE_TTL_S = 60;

type CacheHit = { kind: 'record'; record: MCPClientRecord; expiresAt: number };
type CacheMiss = { kind: 'error'; message: string; oauthError: string; expiresAt: number };
type CacheEntry = CacheHit | CacheMiss;

const cimdCache = new Map<string, CacheEntry>();

/**
 * Thrown when CIMD resolution fails due to a client-side issue (bad URL,
 * invalid document, unsupported auth method, allowedHosts policy).
 * Callers should surface this as the given `oauthError` with the `message`
 * as the `error_description`.
 */
export class CimdClientError extends Error {
	readonly oauthError: string;

	constructor(oauthError: string, message: string) {
		super(message);
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
	if (parts.length !== 4 || parts.some((p) => isNaN(p))) return false;
	const [a, b] = parts;
	return (
		a === 127 || // 127.0.0.0/8 loopback
		a === 10 || // 10.0.0.0/8
		(a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
		(a === 192 && b === 168) || // 192.168.0.0/16
		(a === 169 && b === 254) // 169.254.0.0/16 link-local
	);
}

function isPrivateIpv6(address: string): boolean {
	if (address === '::1') return true;
	const lower = address.toLowerCase();
	// v4-mapped ::ffff:x.x.x.x or ::ffff:hhhh:hhhh
	if (lower.startsWith('::ffff:')) return true;
	// Extract first 16-bit group to check fc00::/7 and fe80::/10
	const firstGroup = lower.split(':')[0];
	if (!firstGroup) return false;
	const n = parseInt(firstGroup.padStart(4, '0'), 16);
	if (isNaN(n)) return false;
	if ((n & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA (fc00–fdff)
	if ((n & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
	return false;
}

/**
 * DNS SSRF gate: resolves all addresses for `hostname` and rejects if any
 * falls within a private/loopback/link-local/ULA range.
 *
 * Note: this is a lookup-gate, not pinned-connect. DNS rebinding between the
 * gate check and the actual HTTP connection is a residual risk acknowledged in
 * the CIMD security considerations (#166). The primary SSRF-reach risk is
 * mitigated by this gate; connecting to an already-validated external address
 * that was then rebinded to private is a secondary, harder-to-exploit risk.
 */
async function checkHostSsrf(hostname: string): Promise<void> {
	let addresses: Array<{ address: string; family: number }>;
	try {
		addresses = await _dnsLookup(hostname, { all: true });
	} catch {
		throw new Error(`DNS resolution failed for CIMD host: ${hostname}`);
	}
	if (addresses.length === 0) {
		throw new Error(`No addresses resolved for CIMD host: ${hostname}`);
	}
	for (const { address, family } of addresses) {
		if (family === 4 && isPrivateIpv4(address)) {
			throw new CimdClientError('invalid_client', `CIMD host resolves to a private address: ${address}`);
		}
		if (family === 6 && isPrivateIpv6(address)) {
			throw new CimdClientError('invalid_client', `CIMD host resolves to a private IPv6 address: ${address}`);
		}
	}
}

// --- URL shape checks ---

/**
 * Return true when `clientId` has the shape of a CIMD client_id:
 * - https scheme
 * - Non-root path (pathname !== '' and pathname !== '/')
 * - No userinfo (username / password)
 * - No fragment
 * - Host is NOT an IP literal (IPv4 dotted-quad or IPv6 [bracket] form)
 *
 * This is a structural check only — no network I/O, no policy enforcement.
 * Policy checks (allowedHosts, SSRF gate) happen inside `resolveCimdClient`.
 */
export function isCimdClientId(clientId: string): boolean {
	let url: URL;
	try {
		url = new URL(clientId);
	} catch {
		return false;
	}
	if (url.protocol !== 'https:') return false;
	if (url.pathname === '' || url.pathname === '/') return false;
	if (url.username || url.password) return false;
	if (url.hash) return false;
	if (isIpLiteral(url.hostname)) return false;
	return true;
}

// --- Cache helpers ---

function parseCacheControlMaxAge(header: string | null): number {
	if (!header) return CACHE_DEFAULT_TTL_S;
	const match = /\bmax-age\s*=\s*(\d+)/i.exec(header);
	if (!match) return CACHE_DEFAULT_TTL_S;
	const seconds = parseInt(match[1], 10);
	if (isNaN(seconds)) return CACHE_DEFAULT_TTL_S;
	return Math.max(CACHE_MIN_TTL_S, Math.min(CACHE_MAX_TTL_S, seconds));
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
 * Throws `CimdClientError` for client-side validation failures.
 * Throws `Error` for server-side failures (DNS, network).
 *
 * Results are cached per URL per process; negative results are cached
 * briefly to avoid hammering on consistently-bad documents.
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
	if (cached && cached.expiresAt > now) {
		if (cached.kind === 'record') return cached.record;
		// Negative cache: re-throw the original error type.
		throw new CimdClientError(cached.oauthError, cached.message);
	}

	// --- Fetch ---
	let record: MCPClientRecord;
	try {
		const parsedUrl = new URL(clientId);
		// SSRF gate: check DNS before connecting.
		await checkHostSsrf(parsedUrl.hostname);

		const fetchTimeout = cimdConfig?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
		const maxBytes = cimdConfig?.maxDocumentBytes ?? DEFAULT_MAX_DOCUMENT_BYTES;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), fetchTimeout);

		let response: Response;
		try {
			response = await _fetch(clientId, {
				method: 'GET',
				headers: { Accept: 'application/json' },
				redirect: 'error',
				signal: controller.signal,
			});
		} finally {
			clearTimeout(timer);
		}

		// Reject non-JSON content-type.
		const contentType = response.headers.get('content-type') ?? '';
		if (!contentType.includes('application/json')) {
			throw new CimdClientError('invalid_client', `CIMD document has non-JSON content-type: ${contentType}`);
		}

		// Enforce size cap.
		const clHeader = response.headers.get('content-length');
		if (clHeader && parseInt(clHeader, 10) > maxBytes) {
			throw new CimdClientError(
				'invalid_client',
				`CIMD document content-length (${clHeader}) exceeds limit (${maxBytes})`
			);
		}

		const cacheControlHeader = response.headers.get('cache-control');

		// Read up to maxBytes.
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

		const body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
		let doc: unknown;
		try {
			doc = JSON.parse(body);
		} catch {
			throw new CimdClientError('invalid_client', 'CIMD document is not valid JSON');
		}

		record = validateCimdDocument(doc, clientId, allowedRedirectUriHosts);

		// Positive cache.
		const ttlSeconds = parseCacheControlMaxAge(cacheControlHeader);
		cimdCache.set(clientId, {
			kind: 'record',
			record,
			expiresAt: now + ttlSeconds * 1000,
		});

		logger?.info?.(`CIMD: resolved client ${clientId} (cached for ${ttlSeconds}s)`);
		return record;
	} catch (err) {
		if (err instanceof CimdClientError) {
			// Negative-cache client errors briefly to avoid hammering.
			cimdCache.set(clientId, {
				kind: 'error',
				message: err.message,
				oauthError: err.oauthError,
				expiresAt: now + NEGATIVE_CACHE_TTL_S * 1000,
			});
			logger?.warn?.(`CIMD: rejected client ${clientId}: ${err.message}`);
			throw err;
		}
		// Server-side failures (DNS, timeout, network) are NOT negative-cached
		// so a transient outage doesn't lock out the client for 60 s.
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
