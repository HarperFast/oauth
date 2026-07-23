/**
 * MCP Well-Known Metadata Endpoints
 *
 * Mounts three discovery documents under `/.well-known/*` for MCP clients:
 *
 * - `/.well-known/oauth-protected-resource` — RFC 9728 Protected Resource
 *   Metadata. The entry point: an MCP client that hits the protected resource
 *   without credentials receives a `401 + WWW-Authenticate: Bearer
 *   resource_metadata="..."` (issued by withMCPAuth, Stage 5) pointing here,
 *   then fetches this document to discover the authorization server.
 * - `/.well-known/oauth-authorization-server` — RFC 8414 Authorization Server
 *   Metadata. Advertises authorize / token / register / JWKS endpoints and
 *   the supported algorithms / methods / response types.
 * - `/.well-known/jwks.json` — Public key set used to verify issued JWTs.
 *   Returns an empty key set until Stage 4 of issue #86 lands key material in
 *   the `harper_oauth_mcp_keys` table.
 *
 * Endpoints are registered through `server.http(handler, { urlPath })` so
 * routing works for `.well-known` paths that don't fit Harper's Resource API.
 * Harper's urlPath matching is prefix-based (segment-boundary aware), so each
 * handler also checks the exact path before responding — sub-paths like
 * `/.well-known/oauth-authorization-server/foo` fall through to 404.
 */

import type { Logger, MCPConfig } from '../../types.ts';
import { dcrEnabled } from './dcr.ts';
import { MCPKeyStore, resolveEffectiveAlg } from './keyStore.ts';
import { publicKeyToJwk } from './tokenIssuer.ts';

interface HarperRequest {
	pathname?: string;
	url?: string;
	protocol?: string;
	host?: string;
	headers?: Record<string, any> & { host?: string };
}

type HttpResponse = {
	status: number;
	headers: Record<string, string>;
	body: string;
};

// Exported so withMCPAuth (Stage 5) builds its `WWW-Authenticate: Bearer
// resource_metadata="<issuer>${PRM_PATH}"` challenge from the same constant the
// PRM document is served at — the discovery loop stays in sync by construction.
export const PRM_PATH = '/.well-known/oauth-protected-resource';
const AS_METADATA_PATH = '/.well-known/oauth-authorization-server';
const JWKS_PATH = '/.well-known/jwks.json';

function jsonResponse(body: unknown, status = 200): HttpResponse {
	return {
		status,
		headers: {
			'Content-Type': 'application/json',
			// Discovery documents are unauthenticated and intended for cross-origin
			// fetches — browser-based MCP clients and inspectors won't be able to
			// read them without CORS. Simple `*` is sufficient because no
			// credentials are involved.
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, OPTIONS',
		},
		body: JSON.stringify(body),
	};
}

/**
 * Resolve the issuer (authorization-server origin). Configured value wins;
 * otherwise derive from the request — scheme + host.
 *
 * Security note: the request-derived path trusts the Host header, which a
 * client controls. For Stage 2 (metadata-only) this is self-defeating — an
 * attacker who spoofs Host gets back metadata describing their own origin.
 * Stage 4 will sign JWTs with `iss`; at that point `mcp.issuer` MUST be
 * pinned at startup (or derived from a fixed config) to prevent attacker-
 * controlled `iss` claims. Production deployments should set `mcp.issuer`
 * explicitly regardless. Documented in docs/configuration.md.
 */
export function resolveIssuer(request: HarperRequest, mcpConfig: MCPConfig): string {
	if (mcpConfig.issuer) {
		// Strip trailing slashes so the `iss` claim and `${issuer}/oauth/...`
		// endpoint URLs don't end up with a doubled slash.
		return mcpConfig.issuer.replace(/\/+$/, '');
	}
	const rawHost = request.host ?? request.headers?.host;
	const host = (Array.isArray(rawHost) ? rawHost[0] : rawHost) ?? 'localhost';
	const scheme = request.protocol ?? 'https';
	return `${scheme}://${host}`;
}

/**
 * Resolve the canonical resource URI (the MCP endpoint clients talk to).
 * Configured value wins; otherwise derive as `<issuer>/mcp`.
 */
export function resolveResource(request: HarperRequest, mcpConfig: MCPConfig): string {
	if (mcpConfig.resource) return mcpConfig.resource;
	return `${resolveIssuer(request, mcpConfig)}/mcp`;
}

/**
 * Canonical RFC 9728 §3.1 Protected Resource Metadata URL for the configured
 * resource: `<resource-origin>/.well-known/oauth-protected-resource[/<resource-path>]`.
 *
 * This is exactly the URL the PRM handler serves — bare for a resource at the
 * origin root, path-appended when the resource carries a path (e.g. `.../mcp`);
 * see {@link wellKnownPathMatches}. withMCPAuth's `WWW-Authenticate: Bearer
 * resource_metadata="..."` challenge points here, so a client that uses the
 * challenge value verbatim fetches a document this server actually answers.
 * Falls back to the request-derived issuer origin (bare path) if the resource
 * URI can't be parsed, so the deny path never throws.
 *
 * The result is interpolated into a quoted `resource_metadata="..."` header
 * param, so it MUST be header-safe: a client-controlled Host (when the issuer
 * is unpinned) must never inject a `"` or control char that breaks the quoting.
 * Every branch normalizes through `new URL().origin`, which rejects/encodes
 * such input; if even the issuer can't be parsed, fall back to the host-less
 * relative path, which is always safe.
 */
export function protectedResourceMetadataUrl(request: HarperRequest, mcpConfig: MCPConfig): string {
	try {
		const { origin, pathname } = new URL(resolveResource(request, mcpConfig));
		const path = pathname && pathname !== '/' ? pathname.replace(/\/+$/, '') : '';
		return `${origin}${PRM_PATH}${path}`;
	} catch {
		try {
			return `${new URL(resolveIssuer(request, mcpConfig)).origin}${PRM_PATH}`;
		} catch {
			return PRM_PATH;
		}
	}
}

/**
 * RFC 9728 Protected Resource Metadata document.
 */
export function buildProtectedResourceMetadata(request: HarperRequest, mcpConfig: MCPConfig): Record<string, unknown> {
	const resource = resolveResource(request, mcpConfig);
	const issuer = resolveIssuer(request, mcpConfig);
	return {
		resource,
		authorization_servers: [issuer],
		bearer_methods_supported: ['header'],
	};
}

/**
 * RFC 8414 Authorization Server Metadata document.
 * Advertises the spec-required fields for the MCP authorization spec 2025-06-18.
 */
export async function buildAuthorizationServerMetadata(
	request: HarperRequest,
	mcpConfig: MCPConfig
): Promise<Record<string, unknown>> {
	const issuer = resolveIssuer(request, mcpConfig);
	// Advertised signing algs: what will sign next (config/pin-derived) UNIONED
	// with the algs of keys still live in the JWKS. During an alg switch — and
	// especially its rolling-deploy damper window, where an old-alg key keeps
	// signing for up to ALG_SWITCH_MIN_KEY_AGE_SECONDS — tokens of both algs are
	// in circulation, and advertising only the config-derived value would
	// misdescribe the tokens actually being minted. Read-only (5s-cached
	// enumeration); [] before the first mint leaves just the effective alg.
	const effectiveAlg = resolveEffectiveAlg(mcpConfig);
	const liveKeys = await new MCPKeyStore().getAllPublicKeys(mcpConfig);
	const advertisedAlgs = [effectiveAlg, ...liveKeys.map((k) => k.alg ?? 'RS256')].filter(
		(alg, index, all) => all.indexOf(alg) === index
	);
	// CIMD is enabled by default when mcp.enabled; disabled by explicit enabled: false.
	const cimdEnabled = mcpConfig.clientIdMetadataDocuments?.enabled !== false;
	// client_credentials is explicit opt-in (#162); advertised only when enabled.
	const clientCredentialsEnabled = mcpConfig.clientCredentials?.enabled === true;
	return {
		issuer,
		authorization_endpoint: `${issuer}/oauth/mcp/authorize`,
		token_endpoint: `${issuer}/oauth/mcp/token`,
		// Advertised under the same predicate the handler enforces (#182):
		// metadata must not point clients at an endpoint that 404s.
		...(dcrEnabled(mcpConfig) ? { registration_endpoint: `${issuer}/oauth/mcp/register` } : {}),
		jwks_uri: `${issuer}${JWKS_PATH}`,
		response_types_supported: ['code'],
		grant_types_supported: [
			'authorization_code',
			'refresh_token',
			...(clientCredentialsEnabled ? ['client_credentials'] : []),
		],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: [
			'none',
			'client_secret_basic',
			'client_secret_post',
			...(clientCredentialsEnabled ? ['private_key_jwt'] : []),
		],
		// EdDSA is the only assertion alg the client_credentials grant verifies.
		...(clientCredentialsEnabled ? { token_endpoint_auth_signing_alg_values_supported: ['EdDSA'] } : {}),
		// Effective alg first, then any other alg still live in the key set (see
		// advertisedAlgs above). Per-key algs are published in the JWKS; EdDSA is
		// deferred (#127).
		id_token_signing_alg_values_supported: advertisedAlgs,
		// RFC 8707 §2: server understands the `resource` parameter.
		resource_parameter_supported: true,
		// RFC 9207: server emits `iss` on every authorization response redirect.
		authorization_response_iss_parameter_supported: true,
		// Advertise CIMD support when enabled (default: true when mcp.enabled).
		...(cimdEnabled ? { client_id_metadata_document_supported: true } : {}),
	};
}

/**
 * JWKS document — the public half of the signing key(s) in
 * `harper_oauth_mcp_keys`, serialized to JWK. Read-only: it never triggers key
 * generation (an unauthenticated fetch must not mint key material), so the set
 * is empty until the first access token is issued.
 */
export async function buildJWKS(mcpConfig: MCPConfig): Promise<Record<string, unknown>> {
	const keys = await new MCPKeyStore().getAllPublicKeys(mcpConfig);
	return { keys: keys.map((k) => publicKeyToJwk(k.public_key_pem, k.kid, k.alg)) };
}

type WellKnownMatch = {
	exactPath: string;
	build: (request: HarperRequest, mcpConfig: MCPConfig) => Record<string, unknown> | Promise<Record<string, unknown>>;
	/**
	 * When true, also serve the RFC 9728 §3.1 path-appended form of this
	 * document for a resource that carries a path. Only the PRM is
	 * resource-scoped this way (the AS-metadata issuer is the origin root here);
	 * see {@link wellKnownPathMatches}.
	 */
	resourcePathAware?: boolean;
};

const HANDLERS: WellKnownMatch[] = [
	{ exactPath: PRM_PATH, build: buildProtectedResourceMetadata, resourcePathAware: true },
	{ exactPath: AS_METADATA_PATH, build: buildAuthorizationServerMetadata },
	{ exactPath: JWKS_PATH, build: (_req, cfg) => buildJWKS(cfg) },
];

/**
 * The protected resource's path component (e.g. `/mcp` for resource
 * `<issuer>/mcp`), or `''` when the resource is at the origin root. Used to
 * serve the RFC 9728 §3.1 path-appended PRM.
 */
function resourcePathOf(req: HarperRequest, cfg: MCPConfig): string {
	try {
		const { pathname } = new URL(resolveResource(req, cfg));
		return pathname && pathname !== '/' ? pathname.replace(/\/+$/, '') : '';
	} catch {
		return '';
	}
}

/**
 * Does an incoming well-known request match this handler? Harper's
 * `server.http({ urlPath })` is prefix-based and passes the path RELATIVE to
 * the mount, so sub-paths reach the handler and must be screened here.
 *
 * Accepts the exact mount — relative `/` (current Harper) or the absolute
 * `exactPath` (older builds) — and, for the resource-path-aware PRM, the
 * RFC 9728 §3.1 path-appended form: relative `<resource-path>` (e.g. `/mcp`) or
 * absolute `exactPath + <resource-path>`. MCP clients (e.g. Claude.ai)
 * construct the PRM URL by path-insertion and fetch the appended form rather
 * than the bare host-root one, so without this the discovery loop 404s. Any
 * other sub-path falls through to 404.
 */
function wellKnownPathMatches(
	reqPath: string | undefined,
	match: WellKnownMatch,
	req: HarperRequest,
	cfg: MCPConfig
): boolean {
	if (reqPath === '/' || reqPath === match.exactPath) return true;
	if (!match.resourcePathAware || !reqPath) return false;
	const resourcePath = resourcePathOf(req, cfg);
	if (!resourcePath) return false;
	// Normalize a single trailing slash on the request path so a resource
	// configured with OR without one both match (resourcePath is already
	// stripped). Exact-after-normalize — NOT prefix matching, which would let
	// `/mcp-evil` match `/mcp`. The bare-mount `/` case is handled above, and an
	// empty resourcePath short-circuits, so this can never broaden to serve `/`.
	const normalized = reqPath.length > 1 && reqPath.endsWith('/') ? reqPath.slice(0, -1) : reqPath;
	return normalized === resourcePath || normalized === match.exactPath + resourcePath;
}

/**
 * Make a Harper http() middleware bound to one well-known path.
 *
 * - Falls through (calls `next`) when MCP is disabled or the request doesn't
 *   match the exact path (urlPath matching is prefix-based, so sub-paths
 *   reach this handler and we must reject them here).
 * - Reads `getConfig()` at request time so live config changes take effect
 *   without re-registering the route.
 */
function makeHandler(
	match: WellKnownMatch,
	getConfig: () => MCPConfig | undefined,
	logger?: Logger
): (req: HarperRequest, next: (r: HarperRequest) => any) => any {
	return async (req, next) => {
		const cfg = getConfig();
		if (!cfg?.enabled) return next(req);
		// Screen the (prefix-matched) request against the mount and, for the PRM,
		// the RFC 9728 path-appended form; other sub-paths fall through to 404.
		const reqPath = req.pathname ?? req.url;
		if (!wellKnownPathMatches(reqPath, match, req, cfg)) return next(req);
		try {
			return jsonResponse(await match.build(req, cfg));
		} catch (error) {
			logger?.error?.(
				`MCP well-known handler ${match.exactPath} failed:`,
				error instanceof Error ? error.message : String(error)
			);
			return jsonResponse({ error: 'server_error' }, 500);
		}
	};
}

/**
 * Register all MCP well-known handlers against the Harper server.
 *
 * `getConfig` is a getter so middleware sees the current config on each
 * request — the OAuth plugin re-initializes its config block on options
 * change, and we want those changes to apply without re-registering routes
 * (Harper's server.http() does not support deregistration).
 */
export function registerWellKnownHandlers(server: any, getConfig: () => MCPConfig | undefined, logger?: Logger): void {
	if (typeof server?.http !== 'function') {
		logger?.warn?.('MCP well-known: server.http() not available; skipping route registration');
		return;
	}
	for (const match of HANDLERS) {
		server.http(makeHandler(match, getConfig, logger), { urlPath: match.exactPath });
	}
	logger?.debug?.('MCP well-known handlers registered');
}
