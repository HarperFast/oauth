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
import { MCPKeyStore } from './keyStore.ts';
import { publicKeyToJwk } from './tokenIssuer.ts';

interface HarperRequest {
	pathname?: string;
	protocol?: string;
	host?: string;
	headers?: Record<string, any> & { host?: string };
}

type HttpResponse = {
	status: number;
	headers: Record<string, string>;
	body: string;
};

const PRM_PATH = '/.well-known/oauth-protected-resource';
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
	const host = request.host ?? request.headers?.host ?? 'localhost';
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
export function buildAuthorizationServerMetadata(
	request: HarperRequest,
	mcpConfig: MCPConfig
): Record<string, unknown> {
	const issuer = resolveIssuer(request, mcpConfig);
	return {
		issuer,
		authorization_endpoint: `${issuer}/oauth/mcp/authorize`,
		token_endpoint: `${issuer}/oauth/mcp/token`,
		registration_endpoint: `${issuer}/oauth/mcp/register`,
		jwks_uri: `${issuer}${JWKS_PATH}`,
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		code_challenge_methods_supported: ['S256'],
		token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
		// RS256 only in v1 — jsonwebtoken cannot emit EdDSA. Matches the key
		// served at the JWKS endpoint; EdDSA is deferred (would need a JOSE lib).
		id_token_signing_alg_values_supported: ['RS256'],
		// RFC 8707 §2: server understands the `resource` parameter.
		resource_parameter_supported: true,
		// CORS-friendly metadata is the spec norm; we serve cross-origin reads.
		// (No spec-mandated field for this — included as a hint for proxy configs.)
	};
}

/**
 * JWKS document — the public half of the signing key(s) in
 * `harper_oauth_mcp_keys`, serialized to JWK. Read-only: it never triggers key
 * generation (an unauthenticated fetch must not mint key material), so the set
 * is empty until the first access token is issued.
 */
export async function buildJWKS(_mcpConfig: MCPConfig): Promise<Record<string, unknown>> {
	const keys = await new MCPKeyStore().getAllPublicKeys();
	return { keys: keys.map((k) => publicKeyToJwk(k.public_key_pem, k.kid, k.alg)) };
}

type WellKnownMatch = {
	exactPath: string;
	build: (request: HarperRequest, mcpConfig: MCPConfig) => Record<string, unknown> | Promise<Record<string, unknown>>;
};

const HANDLERS: WellKnownMatch[] = [
	{ exactPath: PRM_PATH, build: buildProtectedResourceMetadata },
	{ exactPath: AS_METADATA_PATH, build: buildAuthorizationServerMetadata },
	{ exactPath: JWKS_PATH, build: (_req, cfg) => buildJWKS(cfg) },
];

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
		if (req.pathname !== match.exactPath) return next(req);
		try {
			return jsonResponse(await match.build(req, cfg));
		} catch (error) {
			logger?.error?.(`MCP well-known handler ${match.exactPath} failed:`, (error as Error).message);
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
