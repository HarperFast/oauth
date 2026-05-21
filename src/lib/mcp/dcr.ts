/**
 * MCP Dynamic Client Registration (RFC 7591)
 *
 * Implements POST /oauth/mcp/register. MCP clients (Claude Desktop, Cursor,
 * mcp-remote) register at runtime with no pre-baked client_id; the registry
 * persists their issued client_id so it survives Harper restarts.
 *
 * Defaults applied here reflect the MCP authorization spec 2025-06-18: public
 * clients (token_endpoint_auth_method=none), authorization_code + refresh_token
 * grants, response_type=code. Confidential clients can opt in explicitly.
 */

import { randomUUID, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Logger, MCPClientMetadata, MCPClientRecord, MCPConfig } from '../../types.ts';
import { MCPClientStore } from './clientStore.ts';

type ErrorResponse = {
	status: number;
	body: { error: string; error_description?: string };
};

const SUPPORTED_GRANT_TYPES = new Set(['authorization_code', 'refresh_token']);
const SUPPORTED_RESPONSE_TYPES = new Set(['code']);
const SUPPORTED_AUTH_METHODS = new Set(['none', 'client_secret_basic', 'client_secret_post']);
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Validate the Authorization header against a configured initial access token.
 * Returns null when no token is configured (open registration per RFC 7591).
 * Node's HTTP parser lowercases incoming headers, so we read the lowercase form.
 */
function checkInitialAccessToken(authHeader: string | undefined, configured: string | undefined): ErrorResponse | null {
	if (!configured) {
		return null;
	}
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return {
			status: 401,
			body: { error: 'invalid_token', error_description: 'Missing initial access token' },
		};
	}
	const presented = authHeader.slice('Bearer '.length).trim();
	// Constant-time comparison — `!==` leaks per-character timing and lets a
	// precise-latency attacker progressively recover initialAccessToken.
	// timingSafeEqual requires equal-length buffers, so length-check first.
	const presentedBuf = Buffer.from(presented);
	const configuredBuf = Buffer.from(configured);
	if (presentedBuf.length !== configuredBuf.length || !timingSafeEqual(presentedBuf, configuredBuf)) {
		return {
			status: 401,
			body: { error: 'invalid_token', error_description: 'Invalid initial access token' },
		};
	}
	return null;
}

function validateOptionalString(value: unknown, fieldName: string): string | null {
	if (value === undefined) return null;
	if (typeof value !== 'string') return `${fieldName} must be a string`;
	return null;
}

/**
 * Validate a single redirect URI against RFC 7591 + RFC 8252 rules.
 * Returns an error message on failure, null on success.
 */
function validateRedirectUri(uri: unknown, allowedHosts: string[] | undefined): string | null {
	if (typeof uri !== 'string' || uri.length === 0) {
		return 'redirect_uris must contain non-empty strings';
	}
	let parsed: URL;
	try {
		parsed = new URL(uri);
	} catch {
		return `redirect_uri is not a valid URL: ${uri}`;
	}
	if (parsed.hash) {
		return `redirect_uri must not contain a fragment: ${uri}`;
	}
	const isLocal = LOCAL_HOSTS.has(parsed.hostname);
	// HTTPS is required except for loopback addresses (RFC 8252 §8.3).
	if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocal)) {
		return `redirect_uri must use https (or http to a loopback address): ${uri}`;
	}
	if (allowedHosts && allowedHosts.length > 0 && !isLocal && !allowedHosts.includes(parsed.hostname)) {
		return `redirect_uri host not in allowlist: ${parsed.hostname}`;
	}
	return null;
}

function validateStringArray(value: unknown, fieldName: string): string | null {
	if (value === undefined) return null;
	if (!Array.isArray(value)) return `${fieldName} must be an array of strings`;
	for (const item of value) {
		if (typeof item !== 'string') return `${fieldName} must be an array of strings`;
	}
	return null;
}

/**
 * Validate the request body and produce a normalized record (with defaults
 * applied). Returns either a record-shape (no client_id yet) or an error.
 */
function buildClientFromRequest(
	body: any,
	allowedHosts: string[] | undefined
): { record: Omit<MCPClientRecord, 'client_id' | 'client_id_issued_at'> } | ErrorResponse {
	if (!body || typeof body !== 'object') {
		return {
			status: 400,
			body: { error: 'invalid_client_metadata', error_description: 'Request body must be a JSON object' },
		};
	}

	// redirect_uris is required for clients using the authorization code flow.
	if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
		return {
			status: 400,
			body: { error: 'invalid_redirect_uri', error_description: 'redirect_uris is required and must be non-empty' },
		};
	}
	for (const uri of body.redirect_uris) {
		const err = validateRedirectUri(uri, allowedHosts);
		if (err) {
			return { status: 400, body: { error: 'invalid_redirect_uri', error_description: err } };
		}
	}

	for (const [field, value] of Object.entries({
		contacts: body.contacts,
		grant_types: body.grant_types,
		response_types: body.response_types,
	})) {
		const err = validateStringArray(value, field);
		if (err) {
			return { status: 400, body: { error: 'invalid_client_metadata', error_description: err } };
		}
	}

	// Validate optional scalar string fields — without this an attacker could
	// POST `{client_name: {evil: ...}}` and we'd persist the object verbatim.
	for (const [field, value] of Object.entries({
		client_name: body.client_name,
		client_uri: body.client_uri,
		logo_uri: body.logo_uri,
		scope: body.scope,
		software_id: body.software_id,
		software_version: body.software_version,
	})) {
		const err = validateOptionalString(value, field);
		if (err) {
			return { status: 400, body: { error: 'invalid_client_metadata', error_description: err } };
		}
	}

	const grantTypes: string[] = body.grant_types ?? ['authorization_code', 'refresh_token'];
	for (const grant of grantTypes) {
		if (!SUPPORTED_GRANT_TYPES.has(grant)) {
			return {
				status: 400,
				body: { error: 'invalid_client_metadata', error_description: `Unsupported grant_type: ${grant}` },
			};
		}
	}

	const responseTypes: string[] = body.response_types ?? ['code'];
	for (const responseType of responseTypes) {
		if (!SUPPORTED_RESPONSE_TYPES.has(responseType)) {
			return {
				status: 400,
				body: {
					error: 'invalid_client_metadata',
					error_description: `Unsupported response_type: ${responseType}`,
				},
			};
		}
	}

	// MCP default: public clients. RFC 7591's default is "client_secret_basic"
	// but the MCP authorization spec 2025-06-18 expects public clients (Claude
	// Desktop, Cursor, mcp-remote run on user machines without secure secret
	// storage). Confidential clients must opt in explicitly.
	const tokenEndpointAuthMethod: string = body.token_endpoint_auth_method ?? 'none';
	if (!SUPPORTED_AUTH_METHODS.has(tokenEndpointAuthMethod)) {
		return {
			status: 400,
			body: {
				error: 'invalid_client_metadata',
				error_description: `Unsupported token_endpoint_auth_method: ${tokenEndpointAuthMethod}`,
			},
		};
	}

	const applicationType: string = body.application_type ?? 'web';
	if (applicationType !== 'web' && applicationType !== 'native') {
		return {
			status: 400,
			body: { error: 'invalid_client_metadata', error_description: `Unsupported application_type: ${applicationType}` },
		};
	}

	const metadata: MCPClientMetadata = {
		redirect_uris: body.redirect_uris,
		client_name: body.client_name,
		client_uri: body.client_uri,
		logo_uri: body.logo_uri,
		scope: body.scope,
		contacts: body.contacts,
		grant_types: grantTypes,
		response_types: responseTypes,
		token_endpoint_auth_method: tokenEndpointAuthMethod,
		application_type: applicationType,
		software_id: body.software_id,
		software_version: body.software_version,
	};

	return { record: metadata };
}

/**
 * Handle POST /oauth/mcp/register. RFC 7591 §3 returns 201 with the issued
 * client_id (and client_secret for confidential clients) plus echoed metadata.
 *
 * @param request - HTTP request (only used for the Authorization header today)
 * @param body - Parsed JSON request body
 * @param mcpConfig - Plugin MCP configuration
 * @param logger - Optional logger
 */
export async function handleRegister(
	request: { headers?: { authorization?: string } } | undefined,
	body: any,
	mcpConfig: MCPConfig | undefined,
	logger?: Logger
): Promise<any> {
	const dcrConfig = mcpConfig?.dynamicClientRegistration;

	// DCR defaults to enabled when MCP is enabled. Explicit `enabled: false`
	// turns it off and the endpoint returns 404 (existence-hiding).
	if (dcrConfig?.enabled === false) {
		return { status: 404, body: { error: 'Not found' } };
	}

	const authHeader = request?.headers?.authorization;
	const authError = checkInitialAccessToken(authHeader, dcrConfig?.initialAccessToken);
	if (authError) {
		return authError;
	}

	const built = buildClientFromRequest(body, dcrConfig?.allowedRedirectUriHosts);
	if ('status' in built) {
		return built;
	}

	const isConfidential = built.record.token_endpoint_auth_method !== 'none';
	const clientId = randomUUID();
	const clientIdIssuedAt = Math.floor(Date.now() / 1000);

	const record: MCPClientRecord = {
		...built.record,
		client_id: clientId,
		client_id_issued_at: clientIdIssuedAt,
	};
	if (isConfidential) {
		record.client_secret = randomBytes(32).toString('base64url');
		// 0 = never expires; we don't currently rotate client_secrets.
		record.client_secret_expires_at = 0;
	}

	const store = new MCPClientStore(logger);
	try {
		await store.set(record);
	} catch (error) {
		logger?.error?.('MCP client registration storage failed:', (error as Error).message);
		return {
			status: 500,
			body: { error: 'server_error', error_description: 'Failed to persist client registration' },
		};
	}

	logger?.info?.(
		`MCP client registered: ${clientId} (${isConfidential ? 'confidential' : 'public'}, ${record.redirect_uris.length} redirect URI(s))`
	);

	return {
		status: 201,
		body: record,
	};
}
