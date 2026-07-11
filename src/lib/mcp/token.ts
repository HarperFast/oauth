/**
 * MCP Token Endpoint (POST /oauth/mcp/token)
 *
 * Exchanges an authorization code (PKCE-verified) or a refresh token for an
 * audience-bound RS256 JWT access token. Mirrors DCR's JSON request/response
 * shape (`{ status, body }` with OAuth 2.0 error objects).
 *
 * Access tokens are stateless (no token-table round trip); refresh tokens use
 * single-use family rotation (see refreshTokenStore.ts). The upstream IdP token
 * never appears in claims or the response.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import type { HookManager } from '../hookManager.ts';
import type { Logger, MCPClientRecord, MCPConfig, Request } from '../../types.ts';
import { emitMCPAuditEvent } from './audit.ts';
import { MCPAssertionJtiStore } from './assertionJtiStore.ts';
import { MCPAuthCodeStore } from './authCodeStore.ts';
import { CimdClientError, resolveClient } from './cimd.ts';
import { CLIENT_ASSERTION_TYPE_JWT_BEARER, verifyClientAssertion } from './clientAssertion.ts';
import { MCPKeyStore } from './keyStore.ts';
import { createRateLimiter, type RateLimiter } from './rateLimit.ts';
import {
	hashRefreshToken,
	makeRefreshToken,
	MCPRefreshFamilyStore,
	newFamilyId,
	parseRefreshToken,
} from './refreshTokenStore.ts';
import { signAccessToken } from './tokenIssuer.ts';
import { resolveIssuer, resolveResource } from './wellKnown.ts';

const DEFAULT_ACCESS_TOKEN_TTL = 3600; // 1 hour
const DEFAULT_REFRESH_TOKEN_TTL = 2592000; // 30 days
// client_credentials tokens are re-minted on demand (no refresh token), so
// they stay short — ≤5 minutes per #159 security req 2.
const DEFAULT_CLIENT_CREDENTIALS_TTL = 300;

// RFC 7636 §4.1: code_verifier = 43*128unreserved. Mirrors the code_challenge
// check at authorize.ts so a malformed verifier fails fast here too.
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;

type TokenResponse = {
	status: number;
	body: Record<string, unknown>;
	headers?: Record<string, string>;
};

// RFC 6749 §5.1: token responses carry credentials, so intermediaries and
// browsers must not cache them.
const NO_STORE_HEADERS = { 'Cache-Control': 'no-store', 'Pragma': 'no-cache' };

function errorResponse(status: number, error: string, description?: string): TokenResponse {
	return {
		status,
		body: description ? { error, error_description: description } : { error },
		headers: NO_STORE_HEADERS,
	};
}

function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

/**
 * Coerce a configured TTL to a positive number of seconds. Config from `${ENV}`
 * expansion or quoted YAML can arrive as a string; jsonwebtoken would treat a
 * bare numeric string as milliseconds and `now + "86400"` would concatenate, so
 * normalize here and fall back to the default on any non-positive/non-finite value.
 */
function coerceTtl(value: unknown, fallback: number): number {
	const n = typeof value === 'number' ? value : Number(value);
	return Number.isFinite(n) && n > 0 ? n : fallback;
}

// --- client_credentials issuance rate limiting (#163) ---

const RATE_LIMIT_DEFAULT_PER_MINUTE = 30;

/**
 * Resolve `mcp.clientCredentials.rateLimit` to requests/minute or `false`
 * (disabled). `false`/`0` (and their env-expanded string forms) disable the
 * limiter explicitly; anything non-finite/non-positive falls back to the
 * default rather than failing open — mirrors `coerceTtl`.
 */
function resolveRateLimit(value: unknown): number | false {
	if (value === false || value === 0 || value === 'false' || value === '0') return false;
	if (value === undefined || value === null) return RATE_LIMIT_DEFAULT_PER_MINUTE;
	const n = typeof value === 'number' ? value : Number(value);
	return Number.isFinite(n) && n > 0 ? n : RATE_LIMIT_DEFAULT_PER_MINUTE;
}

// Per-node bucket keyed by client_id; memoized on the configured rate so a
// live config change rebuilds it (dropping state — acceptable, the limiter is
// defense-in-depth, not an accounting ledger). Per-node rationale: see
// rateLimit.ts module header.
let grantLimiter: RateLimiter | undefined;
let grantLimiterRate: number | undefined;

function getGrantLimiter(ratePerMinute: number): RateLimiter {
	if (!grantLimiter || grantLimiterRate !== ratePerMinute) {
		grantLimiter = createRateLimiter({ capacity: ratePerMinute, refillPerMinute: ratePerMinute });
		grantLimiterRate = ratePerMinute;
	}
	return grantLimiter;
}

/** Drop grant-limiter state (for testing). @internal */
export function _resetGrantRateLimiter(): void {
	grantLimiter = undefined;
	grantLimiterRate = undefined;
}

/** Does the client's registered grant_types permit refresh tokens? Defaults to true when unspecified (DCR default includes refresh_token). */
function allowsRefresh(client: MCPClientRecord): boolean {
	return !client.grant_types || client.grant_types.includes('refresh_token');
}

/** Constant-time string compare; length-checks first (timingSafeEqual needs equal length). */
function safeEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function parseBasicAuth(authHeader: string | undefined): { clientId: string; clientSecret: string } | null {
	if (!authHeader || !authHeader.startsWith('Basic ')) return null;
	let decoded: string;
	try {
		decoded = Buffer.from(authHeader.slice('Basic '.length).trim(), 'base64').toString('utf8');
	} catch {
		return null;
	}
	const sep = decoded.indexOf(':');
	if (sep < 0) return null;
	return { clientId: decoded.slice(0, sep), clientSecret: decoded.slice(sep + 1) };
}

type ClientAuthResult = { client: MCPClientRecord } | { error: TokenResponse };

/**
 * Authenticate the client per its registered `token_endpoint_auth_method`.
 * Credentials come from the Authorization: Basic header (client_secret_basic)
 * or the body (client_secret_post); public clients (`none`) present only a
 * client_id and rely on PKCE. Mixing methods is rejected (RFC 6749 §2.3).
 */
async function authenticateClient(
	request: Request | undefined,
	body: any,
	mcpConfig: MCPConfig | undefined,
	logger?: Logger
): Promise<ClientAuthResult> {
	const basic = parseBasicAuth(request?.headers?.authorization);
	const bodyClientId = typeof body?.client_id === 'string' ? body.client_id : undefined;
	const bodyClientSecret = typeof body?.client_secret === 'string' ? body.client_secret : undefined;

	if (basic && bodyClientSecret) {
		return { error: errorResponse(400, 'invalid_request', 'Multiple client authentication methods') };
	}
	if (basic && bodyClientId && bodyClientId !== basic.clientId) {
		return { error: errorResponse(400, 'invalid_request', 'client_id mismatch between header and body') };
	}

	const clientId = basic?.clientId ?? bodyClientId;
	if (!clientId) {
		return { error: errorResponse(400, 'invalid_request', 'client_id is required') };
	}

	let client;
	try {
		client = await resolveClient(clientId, mcpConfig, logger);
	} catch (err) {
		if (err instanceof CimdClientError) {
			return { error: errorResponse(401, err.oauthError, err.message) };
		}
		logger?.error?.('MCP token: client lookup failed:', err instanceof Error ? err.message : String(err));
		return { error: errorResponse(500, 'server_error', 'Client lookup failed') };
	}
	if (!client) {
		return { error: errorResponse(401, 'invalid_client', 'Unknown client') };
	}

	const method = client.token_endpoint_auth_method ?? 'none';

	if (method === 'none') {
		// Public client: PKCE is the proof. A presented secret signals misuse.
		if (basic || bodyClientSecret) {
			return { error: errorResponse(401, 'invalid_client', 'Public client must not present a secret') };
		}
		return { client };
	}

	let presentedSecret: string | undefined;
	if (method === 'client_secret_basic') {
		if (!basic) {
			return { error: errorResponse(401, 'invalid_client', 'client_secret_basic requires Authorization: Basic') };
		}
		presentedSecret = basic.clientSecret;
	} else if (method === 'client_secret_post') {
		if (!bodyClientSecret) {
			return { error: errorResponse(401, 'invalid_client', 'client_secret_post requires client_secret in body') };
		}
		presentedSecret = bodyClientSecret;
	} else {
		return { error: errorResponse(401, 'invalid_client', 'Unsupported token endpoint auth method') };
	}

	if (!presentedSecret || !client.client_secret || !safeEqual(presentedSecret, client.client_secret)) {
		return { error: errorResponse(401, 'invalid_client', 'Invalid client credentials') };
	}
	return { client };
}

/** PKCE S256: base64url(sha256(code_verifier)) must equal the stored challenge. */
function pkceMatches(codeVerifier: string, storedChallenge: string): boolean {
	const computed = createHash('sha256').update(codeVerifier).digest('base64url');
	return safeEqual(computed, storedChallenge);
}

async function mintTokenPair(
	request: Request | undefined,
	mcpConfig: MCPConfig,
	grant: {
		user: string;
		resource: string;
		scope?: string;
		clientId: string;
		issueRefresh: boolean;
		/** Pre-coerced TTL override (client_credentials); defaults to mcp.accessTokenTtl. */
		accessTtl?: number;
		/** Hook event type; defaults to 'access' (authorization_code). */
		hookType?: 'access' | 'client_credentials';
	},
	hookManager?: HookManager,
	logger?: Logger
): Promise<TokenResponse> {
	const issuer = resolveIssuer(request as any, mcpConfig);
	const accessTtl = grant.accessTtl ?? coerceTtl(mcpConfig.accessTokenTtl, DEFAULT_ACCESS_TOKEN_TTL);
	const refreshTtl = coerceTtl(mcpConfig.refreshTokenTtl, DEFAULT_REFRESH_TOKEN_TTL);

	const key = await new MCPKeyStore(logger).getSigningKey(mcpConfig);
	const { token: accessToken, jti } = signAccessToken(
		{
			issuer,
			subject: grant.user,
			audience: grant.resource,
			clientId: grant.clientId,
			scope: grant.scope,
			ttlSeconds: accessTtl,
		},
		key
	);

	const responseBody: Record<string, unknown> = {
		access_token: accessToken,
		token_type: 'Bearer',
		expires_in: accessTtl,
	};
	if (grant.scope) responseBody.scope = grant.scope;

	// Only issue a refresh token if the client registered the refresh_token grant.
	if (grant.issueRefresh) {
		const familyId = newFamilyId();
		const { token: refreshToken, hash } = makeRefreshToken(familyId);
		const now = nowSeconds();
		await new MCPRefreshFamilyStore(logger).set({
			family_id: familyId,
			current_token_hash: hash,
			revoked: false,
			client_id: grant.clientId,
			user: grant.user,
			resource: grant.resource,
			scope: grant.scope,
			expires_at: now + refreshTtl,
		});
		responseBody.refresh_token = refreshToken;
	}

	// Emit the audit event + fire the hook only AFTER all token state is durably
	// persisted (the refresh family above) — otherwise a persistence failure
	// would report a phantom successful issuance to audit/billing/rate-limit
	// consumers for an exchange the client never actually received. Both are
	// fire-and-forget (emitMCPAuditEvent and callOnMCPTokenIssued each swallow
	// their own errors), so neither can block the token from reaching the client.
	emitMCPAuditEvent({
		event: 'oauth.mcp.token.issued',
		client_id: grant.clientId,
		sub: grant.user,
		aud: grant.resource,
		scope: grant.scope,
		jti,
		timestamp: new Date().toISOString(),
	});
	if (hookManager) {
		hookManager.callOnMCPTokenIssued(
			{
				type: grant.hookType ?? 'access',
				client_id: grant.clientId,
				sub: grant.user,
				aud: grant.resource,
				scope: grant.scope,
				jti,
			},
			request
		);
	}

	return { status: 200, body: responseBody, headers: NO_STORE_HEADERS };
}

async function handleAuthorizationCodeGrant(
	request: Request | undefined,
	body: any,
	client: MCPClientRecord,
	mcpConfig: MCPConfig,
	hookManager?: HookManager,
	logger?: Logger
): Promise<TokenResponse> {
	const code = typeof body?.code === 'string' ? body.code : undefined;
	const codeVerifier = typeof body?.code_verifier === 'string' ? body.code_verifier : undefined;
	const redirectUri = typeof body?.redirect_uri === 'string' ? body.redirect_uri : undefined;

	if (!code || !codeVerifier || !redirectUri) {
		return errorResponse(400, 'invalid_request', 'code, code_verifier, and redirect_uri are required');
	}
	if (!CODE_VERIFIER_PATTERN.test(codeVerifier)) {
		return errorResponse(400, 'invalid_grant', 'code_verifier must be 43-128 unreserved characters (RFC 7636)');
	}

	const codeStore = new MCPAuthCodeStore(logger);
	const record = await codeStore.get(code);
	if (!record) {
		return errorResponse(400, 'invalid_grant', 'Authorization code is invalid or expired');
	}
	if (record.client_id !== client.client_id) {
		return errorResponse(400, 'invalid_grant', 'Authorization code was issued to a different client');
	}
	if (record.redirect_uri !== redirectUri) {
		return errorResponse(400, 'invalid_grant', 'redirect_uri does not match the authorization request');
	}
	if (!pkceMatches(codeVerifier, record.code_challenge)) {
		return errorResponse(400, 'invalid_grant', 'PKCE verification failed');
	}

	// Strict single-use consume: if the delete fails, the code might still be
	// replayable, so refuse to issue rather than risk a double-spend.
	try {
		await codeStore.consume(code);
	} catch (error) {
		logger?.error?.(
			'MCP token: failed to consume authorization code:',
			error instanceof Error ? error.message : String(error)
		);
		return errorResponse(500, 'server_error', 'Failed to consume authorization code');
	}

	return mintTokenPair(
		request,
		mcpConfig,
		{
			user: record.user,
			resource: record.resource,
			scope: record.scope,
			clientId: client.client_id,
			issueRefresh: allowsRefresh(client),
		},
		hookManager,
		logger
	);
}

async function handleRefreshTokenGrant(
	request: Request | undefined,
	body: any,
	client: MCPClientRecord,
	mcpConfig: MCPConfig,
	hookManager?: HookManager,
	logger?: Logger
): Promise<TokenResponse> {
	if (!allowsRefresh(client)) {
		return errorResponse(400, 'unauthorized_client', 'Client is not authorized for the refresh_token grant');
	}

	const presented = body?.refresh_token;
	const parsed = parseRefreshToken(presented);
	if (!parsed) {
		return errorResponse(400, 'invalid_grant', 'Malformed refresh_token');
	}

	const familyStore = new MCPRefreshFamilyStore(logger);
	const family = await familyStore.get(parsed.familyId);
	if (!family || family.revoked || family.expires_at <= nowSeconds()) {
		return errorResponse(400, 'invalid_grant', 'Refresh token is invalid, revoked, or expired');
	}
	if (family.client_id !== client.client_id) {
		return errorResponse(400, 'invalid_grant', 'Refresh token was issued to a different client');
	}

	if (!safeEqual(hashRefreshToken(presented), family.current_token_hash)) {
		// A superseded (already-rotated) token was replayed — revoke the family.
		// Rejecting the replay must not depend on the revoke write succeeding: a
		// hash mismatch NEVER reissues, and we still try to persist the
		// revocation (logging if that fails) so a transient write error can't
		// leave the family live for a retry.
		family.revoked = true;
		try {
			await familyStore.set(family);
		} catch (error) {
			logger?.error?.(
				`MCP token: failed to persist revocation for family ${family.family_id}:`,
				error instanceof Error ? error.message : String(error)
			);
		}
		logger?.warn?.(`MCP token: refresh replay detected; revoked family ${family.family_id}`);
		return errorResponse(400, 'invalid_grant', 'Refresh token has been superseded; family revoked');
	}

	// Sign the access token BEFORE committing the rotation. If key fetch or
	// signing throws, the family is left untouched so the client's current
	// refresh token still works on retry — otherwise a transient failure would
	// orphan their token and trip replay-revocation on the next attempt.
	const issuer = resolveIssuer(request as any, mcpConfig);
	const accessTtl = coerceTtl(mcpConfig.accessTokenTtl, DEFAULT_ACCESS_TOKEN_TTL);
	const key = await new MCPKeyStore(logger).getSigningKey(mcpConfig);
	const { token: accessToken, jti } = signAccessToken(
		{
			issuer,
			subject: family.user,
			audience: family.resource,
			clientId: client.client_id,
			scope: family.scope,
			ttlSeconds: accessTtl,
		},
		key
	);

	// Rotate only once the new access token is in hand (keep the original expiry).
	const { token: newRefreshToken, hash: newHash } = makeRefreshToken(family.family_id);
	family.current_token_hash = newHash;
	await familyStore.set(family);

	// Emit audit event + fire hook after the token is signed and rotation is
	// committed. Failures are fire-and-forget: must not block the response.
	emitMCPAuditEvent({
		event: 'oauth.mcp.token.refreshed',
		client_id: client.client_id,
		sub: family.user,
		aud: family.resource,
		scope: family.scope,
		jti,
		timestamp: new Date().toISOString(),
	});
	if (hookManager) {
		hookManager.callOnMCPTokenIssued(
			{
				type: 'refresh',
				client_id: client.client_id,
				sub: family.user,
				aud: family.resource,
				scope: family.scope,
				jti,
			},
			request
		);
	}

	const responseBody: Record<string, unknown> = {
		access_token: accessToken,
		token_type: 'Bearer',
		expires_in: accessTtl,
		refresh_token: newRefreshToken,
	};
	if (family.scope) responseBody.scope = family.scope;
	return { status: 200, body: responseBody, headers: NO_STORE_HEADERS };
}

/**
 * RFC 7523 client_credentials grant for headless agents (#162): the client
 * authenticates with a signed EdDSA assertion (private_key_jwt) instead of an
 * interactive consent flow. Client identity resolves through `resolveClient()`
 * — in practice a CIMD document (#161), since DCR never registers
 * private_key_jwt clients. No refresh token is ever issued: agents re-mint on
 * 401, and the short TTL bounds leak blast radius (#159 req 2).
 */
async function handleClientCredentialsGrant(
	request: Request | undefined,
	body: any,
	mcpConfig: MCPConfig,
	hookManager?: HookManager,
	logger?: Logger
): Promise<TokenResponse> {
	const clientId = typeof body?.client_id === 'string' ? body.client_id : undefined;
	const assertionType = typeof body?.client_assertion_type === 'string' ? body.client_assertion_type : undefined;
	const assertion = typeof body?.client_assertion === 'string' ? body.client_assertion : undefined;

	if (!clientId) {
		return errorResponse(400, 'invalid_request', 'client_id is required');
	}
	if (assertionType !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
		return errorResponse(400, 'invalid_request', `client_assertion_type must be ${CLIENT_ASSERTION_TYPE_JWT_BEARER}`);
	}
	if (!assertion) {
		return errorResponse(400, 'invalid_request', 'client_assertion is required');
	}
	// Proof of key possession is the ONLY accepted authentication for this
	// grant — a Basic header or client_secret must not ride along (#159 req 6:
	// no credential type may substitute for the private key). Scheme match is
	// case-insensitive per RFC 9110 §11.1.
	if (/^basic\s/i.test(request?.headers?.authorization ?? '') || typeof body?.client_secret === 'string') {
		return errorResponse(
			400,
			'invalid_request',
			'client_credentials accepts only a client_assertion (no secret or Basic auth)'
		);
	}

	// Issuance rate limit (#163, #159 req 5): checked BEFORE resolveClient so
	// an over-limit client cannot trigger CIMD fetches or crypto work. Keyed
	// by the requested client_id — attacker-chosen, but the bucket map is
	// LRU-bounded and the point is bounding per-identity issuance.
	const ratePerMinute = resolveRateLimit(mcpConfig.clientCredentials?.rateLimit);
	if (ratePerMinute !== false) {
		const limit = getGrantLimiter(ratePerMinute).tryTake(clientId);
		if (!limit.allowed) {
			const response = errorResponse(429, 'slow_down', 'Token issuance rate limit reached for this client');
			response.headers = { ...response.headers, 'Retry-After': String(limit.retryAfterSeconds) };
			return response;
		}
	}

	let client: MCPClientRecord | null;
	try {
		client = await resolveClient(clientId, mcpConfig, logger);
	} catch (err) {
		if (err instanceof CimdClientError) {
			return errorResponse(401, err.oauthError, err.message);
		}
		logger?.error?.('MCP token: client lookup failed:', err instanceof Error ? err.message : String(err));
		return errorResponse(500, 'server_error', 'Client lookup failed');
	}
	if (!client) {
		return errorResponse(401, 'invalid_client', 'Unknown client');
	}
	// Pinned to CIMD-resolved clients: the allowedHosts allowlist — the gate
	// that stands between "hosts a reachable document" and "mints tokens" —
	// is enforced on the CIMD resolution path. A stored (DCR) record must
	// never mint here, even if a future DCR surface could register this
	// shape; lifting this requires its own registration gate (#161's
	// optional initialAccessToken leg).
	if (
		client._cimd !== true ||
		client.token_endpoint_auth_method !== 'private_key_jwt' ||
		client.grant_types?.length !== 1 ||
		client.grant_types[0] !== 'client_credentials'
	) {
		return errorResponse(400, 'unauthorized_client', 'Client is not registered for the client_credentials grant');
	}

	const issuer = resolveIssuer(request as any, mcpConfig);
	const keys = Array.isArray(client.jwks?.keys) ? client.jwks.keys : [];
	const result = verifyClientAssertion({
		assertion,
		clientId,
		tokenEndpoint: `${issuer}/oauth/mcp/token`,
		jwks: keys,
	});
	if (!result.valid) {
		logger?.warn?.(`MCP token: client_assertion rejected for ${clientId}: ${result.reason}`);
		return errorResponse(401, 'invalid_client', `client_assertion verification failed: ${result.reason}`);
	}

	// RFC 8707 resource binding: exact match against the canonical MCP
	// resource, fail closed — no prefix or wildcard comparisons (#159 req 3).
	// Checked BEFORE the jti is consumed: a recoverable request-param mistake
	// must not burn the single-use assertion.
	const canonicalResource = resolveResource(request as any, mcpConfig);
	const requestedResource = typeof body?.resource === 'string' ? body.resource : undefined;
	if (requestedResource !== undefined && requestedResource !== canonicalResource) {
		return errorResponse(400, 'invalid_target', 'resource does not match the configured MCP resource');
	}

	// Replay guard: a storage failure here THROWS to the top-level 500 handler
	// — "could not check" must never degrade to "not seen" (fail closed). Runs
	// LAST: consuming the jti is the one irreversible step before minting.
	// Single-use is best-effort under concurrency — see the bound documented in
	// assertionJtiStore.ts and docs/mcp-oauth.md (atomic reserve: harper#1745).
	const fresh = await new MCPAssertionJtiStore(logger).checkAndRecord(clientId, result.claims.jti);
	if (!fresh) {
		return errorResponse(400, 'invalid_grant', 'client_assertion jti has already been used');
	}

	return mintTokenPair(
		request,
		mcpConfig,
		{
			// RFC 9068 §2.2: for client_credentials, sub is the CLIENT identity —
			// there is no end user in this grant.
			user: clientId,
			resource: canonicalResource,
			scope: client.scope,
			clientId,
			issueRefresh: false,
			accessTtl: coerceTtl(mcpConfig.clientCredentials?.accessTokenTtl, DEFAULT_CLIENT_CREDENTIALS_TTL),
			hookType: 'client_credentials',
		},
		hookManager,
		logger
	);
}

/**
 * Handle POST /oauth/mcp/token. Returns `{ status, body }`; the `enabled` gate
 * is applied upstream in handleMCPPost.
 *
 * `hookManager` is optional so callers that don't have access to it (e.g.
 * unit tests that go directly to this function) can omit it without error.
 * When present, `onMCPTokenIssued` is fired after every successful mint.
 */
export async function handleToken(
	request: Request | undefined,
	body: any,
	mcpConfig: MCPConfig,
	hookManager?: HookManager,
	logger?: Logger
): Promise<TokenResponse> {
	// Top-level guard: any unexpected throw (a signing failure, a store
	// timeout, etc.) must become a structured OAuth error (RFC 6749 §5.2), not
	// propagate to the framework's default 500 handler — which could surface a
	// stack trace or raw error message. The per-grant handlers already return
	// their own 4xx errors; this only catches the unexpected.
	try {
		const grantType = typeof body?.grant_type === 'string' ? body.grant_type : undefined;
		// client_credentials is explicit opt-in (default OFF); when disabled it
		// is indistinguishable from any other unsupported grant.
		const clientCredentialsEnabled = mcpConfig.clientCredentials?.enabled === true;
		if (grantType === 'client_credentials' && clientCredentialsEnabled) {
			return await handleClientCredentialsGrant(request, body, mcpConfig, hookManager, logger);
		}
		if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
			return errorResponse(
				400,
				'unsupported_grant_type',
				clientCredentialsEnabled
					? 'grant_type must be authorization_code, refresh_token, or client_credentials'
					: 'grant_type must be authorization_code or refresh_token'
			);
		}

		const auth = await authenticateClient(request, body, mcpConfig, logger);
		if ('error' in auth) {
			return auth.error;
		}

		if (grantType === 'authorization_code') {
			return await handleAuthorizationCodeGrant(request, body, auth.client, mcpConfig, hookManager, logger);
		}
		return await handleRefreshTokenGrant(request, body, auth.client, mcpConfig, hookManager, logger);
	} catch (error) {
		logger?.error?.(
			'MCP token: unexpected error during token issuance:',
			error instanceof Error ? error.message : String(error)
		);
		return errorResponse(500, 'server_error', 'An unexpected error occurred during token issuance');
	}
}
