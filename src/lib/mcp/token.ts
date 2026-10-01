/**
 * MCP Token Endpoint (POST /oauth/mcp/token)
 *
 * Exchanges an authorization code (PKCE-verified) or a refresh token for an
 * audience-bound signed JWT access token. Mirrors DCR's JSON request/response
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
import { CimdClientError, MAX_CLIENT_ID_LENGTH, resolveClient } from './cimd.ts';
import { allowsGrant } from './clientValidator.ts';
import {
	type AssertionPolicy,
	type ClientAuthMethod,
	headlessAssertionPolicy,
	interactiveAssertionPolicy,
	interactiveKeyIssue,
	isClientAuthMethod,
	isHeadlessCimdClient,
	isInteractiveCimdClient,
	permittedAuthMethod,
} from './clientAuthMethod.ts';
import {
	type AudienceForm,
	CLIENT_ASSERTION_TYPE_JWT_BEARER,
	MAX_ASSERTION_LENGTH,
	verifyClientAssertion,
} from './clientAssertion.ts';
import { getClientJwks } from './jwksFetcher.ts';
import { MCPKeyStore } from './keyStore.ts';
import { createRateLimiter, type RateLimiter } from './rateLimit.ts';
import { getRequestHeader } from '../requestHeaders.ts';
import {
	hashRefreshToken,
	isBoundFamilyId,
	isProvenancedFamilyId,
	makeRefreshToken,
	MCPRefreshFamilyStore,
	newFamilyId,
	parseRefreshToken,
} from './refreshTokenStore.ts';
import { signAccessToken } from './tokenIssuer.ts';
import { resolveIssuer, resolveResource, tokenEndpointUrl } from './wellKnown.ts';

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

/**
 * Map a CimdClientError to a token-endpoint response. A throttle rejection
 * carries `statusCode` (429) and, for the fetch rate limit, `retryAfterSeconds`
 * — surface those (with a `Retry-After` header) instead of the default 401, so
 * a rate-limited client backs off rather than treating it as an auth failure.
 */
function cimdErrorResponse(err: CimdClientError): TokenResponse {
	const response = errorResponse(err.statusCode ?? 401, err.oauthError, err.message);
	if (err.retryAfterSeconds !== undefined) {
		response.headers = { ...response.headers, 'Retry-After': String(err.retryAfterSeconds) };
	}
	return response;
}

/**
 * The handler's line when a superseded family's revocation cannot be written:
 * fixed and single-line, without the error text or the token. The store's own
 * write-error log still carries the underlying error.
 */
const REVOCATION_NOT_PERSISTED_LOG =
	'MCP token: refresh replay detected, but the family revocation could not be persisted; the request was refused with invalid_grant and the family stays live';

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

/** Does the client's registered grant_types permit refresh tokens? Defaults to true when unspecified (legacy default includes refresh_token). */
function allowsRefresh(client: MCPClientRecord): boolean {
	return allowsGrant(client, 'refresh_token');
}

/** Does a space-delimited scope string include `offline_access` (SEP-2207)? */
function scopeIncludesOfflineAccess(scope: string | undefined): boolean {
	return !!scope && scope.split(/\s+/).includes('offline_access');
}

/**
 * Should the authorization_code exchange issue a refresh token? Always gated
 * on the client's registered grant_types; when
 * `mcp.refreshTokenRequiresOfflineAccess` is set, additionally requires the
 * granted scope to carry the explicit `offline_access` opt-in (SEP-2207).
 * Default policy is grant_types-only — most MCP clients never request
 * offline_access, and withholding refresh tokens from them would force
 * hourly re-auth.
 */
function shouldIssueRefresh(client: MCPClientRecord, scope: string | undefined, mcpConfig: MCPConfig): boolean {
	if (!allowsRefresh(client)) return false;
	if (mcpConfig.refreshTokenRequiresOfflineAccess) return scopeIncludesOfflineAccess(scope);
	return true;
}

/** Constant-time string compare; length-checks first (timingSafeEqual needs equal length). */
function safeEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/**
 * application/x-www-form-urlencoded decode of one Basic credential field
 * (RFC 6749 §2.3.1: `+` is a space, then percent-decode). Returns null on
 * malformed percent-encoding so a corrupt credential is rejected, not
 * looked up as-is.
 */
function formUrlDecode(field: string): string | null {
	try {
		return decodeURIComponent(field.replace(/\+/g, ' '));
	} catch {
		return null;
	}
}

/** Strict base64 (standard alphabet, optional padding) for Basic credentials. */
const BASIC_CREDENTIALS_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

type BasicAuth = { absent: true } | { malformed: true } | { clientId: string; clientSecret: string };

/**
 * Read an `Authorization: Basic` header: absent when there is no header or it
 * uses another scheme; malformed when the Basic scheme carries no credentials,
 * or credentials that don't decode to a non-empty client_id and a secret
 * (possibly empty) separated by `:`.
 */
function readBasicAuth(authHeader: string | undefined): BasicAuth {
	if (!authHeader) return { absent: true };
	// A bare `Basic` scheme with no credentials is malformed, not absent.
	if (/^basic$/i.test(authHeader.trim())) return { malformed: true };
	// Scheme name is case-insensitive (RFC 9110 §11.1) — matches the `/^basic\s/i`
	// check on the client_credentials path.
	if (!/^basic\s/i.test(authHeader)) return { absent: true };
	const encoded = authHeader.slice('Basic '.length).trim();
	if (!BASIC_CREDENTIALS_PATTERN.test(encoded)) return { malformed: true };
	const decoded = Buffer.from(encoded, 'base64').toString('utf8');
	// RFC 6749 §2.3.1: each field is form-urlencoded before base64, so the first
	// literal `:` separates them (a `:` inside a field is `%3A`). Split there,
	// then form-decode both — otherwise a URL-shaped CIMD client_id is looked up
	// with its `%3A`/`%2F` literal, or an unencoded one splits at its scheme colon.
	const sep = decoded.indexOf(':');
	if (sep < 0) return { malformed: true };
	const clientId = formUrlDecode(decoded.slice(0, sep));
	const clientSecret = formUrlDecode(decoded.slice(sep + 1));
	if (clientId === null || clientSecret === null || clientId.length === 0) return { malformed: true };
	return { clientId, clientSecret };
}

/** @internal — exported for tests. Null when absent or malformed. */
export function parseBasicAuth(authHeader: string | undefined): { clientId: string; clientSecret: string } | null {
	const basic = readBasicAuth(authHeader);
	return 'clientId' in basic ? basic : null;
}

/**
 * One body parameter's value: `{}` when absent, `{ value }` for a single
 * non-empty string, `{ invalid: true }` when present but empty or repeated
 * (a repeated form field arrives as an array).
 */
function singleParameter(body: any, name: string): { value?: string } | { invalid: true } {
	const raw = body?.[name];
	if (raw === undefined) return {};
	if (typeof raw !== 'string' || raw.length === 0) return { invalid: true };
	return { value: raw };
}

/** The client's identity from an assertion's unverified `sub`, when no client_id was sent (RFC 7521 §4.2). */
function unverifiedAssertionSubject(assertion: string): string | undefined {
	const payloadSegment = assertion.split('.')[1];
	if (!payloadSegment || !/^[A-Za-z0-9_-]+$/.test(payloadSegment)) return undefined;
	try {
		const payload = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
		const sub = payload?.sub;
		return typeof sub === 'string' && sub.length > 0 && sub.length <= MAX_CLIENT_ID_LENGTH ? sub : undefined;
	} catch {
		return undefined;
	}
}

type PresentedCredentials =
	| { method: 'none' }
	| { method: 'client_secret_basic'; secret: string }
	| { method: 'client_secret_post'; secret: string }
	| { method: 'private_key_jwt'; assertion: string };

type ClientAuthResult =
	| { client: MCPClientRecord; method: ClientAuthMethod; audienceForm?: AudienceForm }
	| { error: TokenResponse };

/** The verifier's wording for an over-length assertion, reused where the token endpoint rejects one early. */
const ASSERTION_TOO_LONG = 'client_assertion verification failed: client_assertion exceeds the maximum allowed length';

function invalidClient(description: string): { error: TokenResponse } {
	return { error: errorResponse(401, 'invalid_client', description) };
}

/** RFC 6749 §5.2: a repeated or missing parameter, or more than one authentication mechanism. */
function invalidRequest(description: string): { error: TokenResponse } {
	return { error: errorResponse(400, 'invalid_request', description) };
}

/**
 * RFC 6749 §5.2: a 401 answering a request that authenticated with the
 * `Authorization` header carries a challenge for the scheme it used.
 */
const BASIC_CHALLENGE = 'Basic realm="oauth"';

/** The error for a presentation that differs from the permitted method. */
function methodMismatch(
	permitted: ClientAuthMethod,
	presented: PresentedCredentials['method']
): { error: TokenResponse } {
	if (permitted === 'none') {
		return invalidClient(
			presented === 'private_key_jwt'
				? 'Public client must not present a client assertion'
				: 'Public client must not present a secret'
		);
	}
	if (permitted === 'client_secret_basic') return invalidClient('client_secret_basic requires Authorization: Basic');
	if (permitted === 'client_secret_post') return invalidClient('client_secret_post requires client_secret in body');
	return invalidClient('This client must authenticate with a client_assertion (private_key_jwt)');
}

/**
 * Authenticate the client at the token endpoint (authorization_code and
 * refresh_token grants). The client presents at most one mechanism; the
 * server computes the one method it permits for this client
 * (`permittedAuthMethod`) and rejects any other presentation:
 *
 * - `client_assertion` + `client_assertion_type` → private_key_jwt, which is
 *   verified or rejected, never ignored (OAuth 2.1 §3.2.2 "authenticate the
 *   client if client authentication is included").
 * - `Authorization: Basic` with a non-empty secret → client_secret_basic;
 *   body `client_secret` → client_secret_post.
 * - nothing (or an empty-secret Basic header carrying only the client_id, as
 *   some public clients send) → none; PKCE is the proof.
 *
 * Rejected before any lookup with invalid_request (RFC 6749 §5.2): a
 * repeated parameter, an empty credential parameter, a partial assertion
 * pair, and more than one mechanism (RFC 6749 §2.3, RFC 7521 §4.2.1) — an
 * empty-secret Basic header never accompanies an assertion. Rejected before
 * any lookup with invalid_client: an unknown client_assertion_type, malformed
 * Basic credentials, and an assertion longer than the verifier accepts.
 */
async function authenticateClient(
	request: Request | undefined,
	body: any,
	mcpConfig: MCPConfig | undefined,
	logger?: Logger
): Promise<ClientAuthResult> {
	const basic = readBasicAuth(getRequestHeader(request?.headers, 'authorization'));
	if ('malformed' in basic) return invalidClient('Malformed Basic client credentials');

	const clientIdParam = singleParameter(body, 'client_id');
	const secretParam = singleParameter(body, 'client_secret');
	const assertionParam = singleParameter(body, 'client_assertion');
	const assertionTypeParam = singleParameter(body, 'client_assertion_type');
	for (const [name, param] of [
		['client_id', clientIdParam],
		['client_secret', secretParam],
		['client_assertion', assertionParam],
		['client_assertion_type', assertionTypeParam],
	] as const) {
		if ('invalid' in param) return invalidRequest(`${name} must be a single non-empty value`);
	}
	const secret = (secretParam as { value?: string }).value;
	const assertion = (assertionParam as { value?: string }).value;
	const assertionType = (assertionTypeParam as { value?: string }).value;
	const hasBasic = 'clientId' in basic;

	if (assertion !== undefined || assertionType !== undefined) {
		if (assertion === undefined || assertionType === undefined) {
			return invalidRequest('client_assertion and client_assertion_type must be presented together');
		}
		if (assertionType !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
			return invalidClient(`client_assertion_type must be ${CLIENT_ASSERTION_TYPE_JWT_BEARER}`);
		}
		if (hasBasic || secret !== undefined) return invalidRequest('Multiple client authentication methods');
		// The verifier's length bound, applied before the assertion is parsed for a
		// client_id candidate or any client lookup begins.
		if (assertion.length > MAX_ASSERTION_LENGTH) return invalidClient(ASSERTION_TOO_LONG);
	}
	if (hasBasic && secret !== undefined) return invalidRequest('Multiple client authentication methods');
	const bodyClientId = (clientIdParam as { value?: string }).value;
	if (hasBasic && bodyClientId !== undefined && bodyClientId !== basic.clientId) {
		return invalidRequest('client_id mismatch between header and body');
	}

	const clientId =
		(hasBasic ? basic.clientId : undefined) ??
		bodyClientId ??
		(assertion !== undefined ? unverifiedAssertionSubject(assertion) : undefined);
	if (!clientId) return invalidRequest('client_id is required');

	const presented: PresentedCredentials =
		assertion !== undefined
			? { method: 'private_key_jwt', assertion }
			: hasBasic && basic.clientSecret
				? { method: 'client_secret_basic', secret: basic.clientSecret }
				: secret !== undefined
					? { method: 'client_secret_post', secret }
					: { method: 'none' };

	let client;
	try {
		client = await resolveClient(clientId, mcpConfig, logger);
	} catch (err) {
		if (err instanceof CimdClientError) {
			return { error: cimdErrorResponse(err) };
		}
		logger?.error?.('MCP token: client lookup failed:', err instanceof Error ? err.message : String(err));
		return { error: errorResponse(500, 'server_error', 'Client lookup failed') };
	}
	if (!client) {
		return invalidClient('Unknown client');
	}

	const permitted = permittedAuthMethod(client, mcpConfig);
	if ('error' in permitted) return invalidClient(permitted.error);
	if (presented.method !== permitted.method) return methodMismatch(permitted.method, presented.method);

	if (presented.method === 'none') return { client, method: 'none' };
	if (presented.method === 'private_key_jwt') {
		const verified = await verifyPresentedAssertion(client, presented.assertion, request, mcpConfig, logger);
		if ('error' in verified) return verified;
		return { client, method: 'private_key_jwt', audienceForm: verified.audienceForm };
	}
	if (!client.client_secret || !safeEqual(presented.secret, client.client_secret)) {
		return invalidClient('Invalid client credentials');
	}
	return { client, method: presented.method };
}

/**
 * Verify a private_key_jwt assertion presented on the authorization_code or
 * refresh_token grant, then record its jti. Headless records use their
 * client_credentials policy (EdDSA, inline keys); interactive CIMD records
 * use theirs (RS256/ES256/EdDSA narrowed by the document's pin, inline `jwks`
 * or `jwks_uri`, issuer audience plus the opt-in exception). A stored (DCR)
 * record never authenticates this way.
 */
async function verifyPresentedAssertion(
	client: MCPClientRecord,
	assertion: string,
	request: Request | undefined,
	mcpConfig: MCPConfig | undefined,
	logger?: Logger
): Promise<{ audienceForm: AudienceForm } | { error: TokenResponse }> {
	const issuer = resolveIssuer(request as any, mcpConfig ?? {});
	const tokenEndpoint = tokenEndpointUrl(issuer);
	let policy: AssertionPolicy;
	if (isHeadlessCimdClient(client)) {
		policy = headlessAssertionPolicy(mcpConfig, issuer, tokenEndpoint);
	} else if (isInteractiveCimdClient(client)) {
		const keyIssue = interactiveKeyIssue(client, mcpConfig);
		if (keyIssue) return invalidClient(`client keys are unusable: ${keyIssue}`);
		policy = interactiveAssertionPolicy(client, mcpConfig, issuer, tokenEndpoint);
	} else {
		return invalidClient('private_key_jwt is supported only for CIMD clients');
	}

	const loadKeys = async (
		refetchForUnknownKid: boolean
	): Promise<Record<string, unknown>[] | { error: TokenResponse }> => {
		if (client.jwks_uri === undefined) return client.jwks?.keys ?? [];
		try {
			return await getClientJwks(
				client.client_id,
				client.jwks_uri,
				mcpConfig?.clientIdMetadataDocuments,
				{ refetchForUnknownKid },
				logger
			);
		} catch (err) {
			if (err instanceof CimdClientError) return { error: cimdErrorResponse(err) };
			logger?.error?.('MCP token: client key retrieval failed:', err instanceof Error ? err.message : String(err));
			return { error: errorResponse(500, 'server_error', 'Client key retrieval failed') };
		}
	};

	let keys = await loadKeys(false);
	if (!Array.isArray(keys)) return keys;
	const verify = (jwks: Record<string, unknown>[]) =>
		verifyClientAssertion({
			assertion,
			clientId: client.client_id,
			audiences: policy.audiences,
			jwks,
			allowedAlgorithms: policy.algorithms,
			maxExpiresInSeconds: policy.maxLifetimeSeconds,
		});
	let result = verify(keys);
	if (!result.valid && result.unknownKid && client.jwks_uri !== undefined) {
		// An unknown kid may mean the client rotated: refetch at most once (rate-limited).
		keys = await loadKeys(true);
		if (!Array.isArray(keys)) return keys;
		result = verify(keys);
	}
	if (!result.valid) {
		logger?.warn?.(`MCP token: client_assertion rejected for ${JSON.stringify(client.client_id)}: ${result.reason}`);
		return invalidClient(`client_assertion verification failed: ${result.reason}`);
	}

	// Replay guard: a storage failure THROWS to the top-level 500 handler —
	// "could not check" must never degrade to "not seen" (fail closed).
	const fresh = await new MCPAssertionJtiStore(logger).checkAndRecord(
		client.client_id,
		result.claims.jti,
		result.claims.exp
	);
	if (!fresh) return invalidClient('client_assertion jti has already been used');

	// Record which audience form was accepted; never the assertion itself.
	logger?.info?.(
		`MCP token: client ${JSON.stringify(client.client_id)} authenticated with private_key_jwt ` +
			`(alg ${result.alg}, aud form ${result.audienceForm})`
	);
	return { audienceForm: result.audienceForm };
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
		/** Token-endpoint authentication method bound to the refresh family. */
		clientAuthMethod?: ClientAuthMethod;
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

	// Refresh issuance is decided by the caller (shouldIssueRefresh: client
	// grant_types, plus the offline_access scope opt-in when configured).
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
			client_auth_method: grant.clientAuthMethod,
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
	clientAuthMethod: ClientAuthMethod,
	mcpConfig: MCPConfig,
	hookManager?: HookManager,
	logger?: Logger
): Promise<TokenResponse> {
	// RFC 6749 §5.2: reject if the client's registered grant_types do not
	// include authorization_code.
	if (!allowsGrant(client, 'authorization_code')) {
		return errorResponse(400, 'unauthorized_client', 'Client is not authorized for the authorization_code grant');
	}

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
	// Client-authentication binding, checked before the code is consumed: the
	// exchange must use exactly the method bound at authorization. A code
	// without a binding predates it; both cases require reauthorization.
	if (!isClientAuthMethod(record.client_auth_method)) {
		return errorResponse(
			400,
			'invalid_grant',
			'Authorization code predates client authentication binding; reauthorize'
		);
	}
	if (record.client_auth_method !== clientAuthMethod) {
		return errorResponse(
			400,
			'invalid_grant',
			'Authorization code is bound to a different client authentication method; reauthorize'
		);
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
			issueRefresh: shouldIssueRefresh(client, record.scope, mcpConfig),
			clientAuthMethod,
		},
		hookManager,
		logger
	);
}

async function handleRefreshTokenGrant(
	request: Request | undefined,
	body: any,
	client: MCPClientRecord,
	clientAuthMethod: ClientAuthMethod,
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
		// hash mismatch NEVER reissues, and a failed write still answers
		// invalid_grant. Only a persisted revocation is claimed, in the response
		// and in this handler's log line. After a failed write the handler logs
		// one fixed line naming the failure, without the error text or the token
		// (the store's own write-error log still carries the error), and the
		// family stays live until a later presentation retires or revokes it, or
		// it expires.
		try {
			await familyStore.revoke(family.family_id);
		} catch {
			logger?.error?.(REVOCATION_NOT_PERSISTED_LOG);
			return errorResponse(400, 'invalid_grant', 'Refresh token has been superseded');
		}
		logger?.warn?.(`MCP token: refresh replay detected; revoked family ${family.family_id}`);
		return errorResponse(400, 'invalid_grant', 'Refresh token has been superseded; family revoked');
	}

	// Defense in depth (#229): a family minted before provenance stamping is
	// retired the first time it is presented for refresh, rather than rotated.
	// Lazy, per-family — no startup sweep. Provenance lives in the family id
	// itself (see FAMILY_ID_PREFIX in refreshTokenStore.ts), which rotation
	// reuses (makeRefreshToken(family.family_id) below) and no `put` can
	// change — so mixed-version rollouts are safe: an old worker or node
	// rotating a family minted by this version leaves its id, and therefore
	// its provenance, unchanged. The remaining cost is that every family
	// minted before this upgrade (bare-UUID id) re-authorizes once at its
	// next refresh, and after a rollback only families minted while rolled
	// back re-authorize once after re-upgrading. The client re-authorizes
	// into a fresh, provenanced family per RFC 6749 §5.2.
	if (!isProvenancedFamilyId(family.family_id)) {
		let persisted = false;
		try {
			await familyStore.revoke(family.family_id);
			persisted = true;
		} catch (error) {
			logger?.error?.(
				`MCP token: failed to persist retirement for pre-provenance family ${family.family_id}:`,
				error instanceof Error ? error.message : String(error)
			);
		}
		// Only log/audit the retirement once it is actually persisted — an
		// unpersisted "retired" claim would misstate what the store holds, and
		// the legacy family stays live for a pre-upgrade node to rotate. The
		// response is invalid_grant regardless; the next presentation retries
		// the retirement (and, if it persists, the log/audit). The catch above
		// already records the failure case.
		if (persisted) {
			logger?.warn?.(`MCP token: rejected refresh for pre-provenance family ${family.family_id}; retired`);
			emitMCPAuditEvent({
				event: 'oauth.mcp.token.retired',
				client_id: family.client_id,
				sub: family.user,
				aud: family.resource,
				scope: family.scope,
				family_id: family.family_id,
				reason: 'pre_provenance',
				timestamp: new Date().toISOString(),
			});
		}
		return errorResponse(
			400,
			'invalid_grant',
			'Refresh token family predates provenance tracking; reauthorize to continue'
		);
	}

	// Client-authentication binding, checked before rotation: the refresh must
	// use exactly the method bound to the family. A bound (`p2-`) family
	// without its binding was rewritten by an older writer and is rejected.
	// A legacy (`p1-`) family was issued when CIMD clients authenticated as
	// public clients and stored clients by their registered method, so that
	// is its binding. Any mismatch fails closed and requires reauthorization.
	let boundMethod: string | undefined;
	if (isBoundFamilyId(family.family_id)) {
		boundMethod = family.client_auth_method;
		if (!isClientAuthMethod(boundMethod)) {
			return errorResponse(
				400,
				'invalid_grant',
				'Refresh token family has no client authentication binding; reauthorize'
			);
		}
	} else {
		boundMethod = client._cimd ? 'none' : (client.token_endpoint_auth_method ?? 'none');
	}
	if (boundMethod !== clientAuthMethod) {
		return errorResponse(
			400,
			'invalid_grant',
			'Refresh token is bound to a different client authentication method; reauthorize'
		);
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

	// Rotate only once the new access token is in hand. Only the hash is
	// written, so a revocation committed meanwhile by a concurrent request
	// stays in force.
	const { token: newRefreshToken, hash: newHash } = makeRefreshToken(family.family_id);
	await familyStore.rotate(family.family_id, newHash);

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
	// Cap the client_id length before it becomes a rate-limiter map key
	// (attacker-chosen, retained up to maxKeys entries) — same defense-in-depth
	// family as the repo's request-path and assertion-length caps. 2048 covers
	// any legitimate CIMD URL or DCR id.
	if (clientId.length > MAX_CLIENT_ID_LENGTH) {
		return errorResponse(400, 'invalid_request', 'client_id exceeds the maximum length');
	}
	if (assertionType !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
		return errorResponse(400, 'invalid_request', `client_assertion_type must be ${CLIENT_ASSERTION_TYPE_JWT_BEARER}`);
	}
	if (!assertion) {
		return errorResponse(400, 'invalid_request', 'client_assertion is required');
	}
	if (assertion.length > MAX_ASSERTION_LENGTH) {
		return errorResponse(401, 'invalid_client', ASSERTION_TOO_LONG);
	}
	// Proof of key possession is the ONLY accepted authentication for this
	// grant — a Basic header or client_secret must not ride along (#159 req 6:
	// no credential type may substitute for the private key). Scheme match is
	// case-insensitive per RFC 9110 §11.1.
	if (
		/^basic\s/i.test(getRequestHeader(request?.headers, 'authorization') ?? '') ||
		typeof body?.client_secret === 'string'
	) {
		return errorResponse(
			400,
			'invalid_request',
			'client_credentials accepts only a client_assertion (no secret or Basic auth)'
		);
	}

	let client: MCPClientRecord | null;
	try {
		client = await resolveClient(clientId, mcpConfig, logger);
	} catch (err) {
		if (err instanceof CimdClientError) {
			return cimdErrorResponse(err);
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
	// EdDSA with inline keys; the issuer is accepted, and the token-endpoint
	// URL too unless clientCredentials.acceptTokenEndpointAudience is false.
	const policy = headlessAssertionPolicy(mcpConfig, issuer, tokenEndpointUrl(issuer));
	const result = verifyClientAssertion({
		assertion,
		clientId,
		audiences: policy.audiences,
		jwks: keys,
		allowedAlgorithms: policy.algorithms,
		maxExpiresInSeconds: policy.maxLifetimeSeconds,
	});
	if (!result.valid) {
		logger?.warn?.(`MCP token: client_assertion rejected for ${clientId}: ${result.reason}`);
		return errorResponse(401, 'invalid_client', `client_assertion verification failed: ${result.reason}`);
	}

	// Issuance rate limit (#163, #159 req 5): applied AFTER proof-of-possession,
	// keyed by the now-verified client_id. Running it pre-auth would let any
	// caller drain a real agent's quota by replaying the agent's PUBLIC CIMD
	// client_id URL with a bogus assertion (429 the victim before its valid
	// assertion is even checked). Pre-auth work is bounded elsewhere: CIMD
	// fetches by the per-URL fetch limiter + resolution/DNS concurrency caps,
	// signature verification by Node's request concurrency (no I/O, no jti burn).
	const ratePerMinute = resolveRateLimit(mcpConfig.clientCredentials?.rateLimit);
	if (ratePerMinute !== false) {
		const limit = getGrantLimiter(ratePerMinute).tryTake(clientId);
		if (!limit.allowed) {
			const response = errorResponse(429, 'slow_down', 'Token issuance rate limit reached for this client');
			response.headers = { ...response.headers, 'Retry-After': String(limit.retryAfterSeconds) };
			return response;
		}
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
	// Single use holds per node; see assertionJtiStore.ts.
	const fresh = await new MCPAssertionJtiStore(logger).checkAndRecord(clientId, result.claims.jti, result.claims.exp);
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
	const response = await dispatchToken(request, body, mcpConfig, hookManager, logger);
	if (response.status === 401 && /^\s*basic(\s|$)/i.test(getRequestHeader(request?.headers, 'authorization') ?? '')) {
		response.headers = { ...response.headers, 'WWW-Authenticate': BASIC_CHALLENGE };
	}
	return response;
}

async function dispatchToken(
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
			return await handleAuthorizationCodeGrant(
				request,
				body,
				auth.client,
				auth.method,
				mcpConfig,
				hookManager,
				logger
			);
		}
		return await handleRefreshTokenGrant(request, body, auth.client, auth.method, mcpConfig, hookManager, logger);
	} catch (error) {
		logger?.error?.(
			'MCP token: unexpected error during token issuance:',
			error instanceof Error ? error.message : String(error)
		);
		return errorResponse(500, 'server_error', 'An unexpected error occurred during token issuance');
	}
}
