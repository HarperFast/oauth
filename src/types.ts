/**
 * OAuth Plugin Type Definitions
 */

import type { IncomingMessage } from 'node:http';
import type { Scope, User, RequestTarget } from 'harper';

// ============================================================================
// OAuth Plugin Types
// ============================================================================

/**
 * OAuth Plugin Configuration
 * Runtime configuration for the OAuth plugin
 */
export interface OAuthPluginConfig {
	/** Enable debug mode to expose additional endpoints and information (can be boolean or string from env var) */
	debug?: boolean | string;
	/** OAuth provider configurations */
	providers?: Record<string, any>;
	/** Default redirect URI for all providers */
	redirectUri?: string;
	/** Default post-login redirect path */
	postLoginRedirect?: string;
	/** Default OAuth scopes */
	scope?: string;
	/** Default username claim path */
	usernameClaim?: string;
	/** Default role assignment */
	defaultRole?: string;
	/** Lifecycle hooks */
	hooks?: OAuthHooks;
	/** Cache providers resolved via onResolveProvider hook. true = forever, false = never, number = TTL in seconds. Default: 300s (bounded, so disabled/rotated providers stop being served without a restart). */
	cacheDynamicProviders?: boolean | number;
	/** MCP OAuth flow configuration (RFC 9728 PRM, RFC 7591 DCR, RFC 8707 audience binding) */
	mcp?: MCPConfig;
}

// ============================================================================
// MCP OAuth Types (RFCs 7591, 8707, 9728; MCP authorization spec 2025-06-18)
// ============================================================================

/**
 * MCP OAuth Configuration
 *
 * Opt-in configuration for serving the MCP authorization-server flow alongside
 * the existing human-OAuth (relying party) flow.
 */
export interface MCPConfig {
	/** Master switch for MCP OAuth endpoints */
	enabled?: boolean;
	/**
	 * Canonical resource URI advertised in PRM and validated as the `aud` claim
	 * on issued tokens (RFC 8707). Defaults to `<request-origin>/mcp` when unset.
	 */
	resource?: string;
	/**
	 * Authorization-server issuer URI advertised in AS metadata. Defaults to
	 * the request origin (scheme + host) when unset.
	 */
	issuer?: string;
	/**
	 * Subset of upstream providers eligible to complete the MCP auth flow.
	 * v1 requires exactly one effective provider — if the list (or, when
	 * unset, the full provider registry) resolves to 0 or >1 candidates,
	 * /oauth/mcp/authorize returns a configuration error. Multi-provider
	 * chooser UI is v1.1.
	 */
	providers?: string[];
	/**
	 * Dynamic Client Registration settings (RFC 7591). PRESENCE of this block
	 * enables the /oauth/mcp/register endpoint; omitting it entirely leaves DCR
	 * disabled (the endpoint 404s and metadata omits `registration_endpoint`).
	 * Before #182 an absent block meant open, ungated registration.
	 */
	dynamicClientRegistration?: MCPDynamicClientRegistrationConfig;
	/**
	 * JWT signing algorithm for generated access-token signing keys: "RS256"
	 * (default, universally interoperable) or "ES256" (EC P-256). Changing this
	 * on a running deployment rotates in a new key under the new algorithm
	 * (once the current key is at least 5 minutes old — an age floor that
	 * keeps nodes with briefly-disagreeing configs during a rolling rollout
	 * from rotating against each other; prefer updating all nodes together);
	 * previous keys stay in the JWKS until retired, so outstanding tokens keep
	 * verifying. Ignored when `signingKeyPem` is set — a pinned key's algorithm
	 * is derived from its key material. EdDSA is not supported (jsonwebtoken
	 * cannot emit it; see #127). Default: "RS256".
	 */
	signingAlgorithm?: 'RS256' | 'ES256';
	/**
	 * PEM-encoded private key (PKCS#8; RSA or EC P-256) to sign access tokens
	 * with — the signing algorithm is derived from the key type. When
	 * set, it is persisted to the keys table on first use instead of generating
	 * one — operators provide the same key on every node for deterministic,
	 * race-free key material. When unset, a keypair is generated on first boot.
	 *
	 * Mutually exclusive with `keyRotationInterval`: pin wins; if both are set a
	 * warning is logged and rotation is skipped.
	 */
	signingKeyPem?: string;
	/**
	 * Signing-key rotation interval in seconds. When set and > 0, a new
	 * keypair is lazily generated (at token mint time) whenever the newest key's
	 * age exceeds this value. All public keys remain in the JWKS until their
	 * access tokens can no longer be valid (2× accessTokenTtl after a newer key
	 * supersedes them). Default: 0 (rotation disabled).
	 *
	 * Mutually exclusive with `signingKeyPem`: pin wins. If both are set a
	 * warning is logged at startup and rotation is silently skipped.
	 */
	keyRotationInterval?: number;
	/** Access-token lifetime in seconds. Default: 3600 (1h). */
	accessTokenTtl?: number;
	/** Refresh-token (family) lifetime in seconds. Default: 2592000 (30d). */
	refreshTokenTtl?: number;
	/**
	 * When true, the authorization_code exchange only issues a refresh token
	 * when the granted scope includes `offline_access` (the SEP-2207
	 * OIDC-flavored opt-in). Default: false — any client whose registered
	 * grant_types include refresh_token receives one, since most MCP clients
	 * never request offline_access and withholding refresh tokens would force
	 * re-auth every accessTokenTtl. Flipping this on does not revoke existing
	 * refresh-token families.
	 */
	refreshTokenRequiresOfflineAccess?: boolean;
	/**
	 * Client ID Metadata Document (CIMD) resolution settings.
	 * CIMD is enabled by default when `mcp.enabled: true`. Override here
	 * to opt out or restrict which hosts may be used as CIMD client_ids.
	 */
	clientIdMetadataDocuments?: MCPClientIdMetadataDocumentsConfig;
	/**
	 * RFC 7523 client_credentials grant for headless agents (#159/#162).
	 * Explicit opt-in — disabled unless `enabled: true`, and requires a
	 * non-empty `clientIdMetadataDocuments.allowedHosts` allowlist (enforced
	 * at startup): hosting a reachable metadata document must never suffice
	 * to mint tokens.
	 */
	clientCredentials?: MCPClientCredentialsConfig;
}

/** Configuration for the RFC 7523 client_credentials grant (#162). */
export interface MCPClientCredentialsConfig {
	/** Enable the grant. Default: false (explicit opt-in). */
	enabled?: boolean;
	/**
	 * Access-token lifetime in seconds for this grant. Default: 300 (5 min) —
	 * agents re-mint on 401; no refresh token is ever issued.
	 */
	accessTokenTtl?: number;
	/**
	 * Issuance rate limit in requests/minute per client_id (per node — see
	 * rateLimit.ts). Default: 30. `false` or `0` disables the limiter;
	 * non-finite/non-positive values fall back to the default. Over-limit
	 * requests get 429 + `error: "slow_down"` + `Retry-After`.
	 */
	rateLimit?: number | false;
}

/**
 * Dynamic Client Registration configuration (RFC 7591)
 *
 * Defaults to enabled because Claude Desktop, Cursor, and mcp-remote all
 * register at runtime with no pre-baked client_id. Restricting registration
 * is opt-in via initialAccessToken or allowedRedirectUriHosts.
 */
export interface MCPDynamicClientRegistrationConfig {
	/**
	 * Enable the /register endpoint. Default when this block is present: true.
	 * (DCR as a whole is enabled by the presence of the block — see
	 * `MCPConfig.dynamicClientRegistration`; `enabled: false` disables it while
	 * keeping the block around.)
	 */
	enabled?: boolean;
	/**
	 * If set, registration requests must present `Authorization: Bearer <token>`
	 * matching this value. Default: open registration per RFC 7591 — a
	 * once-per-process warning is logged when DCR runs ungated.
	 */
	initialAccessToken?: string;
	/**
	 * If set, redirect_uris hosts must match an entry in this list. localhost
	 * is always allowed for native clients per RFC 8252. Default: unrestricted.
	 */
	allowedRedirectUriHosts?: string[];
}

/**
 * MCP client metadata (RFC 7591 §2)
 *
 * Request body shape for POST /oauth/mcp/register. Fields with defaults are
 * optional in the request and populated by the registration handler.
 */
export interface MCPClientMetadata {
	/**
	 * Allowed redirect URIs (exact-match validated on /authorize). Required
	 * for redirect-based grants (enforced at registration/resolution);
	 * absent on client_credentials-only CIMD clients, which have no
	 * redirect surface (RFC 7591 §2 requires it only for redirect flows).
	 */
	redirect_uris?: string[];
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
	scope?: string;
	contacts?: string[];
	/** Default: ["authorization_code", "refresh_token"] */
	grant_types?: string[];
	/** Default: ["code"] */
	response_types?: string[];
	/** Default: "none" (public clients). Other values: "client_secret_basic", "client_secret_post". */
	token_endpoint_auth_method?: string;
	/** "web" (default) or "native" */
	application_type?: string;
	software_id?: string;
	software_version?: string;
	/**
	 * Public Ed25519 JWK Set for private_key_jwt client authentication.
	 * Present only on client_credentials CIMD clients (#161); validated at
	 * resolution (OKP/Ed25519, public keys only, bounded count).
	 */
	jwks?: { keys: Record<string, unknown>[] };
}

/**
 * MCP client record as returned from /register and stored in the
 * harper_oauth_mcp_clients table.
 */
export interface MCPClientRecord extends MCPClientMetadata {
	/** Server-issued client identifier */
	client_id: string;
	/** Server-issued secret (only for confidential clients) */
	client_secret?: string;
	/** Unix timestamp (seconds) when the client was registered */
	client_id_issued_at: number;
	/** Unix timestamp (seconds) when client_secret expires; 0 = never */
	client_secret_expires_at?: number;
	/**
	 * Set to true on records resolved from a Client ID Metadata Document
	 * (not persisted in Harper). Callers use this to decide whether to show
	 * the CIMD interstitial confirmation page.
	 * @internal
	 */
	_cimd?: boolean;
}

/**
 * Configuration for Client ID Metadata Document (CIMD) resolution.
 *
 * CIMD is enabled by default when `mcp.enabled: true`. Set `enabled: false`
 * to opt out; set `allowedHosts` to restrict which hosts may be used as
 * CIMD client_ids.
 */
export interface MCPClientIdMetadataDocumentsConfig {
	/**
	 * Enable CIMD resolution. Default: true when `mcp.enabled`.
	 * Set to false to accept only DCR-registered clients.
	 */
	enabled?: boolean;
	/**
	 * Allowlist of hostnames permitted as CIMD client_id URLs. When set,
	 * only these hosts (plus their HTTPS URLs with non-root paths) are
	 * resolved; all other URL client_ids are rejected with `invalid_client`.
	 * When unset, any externally reachable HTTPS host is accepted (subject
	 * to SSRF guards).
	 */
	allowedHosts?: string[];
	/** Fetch timeout in milliseconds. Default: 5000. */
	fetchTimeoutMs?: number;
	/** Maximum document size in bytes. Default: 65536 (64 KB). */
	maxDocumentBytes?: number;
}

/**
 * MCP authorization-request state carried through the upstream IdP round-trip.
 *
 * Stored inside the CSRF token (which the upstream provider echoes back as
 * `state`); the callback handler reads this back to determine whether to mint
 * an MCP authorization code (this object present) or fall through to the
 * standard human-session flow (this object absent).
 */
export interface MCPAuthorizeState {
	/** DCR client_id from /oauth/mcp/authorize */
	clientId: string;
	/** RFC 8707 canonical resource URI */
	resource: string;
	/** PKCE challenge (RFC 7636); verified at /oauth/mcp/token */
	codeChallenge: string;
	/** PKCE method — only "S256" supported (OAuth 2.1 §7.5.2) */
	codeChallengeMethod: 'S256';
	/** Exact redirect_uri the MCP client wants the code delivered to */
	redirectUri: string;
	/** Requested scope, space-separated (may be empty) */
	scope?: string;
	/** Original `state` parameter from the MCP client; echoed verbatim on redirect */
	clientState?: string;
	/**
	 * CIMD consent browser binding: SHA-256 of the per-flow nonce cookie set with
	 * the consent interstitial. Present only on CIMD flows; /oauth/mcp/confirm and
	 * the upstream OAuth callback both require the caller's cookie to hash-match
	 * before proceeding (see lib/mcp/consentBinding.ts).
	 */
	browserNonceHash?: string;
	/**
	 * CIMD consent flow id: identifies which per-flow `__Host-` cookie carries
	 * this flow's nonce, so concurrent authorization flows in one browser don't
	 * collide. Paired with `browserNonceHash`.
	 */
	consentFlowId?: string;
}

/**
 * MCP authorization code record (table `mcp_auth_codes`, `expiration: 300`).
 *
 * One-time use: /oauth/mcp/token (Stage 4) reads-then-deletes.
 */
export interface MCPAuthCodeRecord {
	code: string;
	client_id: string;
	user: string;
	resource: string;
	code_challenge: string;
	code_challenge_method: string;
	redirect_uri: string;
	scope?: string;
}

/**
 * MCP JWT signing key record (table `harper_oauth_mcp_keys`).
 *
 * The private half never leaves the server; only the public half is published
 * at /.well-known/jwks.json. `kid` is surfaced in the JWT header so verifiers
 * can select the right key.
 */
export interface MCPSigningKeyRecord {
	kid: string;
	alg: string;
	public_key_pem: string;
	private_key_pem: string;
	created_at: number;
}

/**
 * Public-facing subset of MCPSigningKeyRecord returned by `getAllPublicKeys`.
 * The private key is stripped before JWKS publication and token verification
 * so private key material never escapes the key store's internal boundaries.
 */
export type MCPPublicKeyRecord = Omit<MCPSigningKeyRecord, 'private_key_pem'>;

/**
 * MCP refresh-token family record (table `mcp_refresh_families`).
 *
 * The opaque token issued to the client is `<family_id>.<secret>`; only the
 * SHA-256 hash of the full value is persisted (`current_token_hash`). Rotation
 * overwrites the hash; replay of a superseded token (hash mismatch) sets
 * `revoked`, which invalidates the whole family.
 */
export interface MCPRefreshFamilyRecord {
	family_id: string;
	current_token_hash: string;
	revoked: boolean;
	client_id: string;
	user: string;
	resource: string;
	scope?: string;
	expires_at: number;
}

/**
 * MCP client-assertion replay-guard record (table `mcp_assertion_jtis`,
 * `expiration: 120`).
 *
 * `id` is sha256(client_id, jti) — see assertionJtiStore.ts for the keying
 * and accepted-race notes. Rows only need to outlive the maximum assertion
 * window; the table TTL evicts them.
 */
export interface MCPAssertionJtiRecord {
	id: string;
	client_id: string;
	/** Harper-assigned (epoch ms) via @createdTime; never written by the app. */
	created_at?: number;
}

/**
 * Structured `onLogin` result — lets the hook control the login outcome (#174).
 *
 * Backward compatible: a hook may still return a plain object (session
 * enrichment, `user` override) or nothing at all — both behave as `ok`.
 * Only `status: 'denied'` and `status: 'needs_confirmation'` change behavior.
 */
export interface OnLoginResultOk {
	/**
	 * 'ok' (stripped before the session merge) — but typed as string because
	 * any value other than 'denied'/'needs_confirmation' keeps the legacy
	 * behavior: it is plain session data and the login proceeds.
	 */
	status?: string;
	/** Harper system username to bind the session (and MCP auth codes) to */
	user?: string;
	/** Additional keys are merged into the session (legacy enrich behavior) */
	[key: string]: any;
}

/**
 * Do NOT establish a session. The browser is sent to `redirect` when given,
 * otherwise to the standard error redirect with `error=access_denied`.
 */
export interface OnLoginResultDenied {
	status: 'denied';
	/**
	 * Short machine-readable reason, surfaced as the `reason` query param on
	 * the error redirect — and, in MCP flows, echoed verbatim to the MCP
	 * client as `error_description`. Use a terse code (e.g. 'not_provisioned'),
	 * never internal details.
	 */
	error?: string;
	/** Where to send the browser instead of the standard error redirect. May be an absolute http(s) URL. */
	redirect?: string;
}

/**
 * Do NOT establish a session yet — the user must complete a step first
 * (e.g. onboarding or confirmation). The browser is sent to `redirect`.
 */
export interface OnLoginResultNeedsConfirmation {
	status: 'needs_confirmation';
	/** Where to send the browser to complete the pending step. May be an absolute http(s) URL. */
	redirect: string;
}

export type OnLoginResult = OnLoginResultOk | OnLoginResultDenied | OnLoginResultNeedsConfirmation;

/**
 * OAuth Lifecycle Hooks
 * Callbacks invoked at key points in the OAuth flow
 */
export interface OAuthHooks {
	/**
	 * Resolve OAuth provider configuration dynamically
	 *
	 * Called when a provider is not found in the static registry.
	 * Allows applications to implement multi-tenant OAuth by
	 * returning provider configurations based on naming conventions.
	 *
	 * Example: Provider name "okta-org_abc123" can be parsed to load
	 * organization-specific Okta configuration from database.
	 *
	 * @param providerName - Provider name from URL path (e.g., "okta-org_abc123")
	 * @param logger - Optional logger instance
	 * @returns Provider configuration or null if not found
	 * @throws Error if resolution fails (returns 500 to client)
	 *
	 * Security Requirements:
	 * - MUST validate tenant ID format before database lookup
	 * - MUST validate domain safety (SSRF protection)
	 * - MUST validate provider-specific configuration
	 * - MUST NOT return configurations for disabled/inactive tenants
	 * - SHOULD log all resolution attempts for audit trail
	 *
	 * @example
	 * ```typescript
	 * onResolveProvider: async (providerName, logger) => {
	 *   // Parse provider name: "okta-org_abc123" → ["okta", "org_abc123"]
	 *   const match = providerName.match(/^(okta|azure|auth0)-(.+)$/);
	 *   if (!match) return null;
	 *
	 *   const [, provider, tenantId] = match;
	 *
	 *   // Validate tenant ID format
	 *   validateTenantId(tenantId);
	 *
	 *   // Query database for tenant config
	 *   const org = await Organization.get(tenantId, context);
	 *   if (!org?.oauthConfig?.enabled) return null;
	 *
	 *   // Build and return provider config
	 *   return buildProviderConfig(org.oauthConfig, provider);
	 * }
	 * ```
	 */
	onResolveProvider?: (providerName: string, logger?: Logger) => Promise<OAuthProviderConfig | null>;

	/**
	 * Called after successful OAuth login, before session is finalized
	 * Use this to provision users, assign roles, etc.
	 *
	 * The return value controls the login outcome (#174):
	 * - `{ status: 'ok', user, ...data }`, a plain object, or nothing —
	 *   establish the session (extra keys are merged into it)
	 * - `{ status: 'denied', error?, redirect? }` — do NOT establish a session;
	 *   the browser is sent to `redirect`, or to the standard error redirect
	 *   with `error=access_denied` (and `reason` from `error`)
	 * - `{ status: 'needs_confirmation', redirect }` — do NOT establish a
	 *   session yet; the browser is sent to `redirect` to finish a step first
	 *
	 * A THROWN error does not gate the login — it is caught and logged and the
	 * flow proceeds as if the hook returned nothing (hooks must not break the
	 * OAuth flow). Deliberate gating is expressed via the return value.
	 *
	 * @param oauthUser - The OAuth user information
	 * @param tokenResponse - The token response from the provider
	 * @param session - The current session object
	 * @param request - The HTTP request object
	 * @param provider - The provider name (e.g., 'github', 'google')
	 * @returns Login outcome, or data to merge into the session
	 */
	onLogin?: (
		oauthUser: OAuthUser,
		tokenResponse: TokenResponse,
		session: any,
		request: any,
		provider: string
	) => Promise<OnLoginResult | void>;

	/**
	 * Called before logout, before session is cleared
	 * Use this to clean up user-specific data
	 * @param session - The current session object
	 * @param request - The HTTP request object
	 */
	onLogout?: (session: any, request: any) => Promise<void>;

	/**
	 * Called after token refresh completes
	 * @param session - The updated session with new tokens
	 * @param refreshed - Whether tokens were actually refreshed
	 * @param request - The HTTP request object (may be undefined for background refresh)
	 */
	onTokenRefresh?: (session: any, refreshed: boolean, request?: any) => Promise<void>;

	/**
	 * Called after an MCP access or refresh token is minted, before the response
	 * is returned. Use for rate-limiting by client_id, usage attribution,
	 * pushing to a queue, etc.
	 *
	 * Failure is caught and logged — a throwing hook NEVER blocks token issuance
	 * (fire-and-forget contract).
	 *
	 * SECURITY: the `event` is sanitized — it carries only the `jti` (token
	 * identifier, safe to log), never the access/refresh token strings. The
	 * `request` is NOT sanitized: on the refresh path its body carries the
	 * refresh_token the client presented, so do not log `request` wholesale.
	 *
	 * @param event - Identifies the token issued: type, client_id, sub, aud, scope, jti
	 * @param request - The HTTP request that triggered issuance (typed as any for
	 *   Harper version independence). NOT sanitized — see SECURITY above.
	 */
	onMCPTokenIssued?: (
		event: {
			/** 'access' = authorization_code; 'client_credentials' = headless agent grant (sub is the client, not a user). */
			type: 'access' | 'refresh' | 'client_credentials';
			client_id: string;
			sub: string;
			aud: string;
			scope?: string;
			jti: string;
		},
		request: any
	) => Promise<void>;
}

/**
 * OAuth Provider Configuration
 * Configuration options for an OAuth 2.0/OIDC provider
 */
export interface OAuthProviderConfig {
	/** Provider identifier (e.g., 'github', 'google', 'azure') */
	provider: string;
	clientId: string;
	clientSecret: string;
	authorizationUrl: string;
	tokenUrl: string;
	userInfoUrl: string;
	redirectUri?: string;
	/** OAuth scopes to request (space-separated) */
	scope?: string;
	/** JWKS URI for ID token validation (OIDC only) */
	jwksUri?: string | null;
	/** Expected token issuer for validation (OIDC only) */
	issuer?: string | null;
	/** Claim to use as username (dot notation supported for nested) */
	usernameClaim?: string;
	/** Claim containing user's email address */
	emailClaim?: string;
	/** Claim containing user's display name */
	nameClaim?: string;
	/** Claim containing user's role/group membership */
	roleClaim?: string;
	/** Default role if not found in claims */
	defaultRole?: string;
	/** URL to redirect after successful login */
	postLoginRedirect?: string;
	/** Prefer ID token claims over userinfo endpoint (OIDC) */
	preferIdToken?: boolean;
	/** Whether to fetch email from provider's dedicated email endpoint */
	fetchEmail?: boolean;
	/** Additional query parameters for authorization URL */
	additionalParams?: Record<string, string>;
	/** Custom function to fetch/transform user info */
	getUserInfo?: (accessToken: string, helpers: GetUserInfoHelpers) => Promise<any>;
	/** Custom function to validate token (for non-expiring tokens like GitHub) */
	validateToken?: (accessToken: string, logger?: Logger) => Promise<boolean>;
	/** Interval for periodic token validation (ms) - only for tokens without expiration */
	tokenValidationInterval?: number;
	/** Provider-specific configuration function (e.g., for tenant/domain setup) */
	configure?: (param: string) => Partial<OAuthProviderConfig>;
}

/**
 * Helpers passed to custom getUserInfo function
 */
export interface GetUserInfoHelpers {
	/** Default getUserInfo implementation to call */
	getUserInfo: (accessToken: string) => Promise<any>;
	logger?: Logger;
}

/**
 * OAuth User Object
 * Represents a user authenticated via OAuth
 */
export interface OAuthUser {
	/** Username extracted from configured claim */
	username: string;
	role: string;
	/** OAuth provider name */
	provider: string;
	/** User ID from the OAuth provider */
	providerUserId?: string;
	email?: string;
	/**
	 * Whether the provider attests that `email` is verified. Normalized from
	 * the provider's boolean `email_verified` claim (OIDC providers; GitHub's
	 * /user/emails `verified` flag). `undefined` when the provider didn't say —
	 * gate on `emailVerified === true`, never on "not false".
	 */
	emailVerified?: boolean;
	name?: string;
	/** Additional provider-specific data */
	metadata?: Record<string, any>;
}

/**
 * OAuth Token Response
 * Standard OAuth 2.0 token endpoint response
 */
export interface TokenResponse {
	access_token: string;
	/** Usually 'Bearer' */
	token_type?: string;
	/** Token lifetime in seconds */
	expires_in?: number;
	refresh_token?: string;
	/** ID token for OIDC providers */
	id_token?: string;
	/** Space-separated granted scopes */
	scope?: string;
	/** Error code if token request failed (some providers return 200 with error) */
	error?: string;
	/** Human-readable error description */
	error_description?: string;
	/** URL to documentation about the error */
	error_uri?: string;
}

/**
 * CSRF Token Data
 * Metadata stored with CSRF tokens during OAuth flow
 */
export interface CSRFTokenData {
	/** Unix timestamp when token was created */
	timestamp: number;
	/** URL to redirect to after successful authentication */
	originalUrl?: string;
	/** Session ID to link OAuth flow with existing session */
	sessionId?: string;
	[key: string]: any;
}

/**
 * OAuth Provider Interface
 * Methods that OAuthProvider class implements
 */
export interface IOAuthProvider {
	config: OAuthProviderConfig;
	logger?: Logger;
	/** Generate CSRF token for OAuth state parameter */
	generateCSRFToken(metadata: Record<string, any>): Promise<string>;
	/** Verify and consume CSRF token (one-time use) */
	verifyCSRFToken(token: string): Promise<CSRFTokenData | null>;
	/** Build authorization URL with all required parameters */
	getAuthorizationUrl(state: string, redirectUri: string): string;
	/** Exchange authorization code for access/refresh tokens */
	exchangeCodeForToken(code: string, redirectUri: string): Promise<TokenResponse>;
	/** Fetch user information from provider */
	getUserInfo(accessToken: string, idTokenClaims?: any): Promise<any>;
	/** Map provider user info to Harper user format */
	mapUserToHarper(userInfo: any): OAuthUser;
	/** Verify and decode ID token (OIDC only) */
	verifyIdToken?(idToken: string): Promise<any>;
	/** Exchange refresh token for new access token */
	refreshAccessToken?(refreshToken: string): Promise<TokenResponse>;
}

/**
 * Provider Registry Entry
 * Stores initialized provider instance with its config
 */
export interface ProviderRegistryEntry {
	/** Initialized OAuth provider instance */
	provider: IOAuthProvider;
	config: OAuthProviderConfig;
}

/**
 * Provider Registry
 * Collection of all configured OAuth providers keyed by name
 */
export interface ProviderRegistry {
	[providerName: string]: ProviderRegistryEntry;
}

// ============================================================================
// Additional Harper Types
// These types are not exported by the harper package but are needed by the plugin
// ============================================================================

/**
 * Harper Table Instance
 * Methods available on a Harper table
 */
export interface Table {
	get(id: string): Promise<any>;
	put(record: any): Promise<any>;
	/**
	 * Insert-if-absent: creates the record, throwing a 409 `ClientError`
	 * ("Record already exists") when a record with the same primary key
	 * exists. NOTE: Harper currently enforces the existence check against the
	 * pre-staging snapshot only — concurrent creates can degrade to
	 * last-write-wins (HarperFast/harper#1745).
	 */
	create(record: any): Promise<any>;
	delete(id: string): Promise<void>;
	/**
	 * Enumerate records matching a query. An empty query (`{}`) returns all rows.
	 * The runtime table returns an `AsyncIterable`; consume with `for await`.
	 */
	search(query: Record<string, any>): AsyncIterable<any>;
}

/**
 * Logger Interface
 * Harper's logger interface for component logging
 */
export interface Logger {
	info?: (message: string, ...args: any[]) => void;
	error?: (message: string, ...args: any[]) => void;
	warn?: (message: string, ...args: any[]) => void;
	debug?: (message: string, ...args: any[]) => void;
}

/**
 * Harper HTTP Request
 * Extended Node.js IncomingMessage with Harper additions
 */
export interface Request extends IncomingMessage {
	/** Authenticated Harper user or username string */
	user?: User | string;
	session?: Session;
	headers: IncomingMessage['headers'];
	/** Client IP address */
	ip?: string;
	/**
	 * Request path (no query string). Harper populates this on the runtime
	 * request; it's declared here so middleware can read `request.pathname`
	 * without an `(request as any)` cast. (`url` — path + query — is inherited
	 * from `IncomingMessage`.)
	 */
	pathname?: string;
	/**
	 * Verified MCP access-token claims, populated by `withMCPAuth` after a
	 * successful Bearer validation. Absent when the request was not guarded by
	 * `withMCPAuth` or did not pass validation (those requests are rejected
	 * before the wrapped handler runs).
	 */
	mcp?: MCPRequestClaims;
}

/**
 * Verified MCP access-token claims attached to the request by `withMCPAuth`.
 * The app's MCP handler reads these to authorize per user/client.
 */
export interface MCPRequestClaims {
	/** Token subject — the end-user identifier (`sub`). */
	sub: string;
	/** OAuth client that obtained the token — the DCR `client_id`. */
	client_id: string;
	/** Audience (`aud`) — the canonical MCP resource URI the token was minted for. */
	aud: string;
	/** Space-separated granted scopes (`scope`), if any. */
	scope?: string;
}

/**
 * OAuth Session Metadata
 * Token and expiration data stored in session for automatic refresh
 */
export interface OAuthSessionMetadata {
	/**
	 * Provider configuration ID/key from config (e.g., 'my-custom-github', 'production-okta').
	 * @deprecated Use `providerConfigId` instead. This field is maintained for backwards compatibility only.
	 */
	provider: string;
	/** Provider configuration ID/key from config (e.g., 'my-custom-github', 'production-okta'). */
	providerConfigId: string;
	/** OAuth provider type (e.g., 'github', 'google', 'okta') */
	providerType: string;
	/** Current access token */
	accessToken: string;
	/** Refresh token for obtaining new access tokens */
	refreshToken?: string;
	/** Unix timestamp (ms) when the access token expires */
	expiresAt?: number;
	/** Unix timestamp (ms) when to proactively refresh (80% of lifetime) */
	refreshThreshold?: number;
	/** Space-separated list of granted scopes */
	scope?: string;
	/** Token type (usually 'Bearer') */
	tokenType?: string;
	/** Unix timestamp (ms) of last successful token refresh */
	lastRefreshed?: number;
	/** Unix timestamp (ms) of last token validation (for non-expiring tokens) */
	lastValidated?: number;
}

/**
 * Harper Session
 * Session data stored for authenticated users
 */
export interface Session {
	id?: string;
	/** Harper username (string) */
	user?: string;
	/** Full OAuth user object */
	oauthUser?: OAuthUser;
	/** OAuth session metadata for automatic token refresh */
	oauth?: OAuthSessionMetadata;
	/** Async session update method (when available) */
	update?: (data: Partial<Session>) => Promise<void>;
}

// Re-export Harper types for convenience
export type { Scope, User, RequestTarget };
