/**
 * Token-endpoint client authentication methods: what the server advertises,
 * and which single method it permits for a given client.
 *
 * "The client presents; the server permits." A client picks a method from the
 * intersection of its declared methods and the server's advertised ones
 * (OpenAI's documented behaviour; MCP SEP-3149, a draft). The server
 * independently computes the one method it permits for that client and
 * rejects any other presentation. One permitted method per client is this
 * implementation's policy, following OAuth 2.1 §2.1 ("A single client_id
 * SHOULD NOT be treated as more than one type of client").
 *
 * Selection for an interactive CIMD client:
 * - declared methods: `token_endpoint_auth_methods_supported` when present,
 *   else `[token_endpoint_auth_method]`, else `["none"]` (a provisional
 *   default for documents declaring neither);
 * - intersection = declared ∩ advertised ∩ permitted-for-this-client, where
 *   `private_key_jwt` is permitted only when the client's keys are usable
 *   (inline `jwks`, or a `jwks_uri` allowed by the location policy) and its
 *   `token_endpoint_auth_signing_alg`, when pinned, is supported;
 * - the singular preference if it is in the intersection; otherwise the sole
 *   member; otherwise `private_key_jwt` when it is a member (the policy
 *   prefers it); otherwise the client is refused;
 * - a client that prefers `private_key_jwt`, which this server advertises,
 *   but whose keys are unusable is refused rather than resolved to `none`
 *   (no silent downgrade).
 *
 * Advertisement: `private_key_jwt` is advertised when the client_credentials
 * grant is enabled (headless agents; EdDSA) or when
 * `clientIdMetadataDocuments.privateKeyJwt.enabled` is set (interactive
 * clients; RS256, ES256, EdDSA). With neither, interactive CIMD clients
 * resolve to `none`.
 */

import type { MCPClientRecord, MCPConfig } from '../../types.ts';
import { ASSERTION_ALGORITHMS, type AcceptedAudience, type AssertionAlgorithm } from './clientAssertion.ts';
import { isJwksUriOnClientOrigin, jwksUriIssue } from './clientKeySet.ts';

export type ClientAuthMethod = 'none' | 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt';

const CLIENT_AUTH_METHODS: readonly ClientAuthMethod[] = [
	'none',
	'client_secret_basic',
	'client_secret_post',
	'private_key_jwt',
];

/** Signature algorithms an interactive CIMD client may use (narrowed by its document's pin). */
export const INTERACTIVE_ASSERTION_ALGORITHMS: readonly AssertionAlgorithm[] = ['RS256', 'ES256', 'EdDSA'];
/** Signature algorithms the headless client_credentials path accepts. */
export const HEADLESS_ASSERTION_ALGORITHMS: readonly AssertionAlgorithm[] = ['EdDSA'];

export function isClientAuthMethod(value: unknown): value is ClientAuthMethod {
	return typeof value === 'string' && (CLIENT_AUTH_METHODS as readonly string[]).includes(value);
}

/** Is interactive `private_key_jwt` switched on by configuration (the metadata change)? */
export function interactivePrivateKeyJwtEnabled(mcpConfig: MCPConfig | undefined): boolean {
	return mcpConfig?.clientIdMetadataDocuments?.privateKeyJwt?.enabled === true;
}

/**
 * RFC 8414 `token_endpoint_auth_methods_supported`: every method the token
 * endpoint verifies across registration mechanisms.
 */
export function advertisedTokenEndpointAuthMethods(mcpConfig: MCPConfig | undefined): ClientAuthMethod[] {
	const methods: ClientAuthMethod[] = ['none', 'client_secret_basic', 'client_secret_post'];
	if (mcpConfig?.clientCredentials?.enabled === true || interactivePrivateKeyJwtEnabled(mcpConfig)) {
		methods.push('private_key_jwt');
	}
	return methods;
}

/**
 * RFC 8414 `token_endpoint_auth_signing_alg_values_supported`, present only
 * when `private_key_jwt` is advertised. Without the interactive setting it
 * stays EdDSA (the headless path), as before.
 */
export function advertisedAssertionSigningAlgorithms(
	mcpConfig: MCPConfig | undefined
): AssertionAlgorithm[] | undefined {
	if (interactivePrivateKeyJwtEnabled(mcpConfig)) return [...INTERACTIVE_ASSERTION_ALGORITHMS];
	if (mcpConfig?.clientCredentials?.enabled === true) return [...HEADLESS_ASSERTION_ALGORITHMS];
	return undefined;
}

/** Is this a headless (client_credentials) CIMD record? */
export function isHeadlessCimdClient(client: MCPClientRecord): boolean {
	return client._cimd === true && (client.grant_types ?? []).includes('client_credentials');
}

/** Is this an interactive (redirect-based) CIMD record? */
export function isInteractiveCimdClient(client: MCPClientRecord): boolean {
	return client._cimd === true && !isHeadlessCimdClient(client);
}

/** Algorithms an interactive CIMD client may sign with: its document's pin, else every interactive algorithm. */
export function interactiveAllowedAlgorithms(client: MCPClientRecord): AssertionAlgorithm[] {
	const pinned = client._cimdAuth?.signingAlg;
	return pinned ? [pinned] : [...INTERACTIVE_ASSERTION_ALGORITHMS];
}

/**
 * Why an interactive CIMD client's `private_key_jwt` keys are unusable under
 * the current configuration, or null when they are usable.
 */
export function interactiveKeyIssue(client: MCPClientRecord, mcpConfig: MCPConfig | undefined): string | null {
	const auth = client._cimdAuth;
	if (!auth) return 'client has no authentication declaration';
	if (auth.signingAlgIssue) return auth.signingAlgIssue;
	if (auth.keyIssue) return auth.keyIssue;
	if (client.jwks_uri !== undefined) {
		const allowedOrigins = mcpConfig?.clientIdMetadataDocuments?.privateKeyJwt?.jwksUriAllowedOrigins ?? [];
		return jwksUriIssue(client.jwks_uri, client.client_id, allowedOrigins);
	}
	if (client.jwks?.keys?.length) return null;
	return 'client declares neither jwks nor jwks_uri';
}

export type PermittedAuthMethod = { method: ClientAuthMethod } | { error: string };

function selectInteractiveMethod(client: MCPClientRecord, mcpConfig: MCPConfig | undefined): PermittedAuthMethod {
	const auth = client._cimdAuth;
	if (!auth) return { error: 'client has no authentication declaration' };
	const advertised = new Set<string>(advertisedTokenEndpointAuthMethods(mcpConfig));
	const keyIssue = interactiveKeyIssue(client, mcpConfig);
	const permitted = new Set<string>(keyIssue ? ['none'] : ['none', 'private_key_jwt']);
	const intersection = [...new Set(auth.declared)].filter(
		(method): method is ClientAuthMethod =>
			advertised.has(method) && permitted.has(method) && isClientAuthMethod(method)
	);

	if (auth.preferred && (intersection as string[]).includes(auth.preferred)) {
		return { method: auth.preferred as ClientAuthMethod };
	}
	// No silent downgrade: a client that prefers private_key_jwt, which this
	// server advertises, will present an assertion; resolving it to `none`
	// would only defer the failure.
	if (auth.preferred === 'private_key_jwt' && advertised.has('private_key_jwt') && keyIssue) {
		return { error: `client prefers private_key_jwt but its keys are unusable: ${keyIssue}` };
	}
	if (intersection.length === 1) return { method: intersection[0] };
	if (intersection.includes('private_key_jwt')) return { method: 'private_key_jwt' };
	return {
		error: 'no token endpoint authentication method is both declared by the client and supported for it by this server',
	};
}

/**
 * The one token-endpoint authentication method this server permits for
 * `client` under the current configuration.
 */
export function permittedAuthMethod(client: MCPClientRecord, mcpConfig: MCPConfig | undefined): PermittedAuthMethod {
	if (isHeadlessCimdClient(client)) return { method: 'private_key_jwt' };
	if (isInteractiveCimdClient(client)) return selectInteractiveMethod(client, mcpConfig);
	// Stored (DCR) clients: their registered method.
	const stored = client.token_endpoint_auth_method ?? 'none';
	if (!isClientAuthMethod(stored)) return { error: 'client has an unsupported token endpoint auth method' };
	return { method: stored };
}

/** The algorithms `private_key_jwt` accepts, ever (for validation of pins). */
export function isAssertionAlgorithm(value: unknown): value is AssertionAlgorithm {
	return typeof value === 'string' && (ASSERTION_ALGORITHMS as readonly string[]).includes(value);
}

// --- Assertion policy per client shape -------------------------------------

/** Longest accepted interactive assertion lifetime (`exp` − now and `exp` − `iat`). */
export const INTERACTIVE_MAX_ASSERTION_LIFETIME_SECONDS = 300;
/** Longest accepted headless (client_credentials) assertion lifetime. */
export const HEADLESS_MAX_ASSERTION_LIFETIME_SECONDS = 60;

/** What a client's assertion may use: algorithms, audiences and lifetime. */
export interface AssertionPolicy {
	algorithms: AssertionAlgorithm[];
	audiences: AcceptedAudience[];
	maxLifetimeSeconds: number;
}

/**
 * Headless agents: EdDSA with inline keys; the issuer is accepted, and the
 * token-endpoint URL too until `clientCredentials.acceptTokenEndpointAudience`
 * is set false (existing signers move to the issuer first).
 */
export function headlessAssertionPolicy(
	mcpConfig: MCPConfig | undefined,
	issuer: string,
	tokenEndpoint: string
): AssertionPolicy {
	const audiences: AcceptedAudience[] = [{ value: issuer, form: 'issuer' }];
	if (mcpConfig?.clientCredentials?.acceptTokenEndpointAudience !== false) {
		audiences.push({ value: tokenEndpoint, form: 'token_endpoint' });
	}
	return {
		algorithms: [...HEADLESS_ASSERTION_ALGORITHMS],
		audiences,
		maxLifetimeSeconds: HEADLESS_MAX_ASSERTION_LIFETIME_SECONDS,
	};
}

/**
 * Does the opt-in token-endpoint audience exception apply to this client on
 * this request? Only for interactive CIMD clients whose independently
 * fetched and validated client ID is listed exactly, while the configured
 * expiry lies in the future, and only when the keys stay on that client ID's
 * own origin (inline `jwks`, or a same-origin `jwks_uri` — never one admitted
 * by the origin allowlist). Eligibility never comes from an unverified claim.
 */
export function tokenEndpointAudienceExceptionApplies(
	client: MCPClientRecord,
	mcpConfig: MCPConfig | undefined,
	nowMs: number = Date.now()
): boolean {
	const exception = mcpConfig?.clientIdMetadataDocuments?.privateKeyJwt?.tokenEndpointAudience;
	if (!exception || !isInteractiveCimdClient(client)) return false;
	const expiresAt = typeof exception.expiresAt === 'number' ? exception.expiresAt : Date.parse(exception.expiresAt);
	if (!Number.isFinite(expiresAt) || nowMs >= expiresAt) return false;
	if (!Array.isArray(exception.clientIds) || !exception.clientIds.includes(client.client_id)) return false;
	if (client.jwks_uri !== undefined && !isJwksUriOnClientOrigin(client.jwks_uri, client.client_id)) return false;
	return true;
}

/**
 * Interactive CIMD clients: RS256, ES256 or EdDSA narrowed by the document's
 * pin; the issuer as the sole audience (RFC 7523bis §4), plus the exact
 * advertised token-endpoint URL while the opt-in exception applies; a
 * 300-second lifetime cap.
 */
export function interactiveAssertionPolicy(
	client: MCPClientRecord,
	mcpConfig: MCPConfig | undefined,
	issuer: string,
	tokenEndpoint: string,
	nowMs: number = Date.now()
): AssertionPolicy {
	const audiences: AcceptedAudience[] = [{ value: issuer, form: 'issuer' }];
	if (tokenEndpointAudienceExceptionApplies(client, mcpConfig, nowMs)) {
		audiences.push({ value: tokenEndpoint, form: 'token_endpoint' });
	}
	return {
		algorithms: interactiveAllowedAlgorithms(client),
		audiences,
		maxLifetimeSeconds: INTERACTIVE_MAX_ASSERTION_LIFETIME_SECONDS,
	};
}
