/**
 * MCP Authorization Endpoint (OAuth 2.1 + RFC 7636 PKCE + RFC 8707 audience)
 *
 * Handles GET /oauth/mcp/authorize. The MCP client navigates the user's
 * browser here with PKCE + resource params; this handler validates the
 * request, picks the configured upstream IdP, and 302-redirects the user
 * to the upstream provider's authorize URL.
 *
 * The PKCE challenge and the MCP client's redirect_uri / state are
 * embedded in the CSRF token that the upstream provider echoes back.
 * `handleMCPCallback` (callback.ts) reads them out on the way back and
 * mints the actual authorization code.
 *
 * Two-phase validation per OAuth 2.1 §3.1.2.5:
 *   - Pre-redirect: client_id + redirect_uri must match a registered
 *     client. Failure → 400 JSON (can't safely redirect to unverified URI).
 *   - Post-redirect: every other validation error → 302 to client's
 *     verified redirect_uri with `?error=...&error_description=...`.
 */

import type { RequestTarget } from 'harper';
import type {
	Logger,
	MCPAuthorizeState,
	MCPClientRecord,
	MCPConfig,
	OAuthProviderConfig,
	ProviderRegistry,
	Request,
} from '../../types.ts';
import { MCPClientStore } from './clientStore.ts';
import { resolveResource } from './wellKnown.ts';

type ErrorJSON = {
	status: 400 | 500;
	body: { error: string; error_description?: string };
};

type Redirect = {
	status: 302;
	headers: { Location: string };
};

/**
 * Resolve which upstream provider an MCP authorize request flows through.
 * v1 requires the resolved set to be exactly one entry (multi-provider
 * chooser UI is v1.1).
 */
export function selectMCPProvider(
	mcpConfig: MCPConfig,
	providers: ProviderRegistry
): { providerName: string } | { error: string; description: string } {
	const allowed = mcpConfig.providers && mcpConfig.providers.length > 0 ? mcpConfig.providers : Object.keys(providers);
	const candidates = allowed.filter((name) => name in providers);

	if (candidates.length === 0) {
		return {
			error: 'server_error',
			description: 'No upstream OAuth provider configured for MCP authorization',
		};
	}
	if (candidates.length > 1) {
		return {
			error: 'server_error',
			description: 'Multiple upstream providers configured; v1 requires `mcp.providers` to resolve to exactly one',
		};
	}
	return { providerName: candidates[0] };
}

/**
 * Match a requested redirect_uri against a list of registered URIs.
 *
 * Exact string match in the general case, but RFC 8252 §7.3 requires
 * authorization servers to accept ANY port on loopback redirect URIs
 * (127.0.0.1 / [::1]) — native MCP clients like Claude Desktop and
 * mcp-remote bind to a dynamic port at runtime and can't pre-register
 * it. We treat `localhost` the same way; the RFC notes its use is "not
 * recommended" but is widespread in practice, and our DCR validation
 * already accepts it as a loopback equivalent (Stage 1).
 *
 * Two URIs match if they're identical, OR they both parse as URLs whose
 * host is in the loopback set AND scheme + pathname + search match.
 */
export function redirectUriMatches(requested: string, registered: string[]): boolean {
	if (registered.includes(requested)) return true;
	let requestedUrl: URL;
	try {
		requestedUrl = new URL(requested);
	} catch {
		return false;
	}
	const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', 'localhost']);
	if (!LOOPBACK_HOSTS.has(requestedUrl.hostname)) return false;
	for (const candidate of registered) {
		let candidateUrl: URL;
		try {
			candidateUrl = new URL(candidate);
		} catch {
			continue;
		}
		if (
			LOOPBACK_HOSTS.has(candidateUrl.hostname) &&
			requestedUrl.hostname === candidateUrl.hostname &&
			requestedUrl.protocol === candidateUrl.protocol &&
			requestedUrl.pathname === candidateUrl.pathname &&
			requestedUrl.search === candidateUrl.search
		) {
			return true;
		}
	}
	return false;
}

function validateCanonicalResource(resource: string, mcpConfig: MCPConfig, request: Request): string | null {
	try {
		const url = new URL(resource);
		if (url.hash) return 'resource must not contain a fragment';
	} catch {
		return 'resource is not a valid URI';
	}
	// Must match the configured canonical URI exactly. resolveResource derives
	// `<issuer>/mcp` when unset — handlers using request-derived defaults
	// inherit the same Host-header caveat documented in Stage 2.
	const expected = resolveResource(request, mcpConfig);
	if (resource !== expected) {
		return `resource does not match this server (expected ${expected})`;
	}
	return null;
}

function buildClientErrorRedirect(
	redirectUri: string,
	error: string,
	description: string,
	clientState: string | undefined
): Redirect {
	const url = new URL(redirectUri);
	url.searchParams.set('error', error);
	url.searchParams.set('error_description', description);
	if (clientState) url.searchParams.set('state', clientState);
	return { status: 302, headers: { Location: url.toString() } };
}

interface AuthorizeQuery {
	client_id?: string;
	redirect_uri?: string;
	response_type?: string;
	code_challenge?: string;
	code_challenge_method?: string;
	resource?: string;
	scope?: string;
	state?: string;
}

function readQuery(target: RequestTarget): AuthorizeQuery {
	return {
		client_id: target.get?.('client_id') ?? undefined,
		redirect_uri: target.get?.('redirect_uri') ?? undefined,
		response_type: target.get?.('response_type') ?? undefined,
		code_challenge: target.get?.('code_challenge') ?? undefined,
		code_challenge_method: target.get?.('code_challenge_method') ?? undefined,
		resource: target.get?.('resource') ?? undefined,
		scope: target.get?.('scope') ?? undefined,
		state: target.get?.('state') ?? undefined,
	};
}

/**
 * Handle GET /oauth/mcp/authorize.
 *
 * Returns either a 302 redirect (success: to upstream IdP; or post-validation
 * error: to client's redirect_uri with error params) or a 400 JSON response
 * (pre-validation error: client_id / redirect_uri mismatch).
 */
export async function handleAuthorize(
	request: Request,
	target: RequestTarget,
	mcpConfig: MCPConfig,
	providers: ProviderRegistry,
	logger?: Logger
): Promise<ErrorJSON | Redirect> {
	const query = readQuery(target);

	// Phase 1: client_id and redirect_uri MUST validate before any redirect.
	if (!query.client_id) {
		return {
			status: 400,
			body: { error: 'invalid_request', error_description: 'client_id is required' },
		};
	}

	const clientStore = new MCPClientStore(logger);
	let client: MCPClientRecord | null;
	try {
		client = await clientStore.get(query.client_id);
	} catch (error) {
		logger?.error?.('MCP authorize: client lookup failed:', (error as Error).message);
		return {
			status: 500,
			body: { error: 'server_error', error_description: 'Client lookup failed' },
		};
	}

	if (!client) {
		return {
			status: 400,
			body: { error: 'invalid_client', error_description: 'Unknown client_id' },
		};
	}

	if (!query.redirect_uri || !redirectUriMatches(query.redirect_uri, client.redirect_uris)) {
		return {
			status: 400,
			body: {
				error: 'invalid_request',
				error_description: 'redirect_uri does not match a registered URI for this client',
			},
		};
	}

	const clientState = query.state;
	// Phase 2: everything else redirects to the verified client redirect_uri.
	const redirect = (error: string, description: string) =>
		buildClientErrorRedirect(query.redirect_uri as string, error, description, clientState);

	if (query.response_type !== 'code') {
		return redirect('unsupported_response_type', 'response_type must be "code"');
	}

	if (!query.code_challenge) {
		return redirect('invalid_request', 'code_challenge is required (PKCE)');
	}
	if (query.code_challenge_method !== 'S256') {
		return redirect('invalid_request', 'code_challenge_method must be "S256" (OAuth 2.1 forbids the plain method)');
	}

	if (!query.resource) {
		return redirect('invalid_target', 'resource is required (RFC 8707)');
	}
	const resourceErr = validateCanonicalResource(query.resource, mcpConfig, request);
	if (resourceErr) {
		return redirect('invalid_target', resourceErr);
	}

	// Resolve the upstream provider that will handle the user-facing OAuth.
	const selection = selectMCPProvider(mcpConfig, providers);
	if ('error' in selection) {
		return redirect(selection.error, selection.description);
	}
	const providerEntry = providers[selection.providerName];
	const providerConfig: OAuthProviderConfig = providerEntry.config;

	// Build the state object the callback handler will pick up to mint the
	// MCP auth code (instead of running the human-session flow).
	const mcpState: MCPAuthorizeState = {
		clientId: query.client_id,
		resource: query.resource,
		codeChallenge: query.code_challenge,
		codeChallengeMethod: 'S256',
		redirectUri: query.redirect_uri,
		scope: query.scope,
		clientState,
	};

	let csrfToken: string;
	try {
		csrfToken = await providerEntry.provider.generateCSRFToken({
			// providerName binds the state to THIS upstream provider so a callback
			// arriving on a different provider's URL is rejected (existing CSRF
			// invariant from handleCallback).
			providerName: selection.providerName,
			mcp: mcpState,
		});
	} catch (error) {
		logger?.error?.('MCP authorize: failed to generate CSRF token:', (error as Error).message);
		return redirect('server_error', 'Failed to initialize upstream OAuth flow');
	}

	const upstreamAuthUrl = providerEntry.provider.getAuthorizationUrl(csrfToken, providerConfig.redirectUri || '');

	logger?.info?.(
		`MCP authorize: client=${query.client_id} -> upstream=${selection.providerName}; bound resource=${query.resource}`
	);

	return { status: 302, headers: { Location: upstreamAuthUrl } };
}
