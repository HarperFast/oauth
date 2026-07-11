/**
 * MCP Authorization Endpoint (OAuth 2.1 + RFC 7636 PKCE + RFC 8707 audience)
 *
 * Handles GET /oauth/mcp/authorize. The MCP client navigates the user's
 * browser here with PKCE + resource params; this handler validates the
 * request, picks the configured upstream IdP, and 302-redirects the user
 * to the upstream provider's authorize URL.
 *
 * For CIMD-resolved clients the handler returns an interstitial HTML page
 * instead of immediately redirecting. The page shows the client_id host
 * (the authoritative CIMD identity), client_name, and redirect URI hostname
 * (with a loopback warning), and requires an explicit user confirmation via
 * POST /oauth/mcp/confirm. This satisfies the MCP auth spec requirement to
 * "clearly display the redirect URI hostname during authorization."
 *
 * The consent is bound to the user's browser via a nonce cookie whose hash
 * travels in the confirm token and upstream state; /confirm and the OAuth
 * callback both verify it (see consentBinding.ts). The page is served with
 * anti-framing headers — a framed consent page can be clickjacked.
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
import { CimdClientError, resolveClient } from './cimd.ts';
import { LOCAL_HOSTS } from './clientValidator.ts';
import {
	buildConsentCookie,
	consentNonceMatches,
	generateConsentFlowId,
	generateConsentNonce,
	hashConsentNonce,
	readConsentNonce,
} from './consentBinding.ts';
import { resolveIssuer, resolveResource } from './wellKnown.ts';

type ErrorJSON = {
	status: 400 | 500;
	body: { error: string; error_description?: string };
};

type Redirect = {
	status: 302;
	headers: { Location: string };
};

type HtmlResponse = {
	status: 200;
	headers: Record<string, string>;
	body: string;
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
	if (!LOCAL_HOSTS.has(requestedUrl.hostname)) return false;
	for (const candidate of registered) {
		let candidateUrl: URL;
		try {
			candidateUrl = new URL(candidate);
		} catch {
			continue;
		}
		if (
			LOCAL_HOSTS.has(candidateUrl.hostname) &&
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
	clientState: string | undefined,
	issuer: string
): Redirect {
	const url = new URL(redirectUri);
	url.searchParams.set('error', error);
	url.searchParams.set('error_description', description);
	if (clientState) url.searchParams.set('state', clientState);
	url.searchParams.set('iss', issuer);
	return { status: 302, headers: { Location: url.toString() } };
}

// RFC 7636 §4.2: code_challenge = 43*128unreserved; unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~".
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;

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
 * Escape HTML special characters. Used to safely embed client-supplied
 * strings (client_name, URIs) into the CIMD interstitial page. Every
 * client-controlled interpolation in `buildInterstitialPage` MUST go
 * through this function — client_name is attacker-controlled.
 */
export function escapeHtml(str: string): string {
	return str
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/**
 * Return true when the redirect URI is a loopback address (any form of
 * localhost, 127.0.0.1, or [::1]) — used to show the loopback warning.
 */
function isLoopbackRedirect(redirectUri: string): boolean {
	try {
		return LOCAL_HOSTS.has(new URL(redirectUri).hostname);
	} catch {
		return false;
	}
}

/**
 * Build the CIMD interstitial confirmation page.
 *
 * SECURITY: every client-supplied string is HTML-escaped via `escapeHtml`
 * before interpolation. client_name and URIs are attacker-controlled.
 */
export function buildInterstitialPage(
	client: MCPClientRecord,
	redirectUri: string,
	confirmToken: string,
	confirmPath: string
): string {
	const clientName = escapeHtml(client.client_name ?? client.client_id);
	// redirect_uri was validated upstream, but render defensively — an
	// unparseable value must degrade to escaped text, not a 500.
	let redirectHostname: string;
	try {
		redirectHostname = escapeHtml(new URL(redirectUri).hostname);
	} catch {
		redirectHostname = escapeHtml(redirectUri);
	}
	const loopback = isLoopbackRedirect(redirectUri);

	// The client_id host is the AUTHORITATIVE identity for a CIMD client —
	// it's the domain that served the metadata document. client_name and
	// client_uri are self-asserted inside that document, so the page must
	// anchor the user's decision on the client_id host (CIMD phishing
	// guidance) and label the rest as unverified.
	let clientIdHostname = '';
	try {
		clientIdHostname = escapeHtml(new URL(client.client_id).hostname);
	} catch {
		// Non-URL client_id — not a CIMD client; the section is omitted.
	}
	const clientIdSection = clientIdHostname ? `<p>Client identity: <strong>${clientIdHostname}</strong></p>` : '';

	let clientUriSection = '';
	if (client.client_uri) {
		try {
			const uriHost = escapeHtml(new URL(client.client_uri).hostname);
			clientUriSection = `<p class="meta">Claimed application domain (unverified): <strong>${uriHost}</strong></p>`;
		} catch {
			// Ignore malformed client_uri — it passed validation at resolve time.
		}
	}

	const loopbackWarning = loopback
		? `<div class="warning" role="alert">
			<strong>Warning:</strong> The redirect URI uses a loopback address
			(<code>${redirectHostname}</code>). Any local process on the same machine
			could potentially receive this authorization code.
		</div>`
		: '';

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — ${clientName}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.12);max-width:480px;width:100%;padding:2rem}
h1{font-size:1.25rem;margin-bottom:1rem;color:#111}
.client-name{color:#0057b7}
.info{margin:1rem 0;padding:1rem;background:#f8f8f8;border-radius:4px;border-left:4px solid #0057b7}
.info p{margin:.25rem 0;color:#333;font-size:.95rem}
.meta{margin:.5rem 0;color:#555;font-size:.9rem}
.warning{margin:1rem 0;padding:1rem;background:#fff3cd;border:1px solid #ffc107;border-radius:4px;font-size:.9rem;color:#856404}
.warning code{background:#ffeaa0;padding:0 .25rem;border-radius:2px}
button{margin-top:1.5rem;width:100%;padding:.75rem;background:#0057b7;color:#fff;border:none;border-radius:4px;font-size:1rem;font-weight:600;cursor:pointer}
button:hover{background:#004499}
</style>
</head>
<body>
<div class="card">
<h1>Sign in to <span class="client-name">${clientName}</span></h1>
<div class="info">
${clientIdSection}
<p>Redirect hostname: <strong>${redirectHostname}</strong></p>
${clientUriSection}
</div>
${loopbackWarning}
<form method="POST" action="${escapeHtml(confirmPath)}">
<input type="hidden" name="confirm_token" value="${escapeHtml(confirmToken)}">
<button type="submit">Continue to sign in</button>
</form>
</div>
</body>
</html>`;
}

/**
 * Redirect the user's browser to the upstream IdP to begin the OAuth dance.
 * Used by both `handleAuthorize` (direct flow for stored/DCR clients) and
 * `handleAuthorizeConfirm` (after the interstitial for CIMD clients).
 */
async function performUpstreamRedirect(
	request: Request,
	mcpState: MCPAuthorizeState,
	providers: ProviderRegistry,
	mcpConfig: MCPConfig,
	logger?: Logger
): Promise<ErrorJSON | Redirect> {
	const issuer = resolveIssuer(request as any, mcpConfig);
	const redirect = (error: string, description: string) =>
		buildClientErrorRedirect(mcpState.redirectUri, error, description, mcpState.clientState, issuer);

	const selection = selectMCPProvider(mcpConfig, providers);
	if ('error' in selection) {
		return redirect(selection.error, selection.description);
	}
	const providerEntry = providers[selection.providerName];
	const providerConfig: OAuthProviderConfig = providerEntry.config;

	let csrfToken: string;
	try {
		csrfToken = await providerEntry.provider.generateCSRFToken({
			providerName: selection.providerName,
			mcp: mcpState,
		});
	} catch (error) {
		logger?.error?.(
			'MCP authorize: failed to generate CSRF token:',
			error instanceof Error ? error.message : String(error)
		);
		return redirect('server_error', 'Failed to initialize upstream OAuth flow');
	}

	const upstreamAuthUrl = providerEntry.provider.getAuthorizationUrl(csrfToken, providerConfig.redirectUri || '');

	logger?.info?.(
		`MCP authorize: client=${mcpState.clientId} -> upstream=${selection.providerName}; bound resource=${mcpState.resource}`
	);

	return { status: 302, headers: { Location: upstreamAuthUrl } };
}

/**
 * Handle GET /oauth/mcp/authorize.
 *
 * Returns either a 302 redirect (success or post-validation error),
 * a 400 JSON response (pre-validation error), or a 200 HTML response
 * (CIMD interstitial page).
 */
export async function handleAuthorize(
	request: Request,
	target: RequestTarget,
	mcpConfig: MCPConfig,
	providers: ProviderRegistry,
	logger?: Logger
): Promise<ErrorJSON | Redirect | HtmlResponse> {
	const query = readQuery(target);

	// Phase 1: client_id and redirect_uri MUST validate before any redirect.
	if (!query.client_id) {
		return {
			status: 400,
			body: { error: 'invalid_request', error_description: 'client_id is required' },
		};
	}

	let client: MCPClientRecord | null;
	try {
		client = await resolveClient(query.client_id, mcpConfig, logger);
	} catch (error) {
		if (error instanceof CimdClientError) {
			return {
				status: 400,
				body: { error: error.oauthError, error_description: error.message },
			};
		}
		logger?.error?.('MCP authorize: client lookup failed:', error instanceof Error ? error.message : String(error));
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

	if (!query.redirect_uri || !redirectUriMatches(query.redirect_uri, client.redirect_uris ?? [])) {
		return {
			status: 400,
			body: {
				error: 'invalid_request',
				error_description: 'redirect_uri does not match a registered URI for this client',
			},
		};
	}

	const clientState = query.state;
	const issuer = resolveIssuer(request as any, mcpConfig);
	// Phase 2: everything else redirects to the verified client redirect_uri.
	const redirect = (error: string, description: string) =>
		buildClientErrorRedirect(query.redirect_uri as string, error, description, clientState, issuer);

	if (query.response_type !== 'code') {
		return redirect('unsupported_response_type', 'response_type must be "code"');
	}

	if (!query.code_challenge) {
		return redirect('invalid_request', 'code_challenge is required (PKCE)');
	}
	if (query.code_challenge_method !== 'S256') {
		return redirect('invalid_request', 'code_challenge_method must be "S256" (OAuth 2.1 forbids the plain method)');
	}
	if (!CODE_CHALLENGE_PATTERN.test(query.code_challenge)) {
		return redirect(
			'invalid_request',
			'code_challenge must be 43-128 characters from the unreserved set [A-Za-z0-9-._~] (RFC 7636)'
		);
	}

	if (!query.resource) {
		return redirect('invalid_target', 'resource is required (RFC 8707)');
	}
	const resourceErr = validateCanonicalResource(query.resource, mcpConfig, request);
	if (resourceErr) {
		return redirect('invalid_target', resourceErr);
	}

	const mcpState: MCPAuthorizeState = {
		clientId: query.client_id,
		resource: query.resource,
		codeChallenge: query.code_challenge,
		codeChallengeMethod: 'S256',
		redirectUri: query.redirect_uri,
		scope: query.scope,
		clientState,
	};

	// CIMD clients: show the interstitial confirmation page before redirecting.
	if (client._cimd) {
		// Select the provider now so we can generate a confirm token bound to it.
		const selection = selectMCPProvider(mcpConfig, providers);
		if ('error' in selection) {
			return redirect(selection.error, selection.description);
		}
		const providerEntry = providers[selection.providerName];

		// Browser binding: the per-flow nonce cookie set below must accompany both
		// the /confirm POST and the eventual upstream callback; only its hash is
		// stored server-side (see consentBinding.ts). The flow id names the cookie
		// so parallel authorization flows in one browser don't collide.
		const consentFlowId = generateConsentFlowId();
		const consentNonce = generateConsentNonce();

		let confirmToken: string;
		try {
			confirmToken = await providerEntry.provider.generateCSRFToken({
				providerName: selection.providerName,
				mcp: { ...mcpState, browserNonceHash: hashConsentNonce(consentNonce), consentFlowId },
				_confirm: true,
			});
		} catch (error) {
			logger?.error?.(
				'MCP authorize: failed to generate CIMD confirm token:',
				error instanceof Error ? error.message : String(error)
			);
			return redirect('server_error', 'Failed to initialize CIMD confirmation');
		}

		logger?.info?.(`MCP authorize: CIMD client=${query.client_id}; showing interstitial page`);

		const html = buildInterstitialPage(client, query.redirect_uri, confirmToken, '/oauth/mcp/confirm');
		return {
			status: 200,
			headers: {
				'Content-Type': 'text/html; charset=utf-8',
				// The consent page is the anti-phishing gate — it must not be
				// frameable (clickjacking the Continue button defeats it) and the
				// body carries a single-use confirm token, so it must not be cached.
				'X-Frame-Options': 'DENY',
				'Content-Security-Policy': "frame-ancestors 'none'",
				'Cache-Control': 'no-store',
				'Set-Cookie': buildConsentCookie(consentFlowId, consentNonce),
			},
			body: html,
		};
	}

	// Stored/DCR clients: redirect directly to the upstream IdP.
	return performUpstreamRedirect(request, mcpState, providers, mcpConfig, logger);
}

/**
 * Handle POST /oauth/mcp/confirm.
 *
 * Validates the one-time confirm token minted by `handleAuthorize` for CIMD
 * clients, then performs the upstream IdP redirect. The token binds the full
 * set of authorize params — redirect_uri, code_challenge, resource, scope,
 * client state — so they cannot be swapped after the interstitial is shown.
 *
 * Invalid/expired/reused tokens return 400 JSON (pre-validation failure —
 * never redirect to an unverified redirect_uri on an invalid token).
 */
export async function handleAuthorizeConfirm(
	request: Request,
	body: any,
	mcpConfig: MCPConfig,
	providers: ProviderRegistry,
	logger?: Logger
): Promise<ErrorJSON | Redirect> {
	const confirmToken = typeof body?.confirm_token === 'string' ? body.confirm_token : undefined;
	if (!confirmToken) {
		return { status: 400, body: { error: 'invalid_request', error_description: 'confirm_token is required' } };
	}

	// Determine the upstream provider (same selection logic as authorize).
	const selection = selectMCPProvider(mcpConfig, providers);
	if ('error' in selection) {
		return { status: 400, body: { error: selection.error, error_description: selection.description } };
	}
	const providerEntry = providers[selection.providerName];

	// Verify + consume the confirm token (one-time use).
	let state: Record<string, any>;
	try {
		const verified = await providerEntry.provider.verifyCSRFToken(confirmToken);
		if (!verified) {
			return {
				status: 400,
				body: { error: 'invalid_request', error_description: 'Confirm token is invalid or expired' },
			};
		}
		state = verified as Record<string, any>;
	} catch (error) {
		logger?.error?.(
			'MCP confirm: failed to verify confirm token:',
			error instanceof Error ? error.message : String(error)
		);
		return {
			status: 400,
			body: { error: 'invalid_request', error_description: 'Confirm token is invalid or expired' },
		};
	}

	// Guard: token must carry the _confirm marker (prevents a regular upstream
	// CSRF token from being replayed here).
	if (!state._confirm || !state.mcp) {
		return { status: 400, body: { error: 'invalid_request', error_description: 'Invalid confirm token payload' } };
	}

	const mcpState = state.mcp as MCPAuthorizeState;
	if (!mcpState.clientId || !mcpState.redirectUri || !mcpState.codeChallenge || !mcpState.resource) {
		return {
			status: 400,
			body: { error: 'invalid_request', error_description: 'Confirm token payload is incomplete' },
		};
	}

	// Browser binding: the confirm POST must come from the browser that was
	// served the interstitial (and its per-flow nonce cookie). Without this, the
	// malicious client itself could fetch and "confirm" the interstitial, then
	// hand the victim the resulting upstream URL — consent bypassed.
	if (
		!mcpState.browserNonceHash ||
		!consentNonceMatches(readConsentNonce(request, mcpState.consentFlowId), mcpState.browserNonceHash)
	) {
		logger?.warn?.(`MCP confirm: consent browser binding mismatch for client=${mcpState.clientId}`);
		return {
			status: 400,
			body: {
				error: 'invalid_request',
				error_description: 'Confirmation must come from the browser that started authorization (cookies are required)',
			},
		};
	}

	logger?.info?.(`MCP confirm: proceeding with CIMD authorization for client=${mcpState.clientId}`);

	return performUpstreamRedirect(request, mcpState, providers, mcpConfig, logger);
}
