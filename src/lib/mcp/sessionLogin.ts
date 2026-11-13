/**
 * MCP authorization through the host application's own Harper session (`mcp.sessionLogin`;
 * docs/mcp-oauth.md "Signing in with the application's session").
 */

import type { HookManager } from '../hookManager.ts';
import type { Logger, MCPAuthorizeState, MCPClientRecord, MCPConfig, Request } from '../../types.ts';
import { SESSION_LOGIN_RETURN_PLACEHOLDER } from '../config.ts';
import { readRawHeader } from '../requestHeaders.ts';
import {
	browserSecretMatches,
	buildBrowserSecretCookie,
	generateBrowserSecret,
	hashBrowserSecret,
	readBrowserSecret,
} from './consentBinding.ts';
import { handleMCPCallback } from './callback.ts';
import { escapeHtml, isLoopbackRedirect } from './authorize.ts';
import { resolveIssuer } from './wellKnown.ts';
import { issueSessionConsent, redeemSessionConsent, SESSION_CONSENT_TOKEN_PATTERN } from './sessionConsentStore.ts';

const AUTHORIZE_PATH = '/oauth/mcp/authorize';
const CONFIRM_PATH = '/oauth/mcp/confirm';
const MAX_RETURN_URL_LENGTH = 2048;

const PAGE_HEADERS = Object.freeze({
	'Content-Type': 'text/html; charset=utf-8',
	'X-Frame-Options': 'DENY',
	'Content-Security-Policy':
		"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
	'Cache-Control': 'no-store',
	'Referrer-Policy': 'no-referrer',
});

type Redirect = { status: 302; headers: Record<string, string> };
type Page = { status: 200; headers: Record<string, string>; body: string };
type ErrorJSON = {
	status: 400 | 500;
	headers: Record<string, string>;
	body: { error: string; error_description: string };
};

function errorJson(status: 400 | 500, error: string, description: string): ErrorJSON {
	return { status, headers: { 'Cache-Control': 'no-store' }, body: { error, error_description: description } };
}

function clientRedirect(
	request: Request,
	mcpConfig: MCPConfig,
	state: Pick<MCPAuthorizeState, 'redirectUri' | 'clientState'>,
	error: string,
	description?: string
): Redirect {
	const url = new URL(state.redirectUri);
	url.searchParams.set('error', error);
	if (description) url.searchParams.set('error_description', description);
	if (state.clientState) url.searchParams.set('state', state.clientState);
	url.searchParams.set('iss', resolveIssuer(request as any, mcpConfig));
	return { status: 302, headers: { 'Location': url.toString(), 'Cache-Control': 'no-store' } };
}

/**
 * The Harper user of this request's cookie session, or undefined. Identity counts only when it came from
 * the session: a request carrying an Authorization header is never treated as signed in here, and the
 * resolved user must be the session's own.
 */
export function sessionUsername(request: Request): string | undefined {
	if (readRawHeader(request?.headers, 'authorization') !== undefined) return undefined;
	const session = (request as any)?.session;
	const user = (request as any)?.user;
	const username = typeof user === 'string' ? user : user?.username;
	if (!session?.id || typeof session.user !== 'string' || !username || session.user !== username) return undefined;
	return username;
}

function authorizeReturnPath(state: MCPAuthorizeState): string {
	const query = new URLSearchParams({
		response_type: 'code',
		client_id: state.clientId,
		redirect_uri: state.redirectUri,
		code_challenge: state.codeChallenge,
		code_challenge_method: state.codeChallengeMethod,
		resource: state.resource,
	});
	if (state.scope) query.set('scope', state.scope);
	if (state.clientState) query.set('state', state.clientState);
	return `${AUTHORIZE_PATH}?${query.toString()}`;
}

function withReturnTo(template: string, returnPath: string): string {
	return template.replace(SESSION_LOGIN_RETURN_PLACEHOLDER, encodeURIComponent(returnPath));
}

function hostnameOf(uri: string): string {
	try {
		return new URL(uri).hostname;
	} catch {
		return uri;
	}
}

function page(title: string, content: string, setCookie?: string): Page {
	const headers: Record<string, string> = { ...PAGE_HEADERS };
	if (setCookie) headers['Set-Cookie'] = setCookie;
	return {
		status: 200,
		headers,
		body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.12);max-width:480px;width:100%;padding:2rem}
h1{font-size:1.25rem;margin-bottom:1rem;color:#111}
p{margin:.5rem 0;color:#333}
.info{margin:1rem 0;padding:1rem;background:#f8f8f8;border-radius:4px;border-left:4px solid #0057b7}
.warning{margin:1rem 0;padding:1rem;background:#fff3cd;border:1px solid #ffc107;border-radius:4px;font-size:.9rem;color:#856404}
.actions{display:flex;gap:.75rem;margin-top:1.5rem}
button{flex:1;padding:.75rem;border:none;border-radius:4px;font-size:1rem;font-weight:600;cursor:pointer}
.approve{background:#0057b7;color:#fff}
.deny{background:#e8e8e8;color:#111}
a{color:#0057b7}
</style>
</head>
<body>
<div class="card">
${content}
</div>
</body>
</html>`,
	};
}

function switchAccountLink(mcpConfig: MCPConfig, returnPath: string): string {
	const template = mcpConfig.sessionLogin?.switchAccountUrl;
	if (!template) return '';
	return `<p><a href="${escapeHtml(withReturnTo(template, returnPath))}">Use a different account</a></p>`;
}

export async function renderSessionAuthorize(
	request: Request,
	client: MCPClientRecord,
	state: MCPAuthorizeState,
	mcpConfig: MCPConfig,
	hookManager: HookManager | undefined,
	logger?: Logger
): Promise<Redirect | Page | ErrorJSON> {
	const sessionLogin = mcpConfig.sessionLogin!;
	const returnPath = authorizeReturnPath(state);
	const user = sessionUsername(request);
	if (!user) {
		const location = withReturnTo(sessionLogin.loginUrl, returnPath);
		if (location.length > MAX_RETURN_URL_LENGTH) {
			return clientRedirect(request, mcpConfig, state, 'invalid_request', 'Authorization request is too long');
		}
		return { status: 302, headers: { 'Location': location, 'Cache-Control': 'no-store' } };
	}

	const clientName = client.client_name ?? client.client_id;
	const decision = hookManager
		? await hookManager.callOnMCPSessionAuthorize(
				{ user, clientId: state.clientId, clientName, scope: state.scope, phase: 'consent' },
				request
			)
		: { allow: true as const };
	const cancelHref = escapeHtml(clientRedirect(request, mcpConfig, state, 'access_denied').headers.Location);
	if (!decision.allow) {
		logger?.info?.(`MCP session authorize: refused at consent for client=${state.clientId}`);
		const reason = decision.description ? `<p>${escapeHtml(decision.description)}</p>` : '';
		return page(
			'Cannot authorize',
			`<h1>This account cannot authorize ${escapeHtml(clientName)}</h1>
${reason}
${switchAccountLink(mcpConfig, returnPath)}
<p><a href="${cancelHref}">Cancel</a></p>`
		);
	}

	const browserSecret = readBrowserSecret(request) ?? generateBrowserSecret();
	const browserNonceHash = hashBrowserSecret(browserSecret);
	let token: string;
	try {
		token = await issueSessionConsent({
			user,
			clientId: state.clientId,
			clientName,
			browserNonceHash,
			state: { ...state, browserNonceHash },
		});
	} catch (error) {
		logger?.error?.(
			'MCP session authorize: failed to store consent:',
			error instanceof Error ? error.message : String(error)
		);
		return clientRedirect(request, mcpConfig, state, 'server_error', 'Failed to start authorization');
	}

	const account = escapeHtml(decision.displayName ?? user);
	const redirectHost = escapeHtml(hostnameOf(state.redirectUri));
	const clientIdHost = /^https:\/\//.test(client.client_id) ? escapeHtml(hostnameOf(client.client_id)) : '';
	const loopback = isLoopbackRedirect(state.redirectUri);
	return page(
		`Authorize ${escapeHtml(clientName)}`,
		`<h1>Allow ${escapeHtml(clientName)} to access your account?</h1>
<p>Signed in as <strong>${account}</strong></p>
<div class="info">
${clientIdHost ? `<p>Client identity: <strong>${clientIdHost}</strong></p>` : ''}
<p>Redirect hostname: <strong>${redirectHost}</strong></p>
</div>
${
	loopback
		? '<div class="warning" role="alert"><strong>Warning:</strong> the redirect URI is a loopback address; any local process on this machine could receive the authorization.</div>'
		: ''
}
<form method="POST" action="${CONFIRM_PATH}">
<input type="hidden" name="consent_token" value="${escapeHtml(token)}">
<div class="actions">
<button class="deny" type="submit" name="decision" value="deny">Deny</button>
<button class="approve" type="submit" name="decision" value="approve">Allow</button>
</div>
</form>
${switchAccountLink(mcpConfig, returnPath)}`,
		buildBrowserSecretCookie(browserSecret)
	);
}

function issuerOrigin(request: Request, mcpConfig: MCPConfig): string | undefined {
	try {
		return new URL(resolveIssuer(request as any, mcpConfig)).origin;
	} catch {
		return undefined;
	}
}

function singleString(value: unknown): string | undefined {
	return typeof value === 'string' ? value : undefined;
}

/**
 * `POST /oauth/mcp/confirm` with a `consent_token` (session mode). Pre-redirect failures answer 400 JSON:
 * the client's redirect_uri is only trusted once the stored consent is redeemed.
 */
export async function handleSessionConsentConfirm(
	request: Request,
	body: any,
	mcpConfig: MCPConfig,
	hookManager: HookManager | undefined,
	logger?: Logger
): Promise<Redirect | ErrorJSON> {
	if (!mcpConfig.sessionLogin) {
		return errorJson(400, 'invalid_request', 'Session sign-in is not enabled');
	}
	const token = singleString(body?.consent_token);
	const decision = singleString(body?.decision);
	if (!token || !SESSION_CONSENT_TOKEN_PATTERN.test(token) || (decision !== 'approve' && decision !== 'deny')) {
		return errorJson(400, 'invalid_request', 'consent_token and decision are required');
	}
	const origin = singleString(readRawHeader(request?.headers, 'origin'));
	const expectedOrigin = issuerOrigin(request, mcpConfig);
	if (!origin || !expectedOrigin || origin !== expectedOrigin) {
		logger?.warn?.('MCP session confirm: refused a POST from another origin');
		return errorJson(400, 'invalid_request', 'Approval must come from the authorization page');
	}
	const user = sessionUsername(request);
	if (!user) return errorJson(400, 'invalid_request', 'Sign in again and restart authorization');
	const browserSecret = readBrowserSecret(request);

	let redeemed: Awaited<ReturnType<typeof redeemSessionConsent>>;
	try {
		redeemed = await redeemSessionConsent(token, (consent) => {
			if (!browserSecretMatches(browserSecret, consent.browserNonceHash)) return 'browser binding mismatch';
			if (consent.user !== user) return 'signed-in account changed';
			return null;
		});
	} catch (error) {
		logger?.error?.(
			'MCP session confirm: consent store failed:',
			error instanceof Error ? error.message : String(error)
		);
		return errorJson(500, 'server_error', 'Failed to record the decision');
	}
	if ('refused' in redeemed) {
		logger?.warn?.(
			`MCP session confirm: refused (${redeemed.refused}${redeemed.detail ? `: ${redeemed.detail}` : ''})`
		);
		return errorJson(400, 'invalid_request', 'This authorization page has expired or was already used; start again');
	}

	const { consent } = redeemed;
	if (decision === 'deny') {
		logger?.info?.(`MCP session confirm: user denied client=${consent.clientId}`);
		return clientRedirect(request, mcpConfig, consent.state, 'access_denied', 'The user denied the request');
	}
	const verdict = hookManager
		? await hookManager.callOnMCPSessionAuthorize(
				{
					user,
					clientId: consent.clientId,
					clientName: consent.clientName,
					scope: consent.state.scope,
					phase: 'approve',
				},
				request
			)
		: { allow: true as const };
	if (!verdict.allow) {
		logger?.info?.(`MCP session confirm: refused by onMCPSessionAuthorize for client=${consent.clientId}`);
		return clientRedirect(
			request,
			mcpConfig,
			consent.state,
			'access_denied',
			verdict.description ?? 'This account cannot authorize the client'
		);
	}
	return handleMCPCallback(request, consent.state, user, mcpConfig, logger);
}
