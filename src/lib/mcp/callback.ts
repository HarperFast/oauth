/**
 * MCP Callback Branch
 *
 * Invoked from the main `handleCallback` (handlers.ts) when the verified
 * CSRF state carries an `mcp` payload — i.e., the flow was kicked off by
 * /oauth/mcp/authorize, not /oauth/<provider>/login. We've already
 * completed the upstream OAuth dance and run the `onLogin` hook; this
 * function mints the MCP authorization code and redirects the user-agent
 * back to the MCP client's `redirect_uri`.
 *
 * Importantly: this branch does NOT create a Harper session. MCP and
 * human-session lifecycles are kept independent in v1 (matches the
 * "independent lifecycle" resolved decision in #86). Future stages may
 * add an opt-in for joint sessions.
 *
 * Never include the upstream IdP token in the response to the MCP client
 * — that's the spec-mandated "no token passthrough" rule.
 */

import { randomBytes } from 'node:crypto';
import type { Logger, MCPAuthCodeRecord, MCPAuthorizeState, Request } from '../../types.ts';
import { MCPAuthCodeStore } from './authCodeStore.ts';

type Redirect = {
	status: 302;
	headers: { Location: string };
};

function buildSuccessRedirect(redirectUri: string, code: string, clientState: string | undefined): Redirect {
	const url = new URL(redirectUri);
	url.searchParams.set('code', code);
	if (clientState) url.searchParams.set('state', clientState);
	return { status: 302, headers: { Location: url.toString() } };
}

function buildErrorRedirect(
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

/**
 * Mint an MCP authorization code and redirect to the MCP client.
 *
 * `userIdentifier` is the resolved Harper identity — the caller passes
 * `hookData?.user ?? oauthUser.username`, so any onLogin mapping that the
 * human-session branch would apply is also reflected on the auth code
 * (and downstream JWT in Stage 4).
 *
 * `request` is unused today but accepted for signature parity with the
 * human-session branch — Stage 6 audit hooks will read from it.
 */
export async function handleMCPCallback(
	_request: Request,
	mcpState: MCPAuthorizeState,
	userIdentifier: string,
	logger?: Logger
): Promise<Redirect> {
	const code = randomBytes(32).toString('base64url');
	const record: MCPAuthCodeRecord = {
		code,
		client_id: mcpState.clientId,
		user: userIdentifier,
		resource: mcpState.resource,
		code_challenge: mcpState.codeChallenge,
		code_challenge_method: mcpState.codeChallengeMethod,
		redirect_uri: mcpState.redirectUri,
		scope: mcpState.scope,
		created_at: Date.now(),
	};

	const store = new MCPAuthCodeStore(logger);
	try {
		await store.set(record);
	} catch (error) {
		logger?.error?.('MCP callback: failed to persist auth code:', (error as Error).message);
		return buildErrorRedirect(
			mcpState.redirectUri,
			'server_error',
			'Failed to persist authorization code',
			mcpState.clientState
		);
	}

	logger?.info?.(`MCP callback: minted auth code for client=${mcpState.clientId} user=${userIdentifier}`);
	return buildSuccessRedirect(mcpState.redirectUri, code, mcpState.clientState);
}
