/**
 * MCP OAuth Endpoint Dispatcher
 *
 * Routes /oauth/mcp/* sub-paths to the appropriate handlers. Kept as a thin
 * dispatcher so OAuthResource doesn't grow MCP-specific logic; Stage 4 will
 * add /token.
 */

import type { RequestTarget } from 'harper';
import type { HookManager } from '../hookManager.ts';
import type { Logger, MCPConfig, ProviderRegistry, Request } from '../../types.ts';
import { handleAuthorize, handleAuthorizeConfirm } from './authorize.ts';
import { handleRegister } from './dcr.ts';
import { handleToken } from './token.ts';

export { MCPAuthCodeStore, resetMCPAuthCodesTableCache } from './authCodeStore.ts';
export { handleAuthorize, handleAuthorizeConfirm, selectMCPProvider } from './authorize.ts';
export { handleMCPCallback } from './callback.ts';
export { isCimdClientId, resolveClient, CimdClientError } from './cimd.ts';
export { CONSENT_COOKIE_NAME } from './consentBinding.ts';
export { MCPClientStore, resetMCPClientsTableCache } from './clientStore.ts';
export { handleRegister } from './dcr.ts';
export { MCPKeyStore, resetMCPKeysTableCache, SIGNING_KEY_ID } from './keyStore.ts';
export { MCPRefreshFamilyStore, resetMCPRefreshFamiliesTableCache } from './refreshTokenStore.ts';
export { handleToken } from './token.ts';
export { publicKeyToJwk, signAccessToken, verifyAccessToken, verifyAccessTokenWithKeySet } from './tokenIssuer.ts';
export type { VerifyWithKeySetOptions } from './tokenIssuer.ts';
export { withMCPAuth } from './withMCPAuth.ts';
export type { WithMCPAuthOptions } from './withMCPAuth.ts';

/**
 * Dispatch POST /oauth/mcp/<action>.
 *
 * Returns 404 when MCP is disabled (existence-hiding — clients shouldn't
 * be able to probe whether MCP support is configured).
 *
 * `hookManager` is forwarded to `handleToken` so `onMCPTokenIssued` fires
 * on successful token issuance.
 */
export async function handleMCPPost(
	action: string,
	request: Request,
	body: any,
	mcpConfig: MCPConfig | undefined,
	providers: ProviderRegistry,
	hookManager?: HookManager,
	logger?: Logger
): Promise<any> {
	if (!mcpConfig?.enabled) {
		return { status: 404, body: { error: 'Not found' } };
	}

	if (action === 'register') {
		return handleRegister(request, body, mcpConfig, logger);
	}

	if (action === 'token') {
		return handleToken(request, body, mcpConfig, hookManager, logger);
	}

	if (action === 'confirm') {
		return handleAuthorizeConfirm(request, body, mcpConfig, providers, logger);
	}

	return { status: 404, body: { error: 'Not found' } };
}

/**
 * Dispatch GET /oauth/mcp/<action>.
 *
 * Returns 404 when MCP is disabled.
 */
export async function handleMCPGet(
	action: string,
	request: Request,
	target: RequestTarget,
	mcpConfig: MCPConfig | undefined,
	providers: ProviderRegistry,
	logger?: Logger
): Promise<any> {
	if (!mcpConfig?.enabled) {
		return { status: 404, body: { error: 'Not found' } };
	}

	if (action === 'authorize') {
		return handleAuthorize(request, target, mcpConfig, providers, logger);
	}

	return { status: 404, body: { error: 'Not found' } };
}
