/**
 * MCP OAuth Endpoint Dispatcher
 *
 * Routes /oauth/mcp/* sub-paths to the appropriate handlers. Kept as a thin
 * dispatcher so OAuthResource doesn't grow MCP-specific logic; Stage 4 will
 * add /token, Stage 3 will add /authorize.
 */

import type { Logger, MCPConfig, Request } from '../../types.ts';
import { handleRegister } from './dcr.ts';

export { MCPClientStore, resetMCPClientsTableCache } from './clientStore.ts';
export { handleRegister } from './dcr.ts';

/**
 * Dispatch POST /oauth/mcp/<action>.
 *
 * Returns 404 when MCP is disabled (existence-hiding — clients shouldn't
 * be able to probe whether MCP support is configured).
 */
export async function handleMCPPost(
	action: string,
	request: Request,
	body: any,
	mcpConfig: MCPConfig | undefined,
	logger?: Logger
): Promise<any> {
	if (!mcpConfig?.enabled) {
		return { status: 404, body: { error: 'Not found' } };
	}

	if (action === 'register') {
		return handleRegister(request, body, mcpConfig, logger);
	}

	return { status: 404, body: { error: 'Not found' } };
}
