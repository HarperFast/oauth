/**
 * MCP OAuth Stage 7 fixture app.
 *
 * Registers a single /mcp route guarded by withMCPAuth. When a valid bearer
 * token is presented the handler echoes the verified claims — sub, client_id,
 * aud, and scope — so the e2e test can assert the token was issued correctly.
 */
import { server } from 'harper';
import { withMCPAuth } from '@harperfast/oauth';

const mcpHandler = (request) => ({
	status: 200,
	headers: { 'Content-Type': 'application/json' },
	body: JSON.stringify({
		ok: true,
		sub: request.mcp?.sub ?? null,
		client_id: request.mcp?.client_id ?? null,
		aud: request.mcp?.aud ?? null,
		scope: request.mcp?.scope ?? null,
	}),
});

// urlPath subroute: Harper's routed dispatch isolates this chain so core auth
// never runs for /mcp — the Bearer challenge can't be clobbered by Basic.
server.http(withMCPAuth(mcpHandler), { urlPath: '/mcp' });
