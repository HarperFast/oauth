/**
 * App code (loaded via the built-in `jsResource` handler) that registers an
 * app-owned MCP route guarded by withMCPAuth, in both registration models the
 * wrapper supports. Route registration happens as an import side effect using
 * the global `server` exported by Harper — `scope.server` is just a
 * name-injecting Proxy over this same object, and our registration does not
 * depend on the injected component name.
 */
import { server } from 'harper';
import { withMCPAuth } from '@harperfast/oauth';

// Echoes the verified MCP subject (null when unauthenticated requests are
// rejected before reaching here) so an authenticated test can assert on it.
const mcpHandler = (request) => ({
	status: 200,
	headers: { 'Content-Type': 'application/json' },
	body: JSON.stringify({ ok: true, sub: request.mcp?.sub ?? null }),
});

// PRIMARY — urlPath subroute. Harper's routed dispatch runs only this chain, so
// core auth (a default-group middleware) never runs for /mcp.
server.http(withMCPAuth(mcpHandler), { urlPath: '/mcp' });

// FALLBACK — default-group middleware ordered ahead of core auth. `path` scopes
// the guard to /mcp-dg (other routes fall through to auth); `before:
// 'authentication'` makes it run outermost.
server.http(withMCPAuth(mcpHandler, { path: '/mcp-dg' }), { before: 'authentication' });
