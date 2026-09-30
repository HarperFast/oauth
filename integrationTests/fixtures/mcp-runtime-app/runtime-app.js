/**
 * TEST-ONLY routes for the runtime characterization suite. They call the
 * plugin's own stores so the suite exercises its real code against real
 * Harper tables, without a CIMD document fetch. Never deploy this fixture.
 *
 *   GET /mcp-test/replay?client_id&jti&exp      → { fresh } (MCPAssertionJtiStore.checkAndRecord)
 *   GET /mcp-test/replay-row?client_id&jti      → { exists, expires_at, expiresAt }
 *   GET /mcp-test/seed-family                   → { refreshToken, familyId } (public stored client, bound none)
 *   GET /mcp-test/family?id                     → the stored family, or { exists: false }
 */
import { server, databases } from 'harper';
import { MCPAssertionJtiStore, jtiKey } from './node_modules/@harperfast/oauth/dist/lib/mcp/assertionJtiStore.js';
import { MCPClientStore } from './node_modules/@harperfast/oauth/dist/lib/mcp/clientStore.js';
import {
	MCPRefreshFamilyStore,
	makeRefreshToken,
	newFamilyId,
} from './node_modules/@harperfast/oauth/dist/lib/mcp/refreshTokenStore.js';

const RUNTIME_CLIENT_ID = 'runtime-public-client';

const json = (body, status = 200) => ({
	status,
	headers: { 'Content-Type': 'application/json' },
	body: JSON.stringify(body),
});

async function handle(request) {
	const url = new URL(request.url, 'http://fixture.invalid');
	const q = url.searchParams;
	switch (url.pathname.replace(/^\/mcp-test/, '')) {
		case '/replay': {
			const fresh = await new MCPAssertionJtiStore().checkAndRecord(
				q.get('client_id'),
				q.get('jti'),
				Number(q.get('exp'))
			);
			return json({ fresh });
		}
		case '/replay-row': {
			const row = await databases.oauth.mcp_assertion_jtis.get(jtiKey(q.get('client_id'), q.get('jti')));
			if (!row) return json({ exists: false });
			return json({
				exists: true,
				expires_at: row.expires_at,
				expiresAt: typeof row.getExpiresAt === 'function' ? (row.getExpiresAt() ?? null) : null,
			});
		}
		case '/seed-family': {
			await new MCPClientStore().set({
				client_id: RUNTIME_CLIENT_ID,
				client_name: 'Runtime public client',
				token_endpoint_auth_method: 'none',
				grant_types: ['authorization_code', 'refresh_token'],
				response_types: ['code'],
				redirect_uris: ['https://client.test/cb'],
				client_id_issued_at: Math.floor(Date.now() / 1000),
			});
			const familyId = newFamilyId();
			const { token, hash } = makeRefreshToken(familyId);
			await new MCPRefreshFamilyStore().set({
				family_id: familyId,
				current_token_hash: hash,
				revoked: false,
				client_id: RUNTIME_CLIENT_ID,
				user: 'runtime-user',
				resource: 'https://mcp.test/mcp',
				scope: 'offline_access',
				expires_at: Math.floor(Date.now() / 1000) + 3600,
				client_auth_method: 'none',
			});
			return json({ refreshToken: token, familyId });
		}
		case '/family': {
			const family = await new MCPRefreshFamilyStore().get(q.get('id'));
			return json(family ? { exists: true, ...family } : { exists: false });
		}
		default:
			return json({ error: 'not found' }, 404);
	}
}

server.http(handle, { urlPath: '/mcp-test' });
