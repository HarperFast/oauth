/**
 * TEST-ONLY routes for the runtime characterization suite. They call the
 * plugin's own stores so the suite exercises its real code against real
 * Harper tables. Never deploy this fixture.
 *
 *   GET /mcp-test/replay?client_id&jti&exp      → { fresh } (MCPAssertionJtiStore.checkAndRecord)
 *   GET /mcp-test/replay-row?client_id&jti      → { exists, expires_at, expiresAt }
 *   GET /mcp-test/seed-family                   → { refreshToken, familyId } (public stored client, bound none)
 *   GET /mcp-test/family?id                     → the stored family, or { exists: false }
 *   GET /mcp-test/revoke?id                     → {} (MCPRefreshFamilyStore.revoke)
 *   GET /mcp-test/rotate?id&hash                → {} (MCPRefreshFamilyStore.rotate)
 *
 * These routes are server.http handlers and run outside a request transaction;
 * Harper's REST handler runs POST /oauth/mcp/token inside one.
 *
 * It also serves the CIMD document of one TEST-ONLY headless
 * (client_credentials) client, HEADLESS_CLIENT_ID, through the plugin's
 * resolver seams (_setDnsLookup, _setFetch), so no network is involved. The
 * document's inline Ed25519 key derives from HEADLESS_KEY_LABEL, which
 * mcp-runtime.test.ts uses to sign that client's assertions.
 */
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { server, databases } from 'harper';
import { MCPAssertionJtiStore, jtiKey } from './node_modules/@harperfast/oauth/dist/lib/mcp/assertionJtiStore.js';
import { _setDnsLookup, _setFetch } from './node_modules/@harperfast/oauth/dist/lib/mcp/cimd.js';
import { MCPClientStore } from './node_modules/@harperfast/oauth/dist/lib/mcp/clientStore.js';
import {
	MCPRefreshFamilyStore,
	makeRefreshToken,
	newFamilyId,
} from './node_modules/@harperfast/oauth/dist/lib/mcp/refreshTokenStore.js';

const RUNTIME_CLIENT_ID = 'runtime-public-client';

const HEADLESS_CLIENT_ID = 'https://agent.test/headless/agent.json';
const HEADLESS_KEY_LABEL = 'mcp-runtime-app headless test key';
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const headlessKey = createPrivateKey({
	key: Buffer.concat([ED25519_PKCS8_PREFIX, createHash('sha256').update(HEADLESS_KEY_LABEL).digest()]),
	format: 'der',
	type: 'pkcs8',
});
const HEADLESS_DOCUMENT = JSON.stringify({
	client_id: HEADLESS_CLIENT_ID,
	client_name: 'Runtime headless agent',
	grant_types: ['client_credentials'],
	token_endpoint_auth_method: 'private_key_jwt',
	jwks: { keys: [createPublicKey(headlessKey).export({ format: 'jwk' })] },
});

_setDnsLookup(async (hostname) => {
	if (hostname !== 'agent.test') throw new Error(`the fixture resolves only agent.test, not ${hostname}`);
	return [{ address: '93.184.216.34', family: 4 }];
});
_setFetch(async (url) => {
	const found = url === HEADLESS_CLIENT_ID;
	const bytes = Buffer.from(found ? HEADLESS_DOCUMENT : '{}');
	let sent = false;
	return {
		status: found ? 200 : 404,
		headers: new Map([
			['content-type', 'application/json'],
			['content-length', String(bytes.length)],
		]),
		body: {
			getReader: () => ({
				read: async () => (sent ? { done: true, value: undefined } : ((sent = true), { done: false, value: bytes })),
				cancel: () => {},
			}),
		},
	};
});

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
		case '/revoke': {
			await new MCPRefreshFamilyStore().revoke(q.get('id'));
			return json({});
		}
		case '/rotate': {
			await new MCPRefreshFamilyStore().rotate(q.get('id'), q.get('hash'));
			return json({});
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
