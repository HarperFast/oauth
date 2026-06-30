/**
 * Tests for audit-event emission and onMCPTokenIssued hook from handleToken.
 *
 * Verifies:
 *  - oauth.mcp.token.issued emits on authorization_code exchange with correct shape
 *  - oauth.mcp.token.refreshed emits on refresh-token rotation with correct shape
 *  - Neither event includes token material (access_token/refresh_token strings)
 *  - onMCPTokenIssued fires after mint with the right event object (type, client_id, sub, aud, scope, jti)
 *  - A throwing onMCPTokenIssued hook does NOT block or error the token response
 *  - onMCPTokenIssued is NOT called when token issuance fails (e.g. invalid grant)
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { logger as harperMockLogger } from 'harper';
import { handleToken } from '../../../dist/lib/mcp/token.js';
import { resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';
import { resetMCPKeysTableCache, SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';
import { resetMCPRefreshFamiliesTableCache, makeRefreshToken } from '../../../dist/lib/mcp/refreshTokenStore.js';
import { HookManager } from '../../../dist/lib/hookManager.js';
import { createMockFn, createMockLogger } from '../../helpers/mockFn.js';

// --- Test fixtures ---

const keypair = generateKeyPairSync('rsa', {
	modulusLength: 2048,
	publicKeyEncoding: { type: 'spki', format: 'pem' },
	privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const CODE_VERIFIER = randomBytes(32).toString('base64url'); // 43 chars, valid
const CODE_CHALLENGE = createHash('sha256').update(CODE_VERIFIER).digest('base64url');

const RESOURCE = 'https://app.example.com/mcp';
const ISSUER = 'https://as.example.com';
const REDIRECT = 'https://mcp.example.com/cb';

const mcpConfig = {
	enabled: true,
	issuer: ISSUER,
	resource: RESOURCE,
	accessTokenTtl: 3600,
	refreshTokenTtl: 86400,
};

function makeTable(map, pkField) {
	return {
		get: async (id) => {
			const raw = map.get(id);
			return raw ? new Proxy(raw, { ownKeys: () => [], getOwnPropertyDescriptor: () => undefined }) : null;
		},
		put: async (rec) => {
			map.set(rec[pkField], rec);
		},
		delete: async (id) => {
			map.delete(id);
		},
	};
}

describe('handleToken — audit events and onMCPTokenIssued hook', () => {
	let originalDatabases;
	let clients;
	let codes;
	let families;
	let keys;

	// Capture info calls on Harper's mock logger.
	let infoCalls;
	let originalHarperInfo;

	before(() => {
		originalDatabases = global.databases;
	});

	after(() => {
		global.databases = originalDatabases;
		harperMockLogger.info = originalHarperInfo;
		// Clear the cached table refs so this file (which mints a signing key)
		// doesn't leak state into other files under Bun's shared-process runner.
		resetMCPClientsTableCache();
		resetMCPAuthCodesTableCache();
		resetMCPRefreshFamiliesTableCache();
		resetMCPKeysTableCache();
	});

	beforeEach(() => {
		resetMCPClientsTableCache();
		resetMCPAuthCodesTableCache();
		resetMCPRefreshFamiliesTableCache();
		resetMCPKeysTableCache();

		clients = new Map();
		codes = new Map();
		families = new Map();
		keys = new Map();

		keys.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: keypair.publicKey,
			private_key_pem: keypair.privateKey,
			created_at: 1700000000,
		});
		clients.set('public-1', {
			client_id: 'public-1',
			token_endpoint_auth_method: 'none',
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});

		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: makeTable(clients, 'client_id'),
				mcp_auth_codes: makeTable(codes, 'code'),
				mcp_refresh_families: makeTable(families, 'family_id'),
				harper_oauth_mcp_keys: makeTable(keys, 'kid'),
			},
		};

		// Reset Harper mock logger spy.
		infoCalls = [];
		originalHarperInfo = harperMockLogger.info;
		harperMockLogger.info = (...args) => infoCalls.push(args);
	});

	function restoreLogger() {
		harperMockLogger.info = originalHarperInfo;
	}

	function seedCode(code, overrides = {}) {
		codes.set(code, {
			code,
			client_id: 'public-1',
			user: 'alice@example.com',
			resource: RESOURCE,
			code_challenge: CODE_CHALLENGE,
			code_challenge_method: 'S256',
			redirect_uri: REDIRECT,
			scope: 'mcp:read',
			created_at: 1700000000,
			...overrides,
		});
	}

	function seedFamily(familyId, overrides = {}) {
		const { token, hash } = makeRefreshToken(familyId);
		families.set(familyId, {
			family_id: familyId,
			current_token_hash: hash,
			revoked: false,
			client_id: 'public-1',
			user: 'alice@example.com',
			resource: RESOURCE,
			scope: 'mcp:read',
			created_at: 1700000000,
			expires_at: Math.floor(Date.now() / 1000) + 86400,
			...overrides,
		});
		return token;
	}

	// ---- Audit: oauth.mcp.token.issued ----

	it('emits oauth.mcp.token.issued audit event on authorization_code exchange', async () => {
		seedCode('code-1');
		await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig
		);
		restoreLogger();

		const auditLog = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token.issued'));
		assert.ok(auditLog, 'audit log for oauth.mcp.token.issued was emitted');
		const parsed = JSON.parse(auditLog[0].replace(/^MCP audit: /, ''));
		assert.equal(parsed.event, 'oauth.mcp.token.issued');
		assert.equal(parsed.client_id, 'public-1');
		assert.equal(parsed.sub, 'alice@example.com');
		assert.equal(parsed.aud, RESOURCE);
		assert.equal(parsed.scope, 'mcp:read');
		assert.ok(parsed.jti, 'jti present');
		assert.ok(parsed.timestamp, 'timestamp present');
	});

	it('audit event for issued token contains no token material', async () => {
		seedCode('code-1');
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig
		);
		restoreLogger();

		const auditLog = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token.issued'));
		assert.ok(auditLog, 'audit log emitted');
		const logged = auditLog[0];

		// The actual token strings must not appear in the audit record.
		const BANNED = [res.body.access_token, res.body.refresh_token].filter(Boolean);
		for (const banned of BANNED) {
			assert.ok(!logged.includes(banned), 'token string must not appear in audit log');
		}
		// Verify no generic credential keys either.
		for (const key of ['access_token', 'refresh_token', 'client_secret']) {
			assert.ok(!logged.includes(`"${key}"`), `"${key}" must not appear in audit log`);
		}
	});

	// ---- Audit: oauth.mcp.token.refreshed ----

	it('emits oauth.mcp.token.refreshed audit event on refresh-token rotation', async () => {
		const token = seedFamily('fam-1');
		await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig
		);
		restoreLogger();

		const auditLog = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token.refreshed'));
		assert.ok(auditLog, 'audit log for oauth.mcp.token.refreshed was emitted');
		const parsed = JSON.parse(auditLog[0].replace(/^MCP audit: /, ''));
		assert.equal(parsed.event, 'oauth.mcp.token.refreshed');
		assert.equal(parsed.client_id, 'public-1');
		assert.equal(parsed.sub, 'alice@example.com');
		assert.equal(parsed.aud, RESOURCE);
		assert.equal(parsed.scope, 'mcp:read');
		assert.ok(parsed.jti, 'jti present');
		assert.ok(parsed.timestamp, 'timestamp present');
	});

	it('audit event for refreshed token contains no token material', async () => {
		const token = seedFamily('fam-1');
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig
		);
		restoreLogger();

		const auditLog = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token.refreshed'));
		assert.ok(auditLog, 'audit log emitted');
		const logged = auditLog[0];

		const BANNED = [res.body.access_token, res.body.refresh_token, token].filter(Boolean);
		for (const banned of BANNED) {
			assert.ok(!logged.includes(banned), 'token string must not appear in audit log');
		}
	});

	it('does NOT emit an audit event when token issuance fails (invalid grant)', async () => {
		// No code seeded — will fail with invalid_grant.
		await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'nonexistent',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig
		);
		restoreLogger();

		const auditLog = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token'));
		assert.equal(auditLog, undefined, 'no audit log emitted on failure');
	});

	// ---- onMCPTokenIssued hook ----

	it('fires onMCPTokenIssued with type=access on authorization_code exchange', async () => {
		seedCode('code-1');
		const hookMock = createMockFn(async () => {});
		const hookManager = new HookManager(createMockLogger());
		hookManager.register({ onMCPTokenIssued: hookMock });

		const request = { headers: {} };
		await handleToken(
			request,
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig,
			hookManager
		);
		restoreLogger();

		assert.equal(hookMock.mock.calls.length, 1, 'hook called exactly once');
		const [eventArg, requestArg] = hookMock.mock.calls[0].arguments;
		assert.equal(eventArg.type, 'access');
		assert.equal(eventArg.client_id, 'public-1');
		assert.equal(eventArg.sub, 'alice@example.com');
		assert.equal(eventArg.aud, RESOURCE);
		assert.equal(eventArg.scope, 'mcp:read');
		assert.ok(eventArg.jti, 'jti present in hook event');
		assert.equal(requestArg, request, 'request object forwarded unchanged');
	});

	it('fires onMCPTokenIssued with type=refresh on refresh-token rotation', async () => {
		const token = seedFamily('fam-1');
		const hookMock = createMockFn(async () => {});
		const hookManager = new HookManager(createMockLogger());
		hookManager.register({ onMCPTokenIssued: hookMock });

		await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig,
			hookManager
		);
		restoreLogger();

		assert.equal(hookMock.mock.calls.length, 1);
		assert.equal(hookMock.mock.calls[0].arguments[0].type, 'refresh');
	});

	it('onMCPTokenIssued jti matches the jti in the audit log', async () => {
		seedCode('code-1');
		const hookMock = createMockFn(async () => {});
		const hookManager = new HookManager(createMockLogger());
		hookManager.register({ onMCPTokenIssued: hookMock });

		await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig,
			hookManager
		);
		restoreLogger();

		const auditLog = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token.issued'));
		const parsed = JSON.parse(auditLog[0].replace(/^MCP audit: /, ''));
		const hookJti = hookMock.mock.calls[0].arguments[0].jti;
		assert.equal(hookJti, parsed.jti, 'hook jti matches the audit-log jti');
	});

	it('a throwing onMCPTokenIssued hook does NOT block the token response (fire-and-forget)', async () => {
		seedCode('code-1');
		const throwingHook = createMockFn(async () => {
			throw new Error('billing service unavailable');
		});
		const mockLogger = createMockLogger();
		const hookManager = new HookManager(mockLogger);
		hookManager.register({ onMCPTokenIssued: throwingHook });

		let res;
		await assert.doesNotReject(async () => {
			res = await handleToken(
				{ headers: {} },
				{
					grant_type: 'authorization_code',
					code: 'code-1',
					code_verifier: CODE_VERIFIER,
					redirect_uri: REDIRECT,
					client_id: 'public-1',
				},
				mcpConfig,
				hookManager
			);
		});
		restoreLogger();

		// Token response is still returned.
		assert.equal(res.status, 200, 'token response is 200 despite throwing hook');
		assert.ok(res.body.access_token, 'access_token present despite throwing hook');

		// Error is logged.
		assert.ok(
			mockLogger.error.mock.calls.some((call) => call.arguments[0].includes('onMCPTokenIssued hook failed')),
			'hook failure is logged'
		);
	});

	it('does NOT call onMCPTokenIssued when the grant fails (hook skipped on failure)', async () => {
		const hookMock = createMockFn(async () => {});
		const hookManager = new HookManager(createMockLogger());
		hookManager.register({ onMCPTokenIssued: hookMock });

		await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'does-not-exist',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig,
			hookManager
		);
		restoreLogger();

		assert.equal(hookMock.mock.calls.length, 0, 'hook must not fire when grant fails');
	});

	// ---- Ordering / failure-tolerance regressions ----

	it('does NOT emit the issued audit event or fire the hook when refresh-family persistence fails (auth-code path)', async () => {
		seedCode('code-1');
		// The refresh-family store rejects — this happens AFTER the JWT is minted,
		// so it exercises the reordering that prevents a phantom successful
		// issuance being reported for an exchange the client never received.
		global.databases.oauth.mcp_refresh_families.put = async () => {
			throw new Error('simulated persistence failure');
		};
		const hookMock = createMockFn(async () => {});
		const hookManager = new HookManager(createMockLogger());
		hookManager.register({ onMCPTokenIssued: hookMock });

		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig,
			hookManager
		);
		restoreLogger();

		// handleToken's top-level guard turns the persistence throw into a clean
		// server_error — NOT a propagated exception — and the side effects (which
		// run only after persistence) never fire.
		assert.equal(res.status, 500, 'persistence failure → structured server_error');
		assert.equal(res.body.error, 'server_error');
		const issued = infoCalls.find((args) => args[0]?.includes('oauth.mcp.token.issued'));
		assert.equal(issued, undefined, 'no phantom issued audit event when persistence fails');
		assert.equal(hookMock.mock.calls.length, 0, 'hook must not fire when persistence fails');
	});

	it('returns the rotated token on the refresh path even when the audit logger throws', async () => {
		const token = seedFamily('fam-1');
		// emitMCPAuditEvent runs AFTER the refresh family is rotated; a logger
		// throw there must be swallowed so the client still receives its new token
		// (otherwise the family is stranded on a hash the client never got).
		harperMockLogger.info = () => {
			throw new Error('simulated logger failure');
		};
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig
		);
		restoreLogger();

		assert.equal(res.status, 200, 'token response returned despite the logger throwing');
		assert.ok(res.body.access_token, 'new access token issued');
		assert.ok(res.body.refresh_token, 'rotated refresh token issued');
	});
});
