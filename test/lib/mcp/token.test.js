/**
 * Tests for the MCP token endpoint (handleToken): authorization_code exchange,
 * PKCE verification, single-use consume, client authentication (all methods),
 * and refresh-token rotation / replay revocation.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { handleToken } from '../../../dist/lib/mcp/token.js';
import { resetMCPAssertionJtisTableCache } from '../../../dist/lib/mcp/assertionJtiStore.js';
import { resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';
import { _clearCimdCache, _setDnsLookup, _setFetch } from '../../../dist/lib/mcp/cimd.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';
import { resetMCPKeysTableCache, SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';
import { resetMCPRefreshFamiliesTableCache, makeRefreshToken } from '../../../dist/lib/mcp/refreshTokenStore.js';
import { verifyAccessToken } from '../../../dist/lib/mcp/tokenIssuer.js';

function asTrackedObject(plain) {
	return new Proxy(plain, {
		ownKeys() {
			return [];
		},
		getOwnPropertyDescriptor() {
			return undefined;
		},
	});
}

function makeTable(map, pkField) {
	return {
		get: async (id) => {
			const raw = map.get(id);
			return raw ? asTrackedObject(raw) : null;
		},
		put: async (rec) => {
			map.set(rec[pkField], rec);
		},
		delete: async (id) => {
			map.delete(id);
		},
		search: async function* () {
			for (const rec of map.values()) {
				yield asTrackedObject(rec);
			}
		},
	};
}

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
const CONF_SECRET = 's3cret-value-xyz-0123456789';

const mcpConfig = {
	enabled: true,
	issuer: ISSUER,
	resource: RESOURCE,
	accessTokenTtl: 3600,
	refreshTokenTtl: 86400,
};

function basicHeader(clientId, secret) {
	return { authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}` };
}

describe('handleToken', () => {
	let originalDatabases;
	let clients;
	let codes;
	let families;
	let keys;

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
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

		// Seed signing key so no per-test generation is needed.
		keys.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: keypair.publicKey,
			private_key_pem: keypair.privateKey,
			created_at: 1700000000,
		});
		// A public client (PKCE only) and a confidential client (basic auth).
		clients.set('public-1', {
			client_id: 'public-1',
			token_endpoint_auth_method: 'none',
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});
		clients.set('conf-1', {
			client_id: 'conf-1',
			client_secret: CONF_SECRET,
			token_endpoint_auth_method: 'client_secret_basic',
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
	});

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

	// ---- grant_type dispatch ----

	it('rejects an unsupported grant_type', async () => {
		const res = await handleToken({ headers: {} }, { grant_type: 'password' }, mcpConfig);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'unsupported_grant_type');
	});

	it('rejects a missing grant_type', async () => {
		const res = await handleToken({ headers: {} }, {}, mcpConfig);
		assert.equal(res.body.error, 'unsupported_grant_type');
	});

	// ---- authorization_code happy path ----

	it('exchanges an authorization code for an audience-bound JWT + refresh token', async () => {
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
		assert.equal(res.status, 200);
		assert.equal(res.body.token_type, 'Bearer');
		assert.equal(res.body.expires_in, 3600);
		assert.equal(res.body.scope, 'mcp:read');
		assert.ok(res.body.access_token);
		assert.ok(res.body.refresh_token);

		const claims = verifyAccessToken(res.body.access_token, keypair.publicKey, { audience: RESOURCE, issuer: ISSUER });
		assert.equal(claims.sub, 'alice@example.com');
		assert.equal(claims.client_id, 'public-1');
		assert.equal(claims.scope, 'mcp:read');

		assert.equal(codes.has('code-1'), false, 'code consumed (single-use)');
		assert.equal(families.size, 1, 'refresh family persisted');
	});

	it('sets no-store cache headers on a successful token response (RFC 6749 §5.1)', async () => {
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
		assert.equal(res.headers['Cache-Control'], 'no-store');
		assert.equal(res.headers['Pragma'], 'no-cache');
	});

	it('coerces string TTLs (from ${ENV}/quoted YAML) to numeric seconds', async () => {
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
			{ ...mcpConfig, accessTokenTtl: '3600', refreshTokenTtl: '86400' }
		);
		assert.equal(res.body.expires_in, 3600);
		const claims = verifyAccessToken(res.body.access_token, keypair.publicKey, { audience: RESOURCE, issuer: ISSUER });
		assert.equal(claims.exp - claims.iat, 3600, 'JWT lifetime is 3600 seconds, not 3600 ms');
	});

	it('omits the refresh token when the client did not register the refresh_token grant', async () => {
		clients.set('noref-1', {
			client_id: 'noref-1',
			token_endpoint_auth_method: 'none',
			grant_types: JSON.stringify(['authorization_code']),
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});
		seedCode('code-1', { client_id: 'noref-1' });
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'noref-1',
			},
			mcpConfig
		);
		assert.equal(res.status, 200);
		assert.ok(res.body.access_token);
		assert.equal(res.body.refresh_token, undefined, 'no refresh token issued');
		assert.equal(families.size, 0, 'no refresh family persisted');
	});

	// ---- authorization_code rejection branches ----

	it('rejects when code, code_verifier, or redirect_uri is missing', async () => {
		seedCode('code-1');
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'authorization_code', code: 'code-1', client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'invalid_request');
	});

	it('rejects a malformed code_verifier (RFC 7636 syntax)', async () => {
		seedCode('code-1');
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: 'too-short',
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
		assert.match(res.body.error_description, /code_verifier/);
	});

	it('rejects an unknown/expired authorization code', async () => {
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'nope',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
	});

	it('rejects a code issued to a different client', async () => {
		seedCode('code-1', { client_id: 'someone-else' });
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
		assert.equal(res.body.error, 'invalid_grant');
		assert.equal(codes.has('code-1'), true, 'code NOT consumed on rejection');
	});

	it('rejects a mismatched redirect_uri', async () => {
		seedCode('code-1');
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: 'https://evil.example.com/cb',
				client_id: 'public-1',
			},
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
	});

	it('rejects a failed PKCE verification', async () => {
		seedCode('code-1');
		const wrongVerifier = randomBytes(32).toString('base64url');
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: wrongVerifier,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
			},
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
		assert.match(res.body.error_description, /PKCE/);
		assert.equal(codes.has('code-1'), true, 'code NOT consumed when PKCE fails');
	});

	it('returns server_error and does not issue if the code consume fails', async () => {
		seedCode('code-1');
		global.databases.oauth.mcp_auth_codes.delete = async () => {
			throw new Error('delete failed');
		};
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
		assert.equal(res.status, 500);
		assert.equal(res.body.error, 'server_error');
		assert.equal(families.size, 0, 'no token issued when consume fails');
	});

	// ---- client authentication ----

	it('rejects an unknown client', async () => {
		seedCode('code-1');
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'ghost',
			},
			mcpConfig
		);
		assert.equal(res.status, 401);
		assert.equal(res.body.error, 'invalid_client');
	});

	it('rejects a public client that presents a secret', async () => {
		seedCode('code-1');
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'public-1',
				client_secret: 'unexpected',
			},
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_client');
	});

	it('authenticates a confidential client via client_secret_basic', async () => {
		seedCode('code-1', { client_id: 'conf-1' });
		const res = await handleToken(
			{ headers: basicHeader('conf-1', CONF_SECRET) },
			{ grant_type: 'authorization_code', code: 'code-1', code_verifier: CODE_VERIFIER, redirect_uri: REDIRECT },
			mcpConfig
		);
		assert.equal(res.status, 200);
		assert.ok(res.body.access_token);
	});

	it('rejects a confidential client with a wrong secret', async () => {
		seedCode('code-1', { client_id: 'conf-1' });
		const res = await handleToken(
			{ headers: basicHeader('conf-1', 'wrong-secret') },
			{ grant_type: 'authorization_code', code: 'code-1', code_verifier: CODE_VERIFIER, redirect_uri: REDIRECT },
			mcpConfig
		);
		assert.equal(res.status, 401);
		assert.equal(res.body.error, 'invalid_client');
	});

	it('rejects mixing Basic header with a body client_secret', async () => {
		seedCode('code-1', { client_id: 'conf-1' });
		const res = await handleToken(
			{ headers: basicHeader('conf-1', CONF_SECRET) },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_secret: CONF_SECRET,
			},
			mcpConfig
		);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'invalid_request');
	});

	it('authenticates a confidential client via client_secret_post (secret in body)', async () => {
		clients.set('post-1', {
			client_id: 'post-1',
			client_secret: CONF_SECRET,
			token_endpoint_auth_method: 'client_secret_post',
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});
		seedCode('code-1', { client_id: 'post-1' });
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'post-1',
				client_secret: CONF_SECRET,
			},
			mcpConfig
		);
		assert.equal(res.status, 200);
		assert.ok(res.body.access_token);
	});

	it('rejects a client_secret_post client that omits its secret', async () => {
		clients.set('post-1', {
			client_id: 'post-1',
			client_secret: CONF_SECRET,
			token_endpoint_auth_method: 'client_secret_post',
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});
		seedCode('code-1', { client_id: 'post-1' });
		const res = await handleToken(
			{ headers: {} },
			{
				grant_type: 'authorization_code',
				code: 'code-1',
				code_verifier: CODE_VERIFIER,
				redirect_uri: REDIRECT,
				client_id: 'post-1',
			},
			mcpConfig
		);
		assert.equal(res.status, 401);
		assert.equal(res.body.error, 'invalid_client');
	});

	// ---- refresh_token rotation ----

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

	it('rotates a refresh token and issues a fresh access token', async () => {
		const token = seedFamily('fam-1');
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(res.status, 200);
		assert.ok(res.body.access_token);
		assert.notEqual(res.body.refresh_token, token, 'a new refresh token is issued');
		const claims = verifyAccessToken(res.body.access_token, keypair.publicKey, { audience: RESOURCE, issuer: ISSUER });
		assert.equal(claims.sub, 'alice@example.com');
	});

	it('detects replay of a superseded refresh token and revokes the family', async () => {
		const oldToken = seedFamily('fam-1');
		const rotated = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: oldToken, client_id: 'public-1' },
			mcpConfig
		);
		const newToken = rotated.body.refresh_token;

		// Replay the OLD token → invalid_grant + family revoked.
		const replay = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: oldToken, client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(replay.body.error, 'invalid_grant');
		assert.equal(families.get('fam-1').revoked, true, 'family revoked on replay');

		// The legitimate (rotated) token is now dead too — whole family is revoked.
		const afterRevoke = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: newToken, client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(afterRevoke.body.error, 'invalid_grant');
	});

	it('still rejects a replayed token when persisting the revocation fails', async () => {
		const oldToken = seedFamily('fam-1');
		await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: oldToken, client_id: 'public-1' },
			mcpConfig
		); // rotate, superseding oldToken
		// A write failure during revocation must not turn the rejection into a 500.
		global.databases.oauth.mcp_refresh_families.put = async () => {
			throw new Error('write failed');
		};
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: oldToken, client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'invalid_grant', 'replay rejected even though revoke persist failed');
	});

	it('rejects a refresh token presented by a different client', async () => {
		const token = seedFamily('fam-1'); // bound to public-1
		const res = await handleToken(
			{ headers: basicHeader('conf-1', CONF_SECRET) },
			{ grant_type: 'refresh_token', refresh_token: token },
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
	});

	it('rejects an expired refresh family', async () => {
		const token = seedFamily('fam-1', { expires_at: Math.floor(Date.now() / 1000) - 1 });
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
	});

	it('rejects the refresh grant for a client that did not register it', async () => {
		clients.set('noref-1', {
			client_id: 'noref-1',
			token_endpoint_auth_method: 'none',
			grant_types: JSON.stringify(['authorization_code']),
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});
		const token = seedFamily('fam-1', { client_id: 'noref-1' });
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'noref-1' },
			mcpConfig
		);
		assert.equal(res.body.error, 'unauthorized_client');
	});

	it('does not rotate the family when token signing fails (old token survives for retry)', async () => {
		const token = seedFamily('fam-1');
		const before = families.get('fam-1').current_token_hash;
		// Corrupt the signing key so signAccessToken throws — this happens before
		// the rotation is persisted, so the family must be left intact. The throw
		// is caught by handleToken's top-level guard and surfaced as a structured
		// server_error (RFC 6749 §5.2), not propagated to the framework.
		keys.set(SIGNING_KEY_ID, { ...keys.get(SIGNING_KEY_ID), private_key_pem: 'not-a-valid-pem' });
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(res.status, 500, 'signing failure → structured server_error, not a propagated throw');
		assert.equal(res.body.error, 'server_error');
		assert.equal(families.get('fam-1').current_token_hash, before, 'family not rotated when signing fails');
	});

	it('rejects a malformed refresh token', async () => {
		const res = await handleToken(
			{ headers: {} },
			{ grant_type: 'refresh_token', refresh_token: 'garbage', client_id: 'public-1' },
			mcpConfig
		);
		assert.equal(res.body.error, 'invalid_grant');
	});
});

describe('handleToken — client_credentials grant (#162)', () => {
	let originalDatabases;
	let clients;
	let keys;
	let jtis;
	let hookEvents;

	const edKeypair = generateKeyPairSync('ed25519');
	const AGENT_JWK = edKeypair.publicKey.export({ format: 'jwk' });
	const AGENT_CLIENT_ID = 'https://agents.example.com/fleet/agent-1.json';
	const TOKEN_ENDPOINT = `${ISSUER}/oauth/mcp/token`;

	const AGENT_DOC = {
		client_id: AGENT_CLIENT_ID,
		client_name: 'Fleet Agent 1',
		grant_types: ['client_credentials'],
		token_endpoint_auth_method: 'private_key_jwt',
		jwks: { keys: [AGENT_JWK] },
	};

	const ccConfig = {
		...mcpConfig,
		clientIdMetadataDocuments: { allowedHosts: ['agents.example.com'] },
		clientCredentials: { enabled: true, accessTokenTtl: 300 },
	};

	const hookManager = {
		callOnMCPTokenIssued(event) {
			hookEvents.push(event);
		},
	};

	function signAssertion(overrides = {}) {
		const now = Math.floor(Date.now() / 1000);
		const {
			iss = AGENT_CLIENT_ID,
			sub = iss,
			aud = TOKEN_ENDPOINT,
			exp = now + 30,
			iat = now,
			jti = randomBytes(8).toString('hex'),
			key = edKeypair.privateKey,
		} = overrides;
		const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
		const payload = Buffer.from(JSON.stringify({ iss, sub, aud, exp, iat, jti })).toString('base64url');
		const signature = sign(null, Buffer.from(`${header}.${payload}`), key).toString('base64url');
		return `${header}.${payload}.${signature}`;
	}

	function grantBody(overrides = {}) {
		return {
			grant_type: 'client_credentials',
			client_id: AGENT_CLIENT_ID,
			client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			client_assertion: signAssertion(),
			...overrides,
		};
	}

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
		_setDnsLookup(null);
		_setFetch(null);
	});

	beforeEach(() => {
		resetMCPClientsTableCache();
		resetMCPKeysTableCache();
		resetMCPAssertionJtisTableCache();
		_clearCimdCache();
		hookEvents = [];

		clients = new Map();
		keys = new Map();
		jtis = new Map();
		keys.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: keypair.publicKey,
			private_key_pem: keypair.privateKey,
			created_at: 1700000000,
		});
		// A DCR public client, to prove stored clients can't use this grant.
		clients.set('public-1', {
			client_id: 'public-1',
			token_endpoint_auth_method: 'none',
			redirect_uris: JSON.stringify([REDIRECT]),
			client_id_issued_at: 1700000000,
		});
		// A stored record wearing the full credentials shape — must still be
		// rejected by the grant's CIMD pin (no allowlist gate on the DCR path).
		clients.set('agent-dcr-1', {
			client_id: 'agent-dcr-1',
			token_endpoint_auth_method: 'private_key_jwt',
			grant_types: JSON.stringify(['client_credentials']),
			client_id_issued_at: 1700000000,
		});

		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: makeTable(clients, 'client_id'),
				harper_oauth_mcp_keys: makeTable(keys, 'kid'),
				mcp_assertion_jtis: {
					...makeTable(jtis, 'id'),
					create: async (record) => {
						if (jtis.has(record.id)) {
							const err = new Error('Record already exists');
							err.statusCode = 409;
							throw err;
						}
						jtis.set(record.id, record);
					},
				},
			},
		};

		// Serve the agent's CIMD document through the stubbed resolver.
		_setDnsLookup(async () => [{ address: '93.184.216.34', family: 4 }]);
		_setFetch(async () => {
			const bytes = Buffer.from(JSON.stringify(AGENT_DOC));
			return {
				status: 200,
				headers: new Map([
					['content-type', 'application/json'],
					['content-length', String(bytes.length)],
				]),
				body: {
					getReader: () => {
						let sent = false;
						return {
							read: async () =>
								sent ? { done: true, value: undefined } : ((sent = true), { done: false, value: bytes }),
							cancel: () => {},
						};
					},
				},
			};
		});
	});

	it('issues a short-TTL token with no refresh token (sub = client identity)', async () => {
		const res = await handleToken({ headers: {} }, grantBody(), ccConfig, hookManager);
		assert.equal(res.status, 200, JSON.stringify(res.body));
		assert.equal(res.body.token_type, 'Bearer');
		assert.equal(res.body.expires_in, 300);
		assert.equal(res.body.refresh_token, undefined, 'client_credentials must never issue a refresh token');
		const claims = verifyAccessToken(res.body.access_token, keypair.publicKey);
		assert.equal(claims.sub, AGENT_CLIENT_ID);
		assert.equal(claims.aud, RESOURCE);
		assert.equal(claims.client_id, AGENT_CLIENT_ID);
		assert.equal(hookEvents.length, 1);
		assert.equal(hookEvents[0].type, 'client_credentials');
	});

	it('rejects a replayed jti', async () => {
		const body = grantBody();
		const first = await handleToken({ headers: {} }, body, ccConfig);
		assert.equal(first.status, 200);
		const replay = await handleToken({ headers: {} }, body, ccConfig);
		assert.equal(replay.status, 400);
		assert.equal(replay.body.error, 'invalid_grant');
		assert.match(replay.body.error_description, /already been used/);
	});

	it('rejects a wrong audience', async () => {
		const res = await handleToken(
			{ headers: {} },
			grantBody({ client_assertion: signAssertion({ aud: 'https://other.example.com/token' }) }),
			ccConfig
		);
		assert.equal(res.status, 401);
		assert.equal(res.body.error, 'invalid_client');
		assert.match(res.body.error_description, /aud/);
	});

	it('rejects an expired assertion', async () => {
		const past = Math.floor(Date.now() / 1000) - 120;
		const res = await handleToken(
			{ headers: {} },
			grantBody({ client_assertion: signAssertion({ exp: past + 30, iat: past }) }),
			ccConfig
		);
		assert.equal(res.status, 401);
		assert.equal(res.body.error, 'invalid_client');
	});

	it('rejects an assertion signed by a different key', async () => {
		const rogue = generateKeyPairSync('ed25519');
		const res = await handleToken(
			{ headers: {} },
			grantBody({ client_assertion: signAssertion({ key: rogue.privateKey }) }),
			ccConfig
		);
		assert.equal(res.status, 401);
		assert.match(res.body.error_description, /signature/);
	});

	it('rejects an iss/client_id mismatch', async () => {
		const res = await handleToken(
			{ headers: {} },
			grantBody({ client_assertion: signAssertion({ iss: 'https://agents.example.com/fleet/agent-2.json' }) }),
			ccConfig
		);
		assert.equal(res.status, 401);
		assert.match(res.body.error_description, /iss/);
	});

	it('accepts an exact resource match and rejects any other target', async () => {
		const ok = await handleToken({ headers: {} }, grantBody({ resource: RESOURCE }), ccConfig);
		assert.equal(ok.status, 200);
		const bad = await handleToken({ headers: {} }, grantBody({ resource: `${RESOURCE}/sub` }), ccConfig);
		assert.equal(bad.status, 400);
		assert.equal(bad.body.error, 'invalid_target');
	});

	it('does not burn the jti on a resource mismatch — the same assertion retries successfully', async () => {
		const assertion = signAssertion();
		const bad = await handleToken(
			{ headers: {} },
			grantBody({ client_assertion: assertion, resource: `${RESOURCE}/sub` }),
			ccConfig
		);
		assert.equal(bad.body.error, 'invalid_target');
		const retry = await handleToken(
			{ headers: {} },
			grantBody({ client_assertion: assertion, resource: RESOURCE }),
			ccConfig
		);
		assert.equal(retry.status, 200, 'a recoverable request-param mistake must not consume the single-use jti');
	});

	it('is indistinguishable from an unknown grant when disabled', async () => {
		const res = await handleToken({ headers: {} }, grantBody(), mcpConfig);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'unsupported_grant_type');
		assert.equal(res.body.error_description, 'grant_type must be authorization_code or refresh_token');
	});

	it('requires the RFC 7523 assertion type and the assertion itself', async () => {
		const wrongType = await handleToken({ headers: {} }, grantBody({ client_assertion_type: 'urn:nope' }), ccConfig);
		assert.equal(wrongType.status, 400);
		assert.equal(wrongType.body.error, 'invalid_request');
		const missing = await handleToken({ headers: {} }, grantBody({ client_assertion: undefined }), ccConfig);
		assert.equal(missing.status, 400);
		assert.equal(missing.body.error, 'invalid_request');
	});

	it('rejects a Basic header or client_secret riding along (key possession only)', async () => {
		const withBasic = await handleToken({ headers: basicHeader('admin', 'admin-secret') }, grantBody(), ccConfig);
		assert.equal(withBasic.status, 400);
		assert.equal(withBasic.body.error, 'invalid_request');
		const withSecret = await handleToken({ headers: {} }, grantBody({ client_secret: 'oops' }), ccConfig);
		assert.equal(withSecret.status, 400);
		// RFC 9110 §11.1: auth schemes are case-insensitive — a lowercase
		// `basic` must not slip past the mixed-auth guard.
		const lowercase = await handleToken(
			{ headers: { authorization: basicHeader('admin', 'admin-secret').authorization.replace(/^Basic/, 'basic') } },
			grantBody(),
			ccConfig
		);
		assert.equal(lowercase.status, 400);
		assert.equal(lowercase.body.error, 'invalid_request');
	});

	it('rejects a stored (DCR) client on this grant', async () => {
		const res = await handleToken({ headers: {} }, grantBody({ client_id: 'public-1' }), ccConfig);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'unauthorized_client');
	});

	it('rejects a stored client even when it wears the full credentials shape (CIMD pin)', async () => {
		const res = await handleToken({ headers: {} }, grantBody({ client_id: 'agent-dcr-1' }), ccConfig);
		assert.equal(res.status, 400);
		assert.equal(res.body.error, 'unauthorized_client');
	});
});
