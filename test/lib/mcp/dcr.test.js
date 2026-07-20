/**
 * Tests for MCP Dynamic Client Registration handler (RFC 7591)
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleRegister } from '../../../dist/lib/mcp/dcr.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';

const VALID_BODY = {
	redirect_uris: ['https://app.example.com/cb'],
	client_name: 'Test MCP Client',
};

function makeRequest(headers = {}) {
	return { headers };
}

describe('handleRegister (RFC 7591 DCR)', () => {
	let originalDatabases;
	let storedRecords;

	before(() => {
		originalDatabases = global.databases;
	});

	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		resetMCPClientsTableCache();
		storedRecords = new Map();
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: {
					get: async (id) => storedRecords.get(id) || null,
					put: async (record) => {
						storedRecords.set(record.client_id, record);
					},
					delete: async (id) => {
						storedRecords.delete(id);
					},
				},
			},
		};
	});

	describe('DCR enable/disable gating', () => {
		it('returns 404 when DCR is explicitly disabled', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: { enabled: false },
			});
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});

		it('returns 404 when the DCR config block is absent (default disabled, #182)', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, { enabled: true });
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});

		it('returns 404 when the DCR block is a bare null (YAML `dynamicClientRegistration:` with no children)', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: null,
			});
			assert.equal(response.status, 404);
			assert.equal(storedRecords.size, 0);
		});

		it('proceeds when the DCR block is present without an explicit enabled flag', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: {},
			});
			assert.equal(response.status, 201);
		});

		it('proceeds when DCR is explicitly enabled', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: { enabled: true },
			});
			assert.equal(response.status, 201);
		});
	});

	describe('initial access token gate', () => {
		const config = {
			enabled: true,
			dynamicClientRegistration: { initialAccessToken: 'secret-token' },
		};

		it('returns 401 when initial access token is configured and Authorization header is missing', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, config);
			assert.equal(response.status, 401);
			assert.equal(response.body.error, 'invalid_token');
		});

		it('returns 401 when Authorization header does not start with Bearer', async () => {
			const response = await handleRegister(makeRequest({ authorization: 'Basic dXNlcjpwYXNz' }), VALID_BODY, config);
			assert.equal(response.status, 401);
		});

		it('returns 401 when Bearer token does not match', async () => {
			const response = await handleRegister(makeRequest({ authorization: 'Bearer wrong-token' }), VALID_BODY, config);
			assert.equal(response.status, 401);
			assert.equal(response.body.error, 'invalid_token');
		});

		it('accepts a matching Bearer token', async () => {
			const response = await handleRegister(makeRequest({ authorization: 'Bearer secret-token' }), VALID_BODY, config);
			assert.equal(response.status, 201);
		});

		it('rejects the capitalized Authorization header (Node HTTP parser lowercases)', async () => {
			// Production: incoming headers are lowercased before reaching us.
			// If a caller hands us a literal { Authorization: ... } object, we
			// treat it as "no token presented" — matching the production contract.
			const response = await handleRegister(makeRequest({ Authorization: 'Bearer secret-token' }), VALID_BODY, config);
			assert.equal(response.status, 401);
		});
	});

	describe('scalar metadata validation', () => {
		const config = { enabled: true, dynamicClientRegistration: {} };

		it('rejects non-string client_name', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], client_name: { evil: 'object' } },
				config
			);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_client_metadata');
		});

		it('rejects non-string logo_uri', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], logo_uri: ['/icons/a.png'] },
				config
			);
			assert.equal(response.status, 400);
		});

		it('rejects non-string software_version', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], software_version: 1.2 },
				config
			);
			assert.equal(response.status, 400);
		});
	});

	describe('redirect_uris validation', () => {
		const config = { enabled: true, dynamicClientRegistration: {} };

		it('rejects missing redirect_uris', async () => {
			const response = await handleRegister(makeRequest(), { client_name: 'X' }, config);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_redirect_uri');
		});

		it('rejects empty redirect_uris array', async () => {
			const response = await handleRegister(makeRequest(), { redirect_uris: [] }, config);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_redirect_uri');
		});

		it('rejects non-array redirect_uris', async () => {
			const response = await handleRegister(makeRequest(), { redirect_uris: 'https://example.com/cb' }, config);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_redirect_uri');
		});

		it('rejects http URIs to non-loopback hosts', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['http://attacker.example.com/cb'] },
				config
			);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_redirect_uri');
		});

		it('accepts http URIs to localhost (RFC 8252 §8.3)', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['http://localhost:6274/oauth/callback'] },
				config
			);
			assert.equal(response.status, 201);
		});

		it('accepts http URIs to 127.0.0.1', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['http://127.0.0.1:6274/oauth/callback'] },
				config
			);
			assert.equal(response.status, 201);
		});

		it('rejects URIs with a fragment', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb#foo'] },
				config
			);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_redirect_uri');
		});

		it('rejects malformed URIs', async () => {
			const response = await handleRegister(makeRequest(), { redirect_uris: ['not-a-url'] }, config);
			assert.equal(response.status, 400);
		});

		it('enforces allowedRedirectUriHosts when configured', async () => {
			const allowlistConfig = {
				enabled: true,
				dynamicClientRegistration: { allowedRedirectUriHosts: ['app.example.com'] },
			};
			const allowed = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'] },
				allowlistConfig
			);
			assert.equal(allowed.status, 201);

			const denied = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://other.example.com/cb'] },
				allowlistConfig
			);
			assert.equal(denied.status, 400);
			assert.equal(denied.body.error, 'invalid_redirect_uri');
		});

		it('always allows localhost even with allowedRedirectUriHosts set', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['http://localhost:6274/cb'] },
				{
					enabled: true,
					dynamicClientRegistration: { allowedRedirectUriHosts: ['app.example.com'] },
				}
			);
			assert.equal(response.status, 201);
		});
	});

	describe('defaults and metadata', () => {
		it('applies MCP-context defaults (public client, code flow)', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: {},
			});
			assert.equal(response.status, 201);
			assert.equal(response.body.token_endpoint_auth_method, 'none');
			assert.deepEqual(response.body.grant_types, ['authorization_code', 'refresh_token']);
			assert.deepEqual(response.body.response_types, ['code']);
			assert.equal(response.body.application_type, 'web');
		});

		it('preserves client-specified values over defaults', async () => {
			const response = await handleRegister(
				makeRequest(),
				{
					redirect_uris: ['https://app.example.com/cb'],
					grant_types: ['authorization_code'],
					application_type: 'native',
				},
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 201);
			assert.deepEqual(response.body.grant_types, ['authorization_code']);
			assert.equal(response.body.application_type, 'native');
		});

		it('rejects unsupported grant_types', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], grant_types: ['client_credentials'] },
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_client_metadata');
		});

		it('rejects unsupported response_types', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], response_types: ['token'] },
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 400);
		});

		it('rejects unsupported token_endpoint_auth_method', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], token_endpoint_auth_method: 'private_key_jwt' },
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 400);
		});

		it('rejects unsupported application_type', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], application_type: 'service' },
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 400);
		});

		it('rejects non-string entries in string-array fields', async () => {
			const response = await handleRegister(
				makeRequest(),
				{ redirect_uris: ['https://app.example.com/cb'], contacts: ['nathan@example.com', 42] },
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 400);
		});
	});

	describe('issued credentials', () => {
		it('issues a client_id and persists the record (public client, no secret)', async () => {
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: {},
			});
			assert.equal(response.status, 201);
			assert.ok(response.body.client_id, 'client_id was issued');
			assert.equal(response.body.client_secret, undefined, 'public clients receive no secret');
			assert.equal(typeof response.body.client_id_issued_at, 'number');

			const stored = storedRecords.get(response.body.client_id);
			assert.ok(stored, 'client was persisted');
		});

		it('issues a client_secret for confidential clients (client_secret_basic)', async () => {
			const response = await handleRegister(
				makeRequest(),
				{
					redirect_uris: ['https://app.example.com/cb'],
					token_endpoint_auth_method: 'client_secret_basic',
				},
				{ enabled: true, dynamicClientRegistration: {} }
			);
			assert.equal(response.status, 201);
			assert.ok(response.body.client_secret, 'confidential client received a secret');
			assert.equal(response.body.client_secret_expires_at, 0, '0 == never expires');
		});

		it('issues unique client_ids for repeated registrations of the same metadata', async () => {
			const a = await handleRegister(makeRequest(), VALID_BODY, { enabled: true, dynamicClientRegistration: {} });
			const b = await handleRegister(makeRequest(), VALID_BODY, { enabled: true, dynamicClientRegistration: {} });
			assert.notEqual(a.body.client_id, b.body.client_id);
			assert.equal(storedRecords.size, 2);
		});
	});

	describe('error handling', () => {
		it('rejects non-object bodies', async () => {
			const response = await handleRegister(makeRequest(), null, { enabled: true, dynamicClientRegistration: {} });
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_client_metadata');
		});

		it('returns 500 when storage fails', async () => {
			global.databases.oauth.harper_oauth_mcp_clients.put = async () => {
				throw new Error('storage failure');
			};
			const response = await handleRegister(makeRequest(), VALID_BODY, {
				enabled: true,
				dynamicClientRegistration: {},
			});
			assert.equal(response.status, 500);
			assert.equal(response.body.error, 'server_error');
		});
	});
});
