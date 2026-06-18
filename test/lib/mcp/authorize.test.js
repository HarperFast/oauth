/**
 * Tests for /oauth/mcp/authorize handler.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleAuthorize, redirectUriMatches, selectMCPProvider } from '../../../dist/lib/mcp/authorize.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';

/**
 * Minimal RequestTarget stub for the existing target.get?.() pattern.
 */
function makeTarget(params) {
	return {
		get(name) {
			return Object.prototype.hasOwnProperty.call(params, name) ? params[name] : undefined;
		},
	};
}

function makeRequest(overrides = {}) {
	return {
		protocol: 'https',
		host: 'app.example.com',
		headers: { host: 'app.example.com' },
		...overrides,
	};
}

const VALID_CLIENT = {
	client_id: 'client-1',
	client_id_issued_at: 1700000000,
	redirect_uris: ['https://mcp-client.example.com/cb', 'http://localhost:6274/cb'],
	grant_types: ['authorization_code', 'refresh_token'],
	response_types: ['code'],
	token_endpoint_auth_method: 'none',
	application_type: 'web',
};

function makeProvider(name = 'github') {
	const generatedTokens = [];
	const builtUrls = [];
	const provider = {
		generateCSRFToken: async (metadata) => {
			generatedTokens.push(metadata);
			return `csrf-${generatedTokens.length}`;
		},
		getAuthorizationUrl: (state, redirectUri) => {
			builtUrls.push({ state, redirectUri });
			return `https://upstream.example.com/authorize?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
		},
	};
	const config = {
		provider: name,
		clientId: 'upstream-client',
		clientSecret: 'upstream-secret',
		authorizationUrl: 'https://upstream.example.com/authorize',
		tokenUrl: 'https://upstream.example.com/token',
		userInfoUrl: 'https://upstream.example.com/userinfo',
		redirectUri: 'https://app.example.com/oauth/' + name + '/callback',
	};
	return { provider, config, generatedTokens, builtUrls };
}

function makeProviderRegistry(...names) {
	const entries = {};
	const harnesses = {};
	for (const name of names) {
		const h = makeProvider(name);
		entries[name] = { provider: h.provider, config: h.config };
		harnesses[name] = h;
	}
	return { entries, harnesses };
}

const BASE_QUERY = {
	client_id: VALID_CLIENT.client_id,
	redirect_uri: VALID_CLIENT.redirect_uris[0],
	response_type: 'code',
	code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', // RFC 7636 Appendix B (43 chars, S256)
	code_challenge_method: 'S256',
	resource: 'https://app.example.com/mcp',
	state: 'mcp-client-state',
	scope: 'mcp:read',
};

describe('redirectUriMatches', () => {
	it('matches by exact string for non-loopback hosts', () => {
		assert.equal(redirectUriMatches('https://app.example.com/cb', ['https://app.example.com/cb']), true);
		assert.equal(redirectUriMatches('https://app.example.com/cb', ['https://app.example.com/other']), false);
		assert.equal(redirectUriMatches('https://app.example.com/cb', []), false);
	});

	it('requires exact port match for non-loopback hosts', () => {
		assert.equal(
			redirectUriMatches('https://app.example.com:8443/cb', ['https://app.example.com/cb']),
			false,
			'different ports should not match for non-loopback'
		);
	});

	it('accepts any port for 127.0.0.1 (RFC 8252 §7.3)', () => {
		assert.equal(redirectUriMatches('http://127.0.0.1:54321/cb', ['http://127.0.0.1:6274/cb']), true);
		assert.equal(redirectUriMatches('http://127.0.0.1/cb', ['http://127.0.0.1:6274/cb']), true);
	});

	it('accepts any port for [::1]', () => {
		assert.equal(redirectUriMatches('http://[::1]:54321/cb', ['http://[::1]:6274/cb']), true);
	});

	it('accepts any port for localhost', () => {
		assert.equal(redirectUriMatches('http://localhost:54321/cb', ['http://localhost:6274/cb']), true);
	});

	it('still requires matching path on loopback', () => {
		assert.equal(redirectUriMatches('http://localhost:5000/different', ['http://localhost:6274/cb']), false);
	});

	it('still requires matching scheme on loopback (no http vs https)', () => {
		assert.equal(redirectUriMatches('https://localhost:5000/cb', ['http://localhost:6274/cb']), false);
	});

	it('does not cross-match loopback variants (127.0.0.1 != localhost != [::1])', () => {
		assert.equal(redirectUriMatches('http://127.0.0.1:5000/cb', ['http://localhost:6274/cb']), false);
		assert.equal(redirectUriMatches('http://localhost:5000/cb', ['http://[::1]:6274/cb']), false);
	});

	it('rejects malformed URIs', () => {
		assert.equal(redirectUriMatches('not-a-url', ['http://localhost:6274/cb']), false);
	});
});

describe('selectMCPProvider', () => {
	it('returns the only provider when none are filtered', () => {
		const result = selectMCPProvider({}, { github: {} });
		assert.deepEqual(result, { providerName: 'github' });
	});

	it('uses mcp.providers to filter when multiple are configured', () => {
		const result = selectMCPProvider({ providers: ['github'] }, { github: {}, google: {} });
		assert.deepEqual(result, { providerName: 'github' });
	});

	it('returns an error when no providers are available', () => {
		const result = selectMCPProvider({}, {});
		assert.ok('error' in result);
		assert.equal(result.error, 'server_error');
	});

	it('returns an error when mcp.providers references nothing valid', () => {
		const result = selectMCPProvider({ providers: ['nonexistent'] }, { github: {} });
		assert.ok('error' in result);
		assert.equal(result.error, 'server_error');
	});

	it('returns an error when multiple providers resolve and the chooser would be needed', () => {
		const result = selectMCPProvider({}, { github: {}, google: {} });
		assert.ok('error' in result);
		assert.match(result.description, /exactly one/);
	});
});

describe('handleAuthorize', () => {
	let originalDatabases;
	let storedClients;

	before(() => {
		originalDatabases = global.databases;
	});

	after(() => {
		global.databases = originalDatabases;
	});

	function encodeClientForStorage(client) {
		// MCPClientStore.decodeRecord expects JSON-encoded array fields — that's
		// what the real Harper table stores. Mirror that representation here so
		// the round-trip matches production.
		const encoded = { ...client };
		for (const field of ['redirect_uris', 'contacts', 'grant_types', 'response_types']) {
			if (Array.isArray(encoded[field])) encoded[field] = JSON.stringify(encoded[field]);
		}
		return encoded;
	}

	beforeEach(() => {
		resetMCPClientsTableCache();
		storedClients = new Map([[VALID_CLIENT.client_id, encodeClientForStorage(VALID_CLIENT)]]);
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: {
					get: async (id) => storedClients.get(id) ?? null,
					put: async () => {},
					delete: async (id) => storedClients.delete(id),
				},
			},
		};
	});

	const validConfig = { enabled: true };
	const newRegistry = () => makeProviderRegistry('github');

	describe('phase 1 — pre-redirect validation (cannot safely redirect)', () => {
		it('rejects missing client_id with 400 JSON', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, client_id: undefined });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_request');
		});

		it('rejects unknown client_id with 400 invalid_client', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, client_id: 'unknown-client' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_client');
		});

		it('rejects unregistered redirect_uri with 400 (no redirect to unverified URI)', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, redirect_uri: 'https://attacker.example.com/steal' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			assert.equal(response.status, 400);
			assert.equal(response.body.error, 'invalid_request');
			assert.match(response.body.error_description, /redirect_uri/);
		});

		it('rejects missing redirect_uri with 400', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, redirect_uri: undefined });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			assert.equal(response.status, 400);
		});
	});

	describe('phase 2 — post-validation redirect to client redirect_uri with error', () => {
		function parseRedirect(response) {
			assert.equal(response.status, 302);
			const url = new URL(response.headers.Location);
			return {
				host: url.host,
				params: Object.fromEntries(url.searchParams),
			};
		}

		it('redirects with unsupported_response_type when response_type is not "code"', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, response_type: 'token' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { host, params } = parseRedirect(response);
			assert.equal(host, 'mcp-client.example.com');
			assert.equal(params.error, 'unsupported_response_type');
			assert.equal(params.state, BASE_QUERY.state, 'client state echoed back');
		});

		it('redirects with invalid_request when PKCE code_challenge missing', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, code_challenge: undefined });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_request');
			assert.match(params.error_description, /code_challenge/);
		});

		it('redirects with invalid_request when code_challenge_method is "plain" (OAuth 2.1 forbids)', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, code_challenge_method: 'plain' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_request');
			assert.match(params.error_description, /S256/);
		});

		it('redirects with invalid_request when code_challenge is too short (RFC 7636 minimum is 43)', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, code_challenge: 'x' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_request');
			assert.match(params.error_description, /code_challenge/);
		});

		it('redirects with invalid_request when code_challenge is too long (RFC 7636 maximum is 128)', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, code_challenge: 'a'.repeat(129) });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_request');
			assert.match(params.error_description, /code_challenge/);
		});

		it('redirects with invalid_request when code_challenge contains chars outside the unreserved set', async () => {
			const { entries } = newRegistry();
			// 43 chars but includes '+' and '/' (base64, not base64url) — RFC 7636 forbids both.
			const target = makeTarget({ ...BASE_QUERY, code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuG+/Sstwcm' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_request');
			assert.match(params.error_description, /code_challenge/);
		});

		it('redirects with invalid_target when resource is missing', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, resource: undefined });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_target');
		});

		it('redirects with invalid_target when resource has a fragment', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, resource: 'https://app.example.com/mcp#frag' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_target');
		});

		it('redirects with invalid_target when resource does not match this server', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, resource: 'https://other-server.example.com/mcp' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'invalid_target');
		});

		it('redirects with server_error when no upstream provider is configured', async () => {
			const target = makeTarget(BASE_QUERY);
			const response = await handleAuthorize(makeRequest(), target, validConfig, {});
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'server_error');
		});

		it('redirects with server_error when multiple upstream providers resolve (v1 single-provider requirement)', async () => {
			const { entries } = makeProviderRegistry('github', 'google');
			const target = makeTarget(BASE_QUERY);
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			const { params } = parseRedirect(response);
			assert.equal(params.error, 'server_error');
		});
	});

	describe('happy path', () => {
		it('redirects to upstream provider with CSRF token carrying MCP state', async () => {
			const { entries, harnesses } = newRegistry();
			const target = makeTarget(BASE_QUERY);
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);

			assert.equal(response.status, 302);
			const upstreamUrl = new URL(response.headers.Location);
			assert.equal(upstreamUrl.host, 'upstream.example.com');

			// The CSRF generation got the MCP state
			assert.equal(harnesses.github.generatedTokens.length, 1);
			const metadata = harnesses.github.generatedTokens[0];
			assert.equal(metadata.providerName, 'github');
			assert.ok(metadata.mcp);
			assert.equal(metadata.mcp.clientId, VALID_CLIENT.client_id);
			assert.equal(metadata.mcp.resource, BASE_QUERY.resource);
			assert.equal(metadata.mcp.codeChallenge, BASE_QUERY.code_challenge);
			assert.equal(metadata.mcp.codeChallengeMethod, 'S256');
			assert.equal(metadata.mcp.redirectUri, BASE_QUERY.redirect_uri);
			assert.equal(metadata.mcp.scope, BASE_QUERY.scope);
			assert.equal(metadata.mcp.clientState, BASE_QUERY.state);
		});

		it('accepts a redirect_uri that matches the registered loopback URI', async () => {
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, redirect_uri: 'http://localhost:6274/cb' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			assert.equal(response.status, 302);
			const url = new URL(response.headers.Location);
			assert.equal(url.host, 'upstream.example.com');
		});

		it('accepts a different port on a registered loopback URI (RFC 8252 §7.3)', async () => {
			const { entries } = newRegistry();
			// Native client registered :6274 but bound to :54321 at runtime
			const target = makeTarget({ ...BASE_QUERY, redirect_uri: 'http://localhost:54321/cb' });
			const response = await handleAuthorize(makeRequest(), target, validConfig, entries);
			assert.equal(response.status, 302, 'loopback port flexibility per RFC 8252 §7.3');
			const url = new URL(response.headers.Location);
			assert.equal(url.host, 'upstream.example.com');
		});

		it('respects an explicitly configured mcp.resource', async () => {
			const { entries } = newRegistry();
			const customResource = 'https://app.example.com/custom-mcp';
			const target = makeTarget({ ...BASE_QUERY, resource: customResource });
			const response = await handleAuthorize(
				makeRequest(),
				target,
				{ enabled: true, resource: customResource },
				entries
			);
			assert.equal(response.status, 302);
			const url = new URL(response.headers.Location);
			assert.equal(url.host, 'upstream.example.com');
		});
	});
});
