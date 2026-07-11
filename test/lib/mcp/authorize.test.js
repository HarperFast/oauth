/**
 * Tests for /oauth/mcp/authorize handler.
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	handleAuthorize,
	handleAuthorizeConfirm,
	redirectUriMatches,
	selectMCPProvider,
	escapeHtml,
	buildInterstitialPage,
} from '../../../dist/lib/mcp/authorize.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';
import { _setDnsLookup, _setFetch, _clearCimdCache } from '../../../dist/lib/mcp/cimd.js';
import { buildConsentCookie, hashConsentNonce } from '../../../dist/lib/mcp/consentBinding.js';

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

	describe('phase 2 — RFC 9207 iss on error redirects', () => {
		it('includes iss matching the configured issuer on a Phase-2 error redirect', async () => {
			const { entries } = newRegistry();
			const configWithIssuer = { enabled: true, issuer: 'https://as.example.com' };
			// Trigger a Phase-2 error (response_type mismatch → redirect, not 400)
			const target = makeTarget({ ...BASE_QUERY, response_type: 'token' });
			const response = await handleAuthorize(makeRequest(), target, configWithIssuer, entries);
			assert.equal(response.status, 302);
			const url = new URL(response.headers.Location);
			assert.equal(url.searchParams.get('iss'), 'https://as.example.com', 'iss must equal the configured issuer');
		});

		it('derives iss from request when issuer is not configured', async () => {
			const { entries } = newRegistry();
			// Trigger a Phase-2 error without a configured issuer
			const target = makeTarget({ ...BASE_QUERY, response_type: 'token' });
			const response = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);
			assert.equal(response.status, 302);
			const url = new URL(response.headers.Location);
			assert.equal(url.searchParams.get('iss'), 'https://app.example.com', 'iss must derive from request scheme+host');
		});

		it('includes iss on all Phase-2 error types (resource mismatch, provider error)', async () => {
			const configWithIssuer = { enabled: true, issuer: 'https://as.example.com' };
			const { entries } = newRegistry();

			// resource mismatch error
			const resourceTarget = makeTarget({ ...BASE_QUERY, resource: 'https://other.example.com/mcp' });
			const resourceResp = await handleAuthorize(makeRequest(), resourceTarget, configWithIssuer, entries);
			assert.equal(new URL(resourceResp.headers.Location).searchParams.get('iss'), 'https://as.example.com');

			// provider selection error
			const noProviderTarget = makeTarget(BASE_QUERY);
			const noProviderResp = await handleAuthorize(makeRequest(), noProviderTarget, configWithIssuer, {});
			assert.equal(new URL(noProviderResp.headers.Location).searchParams.get('iss'), 'https://as.example.com');
		});

		it('does NOT include iss on Phase-1 errors (400 JSON responses)', async () => {
			// Phase-1 errors are 400 JSON, not redirects — iss is only for redirects
			const { entries } = newRegistry();
			const target = makeTarget({ ...BASE_QUERY, client_id: 'unknown-client' });
			const response = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);
			assert.equal(response.status, 400, 'Phase-1 errors are 400 JSON, not redirects');
			assert.ok(!('headers' in response), 'no Location header on Phase-1 errors');
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

// ────────────────────────────────────────────────────────────────────────────
// escapeHtml
// ────────────────────────────────────────────────────────────────────────────

describe('escapeHtml', () => {
	it('escapes all five HTML special characters', () => {
		assert.equal(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
		assert.equal(escapeHtml('"hello"'), '&quot;hello&quot;');
		assert.equal(escapeHtml("it's"), 'it&#39;s');
		assert.equal(escapeHtml('a & b'), 'a &amp; b');
	});

	it('escapes an XSS vector combining multiple specials', () => {
		const xss = '<img src=x onerror=alert(1)>';
		const escaped = escapeHtml(xss);
		assert.ok(!escaped.includes('<'), 'no unescaped <');
		assert.ok(!escaped.includes('>'), 'no unescaped >');
		assert.match(escaped, /&lt;img/);
	});

	it('returns the input unchanged when no special chars present', () => {
		assert.equal(escapeHtml('hello world'), 'hello world');
		assert.equal(escapeHtml('example.com'), 'example.com');
	});
});

// ────────────────────────────────────────────────────────────────────────────
// buildInterstitialPage — XSS prevention
// ────────────────────────────────────────────────────────────────────────────

describe('buildInterstitialPage', () => {
	const safeClient = {
		client_id: 'https://example.com/client.json',
		client_name: 'My App',
		redirect_uris: ['https://example.com/cb'],
	};

	it('renders the client_name and redirect hostname', () => {
		const html = buildInterstitialPage(safeClient, 'https://example.com/cb', 'tok123', '/oauth/mcp/confirm');
		assert.match(html, /My App/);
		assert.match(html, /example\.com/);
	});

	it('escapes XSS in client_name (attacker-controlled field)', () => {
		const maliciousClient = {
			...safeClient,
			client_name: '<script>alert(1)</script><img onerror="steal()">',
		};
		const html = buildInterstitialPage(maliciousClient, 'https://example.com/cb', 'tok', '/oauth/mcp/confirm');
		// Raw opening tags must not be present — after escaping, <script becomes &lt;script
		// and <img becomes &lt;img, so neither tag can execute.
		assert.ok(!html.includes('<script'), 'raw <script tag must not appear in output');
		assert.ok(!html.includes('<img'), 'raw <img tag must not appear in output');
		assert.match(html, /&lt;script/);
	});

	it('includes the confirm_token in the form', () => {
		const html = buildInterstitialPage(safeClient, 'https://example.com/cb', 'my-token-value', '/oauth/mcp/confirm');
		assert.match(html, /name="confirm_token"/);
		assert.match(html, /value="my-token-value"/);
	});

	it('includes a loopback warning when redirect is to localhost', () => {
		const html = buildInterstitialPage(safeClient, 'http://localhost:6274/cb', 'tok', '/oauth/mcp/confirm');
		assert.match(html, /Warning/i);
		assert.match(html, /loopback|local process/i);
	});

	it('does NOT include a loopback warning for non-loopback redirects', () => {
		const html = buildInterstitialPage(safeClient, 'https://example.com/cb', 'tok', '/oauth/mcp/confirm');
		assert.ok(!html.includes('Warning') || !html.includes('loopback'), 'no loopback warning for external redirect');
	});

	it('renders defensively when redirect_uri is unparseable (no throw)', () => {
		const client = { client_id: 'client-x', client_name: 'App', redirect_uris: [] };
		const html = buildInterstitialPage(client, 'not-a-valid-url', 'tok', '/oauth/mcp/confirm');
		assert.match(html, /not-a-valid-url/);
	});

	it('escapes the confirm_token value (defense-in-depth)', () => {
		const dangerousToken = 'tok"><script>evil()</script>';
		const html = buildInterstitialPage(safeClient, 'https://example.com/cb', dangerousToken, '/oauth/mcp/confirm');
		assert.ok(!html.includes('<script>evil()'), 'token value must be escaped in HTML attribute');
	});
});

// ────────────────────────────────────────────────────────────────────────────
// handleAuthorize — CIMD interstitial path
// ────────────────────────────────────────────────────────────────────────────

describe('handleAuthorize — CIMD interstitial', () => {
	let originalDatabases;

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		_clearCimdCache();
		resetMCPClientsTableCache();
		// Empty DCR store — all clients are CIMD.
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: {
					get: async () => null,
					put: async () => {},
					delete: async () => {},
				},
			},
		};
		// Stub DNS and fetch so CIMD resolution succeeds.
		_setDnsLookup(async () => [{ address: '1.2.3.4', family: 4 }]);
	});

	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
	});

	function makeCimdDoc(clientId, overrides = {}) {
		return {
			client_id: clientId,
			client_name: 'CIMD Test App',
			redirect_uris: ['https://mcp-client.example.com/cb'],
			...overrides,
		};
	}

	function makeCimdFetch(doc) {
		return async () => {
			const body = JSON.stringify(doc);
			const bytes = Buffer.from(body);
			return {
				ok: true,
				status: 200,
				headers: new Map([['content-type', 'application/json']]),
				body: {
					getReader: () => {
						let sent = false;
						return {
							read: async () => (sent ? { done: true } : ((sent = true), { done: false, value: bytes })),
							cancel: () => {},
						};
					},
				},
			};
		};
	}

	const CIMD_CLIENT_ID = 'https://mcp-client.example.com/client.json';
	const CIMD_QUERY = {
		...BASE_QUERY,
		client_id: CIMD_CLIENT_ID,
		redirect_uri: 'https://mcp-client.example.com/cb',
		resource: 'https://app.example.com/mcp',
	};

	it('surfaces 429 + Retry-After when the CIMD fetch rate limit trips', async () => {
		// A doc whose client_id doesn't match the URL fails validation and is not
		// cached, so each attempt re-fetches and spends a fetch-limiter token
		// (fixed 10/min per URL). The 11th is throttled and must reach the client
		// as a 429 slow_down with a Retry-After header, not a 400/401.
		_setFetch(makeCimdFetch(makeCimdDoc('https://mcp-client.example.com/mismatch.json')));
		const { entries } = makeProviderRegistry('github');
		const target = makeTarget(CIMD_QUERY);
		for (let i = 0; i < 10; i++) {
			const r = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);
			assert.equal(r.status, 400, `attempt ${i + 1} fails validation (token consumed)`);
		}
		const limited = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);
		assert.equal(limited.status, 429);
		assert.equal(limited.body.error, 'slow_down');
		assert.ok(limited.headers?.['Retry-After'], 'carries a Retry-After header');
	});

	it('returns 200 HTML interstitial page for a CIMD client (not 302)', async () => {
		_setFetch(makeCimdFetch(makeCimdDoc(CIMD_CLIENT_ID)));
		const { entries } = makeProviderRegistry('github');
		const target = makeTarget(CIMD_QUERY);
		const response = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);

		assert.equal(response.status, 200);
		assert.match(response.headers['Content-Type'], /text\/html/);
		assert.match(response.body, /CIMD Test App/);
		assert.match(response.body, /mcp-client\.example\.com/);
		assert.match(response.body, /confirm_token/);
		assert.ok(!response.body.includes('<script>'), 'no raw script tags');
	});

	it('serves the interstitial with anti-clickjacking and no-store headers', async () => {
		_setFetch(makeCimdFetch(makeCimdDoc(CIMD_CLIENT_ID)));
		const { entries } = makeProviderRegistry('github');
		const response = await handleAuthorize(makeRequest(), makeTarget(CIMD_QUERY), { enabled: true }, entries);

		assert.equal(response.status, 200);
		assert.equal(response.headers['X-Frame-Options'], 'DENY');
		assert.match(response.headers['Content-Security-Policy'], /frame-ancestors 'none'/);
		assert.equal(response.headers['Cache-Control'], 'no-store');
	});

	it('sets the consent cookie whose hash is bound into the confirm token state', async () => {
		_setFetch(makeCimdFetch(makeCimdDoc(CIMD_CLIENT_ID)));
		const { entries, harnesses } = makeProviderRegistry('github');
		const response = await handleAuthorize(makeRequest(), makeTarget(CIMD_QUERY), { enabled: true }, entries);

		const setCookie = response.headers['Set-Cookie'];
		assert.ok(setCookie, 'interstitial sets the consent cookie');
		assert.match(setCookie, /^__Host-mcp_consent_[A-Za-z0-9_-]+=/, 'per-flow __Host- cookie');
		assert.match(setCookie, /HttpOnly/);
		assert.match(setCookie, /Secure/);
		assert.match(setCookie, /SameSite=Lax/);
		assert.doesNotMatch(setCookie, /Domain=/i, '__Host- forbids Domain (blocks sibling injection)');

		const [cookieName, nonce] = setCookie.split(';')[0].split('=');
		const flowId = cookieName.replace('__Host-mcp_consent_', '');
		const minted = harnesses.github.generatedTokens[0];
		assert.equal(minted._confirm, true);
		assert.equal(minted.mcp.consentFlowId, flowId, 'state carries the cookie flow id');
		assert.equal(minted.mcp.browserNonceHash, hashConsentNonce(nonce), 'state carries sha256(cookie nonce)');
	});

	it('displays the authoritative client_id hostname and labels client_uri unverified', async () => {
		const doc = makeCimdDoc(CIMD_CLIENT_ID, {
			redirect_uris: ['https://other-app.example.net/cb'],
			client_uri: 'https://claimed-brand.example.org/',
		});
		_setFetch(makeCimdFetch(doc));
		const { entries } = makeProviderRegistry('github');
		const target = makeTarget({ ...CIMD_QUERY, redirect_uri: 'https://other-app.example.net/cb' });
		const response = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);

		assert.equal(response.status, 200);
		assert.match(response.body, /Client identity: <strong>mcp-client\.example\.com<\/strong>/);
		assert.match(response.body, /Redirect hostname: <strong>other-app\.example\.net<\/strong>/);
		assert.match(response.body, /unverified.*claimed-brand\.example\.org/i);
	});

	it('includes a loopback warning when the CIMD redirect is to localhost', async () => {
		const doc = makeCimdDoc(CIMD_CLIENT_ID, { redirect_uris: ['http://localhost:6274/cb'] });
		_setFetch(makeCimdFetch(doc));
		const { entries } = makeProviderRegistry('github');
		const target = makeTarget({ ...CIMD_QUERY, redirect_uri: 'http://localhost:6274/cb' });
		const response = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);

		assert.equal(response.status, 200);
		assert.match(response.body, /Warning|loopback/i);
	});

	it('stored/DCR clients bypass the interstitial and redirect directly (302)', async () => {
		// Put a DCR client in the store
		const dcrClient = VALID_CLIENT;
		resetMCPClientsTableCache();
		const storedClients = new Map([
			[
				dcrClient.client_id,
				(() => {
					const e = { ...dcrClient };
					for (const f of ['redirect_uris', 'grant_types', 'response_types']) {
						if (Array.isArray(e[f])) e[f] = JSON.stringify(e[f]);
					}
					return e;
				})(),
			],
		]);
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: {
					get: async (id) => storedClients.get(id) ?? null,
					put: async () => {},
					delete: async () => {},
				},
			},
		};
		const { entries } = makeProviderRegistry('github');
		const target = makeTarget(BASE_QUERY); // uses VALID_CLIENT.client_id
		const response = await handleAuthorize(makeRequest(), target, { enabled: true }, entries);

		assert.equal(response.status, 302, 'DCR client gets a direct redirect, no interstitial');
		assert.match(response.headers.Location, /upstream\.example\.com/);
	});
});

// ────────────────────────────────────────────────────────────────────────────
// handleAuthorizeConfirm
// ────────────────────────────────────────────────────────────────────────────

describe('handleAuthorizeConfirm', () => {
	const NONCE = 'test-consent-nonce';
	const FLOW_ID = 'testflowid';
	const MCP_STATE = {
		clientId: 'https://mcp-client.example.com/client.json',
		resource: 'https://app.example.com/mcp',
		codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
		codeChallengeMethod: 'S256',
		redirectUri: 'https://mcp-client.example.com/cb',
		scope: 'mcp:read',
		clientState: 'state-xyz',
		browserNonceHash: hashConsentNonce(NONCE),
		consentFlowId: FLOW_ID,
	};

	/** Request carrying the per-flow consent nonce cookie, as the interstitial browser would. */
	function makeConsentRequest(nonce = NONCE, flowId = FLOW_ID) {
		return makeRequest({
			headers: { host: 'app.example.com', cookie: `other=1; ${buildConsentCookie(flowId, nonce).split(';')[0]}` },
		});
	}

	function makeProviderWithCsrf(name = 'github') {
		// Simulate a simple token store: issued → consumed single-use.
		const issued = new Map();
		let counter = 0;
		const provider = {
			generateCSRFToken: async (metadata) => {
				const token = `csrf-${++counter}`;
				issued.set(token, metadata);
				return token;
			},
			verifyCSRFToken: async (token) => {
				const data = issued.get(token);
				if (!data) return null;
				issued.delete(token); // single-use
				return data;
			},
			getAuthorizationUrl: (state) => `https://upstream.example.com/authorize?state=${encodeURIComponent(state)}`,
		};
		return {
			entries: {
				[name]: { provider, config: { provider: name, redirectUri: 'https://app.example.com/oauth/callback' } },
			},
			provider,
		};
	}

	it('rejects missing confirm_token with 400', async () => {
		const { entries } = makeProviderWithCsrf();
		const result = await handleAuthorizeConfirm(makeRequest(), {}, { enabled: true }, entries);
		assert.equal(result.status, 400);
		assert.match(result.body.error_description, /confirm_token/);
	});

	it('rejects an invalid/unknown token with 400', async () => {
		const { entries } = makeProviderWithCsrf();
		const result = await handleAuthorizeConfirm(
			makeRequest(),
			{ confirm_token: 'not-a-real-token' },
			{ enabled: true },
			entries
		);
		assert.equal(result.status, 400);
		assert.equal(result.body.error, 'invalid_request');
	});

	it('valid token + matching consent cookie → 302 redirect to upstream IdP with MCP state', async () => {
		const { entries, provider } = makeProviderWithCsrf();
		// Mint a confirm token as handleAuthorize would.
		const token = await provider.generateCSRFToken({
			providerName: 'github',
			mcp: MCP_STATE,
			_confirm: true,
		});

		const result = await handleAuthorizeConfirm(
			makeConsentRequest(),
			{ confirm_token: token },
			{ enabled: true },
			entries
		);
		assert.equal(result.status, 302);
		assert.match(result.headers.Location, /upstream\.example\.com/);
	});

	it('token is single-use: second confirm returns 400', async () => {
		const { entries, provider } = makeProviderWithCsrf();
		const token = await provider.generateCSRFToken({
			providerName: 'github',
			mcp: MCP_STATE,
			_confirm: true,
		});

		const first = await handleAuthorizeConfirm(
			makeConsentRequest(),
			{ confirm_token: token },
			{ enabled: true },
			entries
		);
		assert.equal(first.status, 302, 'first confirm succeeds');

		const second = await handleAuthorizeConfirm(
			makeConsentRequest(),
			{ confirm_token: token },
			{ enabled: true },
			entries
		);
		assert.equal(second.status, 400, 'second confirm rejected (token consumed)');
	});

	it('rejects a token without the _confirm marker (prevents CSRF token abuse)', async () => {
		const { entries, provider } = makeProviderWithCsrf();
		// Mint a regular authorize CSRF token (no _confirm).
		const token = await provider.generateCSRFToken({
			providerName: 'github',
			mcp: MCP_STATE,
			// Note: no _confirm: true
		});

		const result = await handleAuthorizeConfirm(
			makeConsentRequest(),
			{ confirm_token: token },
			{ enabled: true },
			entries
		);
		assert.equal(result.status, 400);
		assert.match(result.body.error_description, /Invalid confirm token/);
	});

	it('rejects a confirm without the consent cookie — the malicious client cannot self-approve', async () => {
		const { entries, provider } = makeProviderWithCsrf();
		const token = await provider.generateCSRFToken({
			providerName: 'github',
			mcp: MCP_STATE,
			_confirm: true,
		});

		// No cookie header at all (e.g. the client POSTs the token server-side).
		const result = await handleAuthorizeConfirm(makeRequest(), { confirm_token: token }, { enabled: true }, entries);
		assert.equal(result.status, 400);
		assert.match(result.body.error_description, /browser/);
	});

	it('rejects a confirm with a non-matching consent cookie', async () => {
		const { entries, provider } = makeProviderWithCsrf();
		const token = await provider.generateCSRFToken({
			providerName: 'github',
			mcp: MCP_STATE,
			_confirm: true,
		});

		const result = await handleAuthorizeConfirm(
			makeConsentRequest('a-different-nonce'),
			{ confirm_token: token },
			{ enabled: true },
			entries
		);
		assert.equal(result.status, 400);
		assert.match(result.body.error_description, /browser/);
	});

	it('rejects a confirm token minted without a browser binding', async () => {
		const { entries, provider } = makeProviderWithCsrf();
		const unboundState = { ...MCP_STATE };
		delete unboundState.browserNonceHash;
		const token = await provider.generateCSRFToken({
			providerName: 'github',
			mcp: unboundState,
			_confirm: true,
		});

		const result = await handleAuthorizeConfirm(
			makeConsentRequest(),
			{ confirm_token: token },
			{ enabled: true },
			entries
		);
		assert.equal(result.status, 400, 'unbound confirm tokens are never accepted');
	});
});
