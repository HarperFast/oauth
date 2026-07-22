/**
 * Tests for MCP well-known metadata endpoints (RFCs 8414, 9728).
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	buildAuthorizationServerMetadata,
	buildJWKS,
	buildProtectedResourceMetadata,
	registerWellKnownHandlers,
	resolveIssuer,
	resolveResource,
} from '../../../dist/lib/mcp/wellKnown.js';
import { resetMCPKeysTableCache } from '../../../dist/lib/mcp/keyStore.js';
import { generateKeyPairSync } from 'node:crypto';

// Bun runs every test file in ONE shared process (Node isolates per file). The
// JWKS tests below assert an EMPTY key set, which relies on the MCPKeyStore
// module-level table cache being clear — a prior file that minted a signing key
// would otherwise leak its cached table here and these tests would see that
// key. Reset the cache before every test so they're order-independent.
beforeEach(() => resetMCPKeysTableCache());

function makeRequest(overrides = {}) {
	return {
		pathname: '/.well-known/oauth-protected-resource',
		protocol: 'https',
		host: 'app.example.com',
		headers: { host: 'app.example.com' },
		...overrides,
	};
}

describe('MCP well-known: URI resolution', () => {
	it('resolveIssuer uses configured value when set', async () => {
		const req = makeRequest();
		const issuer = resolveIssuer(req, { issuer: 'https://canonical.example.com' });
		assert.equal(issuer, 'https://canonical.example.com');
	});

	it('resolveIssuer derives from request scheme + host when unset', async () => {
		const req = makeRequest({ protocol: 'https', host: 'auto.example.com' });
		assert.equal(resolveIssuer(req, {}), 'https://auto.example.com');
	});

	it('resolveIssuer takes the first value when the Host header is an array', async () => {
		const req = makeRequest({ protocol: 'https', host: undefined, headers: { host: ['first.example.com', 'second'] } });
		assert.equal(resolveIssuer(req, {}), 'https://first.example.com');
	});

	it('resolveResource uses configured value when set', async () => {
		const req = makeRequest();
		const resource = resolveResource(req, { resource: 'https://canonical.example.com/mcp-v2' });
		assert.equal(resource, 'https://canonical.example.com/mcp-v2');
	});

	it('resolveResource derives <issuer>/mcp when unset', async () => {
		const req = makeRequest({ protocol: 'https', host: 'derived.example.com' });
		assert.equal(resolveResource(req, {}), 'https://derived.example.com/mcp');
	});

	it('resolveResource respects configured issuer when resource is unset', async () => {
		const req = makeRequest();
		const resource = resolveResource(req, { issuer: 'https://forced.example.com' });
		assert.equal(resource, 'https://forced.example.com/mcp');
	});
});

describe('MCP well-known: PRM document (RFC 9728)', () => {
	it('includes required fields: resource + authorization_servers', async () => {
		const doc = buildProtectedResourceMetadata(makeRequest(), { enabled: true });
		assert.equal(doc.resource, 'https://app.example.com/mcp');
		assert.deepEqual(doc.authorization_servers, ['https://app.example.com']);
	});

	it('advertises header-based bearer method only (no query-string)', async () => {
		const doc = buildProtectedResourceMetadata(makeRequest(), { enabled: true });
		assert.deepEqual(doc.bearer_methods_supported, ['header']);
	});

	it('reflects configured canonical resource URI verbatim', async () => {
		const doc = buildProtectedResourceMetadata(makeRequest(), {
			enabled: true,
			resource: 'https://my-app.example.com/mcp',
		});
		assert.equal(doc.resource, 'https://my-app.example.com/mcp');
	});
});

describe('MCP well-known: AS metadata document (RFC 8414)', () => {
	it('includes spec-required endpoints', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.equal(doc.issuer, 'https://app.example.com');
		assert.equal(doc.authorization_endpoint, 'https://app.example.com/oauth/mcp/authorize');
		assert.equal(doc.token_endpoint, 'https://app.example.com/oauth/mcp/token');
		assert.equal(doc.jwks_uri, 'https://app.example.com/.well-known/jwks.json');
	});

	it('omits registration_endpoint when the DCR block is absent (default disabled, #182)', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.equal(doc.registration_endpoint, undefined);
	});

	it('advertises registration_endpoint under the same predicate the handler enforces', async () => {
		const withBlock = await buildAuthorizationServerMetadata(makeRequest(), {
			enabled: true,
			dynamicClientRegistration: {},
		});
		assert.equal(withBlock.registration_endpoint, 'https://app.example.com/oauth/mcp/register');

		const explicitlyDisabled = await buildAuthorizationServerMetadata(makeRequest(), {
			enabled: true,
			dynamicClientRegistration: { enabled: false },
		});
		assert.equal(explicitlyDisabled.registration_endpoint, undefined);
	});

	it('omits registration_endpoint for a bare null DCR block (YAML empty key)', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), {
			enabled: true,
			dynamicClientRegistration: null,
		});
		assert.equal(doc.registration_endpoint, undefined);
	});

	it('advertises PKCE S256 only (no plain)', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
	});

	it('advertises only authorization_code + refresh_token grants', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.deepEqual(doc.grant_types_supported, ['authorization_code', 'refresh_token']);
	});

	it('advertises client_credentials + private_key_jwt + EdDSA only when the grant is enabled', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), {
			enabled: true,
			clientCredentials: { enabled: true },
		});
		assert.ok(doc.grant_types_supported.includes('client_credentials'));
		assert.ok(doc.token_endpoint_auth_methods_supported.includes('private_key_jwt'));
		assert.deepEqual(doc.token_endpoint_auth_signing_alg_values_supported, ['EdDSA']);
	});

	it('omits client_credentials discovery when the grant is disabled or unset', async () => {
		for (const mcpConfig of [{ enabled: true }, { enabled: true, clientCredentials: { enabled: false } }]) {
			const doc = await buildAuthorizationServerMetadata(makeRequest(), mcpConfig);
			assert.ok(!doc.grant_types_supported.includes('client_credentials'));
			assert.ok(!doc.token_endpoint_auth_methods_supported.includes('private_key_jwt'));
			assert.equal(doc.token_endpoint_auth_signing_alg_values_supported, undefined);
		}
	});

	it('advertises only `code` response type', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.deepEqual(doc.response_types_supported, ['code']);
	});

	it('advertises token-endpoint auth methods including the public-client default', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		const methods = doc.token_endpoint_auth_methods_supported;
		assert.ok(methods.includes('none'), 'public clients (none) must be advertised');
		assert.ok(methods.includes('client_secret_basic'));
		assert.ok(methods.includes('client_secret_post'));
	});

	it('advertises RS256 as the signing algorithm by default (EdDSA deferred)', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.deepEqual(doc.id_token_signing_alg_values_supported, ['RS256']);
	});

	it('advertises ES256 when mcp.signingAlgorithm is ES256 (#127)', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true, signingAlgorithm: 'ES256' });
		assert.deepEqual(doc.id_token_signing_alg_values_supported, ['ES256']);
	});

	it('advertises both algs while an old-alg key is still live in the key set (P1, #191 review)', async () => {
		// During the alg-switch damper window an RS256 key keeps signing while
		// config says ES256 — metadata must reflect both, not just the config.
		const { publicKey, privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const originalDatabases = global.databases;
		global.databases = {
			oauth: {
				harper_oauth_mcp_keys: {
					search: async function* () {
						yield {
							kid: 'rsa-live',
							alg: 'RS256',
							public_key_pem: publicKey,
							private_key_pem: privateKey,
							created_at: Math.floor(Date.now() / 1000),
						};
					},
				},
			},
		};
		try {
			const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true, signingAlgorithm: 'ES256' });
			assert.deepEqual(doc.id_token_signing_alg_values_supported, ['ES256', 'RS256']);
		} finally {
			global.databases = originalDatabases;
		}
	});

	it("advertises the pinned key's algorithm over mcp.signingAlgorithm (pin wins)", async () => {
		const { privateKey } = generateKeyPairSync('ec', {
			namedCurve: 'P-256',
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true, signingKeyPem: privateKey });
		assert.deepEqual(doc.id_token_signing_alg_values_supported, ['ES256']);
	});

	it('signals RFC 8707 resource-parameter support', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.equal(doc.resource_parameter_supported, true);
	});

	it('signals RFC 9207 authorization_response_iss_parameter_supported', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.equal(doc.authorization_response_iss_parameter_supported, true);
	});

	it('advertises client_id_metadata_document_supported when CIMD is enabled (default)', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), { enabled: true });
		assert.equal(doc.client_id_metadata_document_supported, true);
	});

	it('does not advertise client_id_metadata_document_supported when CIMD is explicitly disabled', async () => {
		const doc = await buildAuthorizationServerMetadata(makeRequest(), {
			enabled: true,
			clientIdMetadataDocuments: { enabled: false },
		});
		assert.ok(
			!('client_id_metadata_document_supported' in doc) || doc.client_id_metadata_document_supported === false,
			'CIMD flag must be absent or false when disabled'
		);
	});
});

describe('MCP well-known: JWKS document', () => {
	it('returns an empty key set when no signing key has been minted yet', async () => {
		const doc = await buildJWKS({ enabled: true });
		assert.deepEqual(doc, { keys: [] });
	});
});

describe('MCP well-known: handler registration', () => {
	let registrations;
	let mockServer;
	let currentConfig;
	let getConfig;

	beforeEach(() => {
		registrations = [];
		mockServer = {
			http: (handler, options) => {
				registrations.push({ handler, options });
			},
		};
		currentConfig = undefined;
		getConfig = () => currentConfig;
	});

	it('registers three handlers with the expected urlPaths', async () => {
		registerWellKnownHandlers(mockServer, getConfig);
		assert.equal(registrations.length, 3);
		const paths = registrations.map((r) => r.options.urlPath).sort();
		assert.deepEqual(paths, [
			'/.well-known/jwks.json',
			'/.well-known/oauth-authorization-server',
			'/.well-known/oauth-protected-resource',
		]);
	});

	it('logs and skips when server.http() is not available', async () => {
		const warnings = [];
		const logger = { warn: (msg) => warnings.push(msg) };
		registerWellKnownHandlers({}, getConfig, logger);
		assert.equal(registrations.length, 0);
		assert.ok(warnings.some((w) => w.includes('server.http')));
	});

	describe('handler behavior at request time', () => {
		beforeEach(() => {
			registerWellKnownHandlers(mockServer, getConfig);
		});

		function findHandler(urlPath) {
			const reg = registrations.find((r) => r.options.urlPath === urlPath);
			return reg.handler;
		}

		it('falls through to next when MCP is disabled', async () => {
			currentConfig = { enabled: false };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			let nextCalled = false;
			const next = () => {
				nextCalled = true;
				return 'fallthrough';
			};
			const result = await handler(makeRequest(), next);
			assert.equal(nextCalled, true);
			assert.equal(result, 'fallthrough');
		});

		it('falls through to next when config is undefined', async () => {
			currentConfig = undefined;
			const handler = findHandler('/.well-known/oauth-authorization-server');
			let nextCalled = false;
			const next = () => {
				nextCalled = true;
				return 'fallthrough';
			};
			handler(makeRequest({ pathname: '/.well-known/oauth-authorization-server' }), next);
			assert.equal(nextCalled, true);
		});

		it('falls through to next on sub-paths (urlPath is prefix-matched)', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			let nextCalled = false;
			const next = () => {
				nextCalled = true;
				return null;
			};
			handler(makeRequest({ pathname: '/.well-known/oauth-protected-resource/extra' }), next);
			assert.equal(nextCalled, true, 'sub-paths should fall through, not be served');
		});

		// Harper's server.http({ urlPath }) mounts the handler at urlPath and
		// passes the path RELATIVE to it: '/' for an exact match, '/sub' for a
		// sub-path. The exact-path check must accept the relative '/' form.
		it('serves on the relative "/" path (Harper passes path relative to urlPath)', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-authorization-server');
			const response = await handler(makeRequest({ pathname: '/' }), () => null);
			assert.equal(response.status, 200, 'relative "/" exact match should be served');
		});

		it('falls through on a relative sub-path ("/extra")', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			let nextCalled = false;
			const next = () => {
				nextCalled = true;
				return null;
			};
			handler(makeRequest({ pathname: '/extra' }), next);
			assert.equal(nextCalled, true, 'relative sub-paths should fall through, not be served');
		});

		// RFC 9728 §3.1: for a resource with a path (here <issuer>/mcp), the PRM is
		// ALSO served at /.well-known/oauth-protected-resource/<resource-path>.
		// MCP clients (Claude.ai) construct that path-appended URL and fetch it
		// rather than the bare host-root form. Harper passes the path relative to
		// the mount, so the appended form arrives as the resource path ("/mcp").
		it('serves the path-appended PRM on the relative resource path ("/mcp")', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const response = await handler(makeRequest({ pathname: '/mcp' }), () => null);
			assert.equal(response.status, 200, 'path-appended PRM should be served');
			const body = JSON.parse(response.body);
			assert.equal(body.resource, 'https://app.example.com/mcp');
		});

		it('serves the path-appended PRM on the absolute form (older builds)', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const response = await handler(
				makeRequest({ pathname: '/.well-known/oauth-protected-resource/mcp' }),
				() => null
			);
			assert.equal(response.status, 200);
		});

		it('honors a configured resource path for the appended PRM', async () => {
			currentConfig = { enabled: true, resource: 'https://app.example.com/mcp-v2' };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const served = await handler(makeRequest({ pathname: '/mcp-v2' }), () => null);
			assert.equal(served.status, 200, 'configured resource path is served');
			// A different sub-path (the default "/mcp") must NOT match when resource is /mcp-v2.
			let nextCalled = false;
			await handler(makeRequest({ pathname: '/mcp' }), () => {
				nextCalled = true;
				return null;
			});
			assert.equal(nextCalled, true, 'non-resource sub-path still falls through');
		});

		// A trailing slash on the configured resource (e.g. https://host/mcp/) must
		// still serve the path-appended PRM: an RFC 9728 §3.1 client inserts the
		// full path component and fetches `/mcp/`. The request-path trailing slash
		// is normalized so it matches the (already-stripped) resource path.
		it('serves the appended PRM when the configured resource has a trailing slash', async () => {
			currentConfig = { enabled: true, resource: 'https://app.example.com/mcp/' };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const served = await handler(makeRequest({ pathname: '/mcp/' }), () => null);
			assert.equal(served.status, 200, 'trailing-slash resource path is served');
			// The slash-less form must match too (clients may send either).
			const alsoServed = await handler(makeRequest({ pathname: '/mcp' }), () => null);
			assert.equal(alsoServed.status, 200, 'slash-less form of the same resource is served');
		});

		it('only the PRM is resource-path-aware (AS metadata sub-path 404s)', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-authorization-server');
			let nextCalled = false;
			handler(makeRequest({ pathname: '/mcp' }), () => {
				nextCalled = true;
				return null;
			});
			assert.equal(nextCalled, true, 'AS-metadata is not resource-path-aware');
		});

		it('falls back to req.url when pathname is absent', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/jwks.json');
			const response = await handler(makeRequest({ pathname: undefined, url: '/' }), () => null);
			assert.equal(response.status, 200, 'should resolve the path from req.url when pathname is missing');
		});

		it('serves PRM as JSON with Content-Type when enabled and path matches', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const response = await handler(makeRequest(), () => null);
			assert.equal(response.status, 200);
			assert.equal(response.headers['Content-Type'], 'application/json');
			const body = JSON.parse(response.body);
			assert.equal(body.resource, 'https://app.example.com/mcp');
			assert.deepEqual(body.authorization_servers, ['https://app.example.com']);
		});

		it('serves PRM with CORS headers so browser MCP clients can fetch cross-origin', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const response = await handler(makeRequest(), () => null);
			assert.equal(response.headers['Access-Control-Allow-Origin'], '*');
			assert.equal(response.headers['Access-Control-Allow-Methods'], 'GET, OPTIONS');
		});

		it('serves AS metadata and JWKS with the same CORS headers', async () => {
			currentConfig = { enabled: true };
			for (const path of ['/.well-known/oauth-authorization-server', '/.well-known/jwks.json']) {
				const handler = findHandler(path);
				const response = await handler(makeRequest({ pathname: path }), () => null);
				assert.equal(response.headers['Access-Control-Allow-Origin'], '*', `${path} should set CORS`);
				assert.equal(response.headers['Access-Control-Allow-Methods'], 'GET, OPTIONS');
			}
		});

		it('serves AS metadata as JSON with Content-Type when path matches', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-authorization-server');
			const response = await handler(makeRequest({ pathname: '/.well-known/oauth-authorization-server' }), () => null);
			assert.equal(response.status, 200);
			assert.equal(response.headers['Content-Type'], 'application/json');
			const body = JSON.parse(response.body);
			assert.equal(body.issuer, 'https://app.example.com');
			assert.deepEqual(body.code_challenge_methods_supported, ['S256']);
		});

		it('serves JWKS as JSON with empty keys', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/jwks.json');
			const response = await handler(makeRequest({ pathname: '/.well-known/jwks.json' }), () => null);
			assert.equal(response.status, 200);
			assert.equal(response.headers['Content-Type'], 'application/json');
			assert.deepEqual(JSON.parse(response.body), { keys: [] });
		});

		it('falls back to localhost when the request omits scheme/host', async () => {
			currentConfig = { enabled: true };
			const handler = findHandler('/.well-known/oauth-protected-resource');
			const response = await handler({ pathname: '/.well-known/oauth-protected-resource' }, () => null);
			assert.equal(response.status, 200);
			const body = JSON.parse(response.body);
			assert.equal(body.resource, 'https://localhost/mcp');
			assert.deepEqual(body.authorization_servers, ['https://localhost']);
		});
	});
});
