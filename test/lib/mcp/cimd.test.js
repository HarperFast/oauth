/**
 * Tests for CIMD (Client ID Metadata Document) resolution.
 *
 * Covers:
 * - isCimdClientId URL-shape detection
 * - resolveCimdClient: allowedHosts policy, SSRF DNS gate, fetch,
 *   document validation, cache (TTL honoring, negative cache)
 * - resolveClient routing (CIMD vs DCR)
 * - CimdClientError typing
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	isCimdClientId,
	resolveCimdClient,
	resolveClient,
	CimdClientError,
	_setDnsLookup,
	_setFetch,
	_clearCimdCache,
} from '../../../dist/lib/mcp/cimd.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';

// Helpers
function makeOkFetch(body, options = {}) {
	return async () => {
		const text = typeof body === 'string' ? body : JSON.stringify(body);
		const bytes = Buffer.from(text);
		return {
			ok: true,
			status: 200,
			headers: new Map(
				Object.entries({
					'content-type': options.contentType ?? 'application/json',
					'cache-control': options.cacheControl ?? null,
					'content-length': String(bytes.length),
				}).filter(([, v]) => v !== null)
			),
			body: {
				getReader: () => {
					let sent = false;
					return {
						read: async () => {
							if (!sent) {
								sent = true;
								return { done: false, value: bytes };
							}
							return { done: true, value: undefined };
						},
						cancel: () => {},
					};
				},
			},
		};
	};
}

function makeDnsOk(addresses = [{ address: '1.2.3.4', family: 4 }]) {
	return async () => addresses;
}

const VALID_DOC = {
	client_id: 'https://example.com/client.json',
	client_name: 'Test App',
	redirect_uris: ['https://example.com/cb'],
};

const VALID_URL = 'https://example.com/client.json';

describe('isCimdClientId', () => {
	it('accepts https URLs with a non-root path', () => {
		assert.equal(isCimdClientId('https://example.com/client.json'), true);
		assert.equal(isCimdClientId('https://example.com/apps/my-app/client'), true);
	});

	it('rejects non-https schemes', () => {
		assert.equal(isCimdClientId('http://example.com/client.json'), false);
		assert.equal(isCimdClientId('ftp://example.com/client.json'), false);
	});

	it('rejects root-only path', () => {
		assert.equal(isCimdClientId('https://example.com'), false);
		assert.equal(isCimdClientId('https://example.com/'), false);
	});

	it('rejects URLs with userinfo', () => {
		assert.equal(isCimdClientId('https://user:pass@example.com/client.json'), false);
		assert.equal(isCimdClientId('https://user@example.com/client.json'), false);
	});

	it('rejects URLs with a fragment', () => {
		assert.equal(isCimdClientId('https://example.com/client.json#section'), false);
	});

	it('rejects IPv4 literal hosts', () => {
		assert.equal(isCimdClientId('https://192.168.1.1/client.json'), false);
		assert.equal(isCimdClientId('https://127.0.0.1/client.json'), false);
		assert.equal(isCimdClientId('https://1.2.3.4/client.json'), false);
	});

	it('rejects IPv6 literal hosts', () => {
		assert.equal(isCimdClientId('https://[::1]/client.json'), false);
		assert.equal(isCimdClientId('https://[2001:db8::1]/client.json'), false);
	});

	it('rejects non-URLs', () => {
		assert.equal(isCimdClientId('uuid-style-client-id'), false);
		assert.equal(isCimdClientId('not-a-url'), false);
		assert.equal(isCimdClientId(''), false);
	});

	it('DCR-issued UUIDs are not CIMD', () => {
		assert.equal(isCimdClientId('a1b2c3d4-e5f6-7890-abcd-ef1234567890'), false);
	});
});

describe('resolveCimdClient — SSRF DNS gate', () => {
	beforeEach(() => _clearCimdCache());
	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
	});

	it('rejects private IPv4 addresses (loopback, RFC1918, link-local)', async () => {
		for (const address of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.1.1']) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk([{ address, family: 4 }]));
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, undefined),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected CimdClientError for ${address}`);
					assert.match(err.message, /private/, `expected 'private' in error for ${address}`);
					return true;
				}
			);
		}
	});

	it('rejects private IPv6 addresses (::1, fc00::/7, fe80::/10, ::ffff:)', async () => {
		for (const address of ['::1', 'fc00::1', 'fd12::abcd', 'fe80::1', '::ffff:192.168.1.1']) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk([{ address, family: 6 }]));
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, undefined),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected CimdClientError for ${address}`);
					return true;
				}
			);
		}
	});

	it('allows public IPv4 addresses', async () => {
		_setDnsLookup(makeDnsOk([{ address: '93.184.216.34', family: 4 }]));
		_setFetch(makeOkFetch(VALID_DOC));
		const record = await resolveCimdClient(VALID_URL, undefined);
		assert.ok(record);
		assert.equal(record.client_id, VALID_URL);
	});

	it('rejects when DNS resolution fails', async () => {
		_setDnsLookup(async () => {
			throw new Error('DNS NXDOMAIN');
		});
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), /DNS resolution failed/);
	});
});

describe('resolveCimdClient — allowedHosts policy', () => {
	beforeEach(() => _clearCimdCache());
	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
	});

	it('returns null (not found) when host is not in allowedHosts', async () => {
		const result = await resolveCimdClient(VALID_URL, { allowedHosts: ['trusted.example.com'] });
		assert.equal(result, null);
	});

	it('proceeds when host is in allowedHosts', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(VALID_DOC));
		const result = await resolveCimdClient(VALID_URL, { allowedHosts: ['example.com'] });
		assert.ok(result);
		assert.equal(result.client_id, VALID_URL);
	});

	it('allowedHosts governs the document host only — NOT redirect URI hosts', async () => {
		// A trusted vendor's document may declare redirect targets on other hosts;
		// the redirect-host policy is dynamicClientRegistration.allowedRedirectUriHosts,
		// passed separately. With no redirect policy set, an off-document-host
		// https redirect URI must be accepted even under a tight allowedHosts.
		_setDnsLookup(makeDnsOk());
		const doc = { ...VALID_DOC, redirect_uris: ['https://agent.other-host.example/callback'] };
		_setFetch(makeOkFetch(doc));
		const result = await resolveCimdClient(VALID_URL, { allowedHosts: ['example.com'] });
		assert.ok(result, 'redirect host outside allowedHosts must not be rejected');
		assert.deepEqual(result.redirect_uris, ['https://agent.other-host.example/callback']);
	});

	it('redirect URIs are enforced against the DCR redirect-host policy when provided', async () => {
		_setDnsLookup(makeDnsOk());
		const doc = { ...VALID_DOC, redirect_uris: ['https://agent.other-host.example/callback'] };
		_setFetch(makeOkFetch(doc));
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, { allowedHosts: ['example.com'] }, ['app.example.com']),
			/not in allowlist/
		);
	});
});

describe('resolveCimdClient — document validation', () => {
	beforeEach(() => _clearCimdCache());
	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
	});

	function setupOk(doc) {
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(doc));
	}

	it('rejects when client_id in doc does not match the URL', async () => {
		setupOk({ ...VALID_DOC, client_id: 'https://other.example.com/client.json' });
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, undefined),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, /does not match/);
				return true;
			}
		);
	});

	it('rejects missing client_name', async () => {
		setupOk({ client_id: VALID_URL, redirect_uris: ['https://example.com/cb'] });
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), CimdClientError);
	});

	it('rejects missing redirect_uris', async () => {
		setupOk({ client_id: VALID_URL, client_name: 'Test' });
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), CimdClientError);
	});

	it('rejects non-JSON content-type', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(JSON.stringify(VALID_DOC), { contentType: 'text/html' }));
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, undefined),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, /content-type/);
				return true;
			}
		);
	});

	it('rejects oversized responses (content-length check)', async () => {
		_setDnsLookup(makeDnsOk());
		// Build a fake response with a very large content-length header.
		_setFetch(async () => ({
			ok: true,
			status: 200,
			headers: new Map([
				['content-type', 'application/json'],
				['content-length', '99999999'],
			]),
			body: null,
		}));
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, { maxDocumentBytes: 1024 }),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, /exceeds limit/);
				return true;
			}
		);
	});

	it('rejects redirect responses (redirect: error semantic)', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(async () => {
			throw new TypeError('Failed to fetch: redirect not allowed');
		});
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), TypeError);
	});

	it('rejects unsupported token_endpoint_auth_method for CIMD', async () => {
		setupOk({ ...VALID_DOC, token_endpoint_auth_method: 'private_key_jwt' });
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, undefined),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, /not yet supported/);
				assert.equal(err.oauthError, 'invalid_client');
				return true;
			}
		);
	});

	it('accepts none token_endpoint_auth_method', async () => {
		setupOk({ ...VALID_DOC, token_endpoint_auth_method: 'none' });
		const record = await resolveCimdClient(VALID_URL, undefined);
		assert.ok(record);
		assert.equal(record.token_endpoint_auth_method, 'none');
		assert.equal(record._cimd, true);
	});

	it('carries through jwks and jwks_uri fields (#159 integration point)', async () => {
		setupOk({
			...VALID_DOC,
			jwks_uri: 'https://example.com/.well-known/jwks.json',
			jwks: { keys: [] },
		});
		const record = await resolveCimdClient(VALID_URL, undefined);
		assert.equal(record.jwks_uri, 'https://example.com/.well-known/jwks.json');
		assert.deepEqual(record.jwks, { keys: [] });
	});
});

describe('resolveCimdClient — cache', () => {
	beforeEach(() => _clearCimdCache());
	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
	});

	it('caches successful resolution; second call skips fetch', async () => {
		let fetchCalls = 0;
		_setDnsLookup(makeDnsOk());
		_setFetch(async (...args) => {
			fetchCalls++;
			return makeOkFetch(VALID_DOC)(...args);
		});

		await resolveCimdClient(VALID_URL, undefined);
		await resolveCimdClient(VALID_URL, undefined);
		assert.equal(fetchCalls, 1, 'second call served from cache');
	});

	it('honors Cache-Control max-age (clamped to [60s, 86400s])', async () => {
		// cache-control: max-age=1 → clamped to 60s minimum
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(VALID_DOC, { cacheControl: 'max-age=1' }));
		const record = await resolveCimdClient(VALID_URL, undefined);
		assert.ok(record);
		// We can't directly inspect expiry, but we verified the cache TTL is clamped:
		// a second call within the same process should return cache (regardless of max-age=1).
		let fetchCalls = 0;
		_setFetch(async (...args) => {
			fetchCalls++;
			return makeOkFetch(VALID_DOC)(...args);
		});
		await resolveCimdClient(VALID_URL, undefined);
		assert.equal(fetchCalls, 0, 'clamped TTL (>=60s) keeps the cache warm');
	});

	it('negative-caches failures; second call does not fetch', async () => {
		let fetchCalls = 0;
		_setDnsLookup(async () => {
			throw new Error('DNS failure');
		});

		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined));

		// DNS failures are NOT negative-cached (server-side errors); fetch is the next step.
		// Validate that CimdClientError failures ARE negative-cached.
		_clearCimdCache();
		_setDnsLookup(makeDnsOk());
		_setFetch(async (...args) => {
			fetchCalls++;
			return makeOkFetch({ ...VALID_DOC, client_id: 'https://other.example.com/different' })(...args);
		});
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), CimdClientError);
		// Second call hits negative cache — fetch is NOT called again.
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), CimdClientError);
		assert.equal(fetchCalls, 1, 'only one fetch; second rejection from negative cache');
	});
});

describe('resolveClient — routing', () => {
	let originalDatabases;
	let storedClients;

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
	});
	beforeEach(() => {
		_clearCimdCache();
		resetMCPClientsTableCache();
		storedClients = new Map();
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: {
					get: async (id) => storedClients.get(id) ?? null,
					put: async (rec) => storedClients.set(rec.client_id, rec),
					delete: async (id) => storedClients.delete(id),
					search: async function* () {
						for (const v of storedClients.values()) yield v;
					},
				},
			},
		};
	});
	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
	});

	it('routes URL-shaped client_ids to CIMD', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(VALID_DOC));
		const record = await resolveClient(VALID_URL, { enabled: true });
		assert.ok(record);
		assert.equal(record._cimd, true);
	});

	it('routes non-URL client_ids to DCR store', async () => {
		const dcrId = 'stored-client-id';
		storedClients.set(dcrId, {
			client_id: dcrId,
			redirect_uris: JSON.stringify(['https://example.com/cb']),
			grant_types: JSON.stringify(['authorization_code']),
			response_types: JSON.stringify(['code']),
		});
		const record = await resolveClient(dcrId, { enabled: true });
		assert.ok(record);
		assert.equal(record.client_id, dcrId);
		assert.equal(record._cimd, undefined, 'DCR record has no _cimd marker');
	});

	it('returns null for unknown DCR client_id', async () => {
		const result = await resolveClient('unknown-id', { enabled: true });
		assert.equal(result, null);
	});

	it('skips CIMD when clientIdMetadataDocuments.enabled is false', async () => {
		// URL-shaped client_id, but CIMD disabled — falls through to DCR lookup (returns null).
		const result = await resolveClient(VALID_URL, {
			enabled: true,
			clientIdMetadataDocuments: { enabled: false },
		});
		assert.equal(result, null);
	});
});
