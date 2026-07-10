/**
 * Tests for CIMD (Client ID Metadata Document) resolution.
 *
 * Covers:
 * - isCimdClientId URL-shape detection (incl. dot-segment rejection)
 * - resolveCimdClient: allowedHosts policy, SSRF DNS gate (v4 + v6 ranges,
 *   generic rejection message), fetch (200-only, full-fetch deadline,
 *   config coercion), document validation, cache (TTL honoring, LRU bound,
 *   no negative caching, live redirect-policy revalidation)
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

	it('rejects dot path segments, raw and percent-encoded', () => {
		assert.equal(isCimdClientId('https://example.com/a/../client.json'), false);
		assert.equal(isCimdClientId('https://example.com/./client.json'), false);
		assert.equal(isCimdClientId('https://example.com/a/..'), false);
		assert.equal(isCimdClientId('https://example.com/a/%2e%2e/client.json'), false);
		assert.equal(isCimdClientId('https://example.com/a/%2E%2E/client.json'), false);
		assert.equal(isCimdClientId('https://example.com/%2e/client.json'), false);
		// Dots inside a segment name are fine.
		assert.equal(isCimdClientId('https://example.com/client.v1.json'), true);
		assert.equal(isCimdClientId('https://example.com/.well-known/client.json'), true);
	});

	it('rejects non-canonical scheme spellings', () => {
		assert.equal(isCimdClientId('HTTPS://example.com/client.json'), false);
		assert.equal(isCimdClientId('hTtPs://example.com/client.json'), false);
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

	// Every DNS-gate rejection uses one generic message — anything specific
	// (the address, resolve-vs-blocked) would let callers probe internal DNS.
	const GENERIC_GATE = /could not be resolved to a permitted address/;

	it('rejects non-global IPv4 addresses', async () => {
		for (const address of [
			'0.0.0.0', // 0/8 routes to loopback on Linux
			'0.255.1.2',
			'127.0.0.1',
			'10.0.0.1',
			'100.64.0.1', // CGNAT
			'100.127.255.254',
			'172.16.0.1',
			'192.168.1.1',
			'169.254.1.1',
			'198.18.0.1', // benchmarking
			'224.0.0.1', // multicast
			'240.0.0.1', // reserved
			'255.255.255.255',
		]) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk([{ address, family: 4 }]));
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, undefined),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected CimdClientError for ${address}`);
					assert.match(err.message, GENERIC_GATE, `expected generic gate message for ${address}`);
					return true;
				}
			);
		}
	});

	it('rejects non-global IPv6 addresses including non-canonical forms', async () => {
		for (const address of [
			'::', // unspecified — routes to loopback
			'::1',
			'::01', // non-canonical loopback
			'0:0:0:0:0:0:0:1', // expanded loopback
			'fc00::1',
			'fd12::abcd',
			'fe80::1',
			'fe80::1%eth0', // zone index
			'ff02::1', // multicast
			'::ffff:192.168.1.1', // v4-mapped private
			'::ffff:127.0.0.1',
			'::ffff:7f00:1', // v4-mapped loopback, hex form
			'64:ff9b::8.8.8.8', // NAT64 — outside 2000::/3, fail closed
			'not-an-address', // unparseable — fail closed
		]) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk([{ address, family: 6 }]));
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, undefined),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected CimdClientError for ${address}`);
					assert.match(err.message, GENERIC_GATE, `expected generic gate message for ${address}`);
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

	it('allows global IPv6 and public v4-mapped addresses', async () => {
		for (const address of ['2606:4700::6810:84e5', '::ffff:93.184.216.34', '::ffff:5db8:d822']) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk([{ address, family: 6 }]));
			_setFetch(makeOkFetch(VALID_DOC));
			const record = await resolveCimdClient(VALID_URL, undefined);
			assert.ok(record, `expected ${address} to be allowed`);
		}
	});

	it('rejects IPv6 transition forms that embed or tunnel to a private IPv4', async () => {
		for (const address of [
			'2002:0a00:0001::', // 6to4 embedding 10.0.0.1
			'2002:c0a8:0101::', // 6to4 embedding 192.168.1.1
			'2002:7f00:0001::', // 6to4 embedding 127.0.0.1
			'2001:0000:4136:e378:8000:63bf:3fff:fdd2', // Teredo (2001:0000::/32)
			'fe80::5efe:10.0.0.1', // ISATAP embedding 10.0.0.1
			'2001:db8::5efe:192.168.0.1', // ISATAP (global prefix) embedding 192.168.0.1
		]) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk([{ address, family: 6 }]));
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, undefined),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected CimdClientError for ${address}`);
					assert.match(err.message, GENERIC_GATE);
					return true;
				}
			);
		}
	});

	it('allows a 6to4 address that embeds a public IPv4', async () => {
		_setDnsLookup(makeDnsOk([{ address: '2002:5db8:d822::', family: 6 }])); // 6to4 for 93.184.216.34
		_setFetch(makeOkFetch(VALID_DOC));
		const record = await resolveCimdClient(VALID_URL, undefined);
		assert.ok(record, '6to4 wrapping a public IPv4 is reachable and allowed');
	});

	it('fails closed on an unexpected DNS address family', async () => {
		_setDnsLookup(makeDnsOk([{ address: 'anything', family: 0 }]));
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, undefined),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, GENERIC_GATE);
				return true;
			}
		);
	});

	it('rejects when DNS resolution fails — same generic message, no detail leak', async () => {
		_setDnsLookup(async () => {
			throw new Error('DNS NXDOMAIN');
		});
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, undefined),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, GENERIC_GATE);
				assert.doesNotMatch(err.message, /NXDOMAIN/);
				return true;
			}
		);
	});

	it('DNS lookups are bounded by the fetch deadline', async () => {
		_setDnsLookup(() => new Promise(() => {})); // hangs forever
		await assert.rejects(() => resolveCimdClient(VALID_URL, { fetchTimeoutMs: 50 }), /CIMD DNS lookup timed out/);
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

	it('rejects non-200 responses even with a valid JSON body', async () => {
		for (const status of [404, 500, 201, 204]) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk());
			_setFetch(async (...args) => {
				const response = await makeOkFetch(VALID_DOC)(...args);
				return { ...response, ok: status < 300, status };
			});
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, undefined),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected CimdClientError for status ${status}`);
					assert.match(err.message, new RegExp(`status ${status}`));
					return true;
				}
			);
		}
	});

	it('size cap fails closed when maxDocumentBytes is NaN/Infinity/garbage', async () => {
		// A ~70 KB document exceeds the 64 KB default; NaN/Infinity would
		// disable the comparison entirely if used unvalidated.
		const bigDoc = { ...VALID_DOC, padding: 'x'.repeat(70 * 1024) };
		for (const maxDocumentBytes of [NaN, Infinity, 'not-a-number', -1, 0]) {
			_clearCimdCache();
			_setDnsLookup(makeDnsOk());
			_setFetch(makeOkFetch(bigDoc));
			await assert.rejects(
				() => resolveCimdClient(VALID_URL, { maxDocumentBytes }),
				(err) => {
					assert.ok(err instanceof CimdClientError, `expected size rejection for ${maxDocumentBytes}`);
					assert.match(err.message, /size limit|exceeds limit/);
					return true;
				}
			);
		}
	});

	it('numeric-string config values are honored', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(VALID_DOC));
		const record = await resolveCimdClient(VALID_URL, { maxDocumentBytes: '2048', fetchTimeoutMs: '5000' });
		assert.ok(record);
	});

	it('deadline covers the body read, not just headers', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(async (url, opts) => ({
			ok: true,
			status: 200,
			headers: new Map([['content-type', 'application/json']]),
			body: {
				getReader: () => ({
					// Headers arrive fine, then the body trickles forever; the
					// abort signal must terminate the read.
					read: () =>
						new Promise((resolve, reject) => {
							opts.signal.addEventListener('abort', () => reject(new Error('body read aborted')), {
								once: true,
							});
						}),
					cancel: () => {},
				}),
			},
		}));
		await assert.rejects(() => resolveCimdClient(VALID_URL, { fetchTimeoutMs: 50 }), /body read aborted/);
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

	it('failures are never cached — the CIMD draft forbids caching errors/invalid documents', async () => {
		let fetchCalls = 0;
		_setDnsLookup(makeDnsOk());
		_setFetch(async (...args) => {
			fetchCalls++;
			return makeOkFetch({ ...VALID_DOC, client_id: 'https://other.example.com/different' })(...args);
		});
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), CimdClientError);
		await assert.rejects(() => resolveCimdClient(VALID_URL, undefined), CimdClientError);
		assert.equal(fetchCalls, 2, 'invalid documents must be re-fetched, not served from a negative cache');
	});

	it('honors no-store/no-cache as the minimum TTL (DoS floor), not literally', async () => {
		_setDnsLookup(makeDnsOk());
		_setFetch(makeOkFetch(VALID_DOC, { cacheControl: 'no-store' }));
		await resolveCimdClient(VALID_URL, undefined);
		let fetchCalls = 0;
		_setFetch(async (...args) => {
			fetchCalls++;
			return makeOkFetch(VALID_DOC)(...args);
		});
		await resolveCimdClient(VALID_URL, undefined);
		assert.equal(fetchCalls, 0, 'no-store floors at 60s — an immediate re-resolve stays cached');
	});

	it('cache is LRU-bounded — attacker-chosen keys cannot grow it unbounded', async () => {
		_setDnsLookup(makeDnsOk());
		const fetched = [];
		_setFetch(async (url, ...rest) => {
			fetched.push(url);
			return makeOkFetch({ ...VALID_DOC, client_id: url })(url, ...rest);
		});
		// Fill past the 1000-entry bound, then re-resolve the first URL: it must
		// have been evicted (re-fetched), while a recent one stays cached.
		for (let i = 0; i < 1001; i++) {
			await resolveCimdClient(`https://example.com/client-${i}.json`, undefined);
		}
		fetched.length = 0;
		await resolveCimdClient('https://example.com/client-0.json', undefined);
		assert.equal(fetched.length, 1, 'oldest entry was evicted at the bound');
		fetched.length = 0;
		await resolveCimdClient('https://example.com/client-1000.json', undefined);
		assert.equal(fetched.length, 0, 'recent entry is still cached');
	});

	it('cached records are revalidated against the live redirect-host policy', async () => {
		_setDnsLookup(makeDnsOk());
		let fetchCalls = 0;
		_setFetch(async (...args) => {
			fetchCalls++;
			return makeOkFetch(VALID_DOC)(...args);
		});
		// Cached under a permissive policy...
		const record = await resolveCimdClient(VALID_URL, undefined);
		assert.ok(record);
		// ...must not survive the operator tightening allowedRedirectUriHosts.
		await assert.rejects(
			() => resolveCimdClient(VALID_URL, undefined, ['app.trusted.example']),
			(err) => {
				assert.ok(err instanceof CimdClientError);
				assert.match(err.message, /not in allowlist/);
				return true;
			}
		);
		assert.equal(fetchCalls, 1, 'rejection came from revalidation, not a re-fetch');
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
