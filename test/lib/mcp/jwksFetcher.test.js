/**
 * Tests for jwks_uri key fetching (jwksFetcher.ts) and key-set validation
 * (clientKeySet.ts): location policy, key-material-only caching, the pinned
 * fetch under redirects and mixed DNS answers, concurrent misses, capacity and
 * attempt limits, per-client cache isolation, and the rate-limited
 * unknown-kid refetch.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { _setDnsLookup, _setFetch, CimdClientError } from '../../../dist/lib/mcp/cimd.js';
import {
	getClientJwks,
	_clearJwksCache,
	_setJwksNow,
	_jwksCacheSize,
	jwksCacheLifetimeMs,
	httpCurrentAgeMs,
	MAX_CONCURRENT_JWKS_FETCHES,
	JWKS_FETCH_ATTEMPTS_PER_MINUTE,
	KID_MISS_REFETCH_INTERVAL_MS,
} from '../../../dist/lib/mcp/jwksFetcher.js';
import {
	jwksUriIssue,
	isJwksUriOnClientOrigin,
	publicKeySetFromDocument,
	MAX_CLIENT_JWKS_KEYS,
} from '../../../dist/lib/mcp/clientKeySet.js';

const CLIENT_A = 'https://client-a.example.com/oauth/client.json';
const CLIENT_B = 'https://client-b.example.com/oauth/client.json';
const JWKS_A = 'https://client-a.example.com/oauth/jwks.json';

function rsaJwk(kid) {
	const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
	return { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
}

const KEY_1 = rsaJwk('key-1');
const KEY_2 = rsaJwk('key-2');

function response(body, { status = 200, contentType = 'application/json', cacheControl, age, date } = {}) {
	const text = typeof body === 'string' ? body : JSON.stringify(body);
	const bytes = Buffer.from(text);
	const headers = new Map([
		['content-type', contentType],
		['content-length', String(bytes.length)],
	]);
	if (cacheControl) headers.set('cache-control', cacheControl);
	if (age !== undefined) headers.set('age', age);
	if (date !== undefined) headers.set('date', date);
	return {
		status,
		headers,
		body: {
			getReader: () => {
				let sent = false;
				return {
					read: async () => (sent ? { done: true, value: undefined } : ((sent = true), { done: false, value: bytes })),
					cancel: () => {},
				};
			},
		},
	};
}

/** A fetch stub that records calls and serves `respond(url, init)`. */
function recordingFetch(respond) {
	const calls = [];
	const fn = async (url, init) => {
		calls.push({ url, init });
		return respond(url, init);
	};
	fn.calls = calls;
	return fn;
}

describe('jwksUriIssue', () => {
	it('accepts an https jwks_uri on the client ID origin', () => {
		assert.equal(jwksUriIssue(JWKS_A, CLIENT_A), null);
		assert.equal(isJwksUriOnClientOrigin(JWKS_A, CLIENT_A), true);
	});

	it('refuses other origins unless allowlisted (exact origin, port included)', () => {
		assert.match(jwksUriIssue('https://keys.example.net/jwks.json', CLIENT_A), /client ID origin/);
		assert.equal(jwksUriIssue('https://keys.example.net/jwks.json', CLIENT_A, ['https://keys.example.net']), null);
		assert.match(jwksUriIssue('https://client-a.example.com:8443/jwks.json', CLIENT_A), /client ID origin/);
		assert.match(
			jwksUriIssue('https://sub.client-a.example.com/jwks.json', CLIENT_A, ['https://client-a.example.com']),
			/client ID origin/
		);
	});

	it('refuses non-https, userinfo, fragments, IP literals and non-strings', () => {
		assert.match(jwksUriIssue('http://client-a.example.com/jwks.json', CLIENT_A), /https/);
		assert.match(
			jwksUriIssue('HTTPS://client-a.example.com/jwks.json', CLIENT_A),
			/https/,
			'canonical lowercase scheme only'
		);
		assert.match(jwksUriIssue('https://u:p@client-a.example.com/jwks.json', CLIENT_A), /userinfo/);
		assert.match(jwksUriIssue('https://client-a.example.com/jwks.json#k', CLIENT_A), /fragment/);
		assert.match(jwksUriIssue('https://93.184.216.34/jwks.json', 'https://93.184.216.34/client.json'), /IP literal/);
		assert.match(jwksUriIssue('https://[::1]/jwks.json', CLIENT_A), /IP literal/);
		assert.match(jwksUriIssue(42, CLIENT_A), /non-empty string/);
		assert.match(jwksUriIssue(`https://client-a.example.com/${'a'.repeat(2048)}`, CLIENT_A), /non-empty string/);
	});
});

describe('publicKeySetFromDocument', () => {
	it('keeps only public signature keys and only their key material', () => {
		const result = publicKeySetFromDocument({
			keys: [{ ...KEY_1, x5c: ['MIIB'], extra: 'dropped' }],
		});
		assert.ok('keys' in result);
		assert.equal(result.keys.length, 1);
		assert.equal(result.keys[0].x5c, undefined);
		assert.equal(result.keys[0].extra, undefined);
		assert.equal(result.keys[0].n, KEY_1.n);
	});

	it('refuses a set carrying private or symmetric key material', () => {
		assert.match(publicKeySetFromDocument({ keys: [{ ...KEY_1, d: 'AAAA' }] }).error, /private or symmetric/);
		assert.match(publicKeySetFromDocument({ keys: [{ kty: 'oct', k: 'c2VjcmV0' }] }).error, /private or symmetric/);
	});

	it('skips encryption and unsupported keys, and needs at least one usable key', () => {
		const result = publicKeySetFromDocument({ keys: [{ ...KEY_2, use: 'enc' }, KEY_1] });
		assert.deepEqual(
			result.keys.map((k) => k.kid),
			['key-1']
		);
		assert.match(publicKeySetFromDocument({ keys: [{ ...KEY_1, use: 'enc' }] }).error, /no usable/);
	});

	it('requires unique kids when several signature keys are present, and bounds the count', () => {
		assert.match(publicKeySetFromDocument({ keys: [KEY_1, { ...KEY_2, kid: 'key-1' }] }).error, /unique kid/);
		const noKid = { ...KEY_2 };
		delete noKid.kid;
		assert.match(publicKeySetFromDocument({ keys: [KEY_1, noKid] }).error, /each have a kid/);
		const many = Array.from({ length: MAX_CLIENT_JWKS_KEYS + 1 }, (_, i) => ({ ...KEY_1, kid: `k${i}` }));
		assert.match(publicKeySetFromDocument({ keys: many }).error, /between 1 and/);
		assert.match(publicKeySetFromDocument({ keys: [] }).error, /between 1 and/);
		assert.match(publicKeySetFromDocument([]).error, /JSON object/);
	});
});

describe('getClientJwks', () => {
	beforeEach(() => {
		_clearJwksCache();
		_setDnsLookup(async () => [{ address: '93.184.216.34', family: 4 }]);
	});
	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
		_setJwksNow(null);
	});

	it('fetches over the pinned connection and serves key material from cache', async () => {
		const fetch = recordingFetch(() => response({ keys: [KEY_1] }));
		_setFetch(fetch);
		const keys = await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(keys[0].kid, 'key-1');
		assert.deepEqual(fetch.calls[0].init.pinnedAddresses, [{ address: '93.184.216.34', family: 4 }]);
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(fetch.calls.length, 1, 'second call served from cache');
	});

	it('accepts application/jwk-set+json and refuses other media types', async () => {
		_setFetch(recordingFetch(() => response({ keys: [KEY_1] }, { contentType: 'application/jwk-set+json' })));
		assert.equal((await getClientJwks(CLIENT_A, JWKS_A, undefined)).length, 1);
		_clearJwksCache();
		_setFetch(recordingFetch(() => response({ keys: [KEY_1] }, { contentType: 'text/html' })));
		await assert.rejects(() => getClientJwks(CLIENT_A, JWKS_A, undefined), /non-JSON content-type/);
	});

	it('compares the media type exactly, excluding parameters', async () => {
		for (const contentType of ['application/json; charset=utf-8', 'Application/JWK-Set+JSON']) {
			_clearJwksCache();
			_setFetch(recordingFetch(() => response({ keys: [KEY_1] }, { contentType })));
			assert.equal((await getClientJwks(CLIENT_A, JWKS_A, undefined)).length, 1, contentType);
		}
		for (const contentType of [
			'text/plain; x=application/json',
			'application/json-seq',
			'application/jsonx',
			'text/application/json',
		]) {
			_clearJwksCache();
			_setFetch(recordingFetch(() => response({ keys: [KEY_1] }, { contentType })));
			await assert.rejects(() => getClientJwks(CLIENT_A, JWKS_A, undefined), /non-JSON content-type/, contentType);
		}
	});

	it('refuses redirects and never caches the failure', async () => {
		const fetch = recordingFetch(() => response('', { status: 302 }));
		_setFetch(fetch);
		await assert.rejects(() => getClientJwks(CLIENT_A, JWKS_A, undefined), /returned status 302/);
		await assert.rejects(() => getClientJwks(CLIENT_A, JWKS_A, undefined), /returned status 302/);
		assert.equal(fetch.calls.length, 2, 'the failure was not cached');
	});

	it('refuses a host whose DNS answers mix public and special-use addresses, before connecting', async () => {
		const fetch = recordingFetch(() => response({ keys: [KEY_1] }));
		_setFetch(fetch);
		_setDnsLookup(async () => [
			{ address: '93.184.216.34', family: 4 },
			{ address: '10.0.0.7', family: 4 },
		]);
		await assert.rejects(
			() => getClientJwks(CLIENT_A, JWKS_A, undefined),
			(err) => err instanceof CimdClientError && /permitted address/.test(err.message)
		);
		assert.equal(fetch.calls.length, 0, 'no connection to an unvalidated address');
	});

	it('enforces the document size cap', async () => {
		_setFetch(recordingFetch(() => response({ keys: [KEY_1], pad: 'x'.repeat(2048) })));
		await assert.rejects(() => getClientJwks(CLIENT_A, JWKS_A, { maxDocumentBytes: 1024 }), /exceeds limit/);
	});

	it('shares one fetch among concurrent misses for the same client and URL', async () => {
		let release;
		const gate = new Promise((r) => (release = r));
		const fetch = recordingFetch(async () => {
			await gate;
			return response({ keys: [KEY_1] });
		});
		_setFetch(fetch);
		const pending = Array.from({ length: 5 }, () => getClientJwks(CLIENT_A, JWKS_A, undefined));
		release();
		const results = await Promise.all(pending);
		assert.equal(fetch.calls.length, 1);
		for (const keys of results) assert.equal(keys[0].kid, 'key-1');
	});

	it('caps total concurrent fetches and fast-rejects past the cap with 429', async () => {
		let release;
		const gate = new Promise((r) => (release = r));
		_setDnsLookup(async () => {
			await gate;
			return [{ address: '93.184.216.34', family: 4 }];
		});
		_setFetch(recordingFetch(() => response({ keys: [KEY_1] })));
		const clients = Array.from(
			{ length: MAX_CONCURRENT_JWKS_FETCHES + 1 },
			(_, i) => `https://c${i}.example.com/client.json`
		);
		const pending = clients.map((client) =>
			getClientJwks(client, client.replace('client.json', 'jwks.json'), undefined).then(
				() => 'ok',
				(err) => err
			)
		);
		release();
		const results = await Promise.all(pending);
		const capacity = results.filter(
			(r) => r instanceof CimdClientError && r.statusCode === 429 && /capacity/.test(r.message)
		);
		assert.equal(capacity.length, 1, 'exactly the request past the cap is refused');
	});

	it('rate-limits fetch attempts per client and URL', async () => {
		const fetch = recordingFetch(() => response('', { status: 500 }));
		_setFetch(fetch);
		for (let i = 0; i < JWKS_FETCH_ATTEMPTS_PER_MINUTE; i++) {
			await assert.rejects(() => getClientJwks(CLIENT_A, JWKS_A, undefined), /status 500/);
		}
		await assert.rejects(
			() => getClientJwks(CLIENT_A, JWKS_A, undefined),
			(err) => err instanceof CimdClientError && err.oauthError === 'slow_down' && err.statusCode === 429
		);
		assert.equal(fetch.calls.length, JWKS_FETCH_ATTEMPTS_PER_MINUTE);
	});

	it('never serves one client the keys cached for another, even for the same URL', async () => {
		const shared = 'https://keys.example.net/jwks.json';
		const config = { privateKeyJwt: { jwksUriAllowedOrigins: ['https://keys.example.net'] } };
		let served = KEY_1;
		const fetch = recordingFetch(() => response({ keys: [served] }));
		_setFetch(fetch);
		assert.equal((await getClientJwks(CLIENT_A, shared, config))[0].kid, 'key-1');
		served = KEY_2;
		assert.equal((await getClientJwks(CLIENT_B, shared, config))[0].kid, 'key-2', 'client B fetched its own keys');
		assert.equal(fetch.calls.length, 2);
		assert.equal((await getClientJwks(CLIENT_A, shared, config))[0].kid, 'key-1', 'client A still sees its own');
	});

	it('allows at most one unknown-kid refetch per interval', async () => {
		let now = Date.parse('2026-09-30T00:00:00Z');
		_setJwksNow(() => now);
		let served = KEY_1;
		const fetch = recordingFetch(() => response({ keys: [served] }, { cacheControl: 'max-age=3600' }));
		_setFetch(fetch);
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		served = KEY_2; // the client rotated
		// Inside the interval: no refetch, the cached keys are returned.
		now += KID_MISS_REFETCH_INTERVAL_MS - 1;
		const early = await getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		assert.equal(early[0].kid, 'key-1');
		assert.equal(fetch.calls.length, 1);
		// After the interval: one refetch picks up the rotated key.
		now += 1;
		const refreshed = await getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		assert.equal(refreshed[0].kid, 'key-2');
		assert.equal(fetch.calls.length, 2);
		// And the next unknown kid right away does not fetch again.
		await getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		assert.equal(fetch.calls.length, 2);
	});

	it('an unknown kid seen while a refetch is in flight waits for that refetch', async () => {
		let now = Date.parse('2026-09-30T00:00:00Z');
		_setJwksNow(() => now);
		let served = KEY_1;
		let gate;
		const fetch = recordingFetch(async () => {
			await gate;
			return response({ keys: [served] }, { cacheControl: 'max-age=3600' });
		});
		_setFetch(fetch);
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		served = KEY_2; // the client rotated
		now += KID_MISS_REFETCH_INTERVAL_MS;
		let release;
		gate = new Promise((resolve) => (release = resolve));
		const first = getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		const second = getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		const plain = await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(plain[0].kid, 'key-1', 'a request without an unknown kid is answered from the cache');
		release();
		assert.equal((await first)[0].kid, 'key-2');
		assert.equal((await second)[0].kid, 'key-2', 'the concurrent unknown-kid request gets the refetched keys');
		assert.equal(fetch.calls.length, 2);
	});

	it('obeys no-store, no-cache and a zero max-age: nothing is stored', async () => {
		for (const cacheControl of ['no-store', 'no-cache', 'max-age=0', 'public, no-store, max-age=600']) {
			_clearJwksCache();
			const fetch = recordingFetch(() => response({ keys: [KEY_1] }, { cacheControl }));
			_setFetch(fetch);
			await getClientJwks(CLIENT_A, JWKS_A, undefined);
			assert.equal(_jwksCacheSize(), 0, `${cacheControl}: no key material kept`);
			await getClientJwks(CLIENT_A, JWKS_A, undefined);
			assert.equal(fetch.calls.length, 2, `${cacheControl}: each request fetched`);
		}
	});

	it('drops a cached set when a refetch answers no-store', async () => {
		let now = Date.parse('2026-09-30T00:00:00Z');
		_setJwksNow(() => now);
		let cacheControl = 'max-age=3600';
		let served = KEY_1;
		const fetch = recordingFetch(() => response({ keys: [served] }, { cacheControl }));
		_setFetch(fetch);
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(_jwksCacheSize(), 1);
		now += KID_MISS_REFETCH_INTERVAL_MS;
		cacheControl = 'no-store';
		served = KEY_2;
		const refetched = await getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		assert.equal(refetched[0].kid, 'key-2');
		assert.equal(_jwksCacheSize(), 0, 'the earlier set is not kept');
		const next = await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(next[0].kid, 'key-2', 'the withdrawn key is not served from cache');
		assert.equal(fetch.calls.length, 3);
	});

	it('never extends an explicit max-age', async () => {
		let now = Date.parse('2026-09-30T00:00:00Z');
		_setJwksNow(() => now);
		const fetch = recordingFetch(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=5' }));
		_setFetch(fetch);
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		now += 4_000;
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(fetch.calls.length, 1, 'cached within max-age');
		now += 2_000;
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		assert.equal(fetch.calls.length, 2, 'refetched once max-age passed');
	});

	it('caps an explicit max-age at 3600 s and defaults to 300 s without a caching directive', async () => {
		const start = Date.parse('2026-09-30T00:00:00Z');
		for (const [cacheControl, seconds] of [
			['max-age=7200', 3600],
			[undefined, 300],
			['public', 300],
		]) {
			_clearJwksCache();
			let now = start;
			_setJwksNow(() => now);
			const fetch = recordingFetch(() => response({ keys: [KEY_1] }, { cacheControl }));
			_setFetch(fetch);
			await getClientJwks(CLIENT_A, JWKS_A, undefined);
			now = start + seconds * 1000 - 1;
			await getClientJwks(CLIENT_A, JWKS_A, undefined);
			assert.equal(fetch.calls.length, 1, `${cacheControl}: cached for ${seconds}s`);
			now = start + seconds * 1000;
			await getClientJwks(CLIENT_A, JWKS_A, undefined);
			assert.equal(fetch.calls.length, 2, `${cacheControl}: expired after ${seconds}s`);
		}
	});

	describe('max-age counts from the response current age (RFC 9111 §4.2.3)', () => {
		const START = Date.parse('2026-09-30T00:00:00Z');

		async function lifetimeOf(respond, { advanceDuringFetch = 0, start = START } = {}) {
			_clearJwksCache();
			let now = start;
			_setJwksNow(() => now);
			const fetch = recordingFetch(() => {
				now += advanceDuringFetch;
				return respond();
			});
			_setFetch(fetch);
			await getClientJwks(CLIENT_A, JWKS_A, undefined);
			const stored = now;
			return {
				fetch,
				at: async (offsetMs) => {
					now = stored + offsetMs;
					await getClientJwks(CLIENT_A, JWKS_A, undefined);
					return fetch.calls.length;
				},
			};
		}

		it('computes the lifetime and current age directly', () => {
			assert.equal(jwksCacheLifetimeMs('max-age=10', 4_000n), 6_000);
			assert.equal(jwksCacheLifetimeMs('max-age=10', 10_000n), 0, 'exhausted: 0, never negative');
			assert.equal(jwksCacheLifetimeMs('max-age=10', 15_000n), 0, 'exhausted: 0, never negative');
			assert.equal(jwksCacheLifetimeMs('max-age=7200', 100_000n), 3_600_000);
			assert.equal(jwksCacheLifetimeMs('no-store', 0n), 0);
			assert.equal(jwksCacheLifetimeMs(null, 999_000n), 300_000, 'the 300 s default applies without max-age');
			const t = START;
			assert.equal(
				httpCurrentAgeMs({ age: '30', date: null, requestTimeMs: t, responseTimeMs: t + 2_000, nowMs: t + 5_000 }),
				35_000n
			);
			assert.equal(
				httpCurrentAgeMs({
					age: null,
					date: new Date(t - 60_000).toUTCString(),
					requestTimeMs: t,
					responseTimeMs: t,
					nowMs: t,
				}),
				60_000n
			);
			assert.equal(
				httpCurrentAgeMs({
					age: null,
					date: new Date(t + 60_000).toUTCString(),
					requestTimeMs: t,
					responseTimeMs: t,
					nowMs: t,
				}),
				0n,
				'a Date in the future adds nothing'
			);
		});

		it('reads Date only as an HTTP-date (RFC 9110 §5.6.7)', () => {
			const t = START;
			const dateAge = (date) => httpCurrentAgeMs({ age: null, date, requestTimeMs: t, responseTimeMs: t, nowMs: t });
			const before = (iso) => BigInt(t - Date.parse(iso));
			assert.equal(dateAge('Tue, 29 Sep 2026 23:59:00 GMT'), 60_000n, 'IMF-fixdate');
			assert.equal(dateAge('Tuesday, 29-Sep-26 23:59:00 GMT'), 60_000n, 'rfc850-date');
			assert.equal(dateAge('Tue Sep 29 23:59:00 2026'), 60_000n, 'asctime-date');
			assert.equal(dateAge('Tue Sep  1 00:00:00 2026'), before('2026-09-01T00:00:00Z'), 'asctime-date, one-digit day');
			assert.equal(dateAge('Mon, 28 Sep 2026 23:59:60 GMT'), before('2026-09-29T00:00:00Z'), 'a leap second');
			// A two-digit year more than 50 years ahead is the most recent past year with those digits.
			assert.equal(dateAge('Sunday, 06-Nov-94 08:49:37 GMT'), before('1994-11-06T08:49:37Z'));
			assert.equal(dateAge('Wednesday, 30-Sep-76 00:00:00 GMT'), 0n, 'exactly 50 years ahead: 2076');
			assert.equal(dateAge('Wednesday, 30-Sep-76 00:00:01 GMT'), before('1976-09-30T00:00:01Z'), 'beyond: 1976');
			// The later century is read if it gives a valid date no more than 50 years ahead, else the
			// earlier century; Date is invalid if the selected reading does not exist.
			const ageAt = (receivedIso, date) => {
				const r = Date.parse(receivedIso);
				return httpCurrentAgeMs({ age: null, date, requestTimeMs: r, responseTimeMs: r, nowMs: r });
			};
			const span = (fromIso, toIso) => BigInt(Date.parse(toIso) - Date.parse(fromIso));
			assert.equal(
				ageAt('2050-01-01T00:00:00Z', 'Tuesday, 29-Feb-00 00:00:00 GMT'),
				span('2000-02-29T00:00:00Z', '2050-01-01T00:00:00Z'),
				'2100 has no 29 Feb: 2000'
			);
			assert.equal(
				ageAt('2400-03-01T00:00:00Z', 'Tuesday, 29-Feb-00 00:00:00 GMT'),
				span('2400-02-29T00:00:00Z', '2400-03-01T00:00:00Z'),
				'2300 has no 29 Feb: 2400, the later century'
			);
			// None of these is an HTTP-date, though Date.parse accepts several; each counts as absent.
			for (const date of [
				'1',
				'2026-09-01T00:00:00Z',
				'tue, 01 sep 2026 00:00:00 gmt',
				'Tue, 01 Sep 2026 00:00:00 +0000',
				' Tue, 01 Sep 2026 00:00:00 GMT',
				'Tue, 01 Sep 2026 00:00:00 GMT x',
				'x Tuesday, 01-Sep-26 00:00:00 GMT',
				'Tuesday, 01-Sep-26 00:00:00 GMT x',
				'x Tue Sep  1 00:00:00 2026',
				'Tue Sep  1 00:00:00 2026 x',
				'Tue, 01 Sep 2026 24:00:00 GMT',
				'Tue, 01 Sep 2026 23:60:00 GMT',
				'Tue, 01 Sep 2026 23:59:61 GMT',
				'Tue, 31 Feb 2026 00:00:00 GMT',
				'Tue, 00 Sep 2026 00:00:00 GMT',
			]) {
				assert.equal(dateAge(date), 0n, `${JSON.stringify(date)} is ignored`);
			}
		});

		it('a nearly expired intermediary response is cached only for its remaining freshness', async () => {
			const probe = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=3600', age: '3590' }));
			assert.equal(await probe.at(9_999), 1, 'cached within the remaining 10 s');
			assert.equal(await probe.at(10_000), 2, 'refetched once the remaining 10 s passed');
		});

		it('a response already stale on arrival is not stored; the next request refetches', async () => {
			for (const age of ['3600', '7200']) {
				const probe = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=3600', age }));
				assert.equal(_jwksCacheSize(), 0, `Age ${age}: nothing stored`);
				assert.equal(await probe.at(0), 2, `Age ${age}: the next request refetched`);
			}
		});

		it('counts the Date header against the response time', async () => {
			const date = new Date(START - 590_000).toUTCString();
			const probe = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=600', date }));
			assert.equal(await probe.at(9_999), 1);
			assert.equal(await probe.at(10_000), 2);
		});

		it('reads rfc850 29-Feb-00 at a 2050 response time as 2000-02-29 (2100 has no 29 Feb)', async () => {
			for (const date of ['Tuesday, 29-Feb-00 00:00:00 GMT', 'Tue, 29 Feb 2000 00:00:00 GMT']) {
				const probe = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=600', date }), {
					start: Date.parse('2050-01-01T00:00:00Z'),
				});
				assert.equal(_jwksCacheSize(), 0, `${date}: 2000-02-29, stale on arrival, nothing stored`);
				assert.equal(await probe.at(0), 2, `${date}: the next request refetched`);
			}
		});

		it('counts the response delay (Age is corrected by it)', async () => {
			const probe = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=10' }), {
				advanceDuringFetch: 4_000,
			});
			assert.equal(await probe.at(5_999), 1);
			assert.equal(await probe.at(6_000), 2);
		});

		it('compares a large Age with max-age exactly, and caps only the remaining lifetime', async () => {
			const exhausted = await lifetimeOf(() =>
				response({ keys: [KEY_1] }, { cacheControl: 'max-age=3000000000', age: '3000000000' })
			);
			assert.equal(_jwksCacheSize(), 0, 'Age equal to a large max-age: nothing stored');
			assert.equal(await exhausted.at(0), 2, 'the next request refetched');
			const oneLeft = await lifetimeOf(() =>
				response({ keys: [KEY_1] }, { cacheControl: 'max-age=9007199254740993', age: '9007199254740992' })
			);
			assert.equal(await oneLeft.at(999), 1, 'beyond 2^53, exactly one second is left');
			assert.equal(await oneLeft.at(1_000), 2);
			const capped = await lifetimeOf(() =>
				response({ keys: [KEY_1] }, { cacheControl: 'max-age=3000000000', age: '2999990000' })
			);
			assert.equal(await capped.at(3_599_999), 1, '10000 s left, capped at 3600 s');
			assert.equal(await capped.at(3_600_000), 2);
		});

		it('ignores an invalid Age or Date, and caps the remaining lifetime at 3600 s', async () => {
			for (const age of ['soon', '1e3', '-5', '10.5', '1, 2']) {
				const invalid = await lifetimeOf(() =>
					response({ keys: [KEY_1] }, { cacheControl: 'max-age=600', age, date: 'not a date' })
				);
				assert.equal(await invalid.at(599_999), 1, `Age ${age}: full max-age when Age and Date are unusable`);
			}
			for (const date of ['1', 'Tue, 01 Sep 2026 00:00:00 +0000']) {
				const invalid = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=600', date }));
				assert.equal(await invalid.at(599_999), 1, `Date ${date}: full max-age when Date is not an HTTP-date`);
			}
			const capped = await lifetimeOf(() => response({ keys: [KEY_1] }, { cacheControl: 'max-age=7200', age: '100' }));
			assert.equal(await capped.at(3_599_999), 1);
			assert.equal(await capped.at(3_600_000), 2);
		});
	});

	it('spaces an unknown-kid refetch from the previous attempt even when that attempt failed', async () => {
		let now = Date.parse('2026-09-30T00:00:00Z');
		_setJwksNow(() => now);
		let fail = false;
		const fetch = recordingFetch(() =>
			fail ? response('', { status: 500 }) : response({ keys: [KEY_1] }, { cacheControl: 'max-age=3600' })
		);
		_setFetch(fetch);
		await getClientJwks(CLIENT_A, JWKS_A, undefined);
		now += KID_MISS_REFETCH_INTERVAL_MS;
		fail = true;
		await assert.rejects(
			() => getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true }),
			/status 500/
		);
		assert.equal(fetch.calls.length, 2);
		// An immediate second unknown kid: no fetch, the cached keys are returned.
		const again = await getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		assert.equal(again[0].kid, 'key-1');
		assert.equal(fetch.calls.length, 2, 'a failed attempt is spaced like a successful one');
		// One interval after the failed attempt, a refetch is allowed again.
		now += KID_MISS_REFETCH_INTERVAL_MS;
		fail = false;
		await getClientJwks(CLIENT_A, JWKS_A, undefined, { refetchForUnknownKid: true });
		assert.equal(fetch.calls.length, 3);
	});

	it('re-checks the location policy on every use, even for cached keys', async () => {
		const other = 'https://keys.example.net/jwks.json';
		const allow = { privateKeyJwt: { jwksUriAllowedOrigins: ['https://keys.example.net'] } };
		const fetch = recordingFetch(() => response({ keys: [KEY_1] }));
		_setFetch(fetch);
		await getClientJwks(CLIENT_A, other, allow);
		await assert.rejects(() => getClientJwks(CLIENT_A, other, undefined), /client ID origin/);
		assert.equal(fetch.calls.length, 1);
	});
});
