/**
 * Tests for OIDC Discovery 1.0 issuer derivation (HarperFast/oauth#264).
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
	startIssuerDiscovery,
	awaitDiscoveredIssuer,
	_clearDiscoveryCache,
	_setDiscoveryTimeouts,
	DISCOVERY_LOGIN_AWAIT_BOUND_MS,
	MAX_DISCOVERY_PREFIXES,
	MAX_CONCURRENT_DISCOVERY_ATTEMPTS,
} from '../../dist/lib/discovery.js';
import { _setFetch, _setDnsLookup } from '../../dist/lib/mcp/cimd.js';

const PUBLIC_IP = { address: '93.184.216.34', family: 4 };

function makeDnsOk() {
	return async () => [PUBLIC_IP];
}

function jsonResponse(body, status = 200) {
	const text = typeof body === 'string' ? body : JSON.stringify(body);
	const bytes = Buffer.from(text);
	return {
		ok: status >= 200 && status < 300,
		status,
		headers: new Map([['content-type', 'application/json']]),
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
}

/** A fetch mock dispatching by exact URL, from a `{ [url]: doc | status }` map. Anything else 404s. */
function fetchFromMap(map) {
	return async (url) => {
		const entry = map[url];
		if (entry === undefined) return jsonResponse({ error: 'not found' }, 404);
		if (typeof entry === 'number') return jsonResponse({ error: 'no' }, entry);
		return jsonResponse(entry);
	};
}

describe('OIDC discovery (#264)', () => {
	beforeEach(() => {
		_clearDiscoveryCache();
		_setDnsLookup(makeDnsOk());
	});
	afterEach(() => {
		_setFetch(null);
		_setDnsLookup(null);
		_setDiscoveryTimeouts(null);
	});

	const AUTH_URL = 'https://idp.example.com/authorize';
	const TOKEN_URL = 'https://idp.example.com/token';
	const JWKS_URI = 'https://idp.example.com/jwks';
	const WELL_KNOWN = 'https://idp.example.com/.well-known/openid-configuration';

	function validDoc(overrides = {}) {
		return {
			issuer: 'https://idp.example.com',
			authorization_endpoint: AUTH_URL,
			token_endpoint: TOKEN_URL,
			jwks_uri: JWKS_URI,
			...overrides,
		};
	}

	describe('accepted', () => {
		it('derives the issuer at the root prefix', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc() }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, 'https://idp.example.com');
		});

		it('accepts a root issuer with a trailing slash too', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc({ issuer: 'https://idp.example.com/' }) }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, 'https://idp.example.com/');
		});

		it('tries ancestor prefixes and accepts a non-root match', async () => {
			const authUrl = 'https://idp.example.com/oauth2/custom/v1/authorize';
			const tokenUrl = 'https://idp.example.com/oauth2/custom/v1/token';
			const jwksUri = 'https://idp.example.com/oauth2/custom/v1/keys';
			const longestWellKnown = 'https://idp.example.com/oauth2/custom/v1/.well-known/openid-configuration';
			const targetWellKnown = 'https://idp.example.com/oauth2/custom/.well-known/openid-configuration';

			_setFetch(
				fetchFromMap({
					[longestWellKnown]: 404, // longest prefix: no document here
					[targetWellKnown]: {
						issuer: 'https://idp.example.com/oauth2/custom',
						authorization_endpoint: authUrl,
						token_endpoint: tokenUrl,
						jwks_uri: jwksUri,
					},
				})
			);
			startIssuerDiscovery(authUrl, jwksUri, tokenUrl, 'okta-custom-as');
			const issuer = await awaitDiscoveredIssuer(authUrl, jwksUri, tokenUrl);
			assert.equal(issuer, 'https://idp.example.com/oauth2/custom');
		});
	});

	describe('refused', () => {
		it('issuer mismatch', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc({ issuer: 'https://wrong.example.com' }) }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('authorization_endpoint mismatch', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc({ authorization_endpoint: 'https://idp.example.com/other' }) }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('jwks_uri mismatch', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc({ jwks_uri: 'https://idp.example.com/other-jwks' }) }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('token_endpoint mismatch (#264: two authorities can share an authorization endpoint and jwks_uri but differ in token endpoint)', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc({ token_endpoint: 'https://idp.example.com/other-token' }) }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('a document that omits token_endpoint entirely refuses rather than bypassing the check', async () => {
			const { token_endpoint, ...doc } = validDoc();
			_setFetch(fetchFromMap({ [WELL_KNOWN]: doc }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('cross-origin is structurally impossible — a document naming another origin never matches any candidate', async () => {
			_setFetch(
				fetchFromMap({
					[WELL_KNOWN]: validDoc({
						issuer: 'https://attacker.example.com',
						authorization_endpoint: 'https://attacker.example.com/authorize',
						jwks_uri: 'https://attacker.example.com/jwks',
						token_endpoint: 'https://attacker.example.com/token',
					}),
				})
			);
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('a redirect (3xx) surfaces as non-200 via the pinned, no-follow transport', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: 302 }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});

		it('a hanging fetch is bounded by the per-fetch timeout', async () => {
			_setDiscoveryTimeouts({ perFetchMs: 25, overallBudgetMs: 200 });
			// A faithful mock respects the abort signal, exactly like the real
			// https.request-based transport (which node:https aborts natively).
			_setFetch(
				(url, init) =>
					new Promise((_resolve, reject) => {
						init.signal.addEventListener('abort', () => reject(new Error('aborted')));
					})
			);
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL, undefined, 500);
			assert.equal(issuer, null);
		});

		it('an oversize document is rejected', async () => {
			const big = { ...validDoc(), padding: 'x'.repeat(10 * 1024 * 1024) };
			_setFetch(fetchFromMap({ [WELL_KNOWN]: big }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});
	});

	describe('bounds', () => {
		it('prefix count is capped at MAX_DISCOVERY_PREFIXES for a pathological long path', async () => {
			const segments = Array.from({ length: 30 }, (_, i) => `seg${i}`);
			const authUrl = `https://idp.example.com/${segments.join('/')}`;
			let calls = 0;
			_setFetch(async () => {
				calls++;
				return jsonResponse({ error: 'no' }, 404);
			});
			startIssuerDiscovery(authUrl, JWKS_URI, TOKEN_URL, 'deep-idp');
			await awaitDiscoveredIssuer(authUrl, JWKS_URI, TOKEN_URL);
			assert.ok(calls <= MAX_DISCOVERY_PREFIXES, `expected at most ${MAX_DISCOVERY_PREFIXES} attempts, got ${calls}`);
		});

		it('the overall budget stops trying further candidates once exhausted', async () => {
			_setDiscoveryTimeouts({ perFetchMs: 500, overallBudgetMs: 30 });
			let calls = 0;
			_setFetch(async () => {
				calls++;
				await new Promise((resolve) => setTimeout(resolve, 50));
				return jsonResponse({ error: 'no' }, 404);
			});
			const authUrl = 'https://idp.example.com/a/b/c/d/authorize';
			startIssuerDiscovery(authUrl, JWKS_URI, TOKEN_URL, 'slow-idp');
			await awaitDiscoveredIssuer(authUrl, JWKS_URI, TOKEN_URL, undefined, 2000);
			assert.ok(calls < 5, `expected the overall budget to stop further candidates, got ${calls} calls`);
		});
	});

	describe('concurrency cap', () => {
		it('caps simultaneous discovery attempts at MAX_CONCURRENT_DISCOVERY_ATTEMPTS', async () => {
			let inFlight = 0;
			let maxObservedInFlight = 0;
			let pendingResolvers = [];
			_setFetch(
				() =>
					new Promise((resolve) => {
						inFlight++;
						maxObservedInFlight = Math.max(maxObservedInFlight, inFlight);
						pendingResolvers.push(() => {
							inFlight--;
							resolve(jsonResponse(validDoc()));
						});
					})
			);

			const providerCount = MAX_CONCURRENT_DISCOVERY_ATTEMPTS + 5;
			const targets = [];
			for (let i = 0; i < providerCount; i++) {
				const authUrl = `https://idp${i}.example.com/authorize`;
				const jwksUri = `https://idp${i}.example.com/jwks`;
				const tokenUrl = `https://idp${i}.example.com/token`;
				startIssuerDiscovery(authUrl, jwksUri, tokenUrl, `idp-${i}`);
				targets.push({ authUrl, jwksUri, tokenUrl });
			}

			// Let every immediately-startable attempt begin.
			await new Promise((resolve) => setTimeout(resolve, 10));
			assert.ok(
				maxObservedInFlight <= MAX_CONCURRENT_DISCOVERY_ATTEMPTS,
				`expected at most ${MAX_CONCURRENT_DISCOVERY_ATTEMPTS} in flight, saw ${maxObservedInFlight}`
			);

			// Drain in rounds until every target has settled, so the test leaves
			// no dangling promises behind.
			for (let round = 0; round < providerCount && pendingResolvers.length > 0; round++) {
				const toResolve = pendingResolvers;
				pendingResolvers = [];
				toResolve.forEach((resolve) => resolve());
				await new Promise((resolve) => setTimeout(resolve, 5));
			}
			await Promise.all(targets.map((t) => awaitDiscoveredIssuer(t.authUrl, t.jwksUri, t.tokenUrl)));
		});
	});

	describe('boot does not wait; first-caller-only bounded await', () => {
		it('startIssuerDiscovery returns immediately without waiting for the fetch to resolve', () => {
			_setFetch(() => new Promise(() => {})); // never resolves
			const start = Date.now();
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			assert.ok(Date.now() - start < 50, 'startIssuerDiscovery must not block');
		});

		it('the first caller awaits within the bound and is upgraded if discovery resolves in time', async () => {
			_setFetch(async (url) => {
				await new Promise((resolve) => setTimeout(resolve, 20));
				return jsonResponse(validDoc());
			});
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL, undefined, DISCOVERY_LOGIN_AWAIT_BOUND_MS);
			assert.equal(issuer, 'https://idp.example.com');
		});

		it('a second, concurrent caller does not wait, even though discovery resolves moments later', async () => {
			let resolveFetch;
			_setFetch(
				() =>
					new Promise((resolve) => {
						resolveFetch = () => resolve(jsonResponse(validDoc()));
					})
			);
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');

			const firstCallerPromise = awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			// Give the first caller's `entry.awaited = true` a tick to land before the second caller checks it.
			await new Promise((resolve) => setTimeout(resolve, 5));
			const secondCallerResult = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(secondCallerResult, null, 'the second, concurrent caller does not wait');

			resolveFetch();
			const firstCallerResult = await firstCallerPromise;
			assert.equal(firstCallerResult, 'https://idp.example.com', 'the first caller is upgraded once discovery resolves');
		});
	});

	describe('cache: settled results, retry cooldown, dynamic providers', () => {
		it('a settled entry (success or failure) costs one lookup — no further fetches', async () => {
			let calls = 0;
			_setFetch(async () => {
				calls++;
				return jsonResponse(validDoc());
			});
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			const callsAfterFirst = calls;
			for (let i = 0; i < 5; i++) {
				await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			}
			assert.equal(calls, callsAfterFirst, 'no additional fetches for a settled, cached result');
		});

		it('a failed entry is retried only via a fresh startIssuerDiscovery call after the cooldown, never from the read path', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: 500 }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			assert.equal(await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL), null);

			// Reading again (no reload) never retries, regardless of how long we wait.
			let calls = 0;
			_setFetch(async () => {
				calls++;
				return jsonResponse(validDoc());
			});
			await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(calls, 0, 'the read path never starts a retry');

			// A fresh startIssuerDiscovery call (a live reload) is a no-op within the cooldown window.
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			await new Promise((resolve) => setTimeout(resolve, 10));
			assert.equal(calls, 0, 'still within the cooldown window');
		});

		it('a failed entry IS retried once the cooldown has elapsed, via a fresh startIssuerDiscovery call', async () => {
			_setDiscoveryTimeouts({ retryCooldownMs: 20 });
			_setFetch(fetchFromMap({ [WELL_KNOWN]: 500 }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			assert.equal(await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL), null);

			await new Promise((resolve) => setTimeout(resolve, 30)); // past the (shortened) cooldown
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc() }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, 'https://idp.example.com');
		});

		it('a dynamic provider reads an already-cached result with zero fetches of its own', async () => {
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc() }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'static-idp');
			// Settle the entry first (this is the "static provider" side).
			const settled = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(settled, 'https://idp.example.com');

			// A "dynamic provider" reading the same already-settled key must never fetch.
			_setFetch(() => {
				throw new Error('a dynamic provider must never fetch');
			});
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, 'https://idp.example.com');
		});

		it('a dynamic provider with no matching cache entry gets null immediately, with no fetch', async () => {
			_setFetch(() => {
				throw new Error('must never fetch for an uncached key');
			});
			const issuer = await awaitDiscoveredIssuer(
				'https://never-started.example.com/authorize',
				'https://never-started.example.com/jwks',
				'https://never-started.example.com/token'
			);
			assert.equal(issuer, null);
		});
	});

	describe('containment', () => {
		it('a throwing logger at every level does not prevent kickoff, success logging, or failure logging from completing', async () => {
			const throwingLogger = {
				debug: () => {
					throw new Error('boom');
				},
				info: () => {
					throw new Error('boom');
				},
				warn: () => {
					throw new Error('boom');
				},
				error: () => {
					throw new Error('boom');
				},
			};
			_setFetch(fetchFromMap({ [WELL_KNOWN]: validDoc() }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp', throwingLogger);
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL, throwingLogger);
			assert.equal(issuer, 'https://idp.example.com');
		});

		it('a throwing logger does not prevent a failure from being reported as null', async () => {
			const throwingLogger = {
				debug: () => {
					throw new Error('boom');
				},
				info: () => {
					throw new Error('boom');
				},
				warn: () => {
					throw new Error('boom');
				},
				error: () => {
					throw new Error('boom');
				},
			};
			_setFetch(fetchFromMap({ [WELL_KNOWN]: 500 }));
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp', throwingLogger);
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL, throwingLogger);
			assert.equal(issuer, null);
		});

		it('a DNS failure resolves to null, not a rejection', async () => {
			_setDnsLookup(async () => {
				throw new Error('NXDOMAIN');
			});
			startIssuerDiscovery(AUTH_URL, JWKS_URI, TOKEN_URL, 'custom-idp');
			const issuer = await awaitDiscoveredIssuer(AUTH_URL, JWKS_URI, TOKEN_URL);
			assert.equal(issuer, null);
		});
	});
});
