/**
 * Tests for withMCPAuth — the MCP bearer-token guard (Stage 5).
 *
 * Covers every rejection branch (no/malformed Authorization, bad signature,
 * expired, audience mismatch, unknown kid, query-string token, MCP disabled,
 * no keys), the happy path (claims attached, handler invoked once, response
 * returned verbatim), the WWW-Authenticate PRM contract, header-shape
 * robustness, the default-group `path` fall-through, and onAuthError.
 *
 * Dependencies are injected (getConfig / keyStore) so the test never touches
 * the live OAuthResource config or the Harper keys table.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { withMCPAuth } from '../../../dist/lib/mcp/withMCPAuth.js';
import { signAccessToken } from '../../../dist/lib/mcp/tokenIssuer.js';
import { SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';

const ISSUER = 'https://as.example.com';
const RESOURCE = 'https://app.example.com/mcp';
// RFC 9728 §3.1: the PRM URL is derived from the RESOURCE (origin + well-known +
// the resource's path), not the issuer — so it's the app origin with /mcp appended.
const PRM_URL = 'https://app.example.com/.well-known/oauth-protected-resource/mcp';
const EXPECTED_CHALLENGE = `Bearer resource_metadata="${PRM_URL}"`;

function makeKey(modulusKid = SIGNING_KEY_ID) {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	return {
		kid: modulusKid,
		alg: 'RS256',
		public_key_pem: publicKey,
		private_key_pem: privateKey,
		created_at: 1700000000,
	};
}

const key = makeKey();

function mint(overrides = {}, signingKey = key) {
	const params = {
		issuer: ISSUER,
		subject: 'alice@example.com',
		audience: RESOURCE,
		clientId: 'client-123',
		scope: 'mcp:read',
		ttlSeconds: 3600,
		...overrides,
	};
	return signAccessToken(params, signingKey);
}

const config = { enabled: true, issuer: ISSUER, resource: RESOURCE };
const silentLogger = { error() {}, warn() {}, info() {}, debug() {} };

/** Build the options bag with injected config + key set (defaults to [key]). */
function opts(extra = {}) {
	return {
		getConfig: () => config,
		keyStore: {
			async getAllPublicKeys() {
				return extra.keys ?? [key];
			},
		},
		logger: silentLogger,
		...extra,
	};
}

/** A request with a plain-object headers map (Node IncomingMessage shape). */
function req(authorization, { pathname = '/mcp', url } = {}) {
	const headers = {};
	if (authorization !== undefined) headers.authorization = authorization;
	headers.host = 'app.example.com';
	return { headers, pathname, url: url ?? pathname, method: 'POST' };
}

/** Records handler invocations; returns a unique sentinel response. */
function spyHandler(response = { status: 200, body: 'ok' }) {
	const calls = [];
	const handler = (request, next) => {
		calls.push({ request, next });
		return response;
	};
	return { handler, calls, response };
}

const NEXT = (request) => ({ __next: true, request });

describe('withMCPAuth — construction', () => {
	it('throws if handler is not a function', () => {
		assert.throws(() => withMCPAuth(undefined), TypeError);
		assert.throws(() => withMCPAuth({}), TypeError);
	});
});

describe('withMCPAuth — rejections (all return 401 + Bearer PRM challenge)', () => {
	it('rejects a request with no Authorization header', async () => {
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(handler, opts())(req(undefined), NEXT);
		assert.equal(res.status, 401);
		assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE);
		assert.equal(res.headers['Content-Type'], 'application/json');
		assert.equal(calls.length, 0, 'handler must not run');
	});

	it('rejects a malformed Authorization header (wrong scheme / empty token)', async () => {
		for (const bad of ['Basic abc123', 'Bearer', 'Bearer    ', 'Token xyz', 'xyz']) {
			const { handler, calls } = spyHandler();
			const res = await withMCPAuth(handler, opts())(req(bad), NEXT);
			assert.equal(res.status, 401, `"${bad}" should 401`);
			assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE, `"${bad}" same challenge`);
			assert.equal(calls.length, 0);
		}
	});

	it('rejects a token with an invalid signature', async () => {
		// Same kid, different key material → selected by kid, fails signature.
		const forged = makeKey(SIGNING_KEY_ID);
		const token = mint({}, forged);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(handler, opts())(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
		assert.equal(calls.length, 0);
	});

	it('rejects a token with an unknown kid (no silent fallback to another key)', async () => {
		const other = makeKey('some-other-kid');
		const token = mint({}, other);
		const res = await withMCPAuth(spyHandler().handler, opts())(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
	});

	it('rejects an expired token', async () => {
		const token = mint({ ttlSeconds: -10 });
		const res = await withMCPAuth(spyHandler().handler, opts())(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
	});

	it('rejects a token whose audience does not match mcp.resource (RFC 8707)', async () => {
		const token = mint({ audience: 'https://evil.example.com/mcp' });
		const res = await withMCPAuth(spyHandler().handler, opts())(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
	});

	it('rejects a token whose issuer does not match', async () => {
		const token = mint({ issuer: 'https://evil.example.com' });
		const res = await withMCPAuth(spyHandler().handler, opts())(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
	});

	it('ignores a query-string token (header-only; never validated)', async () => {
		const token = mint();
		const { handler, calls } = spyHandler();
		const request = req(undefined, { url: `/mcp?access_token=${token}` });
		const res = await withMCPAuth(handler, opts())(request, NEXT);
		assert.equal(res.status, 401, 'query-string token treated as no token');
		assert.equal(calls.length, 0);
	});

	it('fails closed when MCP is disabled', async () => {
		const token = mint();
		const res = await withMCPAuth(spyHandler().handler, opts({ getConfig: () => ({ enabled: false }) }))(
			req(`Bearer ${token}`),
			NEXT
		);
		assert.equal(res.status, 401);
	});

	it('fails closed when config is entirely absent (challenge still well-formed)', async () => {
		const res = await withMCPAuth(spyHandler().handler, opts({ getConfig: () => undefined }))(req(undefined), NEXT);
		assert.equal(res.status, 401);
		// No config → resource derives as <request-origin>/mcp, so the PRM URL is
		// the request host with the /mcp path appended.
		assert.equal(
			res.headers['WWW-Authenticate'],
			'Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource/mcp"'
		);
	});

	it('fails closed when no signing keys are published', async () => {
		const token = mint();
		const res = await withMCPAuth(spyHandler().handler, opts({ keys: [] }))(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
	});

	it('emits the BARE PRM challenge when the resource is at the origin root (no path)', async () => {
		const res = await withMCPAuth(
			spyHandler().handler,
			opts({ getConfig: () => ({ enabled: true, issuer: ISSUER, resource: 'https://app.example.com' }) })
		)(req(undefined), NEXT);
		assert.equal(res.status, 401);
		assert.equal(
			res.headers['WWW-Authenticate'],
			'Bearer resource_metadata="https://app.example.com/.well-known/oauth-protected-resource"',
			'a root resource has no path to append'
		);
	});
});

describe('withMCPAuth — happy path', () => {
	it('attaches request.mcp and invokes the handler once with the response returned verbatim', async () => {
		const token = mint();
		const sentinel = { status: 201, body: { hello: 'world' }, headers: { 'X-Custom': '1' } };
		const { handler, calls } = spyHandler(sentinel);
		const request = req(`Bearer ${token}`);
		const res = await withMCPAuth(handler, opts())(request, NEXT);

		assert.equal(res, sentinel, 'response returned verbatim (no double-wrap)');
		assert.equal(calls.length, 1, 'handler invoked exactly once');
		assert.deepEqual(request.mcp, {
			sub: 'alice@example.com',
			client_id: 'client-123',
			aud: RESOURCE,
			scope: 'mcp:read',
		});
		// The handler observes request.mcp already populated.
		assert.equal(calls[0].request.mcp.sub, 'alice@example.com');
	});

	it('forwards next to the wrapped handler', async () => {
		const token = mint();
		let received;
		const handler = (_request, next) => {
			received = next;
			return { status: 200 };
		};
		await withMCPAuth(handler, opts())(req(`Bearer ${token}`), NEXT);
		assert.equal(received, NEXT);
	});

	it('accepts a token with no scope (scope omitted from claims)', async () => {
		const token = mint({ scope: undefined });
		const request = req(`Bearer ${token}`);
		await withMCPAuth(spyHandler().handler, opts())(request, NEXT);
		assert.equal(request.mcp.scope, undefined);
		assert.equal(request.mcp.sub, 'alice@example.com');
	});

	it('reads the bearer token from a Web Headers object (.get)', async () => {
		const token = mint();
		const request = {
			headers: new Headers({ authorization: `Bearer ${token}`, host: 'app.example.com' }),
			pathname: '/mcp',
		};
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(handler, opts())(request, NEXT);
		assert.equal(calls.length, 1);
		assert.equal(res.status, 200);
	});

	it('reads the bearer token from a Harper headers wrapper (.asObject)', async () => {
		const token = mint();
		const request = {
			headers: { asObject: { authorization: `Bearer ${token}`, host: 'app.example.com' } },
			pathname: '/mcp',
		};
		const { handler, calls } = spyHandler();
		await withMCPAuth(handler, opts())(request, NEXT);
		assert.equal(calls.length, 1);
	});
});

describe('withMCPAuth — default-group registration (path option)', () => {
	it('falls through (calls next) for a path it does not own', async () => {
		const { handler, calls } = spyHandler();
		const wrapped = withMCPAuth(handler, opts({ path: '/mcp' }));
		const res = await wrapped(req(undefined, { pathname: '/other' }), NEXT);
		assert.deepEqual(res, { __next: true, request: res.request });
		assert.equal(res.__next, true, 'next() was called for unowned path');
		assert.equal(calls.length, 0, 'guard did not run for unowned path');
	});

	it('guards its own path and sub-paths', async () => {
		const token = mint();
		const wrapped = withMCPAuth(spyHandler().handler, opts({ path: '/mcp' }));
		// Unowned look-alike must fall through, not be guarded.
		const lookalike = await wrapped(req(undefined, { pathname: '/mcponaut' }), NEXT);
		assert.equal(lookalike.__next, true);
		// Owned sub-path with no token must be rejected.
		const denied = await wrapped(req(undefined, { pathname: '/mcp/tools' }), NEXT);
		assert.equal(denied.status, 401);
		// Owned path with a valid token must pass.
		const { handler, calls } = spyHandler();
		const wrapped2 = withMCPAuth(handler, opts({ path: '/mcp' }));
		const ok = await wrapped2(req(`Bearer ${token}`, { pathname: '/mcp' }), NEXT);
		assert.equal(ok.status, 200);
		assert.equal(calls.length, 1);
	});
});

describe('withMCPAuth — onAuthError', () => {
	it('returns the callback result when it provides one', async () => {
		const custom = { status: 403, body: 'denied by app' };
		const res = await withMCPAuth(spyHandler().handler, opts({ onAuthError: () => custom }))(req(undefined), NEXT);
		assert.equal(res, custom);
	});

	it('falls back to the default 401 when the callback returns undefined (fail closed)', async () => {
		let seen;
		const onAuthError = (request, error) => {
			seen = { error };
			// no return — must NOT become a pass
		};
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(handler, opts({ onAuthError }))(req(undefined), NEXT);
		assert.equal(res.status, 401);
		assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE);
		assert.equal(calls.length, 0, 'a no-return callback never lets the handler run');
		assert.ok(seen.error, 'callback received a reason string');
	});

	it('falls back to the default 401 for ANY falsy callback return (fail closed by construction)', async () => {
		// Guards the `||` (not `??`) fallback: a handler that returns false / '' /
		// 0 / null must never produce a non-response that bypasses the challenge.
		for (const falsy of [false, '', 0, null, NaN]) {
			const res = await withMCPAuth(spyHandler().handler, opts({ onAuthError: () => falsy }))(req(undefined), NEXT);
			assert.equal(res.status, 401, `falsy return ${String(falsy)} must yield the default 401`);
			assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE);
		}
	});
});

describe('withMCPAuth — hardening', () => {
	it('rejects an over-length request path (>2048) before any token work (repo invariant)', async () => {
		const token = mint();
		const { handler, calls } = spyHandler();
		const longPath = '/mcp/' + 'a'.repeat(2100);
		const res = await withMCPAuth(handler, opts())(req(`Bearer ${token}`, { pathname: longPath }), NEXT);
		assert.equal(res.status, 401, 'over-length path is rejected');
		assert.equal(calls.length, 0, 'handler must not run');
	});

	it('keeps the WWW-Authenticate challenge header-safe against a quote-injecting Host', async () => {
		// No config → issuer derives from the request Host (RFC 9728 fallback). A
		// Host carrying a `"` must NOT break out of resource_metadata="...".
		const request = req(undefined, { pathname: '/mcp' });
		request.headers.host = 'evil.com" injected_param="x';
		const res = await withMCPAuth(spyHandler().handler, opts({ getConfig: () => undefined }))(request, NEXT);
		assert.equal(res.status, 401);
		const wa = res.headers['WWW-Authenticate'];
		assert.equal((wa.match(/"/g) || []).length, 2, `exactly one quoted param; got: ${wa}`);
		assert.ok(!wa.includes('injected_param'), `no injected header param; got: ${wa}`);
	});

	it('sets CORS headers on the deny response so browser clients can read the challenge', async () => {
		const res = await withMCPAuth(spyHandler().handler, opts())(req(undefined), NEXT);
		assert.equal(res.status, 401);
		assert.equal(res.headers['Access-Control-Allow-Origin'], '*');
		assert.equal(res.headers['Access-Control-Expose-Headers'], 'WWW-Authenticate');
	});
});
