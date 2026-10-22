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
import { credentialRejectionError } from 'harper';
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
	return signAccessToken(params, signingKey).token;
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

describe('withMCPAuth — rejected-token audit (oauth.mcp.token.rejected)', () => {
	// Inject an emitAudit spy; returns the captured events + the options bag.
	function auditOpts(extra = {}) {
		const events = [];
		return { events, opts: opts({ emitAudit: (p) => events.push(p), ...extra }) };
	}

	it('emits oauth.mcp.token.rejected when a presented token fails validation', async () => {
		const token = mint({}, makeKey(SIGNING_KEY_ID)); // valid kid, wrong key → bad signature
		const { events, opts: o } = auditOpts();
		const res = await withMCPAuth(spyHandler().handler, o)(req(`Bearer ${token}`), NEXT);

		assert.equal(res.status, 401);
		assert.equal(events.length, 1, 'exactly one rejected audit event');
		assert.equal(events[0].event, 'oauth.mcp.token.rejected');
		assert.equal(events[0].aud, RESOURCE, 'aud is the configured resource, not the token claim');
		assert.ok(events[0].reason, 'reason present');
		assert.ok(events[0].timestamp, 'timestamp present');
		// A rejected token has no trustworthy claims — none may leak into the record.
		assert.equal(events[0].client_id, undefined);
		assert.equal(events[0].sub, undefined);
		assert.equal(events[0].jti, undefined);
	});

	it('audits a wrong-audience token (RFC 8707 rejection)', async () => {
		const token = mint({ audience: 'https://evil.example.com/mcp' });
		const { events, opts: o } = auditOpts();
		const res = await withMCPAuth(spyHandler().handler, o)(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401);
		assert.equal(events.length, 1);
		assert.equal(events[0].event, 'oauth.mcp.token.rejected');
	});

	it('does NOT audit a missing-token request (unauthenticated probe, not a rejected token)', async () => {
		const { events, opts: o } = auditOpts();
		const res = await withMCPAuth(spyHandler().handler, o)(req(undefined), NEXT);
		assert.equal(res.status, 401);
		assert.equal(events.length, 0, 'no audit event for a missing token');
	});

	it('does NOT audit when MCP is disabled (denial before any token work)', async () => {
		const { events, opts: o } = auditOpts({ getConfig: () => ({ enabled: false }) });
		const res = await withMCPAuth(spyHandler().handler, o)(req(`Bearer ${mint()}`), NEXT);
		assert.equal(res.status, 401);
		assert.equal(events.length, 0, 'no audit event when the guard short-circuits before token validation');
	});

	it('does NOT audit the path-length guard (pre-token DoS rejection)', async () => {
		const { events, opts: o } = auditOpts();
		const longPath = '/mcp/' + 'a'.repeat(2100);
		const res = await withMCPAuth(spyHandler().handler, o)(req(`Bearer ${mint()}`, { pathname: longPath }), NEXT);
		assert.equal(res.status, 401);
		assert.equal(events.length, 0, 'no audit event for an oversized path');
	});

	it('a throwing emitAudit sink never breaks the fail-closed 401 (no 500)', async () => {
		// emitAudit is part of the exported options surface; a custom sink that throws
		// must not turn the denial into a rejected promise / framework 500.
		const token = mint({}, makeKey(SIGNING_KEY_ID)); // valid kid, wrong key → bad signature
		const o = opts({
			emitAudit: () => {
				throw new Error('audit sink down');
			},
		});
		const res = await withMCPAuth(spyHandler().handler, o)(req(`Bearer ${token}`), NEXT);
		assert.equal(res.status, 401, 'a throwing audit sink must not break the 401');
		assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE);
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
		assert.equal(calls[0].request.mcp.sub, 'alice@example.com');
		assert.equal(request.user, undefined);
	});

	it('resolves request.user via getUser(sub, null, request) when available (#279)', async () => {
		const token = mint();
		const harperUser = {
			username: 'alice@example.com',
			active: true,
			role: { id: 'developer', permission: { super_user: false } },
		};
		const getUserCalls = [];
		const getUser = async (username, password, requestArg) => {
			getUserCalls.push({ username, password, requestArg });
			return harperUser;
		};
		const request = req(`Bearer ${token}`);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(handler, opts({ getUser }))(request, NEXT);

		assert.equal(res.status, 200);
		assert.equal(calls.length, 1);
		assert.equal(getUserCalls.length, 1);
		assert.equal(getUserCalls[0].username, 'alice@example.com');
		assert.equal(getUserCalls[0].password, null);
		assert.equal(getUserCalls[0].requestArg, request);
		assert.equal(request.user, harperUser);
	});

	it('leaves request.user undefined when getUser returns a role-less view ({ username: sub }) for subjects with no hdb_user row', async () => {
		const sub = 'https://agent.example.com/client.json';
		const token = mint({ subject: sub });
		const request = req(`Bearer ${token}`);
		const res = await withMCPAuth(spyHandler().handler, opts({ getUser: async (username) => ({ username }) }))(
			request,
			NEXT
		);

		assert.equal(res.status, 200);
		assert.equal(request.user, undefined);
		assert.equal(request.mcp.sub, sub);
	});

	it('skips getUser lookup and leaves request.user undefined when resolveUser: false is set', async () => {
		const token = mint();
		let getUserCalled = false;
		const request = req(`Bearer ${token}`);
		const res = await withMCPAuth(
			spyHandler().handler,
			opts({
				resolveUser: false,
				getUser: async () => {
					getUserCalled = true;
					return {
						username: 'alice@example.com',
						active: true,
						role: { id: 'developer', permission: { super_user: false } },
					};
				},
			})
		)(request, NEXT);

		assert.equal(res.status, 200);
		assert.equal(getUserCalled, false, 'getUser must not be called when resolveUser is false');
		assert.equal(request.user, undefined);
		assert.equal(request.mcp.sub, 'alice@example.com');
	});

	it('binds default server.getUser to server when resolving request.user', async () => {
		const token = mint();
		const request = req(`Bearer ${token}`);
		const prevServer = globalThis.server;
		globalThis.server = {
			tag: 'bound-server',
			async getUser(username) {
				return {
					username,
					boundTag: this.tag,
					role: { id: 'developer', permission: { super_user: false } },
				};
			},
		};
		try {
			const res = await withMCPAuth(spyHandler().handler, opts())(request, NEXT);
			assert.equal(res.status, 200);
			assert.deepEqual(request.user, {
				username: 'alice@example.com',
				boundTag: 'bound-server',
				role: { id: 'developer', permission: { super_user: false } },
			});
		} finally {
			globalThis.server = prevServer;
		}
	});

	it('fails closed with 401 when getUser throws a credential rejection (e.g. inactive user in hdb_user)', async () => {
		const token = mint();
		const events = [];
		const request = req(`Bearer ${token}`);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				emitAudit: (p) => events.push(p),
				getUser: async () => {
					throw credentialRejectionError('User is not active', 401);
				},
			})
		)(request, NEXT);

		assert.equal(res.status, 401);
		assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE);
		assert.equal(calls.length, 0, 'handler must not run when getUser rejects');
		assert.equal(request.user, undefined, 'request.user must not be populated on denial');
		assert.equal(request.mcp, undefined, 'request.mcp must not be populated on denial');
		assert.equal(events.length, 1);
		assert.equal(events[0].event, 'oauth.mcp.token.rejected');

		const symErr = new Error('User is not active');
		Object.defineProperty(symErr, Symbol('harper.credentialRejection'), { value: true });
		const symRes = await withMCPAuth(
			handler,
			opts({
				getUser: async () => {
					throw symErr;
				},
			})
		)(req(`Bearer ${token}`), NEXT);
		assert.equal(symRes.status, 401);
	});

	it('fails closed with 401 and emits oauth.mcp.token.rejected when getUser throws an untagged error', async () => {
		const token = mint();
		const events = [];
		const request = req(`Bearer ${token}`);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				emitAudit: (p) => events.push(p),
				getUser: async () => {
					throw new Error('user disabled');
				},
			})
		)(request, NEXT);

		assert.equal(res.status, 401);
		assert.equal(res.headers['WWW-Authenticate'], EXPECTED_CHALLENGE);
		assert.equal(calls.length, 0, 'handler must not run when getUser throws');
		assert.equal(request.user, undefined);
		assert.equal(request.mcp, undefined);
		assert.equal(events.length, 1);
		assert.equal(events[0].event, 'oauth.mcp.token.rejected');
		assert.equal(events[0].reason, 'failed to resolve Harper user');
	});

	it('returns 503 Retry-After without emitting oauth.mcp.token.rejected when getUser times out', async () => {
		const token = mint();
		const events = [];
		const request = req(`Bearer ${token}`);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				emitAudit: (p) => events.push(p),
				userLookupTimeoutMs: 20,
				getUser: () => new Promise(() => {}),
			})
		)(request, NEXT);

		assert.equal(res.status, 503);
		assert.equal(res.headers['Retry-After'], '5');
		assert.equal(res.headers['Access-Control-Allow-Origin'], '*');
		assert.equal(res.headers['Access-Control-Expose-Headers'], 'Retry-After');
		assert.equal(calls.length, 0);
		assert.equal(request.user, undefined);
		assert.equal(request.mcp, undefined);
		assert.equal(events.length, 0);
	});

	it('fails closed with 401 when getUser returns an object with active === false', async () => {
		const token = mint();
		const request = req(`Bearer ${token}`);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				getUser: async () => ({ username: 'alice@example.com', active: false }),
			})
		)(request, NEXT);

		assert.equal(res.status, 401);
		assert.equal(calls.length, 0);
		assert.equal(request.user, undefined);
		assert.equal(request.mcp, undefined);
	});

	it('does NOT populate request.user or call getUser for a quarantined subject (#231)', async () => {
		const quarantinedSub = 'unverified:alice@example.com#0123456789abcdef';
		const token = mint({ subject: quarantinedSub });
		let getUserCalled = false;
		const request = req(`Bearer ${token}`);
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				getUser: async () => {
					getUserCalled = true;
					return { username: quarantinedSub, active: true };
				},
			})
		)(request, NEXT);

		assert.equal(res.status, 200);
		assert.equal(calls.length, 1);
		assert.equal(getUserCalled, false, 'getUser must never be called for a quarantine principal');
		assert.equal(request.user, undefined, 'request.user must remain undefined for a quarantine principal');
		assert.equal(request.mcp.sub, quarantinedSub, 'request.mcp still carries the quarantined subject');
	});

	it('preserves an already-populated request.user when its username matches token sub without calling getUser', async () => {
		const token = mint();
		const existingUser = { username: 'alice@example.com', role: { id: 'admin' } };
		let getUserCalled = false;
		const request = req(`Bearer ${token}`);
		request.user = existingUser;
		const res = await withMCPAuth(
			spyHandler().handler,
			opts({
				getUser: async () => {
					getUserCalled = true;
					return { username: 'other' };
				},
			})
		)(request, NEXT);

		assert.equal(res.status, 200);
		assert.equal(getUserCalled, false);
		assert.equal(request.user, existingUser);
	});

	it('fails closed with 401 when an already-populated request.user does not match token sub', async () => {
		const token = mint();
		const events = [];
		const request = req(`Bearer ${token}`);
		request.user = { username: 'different-user', role: { id: 'admin' } };
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				emitAudit: (p) => events.push(p),
			})
		)(request, NEXT);

		assert.equal(res.status, 401);
		assert.equal(calls.length, 0);
		assert.equal(events.length, 1);
		assert.equal(events[0].reason, 'token subject does not match the authenticated user');
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
		// Unowned REST paths with encoded slashes or special segments must also fall through.
		const encodedOther = await wrapped(req(undefined, { pathname: '/Product/abc%2Fdef' }), NEXT);
		assert.equal(encodedOther.__next, true);
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

	it('matches mount-relative request.pathname when Harper sets originalPathname for a mounted app', async () => {
		const token = mint();
		const { handler, calls } = spyHandler();
		const wrapped = withMCPAuth(handler, opts({ path: '/mcp' }));
		const mountedReq = {
			...req(`Bearer ${token}`, { pathname: '/mcp' }),
			originalPathname: '/app1/mcp',
		};
		const ok = await wrapped(mountedReq, NEXT);
		assert.equal(ok.status, 200);
		assert.equal(calls.length, 1);
	});

	it('clears a populated request.user if a default-group handler mistakenly calls next(request)', async () => {
		const token = mint();
		const resolvedUser = {
			username: 'alice@example.com',
			active: true,
			role: { id: 'developer', permission: { super_user: false } },
		};
		let seenInsideHandler;
		const fallthroughHandler = (request, next) => {
			seenInsideHandler = request.user;
			return next(request);
		};
		const wrapped = withMCPAuth(
			fallthroughHandler,
			opts({
				path: '/mcp',
				getUser: async () => resolvedUser,
			})
		);
		const request = req(`Bearer ${token}`, { pathname: '/mcp' });
		const res = await wrapped(request, NEXT);
		assert.equal(seenInsideHandler, resolvedUser, 'handler sees resolved request.user while running');
		assert.equal(res.__next, true);
		assert.equal(request.user, undefined, 'request.user must be cleared before falling through to default chain');
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

	it('rejects dot-segments, encoded dots/slashes, backslashes, and double-slashes before any token work', async () => {
		const token = mint();
		const { handler, calls } = spyHandler();
		const wrapped = withMCPAuth(handler, opts());
		for (const badPath of [
			'/mcp/../SomeTable/1',
			'/mcp/.',
			'/mcp/%2e%2e/SomeTable/1',
			'/mcp/%2fSomeTable/1',
			'/mcp\\SomeTable',
			'//mcp',
			'/mcp//tools',
		]) {
			const res = await wrapped(req(`Bearer ${token}`, { pathname: badPath }), NEXT);
			assert.equal(res.status, 401, `ambiguous path ${badPath} must be rejected with 401`);
		}
		assert.equal(calls.length, 0, 'handler must not run for any ambiguous path');
	});

	it('path: "/" matches only exact "/" and falls through to next() on other paths', async () => {
		const token = mint();
		const { handler, calls } = spyHandler();
		const wrapped = withMCPAuth(handler, opts({ path: '/' }));

		const rootRes = await wrapped(req(`Bearer ${token}`, { pathname: '/' }), NEXT);
		assert.equal(rootRes.status, 200);
		assert.equal(calls.length, 1);

		const otherRes = await wrapped(req(undefined, { pathname: '/other' }), NEXT);
		assert.equal(otherRes.__next, true, 'non-root path must pass through to next() when path is "/"');
		assert.equal(calls.length, 1);
	});

	it('returns 503 Retry-After without emitting oauth.mcp.token.rejected when keyStore throws (#279)', async () => {
		const token = mint();
		const events = [];
		const { handler, calls } = spyHandler();
		const res = await withMCPAuth(
			handler,
			opts({
				emitAudit: (p) => events.push(p),
				keyStore: {
					async getAllPublicKeys() {
						throw new Error('storage read failure');
					},
				},
			})
		)(req(`Bearer ${token}`), NEXT);

		assert.equal(res.status, 503);
		assert.equal(res.headers['Retry-After'], '5');
		assert.equal(res.headers['Access-Control-Allow-Origin'], '*');
		assert.equal(res.headers['Access-Control-Expose-Headers'], 'Retry-After');
		assert.equal(calls.length, 0);
		assert.equal(events.length, 0, 'transient keyStore error must not emit false token.rejected audit');
	});

	it('memoizes verified tokens across repeat calls and isolates request.mcp mutations (#279)', async () => {
		const token = mint();
		let pemReads = 0;
		const trackedKey = {
			kid: key.kid,
			alg: key.alg,
			get public_key_pem() {
				pemReads++;
				return key.public_key_pem;
			},
			created_at: key.created_at,
		};
		const activeKeys = [trackedKey];
		const seenSubs = [];
		const wrapped = withMCPAuth(
			(request) => {
				seenSubs.push(request.mcp.sub);
				request.mcp.sub = 'mutated-by-handler';
				return { status: 200 };
			},
			opts({
				keyStore: {
					async getAllPublicKeys() {
						return activeKeys;
					},
				},
			})
		);

		const req1 = req(`Bearer ${token}`);
		const res1 = await wrapped(req1, NEXT);
		assert.equal(res1.status, 200);
		assert.equal(pemReads, 1, 'first call verifies signature');
		assert.equal(req1.mcp.sub, 'mutated-by-handler');

		const req2 = req(`Bearer ${token}`);
		const res2 = await wrapped(req2, NEXT);
		assert.equal(res2.status, 200);
		assert.equal(pemReads, 1, 'repeat call on same wrapper hits verifiedTokenMemo without re-verifying signature');
		assert.deepEqual(
			seenSubs,
			['alice@example.com', 'alice@example.com'],
			'memoized claims must be isolated from handler mutation'
		);
	});
});
