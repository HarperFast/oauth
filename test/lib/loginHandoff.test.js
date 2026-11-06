/**
 * Tests for the sign-in handoff to an allowlisted origin
 * (postLoginRedirectOrigins; HarperFast/central-manager#911).
 *
 * Every security requirement has a test here that fails when its guard is
 * removed: https only, one-label wildcards, no userinfo/port/path tricks,
 * single-use + 60s + origin/browser-bound codes, the redeem's Origin check,
 * the empty-allowlist no-op, and code-free refusal logs.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import {
	parseOriginPattern,
	normalizePostLoginRedirectOrigins,
	matchAllowedOrigin,
	resolveHandoffTarget,
	appendHandoffCode,
	issueLoginHandoff,
	redeemLoginHandoff,
	handleLoginHandoffRedeem,
	handoffKey,
	resetLoginHandoffTableCache,
	setLoginHandoffMissRetryDelays,
	LOGIN_HANDOFF_TTL_MS,
	HANDOFF_FRAGMENT_PARAM,
} from '../../dist/lib/loginHandoff.js';
import { handleLogin, handleCallback } from '../../dist/lib/handlers.js';
import { OAuthResource } from '../../dist/lib/resource.js';
import { extractPluginDefaults } from '../../dist/lib/config.js';
import { hashBrowserSecret, buildBrowserSecretCookie } from '../../dist/lib/mcp/consentBinding.js';
import { createMockFn, createMockLogger } from '../helpers/mockFn.js';

const PREVIEWS = 'https://*.app.dev.studio.example.com';
const PREVIEW = 'https://hdbms-pr-12.app.dev.studio.example.com';
const OTHER_PREVIEW = 'https://hdbms-pr-13.app.dev.studio.example.com';
const SECRET = 'S'.repeat(43);
const OTHER_SECRET = 'O'.repeat(43);

function patterns(...entries) {
	return normalizePostLoginRedirectOrigins(entries.length ? entries : [PREVIEWS]);
}

function cookieFor(secret) {
	return buildBrowserSecretCookie(secret).split(';')[0];
}

/**
 * Everything any logger method received, joined, to assert a secret never
 * appears. Objects are inspected as a logger would print them, own properties
 * and `cause` included.
 */
function loggedText(logger) {
	return ['debug', 'info', 'warn', 'error']
		.flatMap((level) =>
			logger[level].mock.calls.flatMap((call) =>
				call.arguments.map((a) => (typeof a === 'string' ? a : inspect(a, { depth: 10 })))
			)
		)
		.join('\n');
}

/** A storage-style error whose own property and `cause` carry a provider token. */
function errorCarryingToken(message) {
	const error = new Error(message, { cause: new Error('write of {"accessToken":"gho_CAUSE"} failed') });
	error.record = { session: '{"accessToken":"gho_PROPERTY"}' };
	return error;
}

function assertLoggedStackWithoutTokens(logger, message) {
	const text = loggedText(logger);
	assert.ok(text.includes(`Error: ${message}\n    at `), 'the stack is logged');
	assert.ok(!text.includes('gho_CAUSE') && !text.includes('gho_PROPERTY'), 'no token from the error object');
}

/** Harper's patch: plain fields replace, `{ __op__: 'add' }` adds to the stored number. */
function applyPatch(stored, update) {
	const next = { ...stored };
	for (const [name, value] of Object.entries(update)) {
		next[name] = value?.__op__ === 'add' ? (Number(next[name]) || 0) + value.value : value;
	}
	return next;
}

/**
 * A read without a context joins the request's transaction and sees its
 * snapshot, taken at the first such read (AGENTS.md); a context opens a fresh
 * one that sees committed writes. The mock models both, so a read-back that
 * lost its fresh context would see the pre-patch row and fail the tests.
 */
function installHandoffTable() {
	const rows = new Map();
	const snapshot = new Map();
	const table = {
		rows,
		puts: [],
		readContexts: [],
		get: async (id, context) => {
			table.readContexts.push(context);
			if (context !== undefined) return rows.get(id) ?? null;
			if (!snapshot.has(id)) snapshot.set(id, rows.get(id) ?? null);
			return snapshot.get(id);
		},
		put: async (record, context) => {
			table.puts.push({ record, context });
			rows.set(record.id, { ...record });
		},
		patch: async (id, update) => {
			rows.set(id, applyPatch(rows.get(id), update));
		},
		delete: async (id) => {
			rows.delete(id);
		},
	};
	globalThis.databases = {
		...(globalThis.databases ?? {}),
		oauth: { login_handoffs: table },
		system: { hdb_user: { get: async () => null } },
	};
	resetLoginHandoffTableCache();
	setLoginHandoffMissRetryDelays([]);
	return table;
}

describe('postLoginRedirectOrigins patterns', () => {
	describe('https only', () => {
		it('rejects an http pattern at config load', () => {
			assert.throws(() => parseOriginPattern('http://*.app.example.com'), /postLoginRedirectOrigins.*https:\/\//);
		});

		it('does not match an http URL on an allowlisted host', () => {
			assert.equal(matchAllowedOrigin('http://hdbms-pr-12.app.dev.studio.example.com/', patterns()), null);
			assert.equal(matchAllowedOrigin(`${PREVIEW}/`, patterns()), PREVIEW);
		});
	});

	describe('a wildcard matches exactly one label', () => {
		it('matches one label', () => {
			assert.equal(matchAllowedOrigin(`${PREVIEW}/#/check-oauth`, patterns()), PREVIEW);
		});

		it('does not match two labels', () => {
			assert.equal(matchAllowedOrigin('https://a.b.app.dev.studio.example.com/', patterns()), null);
		});

		it('does not match the bare suffix', () => {
			assert.equal(matchAllowedOrigin('https://app.dev.studio.example.com/', patterns()), null);
		});

		it('does not match the suffix inside a longer host', () => {
			assert.equal(matchAllowedOrigin('https://x.app.dev.studio.example.com.evil.com/', patterns()), null);
			assert.equal(matchAllowedOrigin('https://xapp.dev.studio.example.com/', patterns()), null);
		});

		it('an exact entry matches only that host', () => {
			const exact = patterns('https://studio.example.com');
			assert.equal(matchAllowedOrigin('https://studio.example.com/x', exact), 'https://studio.example.com');
			assert.equal(matchAllowedOrigin('https://a.studio.example.com/', exact), null);
		});
	});

	describe('no userinfo, port or path tricks', () => {
		it('rejects credentials, even on an allowlisted host', () => {
			assert.equal(matchAllowedOrigin('https://user:pw@hdbms-pr-12.app.dev.studio.example.com/', patterns()), null);
			assert.equal(matchAllowedOrigin('https://hdbms-pr-12.app.dev.studio.example.com@evil.com/', patterns()), null);
		});

		it('rejects a non-default port unless the pattern names it', () => {
			assert.equal(matchAllowedOrigin('https://hdbms-pr-12.app.dev.studio.example.com:444/', patterns()), null);
			assert.equal(matchAllowedOrigin('https://hdbms-pr-12.app.dev.studio.example.com:443/', patterns()), PREVIEW);
			const withPort = patterns('https://*.app.example.com:8443');
			assert.equal(matchAllowedOrigin('https://a.app.example.com:8443/', withPort), 'https://a.app.example.com:8443');
			assert.equal(matchAllowedOrigin('https://a.app.example.com/', withPort), null);
		});

		it('judges the parsed host, not a substring of the URL', () => {
			for (const evil of [
				'https://evil.com/?x.app.dev.studio.example.com',
				'https://evil.com/#.app.dev.studio.example.com',
				'https://evil.com/a.app.dev.studio.example.com',
				'https://evil.com\\@a.app.dev.studio.example.com',
				'//hdbms-pr-12.app.dev.studio.example.com/',
				'/hdbms-pr-12.app.dev.studio.example.com',
				'javascript:alert(1)//hdbms-pr-12.app.dev.studio.example.com',
			]) {
				assert.equal(matchAllowedOrigin(evil, patterns()), null, evil);
			}
		});

		it('rejects malformed patterns', () => {
			for (const bad of [
				'https://*.com',
				'https://a.*.example.com',
				'https://*example.com',
				'https://**.example.com',
				'https://example.com/path',
				'https://example.com?x=1',
				'https://example.com#x',
				'https://user@example.com',
				'*.example.com',
				'https://1.2.3.4',
				'https://[::1]',
				'https://example.com:99999',
			]) {
				assert.throws(() => parseOriginPattern(bad), /postLoginRedirectOrigins/, bad);
			}
		});
	});

	describe('normalizePostLoginRedirectOrigins', () => {
		const ENV = 'OAUTH_TEST_HANDOFF_ORIGINS';
		afterEach(() => delete process.env[ENV]);

		it('empty, absent, or an unset ${VAR} is an empty allowlist', () => {
			assert.deepEqual(normalizePostLoginRedirectOrigins(undefined), []);
			assert.deepEqual(normalizePostLoginRedirectOrigins(null), []);
			assert.deepEqual(normalizePostLoginRedirectOrigins(''), []);
			assert.deepEqual(normalizePostLoginRedirectOrigins([]), []);
			assert.deepEqual(normalizePostLoginRedirectOrigins(`\${${ENV}}`), []);
		});

		it('expands ${VAR} to a comma- or space-separated list', () => {
			process.env[ENV] = 'https://studio.example.com, https://*.app.example.com';
			const parsed = normalizePostLoginRedirectOrigins(`\${${ENV}}`);
			assert.deepEqual(
				parsed.map((p) => p.source),
				['https://studio.example.com', 'https://*.app.example.com']
			);
		});

		it('drops an unset ${VAR} piece of a comma-separated string, with a warning', () => {
			const logger = createMockLogger();
			const parsed = normalizePostLoginRedirectOrigins(`${PREVIEWS}, \${${ENV}}`, logger);
			assert.deepEqual(
				parsed.map((p) => p.source),
				[PREVIEWS]
			);
			assert.equal(logger.warn.mock.calls.length, 1);
		});

		it('expands a set ${VAR} piece of a comma-separated string', () => {
			process.env[ENV] = `${PREVIEW}, ${OTHER_PREVIEW}`;
			const parsed = normalizePostLoginRedirectOrigins(`https://studio.example.com, \${${ENV}}`);
			assert.deepEqual(
				parsed.map((p) => p.source),
				['https://studio.example.com', PREVIEW, OTHER_PREVIEW]
			);
			const listed = normalizePostLoginRedirectOrigins([`https://studio.example.com \${${ENV}}`]);
			assert.equal(listed.length, 3);
		});

		it('does not expand a variable named inside another variable, with a warning', () => {
			const logger = createMockLogger();
			process.env[`${ENV}_INNER`] = PREVIEW;
			process.env[ENV] = `https://studio.example.com, \${${ENV}_INNER}`;
			try {
				const parsed = normalizePostLoginRedirectOrigins(`\${${ENV}}`, logger);
				assert.deepEqual(
					parsed.map((p) => p.source),
					['https://studio.example.com']
				);
				assert.equal(logger.warn.mock.calls.length, 1);
			} finally {
				delete process.env[`${ENV}_INNER`];
			}
		});

		it('drops an unset ${VAR} entry inside a list, with a warning', () => {
			const logger = createMockLogger();
			const parsed = normalizePostLoginRedirectOrigins([`\${${ENV}}`, PREVIEWS], logger);
			assert.deepEqual(
				parsed.map((p) => p.source),
				[PREVIEWS]
			);
			assert.equal(logger.warn.mock.calls.length, 1);
		});

		it('throws on an invalid entry, naming the option', () => {
			assert.throws(() => normalizePostLoginRedirectOrigins(['http://x.example.com']), /postLoginRedirectOrigins/);
			assert.throws(() => normalizePostLoginRedirectOrigins({ a: 1 }), /postLoginRedirectOrigins/);
		});

		it('is a plugin-level option, not copied into provider defaults', () => {
			const defaults = extractPluginDefaults({ postLoginRedirectOrigins: [PREVIEWS], scope: 'openid' });
			assert.equal(defaults.postLoginRedirectOrigins, undefined);
			assert.equal(defaults.scope, 'openid');
		});
	});

	describe('isAllowedPostLoginOrigin (package export)', () => {
		it('is exported from the package entry and applies the same rules', async () => {
			const { isAllowedPostLoginOrigin } = await import('../../dist/index.js');
			const dev = 'https://*.app.dev.studio.harperfabric.com';
			assert.equal(isAllowedPostLoginOrigin('https://hdbms-pr-12.app.dev.studio.harperfabric.com/#/x', dev), true);
			for (const bad of [
				'http://hdbms-pr-12.app.dev.studio.harperfabric.com/',
				'https://a.b.app.dev.studio.harperfabric.com/',
				'https://hdbms-pr-12.app.dev.studio.harperfabric.com.evil.com/',
				'https://u@hdbms-pr-12.app.dev.studio.harperfabric.com/',
				'https://hdbms-pr-12.app.dev.studio.harperfabric.com:8443/',
				'https://evil.com/hdbms-pr-12.app.dev.studio.harperfabric.com',
			]) {
				assert.equal(isAllowedPostLoginOrigin(bad, dev), false, bad);
			}
			assert.equal(isAllowedPostLoginOrigin('https://hdbms-pr-12.app.dev.studio.harperfabric.com/', ''), false);
			assert.equal(isAllowedPostLoginOrigin('https://studio.example.com/', `${dev}, https://studio.example.com`), true);
			// central-manager passes config.yaml's literal `${VAR}` and relies on it being expanded.
			const ENV = 'OAUTH_TEST_EXPORT_HANDOFF_ORIGINS';
			try {
				assert.equal(isAllowedPostLoginOrigin('https://pr-1.app.dev.studio.harperfabric.com/', `\${${ENV}}`), false);
				process.env[ENV] = dev;
				assert.equal(isAllowedPostLoginOrigin('https://pr-1.app.dev.studio.harperfabric.com/', `\${${ENV}}`), true);
			} finally {
				delete process.env[ENV];
			}
		});
	});

	describe('resolveHandoffTarget', () => {
		it('returns the parsed target and its origin', () => {
			assert.deepEqual(
				resolveHandoffTarget('https://HDBMS-PR-12.app.dev.studio.example.com/#/check-oauth', patterns()),
				{
					origin: PREVIEW,
					target: `${PREVIEW}/#/check-oauth`,
				}
			);
		});

		it('does not hand off a relative path, a non-string, or an over-long target', () => {
			assert.equal(resolveHandoffTarget('/#/check-oauth', patterns()), null);
			assert.equal(resolveHandoffTarget(['https://x'], patterns()), null);
			assert.equal(resolveHandoffTarget(`${PREVIEW}/#/${'a'.repeat(2048)}`, patterns()), null);
			// Under the cap raw, over it once normalized (each space becomes %20).
			assert.equal(resolveHandoffTarget(`${PREVIEW}/#/${' '.repeat(900)}x`, patterns()), null);
		});
	});

	describe('appendHandoffCode', () => {
		it('puts the code in the fragment, as the hash router query', () => {
			assert.equal(
				appendHandoffCode(`${PREVIEW}/#/check-oauth`, 'CODE'),
				`${PREVIEW}/#/check-oauth?${HANDOFF_FRAGMENT_PARAM}=CODE`
			);
			assert.equal(appendHandoffCode(`${PREVIEW}/#/a?b=1`, 'CODE'), `${PREVIEW}/#/a?b=1&oauth_handoff=CODE`);
			assert.equal(appendHandoffCode(`${PREVIEW}/x?q=1`, 'CODE'), `${PREVIEW}/x?q=1#?oauth_handoff=CODE`);
		});

		it('drops a planted oauth_handoff so the page cannot read it first', () => {
			assert.equal(
				appendHandoffCode(`${PREVIEW}/#/a?oauth_handoff=PLANTED&b=1&oauth_handoff`, 'CODE'),
				`${PREVIEW}/#/a?b=1&oauth_handoff=CODE`
			);
			const encoded = new URL(appendHandoffCode(`${PREVIEW}/#/a?%6fauth_handoff=PLANTED&o%61uth_handoff=X`, 'CODE'));
			const query = encoded.hash.slice(encoded.hash.indexOf('?') + 1);
			assert.deepEqual(new URLSearchParams(query).getAll('oauth_handoff'), ['CODE']);
		});
	});
});

describe('handoff code store', () => {
	let table;
	beforeEach(() => {
		table = installHandoffTable();
	});
	afterEach(() => {
		delete globalThis.databases;
		resetLoginHandoffTableCache();
	});

	const record = () => ({
		origin: PREVIEW,
		browserNonceHash: hashBrowserSecret(SECRET),
		provider: 'github',
		session: { user: 'alice@example.com', oauth: { accessToken: 'at-1' }, ssoAuthAt: 1730000000000 },
	});

	it('stores only the hash of the code, with a ~60s expiry', async () => {
		const before = Date.now();
		const code = await issueLoginHandoff(record());
		assert.match(code, /^[A-Za-z0-9_-]{43}$/);
		assert.equal(table.rows.has(code), false);
		const row = table.rows.get(handoffKey(code));
		assert.ok(row);
		assert.ok(!JSON.stringify(row).includes(code), 'the code itself is never stored');
		assert.equal(LOGIN_HANDOFF_TTL_MS, 60_000);
		assert.ok(row.expires_at >= before + 60_000 && row.expires_at <= Date.now() + 60_000);
		assert.equal(table.puts[0].context.expiresAt, row.expires_at, 'per-record Harper expiry set');
	});

	it('reads in fresh transactions, never the request snapshot', async () => {
		const code = await issueLoginHandoff(record());
		assert.ok((await redeemLoginHandoff(code)).record);
		assert.ok(table.readContexts.length >= 2);
		assert.ok(table.readContexts.every((context) => context && typeof context === 'object'));
		assert.equal(new Set(table.readContexts).size, table.readContexts.length, 'a new context per read');
	});

	it('is single-use, keeping a scrubbed tombstone until expiry', async () => {
		const code = await issueLoginHandoff(record());
		const first = await redeemLoginHandoff(code);
		assert.equal(first.record.origin, PREVIEW);
		assert.deepEqual(first.record.session, record().session);
		assert.deepEqual(await redeemLoginHandoff(code), { refused: 'replayed' });
		const tombstone = table.rows.get(handoffKey(code));
		assert.equal(tombstone.uses, 1);
		assert.equal(tombstone.session, null, 'provider tokens do not outlive the redeem');
	});

	it('a presenter that read the live row before the winner finished cannot also win', async () => {
		const code = await issueLoginHandoff(record());
		const patch = table.patch;
		let patches = 0;
		let releaseSecond;
		const gate = new Promise((resolve) => (releaseSecond = resolve));
		table.patch = async (...args) => {
			if (++patches === 2) await gate;
			return patch(...args);
		};
		const first = redeemLoginHandoff(code);
		const second = redeemLoginHandoff(code);
		assert.ok((await first).record, 'the first presenter wins');
		releaseSecond();
		assert.deepEqual(await second, { refused: 'replayed' });
	});

	it('never lets two concurrent presentations both win', async () => {
		const code = await issueLoginHandoff(record());
		const results = await Promise.all([redeemLoginHandoff(code), redeemLoginHandoff(code), redeemLoginHandoff(code)]);
		assert.ok(results.filter((r) => r.record).length <= 1);
		assert.ok(results.filter((r) => r.refused === 'replayed').length >= 2);
	});

	it('a refused check consumes nothing', async () => {
		const code = await issueLoginHandoff(record());
		assert.deepEqual(await redeemLoginHandoff(code, () => 'wrong origin'), {
			refused: 'mismatch',
			detail: 'wrong origin',
		});
		assert.ok((await redeemLoginHandoff(code)).record);
	});

	it('bounds how many redeems re-read a miss at once', async () => {
		setLoginHandoffMissRetryDelays([20]);
		const before = table.readContexts.length;
		const misses = Array.from({ length: 40 }, (_, i) => redeemLoginHandoff(String(i).padStart(43, 'Z')));
		assert.ok((await Promise.all(misses)).every((r) => r.refused === 'unknown'));
		assert.equal(table.readContexts.length - before, 40 + 32, 'only 32 of 40 concurrent misses re-read');
	});

	it('re-reads a code not found yet (replication lag), then gives up', async () => {
		setLoginHandoffMissRetryDelays([1, 1]);
		const code = await issueLoginHandoff(record());
		const row = table.rows.get(handoffKey(code));
		table.rows.delete(handoffKey(code));
		const get = table.get;
		let reads = 0;
		table.get = async (id, context) => {
			if (++reads === 2) table.rows.set(handoffKey(code), row);
			return get(id, context);
		};
		assert.ok((await redeemLoginHandoff(code)).record, 'found on a re-read');
		table.get = get;
		assert.deepEqual(await redeemLoginHandoff('A'.repeat(43)), { refused: 'unknown' });
	});

	it('expires after the TTL', async () => {
		const code = await issueLoginHandoff(record());
		const row = table.rows.get(handoffKey(code));
		table.rows.set(handoffKey(code), { ...row, expires_at: Date.now() - 1 });
		assert.deepEqual(await redeemLoginHandoff(code), { refused: 'expired' });
	});

	it('logs a storage failure with its stack but not the error object', async () => {
		const logger = createMockLogger();
		table.put = async () => {
			throw errorCarryingToken('put failed');
		};
		await assert.rejects(issueLoginHandoff(record(), logger), (error) => {
			assert.equal(error.cause, undefined);
			return true;
		});
		assertLoggedStackWithoutTokens(logger, 'put failed');
	});
});

describe('POST /oauth/handoff (handleLoginHandoffRedeem)', () => {
	let logger;
	let code;
	let session;

	beforeEach(async () => {
		installHandoffTable();
		logger = createMockLogger();
		code = await issueLoginHandoff({
			origin: PREVIEW,
			browserNonceHash: hashBrowserSecret(SECRET),
			provider: 'github',
			session: { user: 'alice@example.com', oauthUser: { username: 'alice' }, ssoAuthAt: 1730000000000 },
		});
		session = { update: createMockFn(async () => {}) };
	});
	afterEach(() => {
		delete globalThis.databases;
		resetLoginHandoffTableCache();
	});

	const redeemRequest = (headers) => ({ headers, session });
	const redeem = (headers, body = { code }, list = patterns()) =>
		handleLoginHandoffRedeem(redeemRequest(headers), body, list, logger);

	it('writes the stored session for the calling origin', async () => {
		const result = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		assert.equal(result.status, 200);
		assert.deepEqual(result.body, { authenticated: true, provider: 'github' });
		assert.equal(session.update.mock.calls.length, 1);
		assert.deepEqual(session.update.mock.calls[0].arguments[0], {
			user: 'alice@example.com',
			oauthUser: { username: 'alice' },
			ssoAuthAt: 1730000000000,
		});
	});

	it('is a 404, exactly as before, while the allowlist is empty', async () => {
		const result = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) }, { code }, []);
		assert.equal(result.status, 404);
		assert.equal(session.update.mock.calls.length, 0);
		const resource = new OAuthResource();
		resource.setContext(redeemRequest({ origin: PREVIEW }));
		OAuthResource.reset();
		const viaResource = await resource.post({ id: 'handoff' }, { code });
		assert.equal(viaResource.status, 404);
	});

	describe('checks the request Origin', () => {
		for (const [label, headers] of [
			['missing', { cookie: cookieFor(SECRET) }],
			['null', { origin: 'null', cookie: cookieFor(SECRET) }],
			['not allowlisted', { origin: 'https://evil.example.com', cookie: cookieFor(SECRET) }],
			['http', { origin: 'http://hdbms-pr-12.app.dev.studio.example.com', cookie: cookieFor(SECRET) }],
			['repeated', { origin: [PREVIEW, PREVIEW], cookie: cookieFor(SECRET) }],
			['not a bare origin', { origin: `${PREVIEW}/`, cookie: cookieFor(SECRET) }],
		]) {
			it(`refuses a ${label} Origin before touching the code`, async () => {
				const result = await redeem(headers);
				assert.equal(result.status, 403);
				assert.equal(result.body.error, 'origin_not_allowed');
				assert.equal(session.update.mock.calls.length, 0);
				assert.equal((await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) })).status, 200);
			});
		}

		it('refuses a code issued for a different allowlisted origin, without consuming it', async () => {
			const result = await redeem({ origin: OTHER_PREVIEW, cookie: cookieFor(SECRET) });
			assert.equal(result.status, 400);
			assert.equal(result.body.error, 'invalid_grant');
			assert.equal(session.update.mock.calls.length, 0);
			assert.equal((await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) })).status, 200);
		});
	});

	it('refuses a code presented from another browser, without consuming it', async () => {
		const result = await redeem({ origin: PREVIEW, cookie: cookieFor(OTHER_SECRET) });
		assert.equal(result.status, 400);
		assert.equal(result.body.error, 'invalid_grant');
		assert.equal((await redeem({ origin: PREVIEW })).status, 400);
		assert.equal(session.update.mock.calls.length, 0);
		assert.equal((await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) })).status, 200);
	});

	it('refuses a request without a browser cookie before reading storage', async () => {
		const table = globalThis.databases.oauth.login_handoffs;
		const reads = table.readContexts.length;
		const result = await redeem({ origin: PREVIEW });
		assert.equal(result.status, 400);
		assert.equal(result.body.error, 'invalid_grant');
		assert.equal(table.readContexts.length, reads);
	});

	it('refuses a malformed browser cookie before reading storage', async () => {
		const table = globalThis.databases.oauth.login_handoffs;
		const reads = table.readContexts.length;
		const result = await redeem({ origin: PREVIEW, cookie: '__Host-oauth_browser=forged' });
		assert.equal(result.status, 400);
		assert.equal(table.readContexts.length, reads);
	});

	it('an origin removed during the first read is refused without consuming the code', async () => {
		let live = patterns();
		const table = globalThis.databases.oauth.login_handoffs;
		const get = table.get;
		table.get = async (...args) => {
			live = [];
			return get(...args);
		};
		const refused = await handleLoginHandoffRedeem(
			redeemRequest({ origin: PREVIEW, cookie: cookieFor(SECRET) }),
			{ code },
			() => live,
			logger
		);
		assert.equal(refused.status, 403);
		assert.equal(refused.body.error, 'origin_not_allowed');
		table.get = get;
		assert.equal((await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) })).status, 200);
	});

	it('re-checks the live allowlist before writing the session', async () => {
		let live = patterns();
		const table = globalThis.databases.oauth.login_handoffs;
		const patch = table.patch;
		table.patch = async (...args) => {
			live = []; // a reload lands during the redeem's storage round trips
			return patch(...args);
		};
		const result = await handleLoginHandoffRedeem(
			redeemRequest({ origin: PREVIEW, cookie: cookieFor(SECRET) }),
			{ code },
			() => live,
			logger
		);
		assert.equal(result.status, 403);
		assert.equal(result.body.error, 'origin_not_allowed');
		assert.equal(session.update.mock.calls.length, 0);
	});

	it('answers server_error for a corrupt stored session without logging it', async () => {
		const table = globalThis.databases.oauth.login_handoffs;
		const [id] = table.rows.keys();
		table.rows.set(id, { ...table.rows.get(id), session: '{"accessToken":"gho_SECRET' });
		const result = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		assert.equal(result.status, 500);
		assert.ok(!loggedText(logger).includes('gho_SECRET'));
	});

	it('refuses a second redeem', async () => {
		assert.equal((await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) })).status, 200);
		const second = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		assert.equal(second.status, 400);
		assert.equal(second.body.error, 'invalid_grant');
		assert.equal(session.update.mock.calls.length, 1);
	});

	it('refuses a missing, repeated or malformed code', async () => {
		for (const body of [{}, { code: [code, code] }, { code: `${code}x` }, { code: 'short' }, null, [code]]) {
			const result = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) }, body);
			assert.equal(result.status, 400, JSON.stringify(body));
			assert.equal(result.body.error, 'invalid_request');
		}
	});

	it('answers server_error when storage fails, logging the stack but not the error object', async () => {
		globalThis.databases.oauth.login_handoffs.get = async () => {
			throw errorCarryingToken('disk on fire');
		};
		const result = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		assert.equal(result.status, 500);
		assert.equal(result.body.error, 'server_error');
		assertLoggedStackWithoutTokens(logger, 'disk on fire');
	});

	it('answers server_error when the session write fails, logging the stack but not the error object', async () => {
		session.update = createMockFn(async () => {
			throw errorCarryingToken('session store down');
		});
		const result = await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		assert.equal(result.status, 500);
		assert.equal(result.body.error, 'server_error');
		assertLoggedStackWithoutTokens(logger, 'session store down');
	});

	it('logs every refusal without the code', async () => {
		await redeem({ origin: 'https://evil.example.com' });
		await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) }, { code: [code, code] });
		await redeem({ origin: OTHER_PREVIEW, cookie: cookieFor(SECRET) });
		await redeem({ origin: PREVIEW, cookie: cookieFor(OTHER_SECRET) });
		await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) });
		await redeem({ origin: PREVIEW, cookie: cookieFor(SECRET) }, { code: 'B'.repeat(43) });
		const text = loggedText(logger);
		assert.equal(logger.warn.mock.calls.length, 6, 'each refusal is logged');
		assert.ok(text.includes('evil.example.com') && text.includes(OTHER_PREVIEW), 'origins are logged');
		assert.ok(!text.includes(code), 'the code never reaches a log line');
		assert.ok(!text.includes(handoffKey(code)), 'nor its storage key');
	});
});

describe('login and callback with postLoginRedirectOrigins', () => {
	let provider;
	let config;
	let hookManager;
	let logger;
	let stateData;
	let request;

	const target = (params) => ({ get: (key) => params[key] });

	beforeEach(() => {
		installHandoffTable();
		logger = createMockLogger();
		config = {
			provider: 'github',
			redirectUri: 'https://dev.studio.example.com/oauth/github/callback',
			postLoginRedirect: '/#/check-oauth',
		};
		hookManager = {
			callOnLogin: createMockFn(async () => ({ user: 'alice@example.com', ssoAuthAt: 1730000000000 })),
			callResolveEmail: createMockFn(async () => undefined),
			hasHook: createMockFn(() => true),
		};
		stateData = {
			originalUrl: `${PREVIEW}/#/check-oauth`,
			handoffOrigin: PREVIEW,
			providerName: 'github',
			browserNonceHash: hashBrowserSecret(SECRET),
			timestamp: Date.now(),
		};
		provider = {
			generateCSRFToken: createMockFn(async () => 'state-1'),
			getAuthorizationUrl: createMockFn(() => 'https://github.com/login/oauth/authorize?state=state-1'),
			verifyCSRFToken: createMockFn(async () => stateData),
			exchangeCodeForToken: createMockFn(async () => ({
				access_token: 'gho_access_token_value',
				refresh_token: 'ghr_refresh_token_value',
				id_token: 'eyJ.id.token',
			})),
			getUserInfo: createMockFn(async () => ({ login: 'alice', email: 'alice@example.com' })),
			mapUserToHarper: createMockFn(() => ({
				username: 'alice',
				email: 'alice@example.com',
				provider: 'github',
			})),
		};
		request = {
			headers: { cookie: cookieFor(SECRET) },
			session: { id: 'dev-studio-session', update: createMockFn(async () => {}) },
		};
	});
	afterEach(() => {
		delete globalThis.databases;
		resetLoginHandoffTableCache();
	});

	const callback = (handoffOrigins = patterns()) =>
		handleCallback(request, target({ code: 'idp-code', state: 'state-1' }), provider, config, hookManager, 'github', {
			logger,
			handoffOrigins,
		});

	describe('handleLogin', () => {
		const login = (params, handoffOrigins, headers = {}) =>
			handleLogin({ headers, session: {} }, target(params), provider, config, 'github', logger, { handoffOrigins });

		it('records an allowlisted absolute redirect as the handoff target', async () => {
			await login({ redirect: `${PREVIEW}/#/check-oauth` }, patterns());
			const metadata = provider.generateCSRFToken.mock.calls[0].arguments[0];
			assert.equal(metadata.originalUrl, `${PREVIEW}/#/check-oauth`);
			assert.equal(metadata.handoffOrigin, PREVIEW);
		});

		it('keeps today’s path-only redirect when the allowlist is empty', async () => {
			await login({ redirect: `${PREVIEW}/#/check-oauth` }, []);
			const metadata = provider.generateCSRFToken.mock.calls[0].arguments[0];
			assert.equal(metadata.originalUrl, '/#/check-oauth');
			assert.equal('handoffOrigin' in metadata, false);
		});

		it('keeps today’s path-only redirect for an origin not on the list', async () => {
			await login({ redirect: 'https://evil.example.com/#/check-oauth' }, patterns());
			const metadata = provider.generateCSRFToken.mock.calls[0].arguments[0];
			assert.equal(metadata.originalUrl, '/#/check-oauth');
			assert.equal('handoffOrigin' in metadata, false);
		});

		it('never hands off on a Referer alone', async () => {
			await login({}, patterns(), { referer: `${PREVIEW}/#/sign-in` });
			const metadata = provider.generateCSRFToken.mock.calls[0].arguments[0];
			assert.equal(metadata.originalUrl, '/#/sign-in');
			assert.equal('handoffOrigin' in metadata, false);
		});

		it('returns a state-storage error to the allowlisted origin', async () => {
			provider.generateCSRFToken = createMockFn(async () => {
				throw new Error('no table');
			});
			const result = await login({ redirect: `${PREVIEW}/#/check-oauth` }, patterns());
			assert.equal(result.headers.Location, `${PREVIEW}/?error=server_error&reason=state_storage#/check-oauth`);
		});
	});

	describe('handleCallback', () => {
		it('hands the session to the target origin with a one-time code in the fragment', async () => {
			const result = await callback();
			assert.equal(result.status, 302);
			const location = new URL(result.headers.Location);
			assert.equal(location.origin, PREVIEW);
			assert.equal(location.search, '', 'nothing in the query (no server log, no Referer)');
			const match = /^#\/check-oauth\?oauth_handoff=([A-Za-z0-9_-]{43})$/.exec(location.hash);
			assert.ok(match, result.headers.Location);
			assert.equal(request.session.update.mock.calls.length, 0);
			for (const secret of [
				'gho_access_token_value',
				'ghr_refresh_token_value',
				'eyJ.id.token',
				'dev-studio-session',
			]) {
				assert.ok(!result.headers.Location.includes(secret), secret);
			}
			const redeemed = await redeemLoginHandoff(match[1]);
			assert.equal(redeemed.record.origin, PREVIEW);
			assert.equal(redeemed.record.browserNonceHash, hashBrowserSecret(SECRET));
			assert.equal(redeemed.record.provider, 'github');
			assert.equal(redeemed.record.session.user, 'alice@example.com');
			assert.equal(redeemed.record.session.ssoAuthAt, 1730000000000);
			assert.equal(redeemed.record.session.oauth.accessToken, 'gho_access_token_value');
			assert.equal(redeemed.record.session.oauth.authTrust, 'hook');
		});

		it('keeps today’s behavior for a flow started without a handoff', async () => {
			delete stateData.handoffOrigin;
			stateData.originalUrl = '/#/check-oauth';
			const result = await callback([]);
			assert.equal(result.headers.Location, '/#/check-oauth');
			assert.equal(request.session.update.mock.calls.length, 1);
			assert.equal(globalThis.databases.oauth.login_handoffs.rows.size, 0);
		});

		it('refuses a flow whose origin was removed since login, without a session anywhere', async () => {
			const result = await callback([]);
			assert.equal(result.headers.Location, '/?error=access_denied&reason=handoff_origin_not_allowed#/check-oauth');
			assert.equal(provider.exchangeCodeForToken.mock.calls.length, 0, 'refused before the code exchange');
			assert.equal(request.session.update.mock.calls.length, 0);
			assert.equal(globalThis.databases.oauth.login_handoffs.rows.size, 0);
		});

		it('does not send the browser to an origin removed while the code was being stored', async () => {
			let live = patterns();
			const table = globalThis.databases.oauth.login_handoffs;
			const put = table.put;
			table.put = async (...args) => {
				live = [];
				return put(...args);
			};
			const result = await handleCallback(
				request,
				target({ code: 'idp-code', state: 'state-1' }),
				provider,
				config,
				hookManager,
				'github',
				{ logger, handoffOrigins: () => live }
			);
			assert.equal(result.headers.Location, '/?error=access_denied&reason=handoff_origin_not_allowed#/check-oauth');
		});

		it('re-checks the live allowlist before issuing the code', async () => {
			let live = patterns();
			const exchange = provider.exchangeCodeForToken;
			provider.exchangeCodeForToken = createMockFn(async (...args) => {
				live = []; // a reload lands while the provider exchange runs
				return exchange(...args);
			});
			const result = await handleCallback(
				request,
				target({ code: 'idp-code', state: 'state-1' }),
				provider,
				config,
				hookManager,
				'github',
				{ logger, handoffOrigins: () => live }
			);
			assert.equal(result.headers.Location, '/?error=access_denied&reason=handoff_origin_not_allowed#/check-oauth');
			assert.equal(request.session.update.mock.calls.length, 0);
			assert.equal(globalThis.databases.oauth.login_handoffs.rows.size, 0);
		});

		it('hands off a roleless (quarantined) session the same way', async () => {
			hookManager.callOnLogin = createMockFn(async () => undefined);
			const result = await callback();
			assert.match(result.headers.Location, /#\/check-oauth\?oauth_handoff=[A-Za-z0-9_-]{43}$/);
			assert.equal(request.session.update.mock.calls.length, 0);
			const [row] = globalThis.databases.oauth.login_handoffs.rows.values();
			assert.equal(JSON.parse(row.session).oauth.authTrust, 'untrusted');
		});

		it('does not send an error to an origin removed while the provider exchange ran', async () => {
			let live = patterns();
			provider.exchangeCodeForToken = createMockFn(async () => {
				live = [];
				throw new Error('Token exchange failed: 400');
			});
			const result = await handleCallback(
				request,
				target({ code: 'idp-code', state: 'state-1' }),
				provider,
				config,
				hookManager,
				'github',
				{ logger, handoffOrigins: () => live }
			);
			assert.equal(result.headers.Location, '/?error=auth_failed&reason=token_exchange#/check-oauth');
		});

		it('returns upstream errors to the target origin, params before the fragment', async () => {
			provider.exchangeCodeForToken = createMockFn(async () => {
				throw new Error('Token exchange failed: 400');
			});
			const result = await callback();
			assert.equal(result.headers.Location, `${PREVIEW}/?error=auth_failed&reason=token_exchange#/check-oauth`);
		});

		it('maps a code storage failure to server_error / handoff_storage', async () => {
			globalThis.databases.oauth.login_handoffs.put = async () => {
				throw new Error('disk on fire');
			};
			const result = await callback();
			assert.equal(result.headers.Location, `${PREVIEW}/?error=server_error&reason=handoff_storage#/check-oauth`);
			assert.equal(request.session.update.mock.calls.length, 0);
		});

		it('ends in a session for the calling origin when the page redeems the code', async () => {
			const result = await callback();
			const handoffCode = new URL(result.headers.Location).hash.split('oauth_handoff=')[1];
			const previewSession = { update: createMockFn(async () => {}) };
			const redeemed = await handleLoginHandoffRedeem(
				{ headers: { origin: PREVIEW, cookie: cookieFor(SECRET) }, session: previewSession },
				{ code: handoffCode },
				patterns(),
				logger
			);
			assert.equal(redeemed.status, 200);
			const written = previewSession.update.mock.calls[0].arguments[0];
			assert.equal(written.user, 'alice@example.com');
			assert.equal(written.oauth.providerConfigId, 'github');
			assert.ok(!loggedText(logger).includes(handoffCode));
		});
	});
});
