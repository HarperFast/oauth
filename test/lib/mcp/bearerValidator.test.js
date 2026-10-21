import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { createMCPBearerValidator, registerMCPBearerValidator } from '../../../dist/lib/mcp/bearerValidator.js';
import { signAccessToken } from '../../../dist/lib/mcp/tokenIssuer.js';
import { SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';

function isCredentialRejection(error) {
	return Boolean(
		error &&
		typeof error === 'object' &&
		Object.getOwnPropertySymbols(error).some((s) => s.description === 'harper.credentialRejection' && error[s] === true)
	);
}

const ISSUER = 'https://as.example.com';
const RESOURCE = 'https://app.example.com/mcp';

function makeKey(kid = SIGNING_KEY_ID) {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	return {
		kid,
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

function makeValidator(extra = {}) {
	const events = [];
	const defaultKeys = extra.keys ?? [key];
	const validator = createMCPBearerValidator({
		getConfig: () => config,
		keyStore: {
			async getAllPublicKeys() {
				return defaultKeys;
			},
		},
		logger: silentLogger,
		emitAudit: (p) => events.push(p),
		...extra,
	});
	return { validator, events };
}

function req({ pathname = '/mcp', originalPathname, url, host = 'app.example.com' } = {}) {
	return {
		headers: { host },
		pathname,
		...(originalPathname !== undefined ? { originalPathname } : {}),
		url: url ?? pathname,
		method: 'POST',
	};
}

describe('createMCPBearerValidator — ownership ("not mine" returns undefined)', () => {
	it('returns undefined synchronously when MCP is disabled or unconfigured', () => {
		const token = mint();
		for (const cfg of [undefined, { enabled: false, issuer: ISSUER }, { enabled: true }]) {
			const { validator, events } = makeValidator({ getConfig: () => cfg });
			const res = validator(token, req());
			assert.equal(res, undefined);
			assert.equal(events.length, 0);
		}
	});

	it('returns undefined synchronously for non-JWT or malformed compact tokens without auditing', () => {
		const { validator, events } = makeValidator();
		const nonJwts = [
			'',
			'opaque-bearer-token',
			'only.two',
			'four.parts.in.token',
			'.leading.dot',
			'trailing.dot.',
			'a..c',
			`a.${Buffer.from('not-json').toString('base64url')}.c`,
			`a.${Buffer.from(JSON.stringify(['array'])).toString('base64url')}.c`,
			`a.${Buffer.from(JSON.stringify({ sub: 'no-issuer' })).toString('base64url')}.c`,
			`a.${Buffer.from(JSON.stringify({ iss: '' })).toString('base64url')}.c`,
			`a.${Buffer.from(JSON.stringify({ iss: 123 })).toString('base64url')}.c`,
			'a.' + 'x'.repeat(17000) + '.c',
		];
		for (const bad of nonJwts) {
			const res = validator(bad, req());
			assert.equal(res, undefined, `expected undefined for non-owned token: ${bad.slice(0, 40)}`);
		}
		assert.equal(events.length, 0, 'non-owned tokens must never emit rejection audit events');
	});

	it('returns undefined synchronously when the token iss belongs to another issuer (e.g. Harper operation token)', () => {
		const otherToken = mint({ issuer: 'https://other-issuer.example.com' });
		const { validator, events } = makeValidator();
		const res = validator(otherToken, req());
		assert.equal(res, undefined);
		assert.equal(events.length, 0);
	});

	it('returns undefined synchronously when a token minted for /mcp is presented to a non-MCP route without auditing or reading keys', () => {
		const token = mint();
		let keyReads = 0;
		const { validator, events } = makeValidator({
			keyStore: {
				async getAllPublicKeys() {
					keyReads++;
					return [key];
				},
			},
		});

		for (const badPath of [
			'/SomeTable/1',
			'/mcponaut',
			'/mcp/../SomeTable/1',
			'/mcp/%2e%2e/SomeTable/1',
			'/mcp/%2E/tools',
			'/mcp%2f../SomeTable/1',
			'/mcp\\..\\SomeTable/1',
			'//mcp',
		]) {
			const res = validator(token, req({ pathname: badPath }));
			assert.equal(res, undefined, `expected undefined for path: ${badPath}`);
		}
		assert.equal(keyReads, 0, 'off-path route must not read signing keys');
		assert.equal(events.length, 0, 'off-path route must not emit audit events');
	});

	it('abstains synchronously when mcp.resource has root pathname "/" so MCP tokens never become blanket credentials for all REST routes', () => {
		const rootResource = 'https://app.example.com';
		const token = mint({ subject: 'alice@example.com', audience: rootResource });
		let keyReads = 0;
		const { validator, events } = makeValidator({
			getConfig: () => ({ enabled: true, issuer: ISSUER, resource: rootResource }),
			keyStore: {
				async getAllPublicKeys() {
					keyReads++;
					return [key];
				},
			},
		});

		assert.equal(validator(token, req({ pathname: '/SomeTable/1' })), undefined);
		assert.equal(validator(token, req({ pathname: '/' })), undefined);
		assert.equal(keyReads, 0);
		assert.equal(events.length, 0);
	});
});

describe('createMCPBearerValidator — owned-token rejections (fail closed with credentialRejectionError)', () => {
	async function assertCredentialRejection(promise, expectedMessagePattern) {
		await assert.rejects(promise, (err) => {
			assert.equal(err.statusCode, 401, 'must carry statusCode 401');
			assert.equal(isCredentialRejection(err), true, 'must be tagged via credentialRejectionError');
			if (expectedMessagePattern) {
				assert.match(err.message, expectedMessagePattern);
			}
			return true;
		});
	}

	it('rejects a token with an invalid signature and emits oauth.mcp.token.rejected', async () => {
		const forged = makeKey(SIGNING_KEY_ID);
		const token = mint({}, forged);
		const { validator, events } = makeValidator();

		await assertCredentialRejection(
			validator(token, req()),
			/access token is invalid, expired, or not issued for this resource/
		);
		assert.equal(events.length, 1);
		assert.equal(events[0].event, 'oauth.mcp.token.rejected');
		assert.equal(events[0].aud, RESOURCE);
		assert.equal(events[0].sub, undefined, 'unverified claims must not leak into audit');
	});

	it('rejects a token with an unknown kid', async () => {
		const otherKey = makeKey('unknown-kid');
		const token = mint({}, otherKey);
		const { validator, events } = makeValidator();

		await assertCredentialRejection(validator(token, req()));
		assert.equal(events.length, 1);
	});

	it('rejects an expired token claiming our issuer', async () => {
		const token = mint({ ttlSeconds: -10 });
		const { validator, events } = makeValidator();

		await assertCredentialRejection(validator(token, req()));
		assert.equal(events.length, 1);
	});

	it('rejects a token with a mismatched audience (RFC 8707)', async () => {
		const token = mint({ audience: 'https://other-resource.example.com/mcp' });
		const { validator, events } = makeValidator();

		await assertCredentialRejection(validator(token, req()));
		assert.equal(events.length, 1);
		assert.equal(events[0].aud, RESOURCE);
	});

	it('fails closed with credentialRejectionError when mcp.resource is not a valid URL', async () => {
		const token = mint();
		const { validator, events } = makeValidator({
			getConfig: () => ({ enabled: true, issuer: ISSUER, resource: 'not a valid url' }),
		});

		await assertCredentialRejection(validator(token, req()), /MCP resource URL is invalid/);
		assert.equal(events.length, 1);
		assert.equal(events[0].reason, 'MCP resource URL is invalid');
	});

	it('rejects a token with a disallowed typ header that claims our issuer', async () => {
		const wrongTypToken = jwt.sign(
			{
				iss: ISSUER,
				sub: 'alice@example.com',
				aud: RESOURCE,
				client_id: 'client-123',
			},
			key.private_key_pem,
			{ algorithm: 'RS256', keyid: key.kid, header: { alg: 'RS256', typ: 'id_token+jwt', kid: key.kid } }
		);
		const { validator, events } = makeValidator();

		await assertCredentialRejection(validator(wrongTypToken, req()));
		assert.equal(events.length, 1);
	});

	it('rejects when no signing keys are available or keyStore throws (without false token.rejected audit on transient error)', async () => {
		const token = mint();
		const empty = makeValidator({ keys: [] });
		await assertCredentialRejection(empty.validator(token, req()), /no signing keys available/);
		assert.equal(empty.events.length, 1);

		const throwing = makeValidator({
			keyStore: {
				async getAllPublicKeys() {
					throw new Error('db offline');
				},
			},
		});
		await assertCredentialRejection(throwing.validator(token, req()), /temporarily unable to load MCP signing keys/);
		assert.equal(throwing.events.length, 0, 'transient keyStore error must not emit oauth.mcp.token.rejected');
	});

	it('fails closed when MCP is disabled during an in-flight key lookup', async () => {
		const token = mint();
		let liveCfg = { enabled: true, issuer: ISSUER, resource: RESOURCE };
		const { validator, events } = makeValidator({
			getConfig: () => liveCfg,
			keyStore: {
				async getAllPublicKeys() {
					liveCfg = { enabled: false, issuer: ISSUER, resource: RESOURCE };
					return [key];
				},
			},
		});

		await assertCredentialRejection(validator(token, req()), /MCP authentication is not enabled/);
		assert.equal(events.length, 1);
	});

	it('rejects a quarantined unverified:<claim>#<16-hex> subject and logs a warning once per validator (#231)', async () => {
		const quarantined = mint({ subject: 'unverified:alice@example.com#0123456789abcdef' });
		const warnings = [];
		const { validator, events } = makeValidator({
			logger: { ...silentLogger, warn: (...args) => warnings.push(args.join(' ')) },
		});

		await assertCredentialRejection(
			validator(quarantined, req()),
			/unverified subject cannot authenticate as a Harper user/
		);
		await assertCredentialRejection(
			validator(quarantined, req()),
			/unverified subject cannot authenticate as a Harper user/
		);
		assert.equal(events.length, 2);
		assert.equal(events[0].reason, 'unverified subject cannot authenticate as a Harper user');
		assert.equal(warnings.length, 1, 'must warn only once per validator instance for quarantined subjects');
		assert.match(warnings[0], /quarantined unverified subject/);
	});

	it('rejects an oversized request path (>2048 chars) without emitting audit', async () => {
		const token = mint();
		const { validator, events } = makeValidator();
		const longPath = '/mcp/' + 'a'.repeat(2100);

		await assertCredentialRejection(
			validator(token, req({ pathname: longPath })),
			/request path exceeds the maximum allowed length/
		);
		assert.equal(events.length, 0);
	});

	it('still rejects when a custom emitAudit sink throws', async () => {
		const forged = makeKey(SIGNING_KEY_ID);
		const token = mint({}, forged);
		const { validator } = makeValidator({
			emitAudit: () => {
				throw new Error('audit sink failure');
			},
		});

		await assertCredentialRejection(validator(token, req()));
	});

	it('maps an unexpected untagged error during async validation to a tagged 401 credentialRejectionError', async () => {
		const token = mint();
		let calls = 0;
		const { validator } = makeValidator({
			getConfig: () => {
				calls++;
				if (calls > 1) {
					throw new Error('unexpected post-await failure');
				}
				return config;
			},
		});

		await assertCredentialRejection(validator(token, req()), /MCP bearer token validation failed/);
	});
});

describe('createMCPBearerValidator — happy path', () => {
	it('returns { username, authExpiresAt, authCacheable: false } and only Harper RESULT_FIELDS', async () => {
		const token = mint({ subject: 'alice@example.com', ttlSeconds: 1800 });
		const { validator, events } = makeValidator();
		const result = await validator(token, req());

		assert.ok(result, 'expected a validation result');
		assert.equal(result.username, 'alice@example.com');
		assert.equal(typeof result.authExpiresAt, 'number');
		assert.ok(result.authExpiresAt > Math.floor(Date.now() / 1000));
		assert.equal(result.authCacheable, false, 'must opt out of header-only authorizationCache');
		assert.deepEqual(
			Object.keys(result).sort(),
			['authCacheable', 'authExpiresAt', 'username'],
			'must only return fields permitted by Harper security/bearerValidators.ts RESULT_FIELDS'
		);
		assert.equal(events.length, 0);
	});

	it('reads request.originalPathname when Harper stripPrefix sets request.pathname to "/" on native /mcp', async () => {
		const token = mint({ subject: 'alice@example.com' });
		const { validator } = makeValidator();
		const result = await validator(token, req({ pathname: '/', originalPathname: '/mcp' }));
		assert.equal(result?.username, 'alice@example.com');
		assert.equal(result?.authCacheable, false);
	});

	it('clamps authExpiresAt to at most 365 days in the future so Harper effectiveExpiry does not throw', async () => {
		const twoYearsSeconds = 2 * 365 * 24 * 60 * 60;
		const token = mint({ subject: 'alice@example.com', ttlSeconds: twoYearsSeconds });
		const { validator } = makeValidator();
		const beforeSec = Math.floor(Date.now() / 1000);
		const result = await validator(token, req());
		const afterSec = Math.floor(Date.now() / 1000);
		const maxAllowed = 365 * 24 * 60 * 60;
		assert.ok(result?.authExpiresAt >= beforeSec + maxAllowed - 1);
		assert.ok(result?.authExpiresAt <= afterSec + maxAllowed);
	});

	it('memoizes verified tokens across repeat calls while re-checking pathOwned, mcp.enabled, and active keys', async () => {
		const token = mint({ subject: 'alice@example.com', ttlSeconds: 1800 });
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
		let activeKeys = [trackedKey];
		let liveCfg = { enabled: true, issuer: ISSUER, resource: RESOURCE };
		const { validator } = makeValidator({
			getConfig: () => liveCfg,
			keyStore: {
				async getAllPublicKeys() {
					return activeKeys;
				},
			},
		});

		const first = await validator(token, req());
		assert.equal(pemReads, 1, 'first call must run signature verification');
		const second = await validator(token, req());
		assert.equal(pemReads, 1, 'second call with same key-set reference must hit the verified-token memo');
		assert.equal(first?.username, 'alice@example.com');
		assert.equal(second?.username, 'alice@example.com');
		assert.equal(second?.authCacheable, false);

		// Off-path request still abstains synchronously even after token is memoized.
		assert.equal(validator(token, req({ pathname: '/SomeTable/1' })), undefined);

		// Key rotation invalidates the memoized entry immediately.
		activeKeys = [makeKey('rotated-kid')];
		await assert.rejects(validator(token, req()), (err) => isCredentialRejection(err));

		// Disabling mcp.enabled after memoization abstains synchronously.
		activeKeys = [trackedKey];
		liveCfg = { enabled: false, issuer: ISSUER, resource: RESOURCE };
		assert.equal(validator(token, req()), undefined);
	});
});

describe('registerMCPBearerValidator', () => {
	it('returns undefined when server.registerBearerValidator is not available', () => {
		assert.equal(registerMCPBearerValidator(undefined), undefined);
		assert.equal(registerMCPBearerValidator({}), undefined);
		assert.equal(registerMCPBearerValidator({ registerBearerValidator: 'not-a-fn' }), undefined);
	});

	it('returns a no-op disposer when server.registerBearerValidator returns void so reload tracking stays idempotent', () => {
		let registerCount = 0;
		const server = {
			registerBearerValidator() {
				registerCount++;
			},
		};
		const unregister = registerMCPBearerValidator(server, () => config, { logger: silentLogger });
		assert.equal(registerCount, 1);
		assert.equal(typeof unregister, 'function');
		unregister();
	});

	it('registers the validator with server.registerBearerValidator and returns its disposer', async () => {
		let registeredValidator = null;
		let disposed = false;
		const server = {
			registerBearerValidator(fn) {
				registeredValidator = fn;
				return () => {
					disposed = true;
				};
			},
		};

		const unregister = registerMCPBearerValidator(server, () => config, {
			keyStore: {
				async getAllPublicKeys() {
					return [key];
				},
			},
			logger: silentLogger,
		});

		assert.equal(typeof unregister, 'function');
		assert.equal(typeof registeredValidator, 'function');

		const result = await registeredValidator(mint({ subject: 'bob' }), req());
		assert.equal(result?.username, 'bob');
		assert.equal(result?.authCacheable, false);

		unregister();
		assert.equal(disposed, true);
	});
});
