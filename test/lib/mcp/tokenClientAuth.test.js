/**
 * Tests for the shared token-endpoint authenticator (authorization_code and
 * refresh_token grants): presented credentials are classified strictly,
 * partial/empty/duplicate/conflicting credentials are rejected, a presented
 * assertion is verified or rejected (never ignored), and interactive CIMD
 * clients authenticate with private_key_jwt where it is the permitted method.
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { handleToken } from '../../../dist/lib/mcp/token.js';
import { resetMCPAssertionJtisTableCache } from '../../../dist/lib/mcp/assertionJtiStore.js';
import { resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';
import { _clearCimdCache, _setDnsLookup, _setFetch } from '../../../dist/lib/mcp/cimd.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';
import { _clearJwksCache, _setJwksNow } from '../../../dist/lib/mcp/jwksFetcher.js';
import { resetMCPKeysTableCache, SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';
import { resetMCPRefreshFamiliesTableCache } from '../../../dist/lib/mcp/refreshTokenStore.js';

const ISSUER = 'https://as.example.com';
const TOKEN_ENDPOINT = `${ISSUER}/oauth/mcp/token`;
const RESOURCE = 'https://app.example.com/mcp';
const REDIRECT = 'https://mcp.example.com/cb';

const ASSISTANT = 'https://assistant.example.com/oauth/client.json';
const ASSISTANT_JWKS = 'https://assistant.example.com/oauth/jwks.json';
const ASSISTANT_REDIRECT = 'https://assistant.example.com/cb';
const FOREIGN = 'https://foreign.example.com/oauth/client.json';
const PUBLIC_CIMD = 'https://public.example.com/client.json';

const signingKeypair = generateKeyPairSync('rsa', {
	modulusLength: 2048,
	publicKeyEncoding: { type: 'spki', format: 'pem' },
	privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

function rsaPair(kid) {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
	return { privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } };
}
const KEY_1 = rsaPair('k1');
const KEY_2 = rsaPair('k2');

const CODE_VERIFIER = randomBytes(32).toString('base64url');
const CODE_CHALLENGE = createHash('sha256').update(CODE_VERIFIER).digest('base64url');

// ChatGPT-shaped document for a client we hold the key for.
const ASSISTANT_DOC = {
	client_id: ASSISTANT,
	client_name: 'Assistant',
	redirect_uris: [ASSISTANT_REDIRECT],
	grant_types: ['authorization_code', 'refresh_token'],
	response_types: ['code'],
	token_endpoint_auth_method: 'private_key_jwt',
	token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
	token_endpoint_auth_signing_alg: 'RS256',
	jwks_uri: ASSISTANT_JWKS,
};
const FOREIGN_DOC = {
	...ASSISTANT_DOC,
	client_id: FOREIGN,
	redirect_uris: ['https://foreign.example.com/cb'],
	jwks_uri: 'https://keys.example.net/jwks.json',
};
const PUBLIC_DOC = { client_id: PUBLIC_CIMD, client_name: 'Public', redirect_uris: ['https://public.example.com/cb'] };

const BASE = { enabled: true, issuer: ISSUER, resource: RESOURCE, accessTokenTtl: 3600, refreshTokenTtl: 86400 };
const DEFAULT = BASE;
const MIXED = { ...BASE, clientCredentials: { enabled: true } };
const SETTING_ON = { ...BASE, clientIdMetadataDocuments: { privateKeyJwt: { enabled: true } } };

function makeTable(map, pkField) {
	return {
		get: async (id) => map.get(id) ?? null,
		put: async (rec) => {
			map.set(rec[pkField], rec);
		},
		delete: async (id) => {
			map.delete(id);
		},
		search: async function* () {
			yield* map.values();
		},
	};
}

function jsonResponse(body) {
	const bytes = Buffer.from(JSON.stringify(body));
	return {
		status: 200,
		headers: new Map([
			['content-type', 'application/json'],
			['content-length', String(bytes.length)],
		]),
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

function b64url(value) {
	return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function signAssertion({ key = KEY_1, alg = 'RS256', header = {}, claims = {} } = {}) {
	const now = Math.floor(Date.now() / 1000);
	const h = b64url({ alg, kid: key.jwk.kid, ...header });
	const p = b64url({
		iss: ASSISTANT,
		sub: ASSISTANT,
		aud: ISSUER,
		iat: now,
		exp: now + 60,
		jti: randomBytes(12).toString('hex'),
		...claims,
	});
	const signature = sign('sha256', Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url');
	return `${h}.${p}.${signature}`;
}

describe('handleToken — shared client authenticator', () => {
	let originalDatabases;
	let clients;
	let codes;
	let jtis;
	let served;
	let fetches;
	let jtiCreate;
	let logLines;
	const logger = {
		info: (m) => logLines.push(m),
		warn: (m) => logLines.push(m),
		error: (m) => logLines.push(m),
		debug: () => {},
	};

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		for (const reset of [
			resetMCPClientsTableCache,
			resetMCPAuthCodesTableCache,
			resetMCPRefreshFamiliesTableCache,
			resetMCPKeysTableCache,
			resetMCPAssertionJtisTableCache,
			_clearCimdCache,
			_clearJwksCache,
		]) {
			reset();
		}
		logLines = [];
		clients = new Map([
			['public-1', { client_id: 'public-1', token_endpoint_auth_method: 'none', client_id_issued_at: 1 }],
			[
				'conf-1',
				{
					client_id: 'conf-1',
					token_endpoint_auth_method: 'client_secret_basic',
					client_secret: 'conf-secret',
					client_id_issued_at: 1,
				},
			],
		]);
		codes = new Map();
		jtis = new Map();
		jtiCreate = async (record, context) => {
			if (jtis.has(record.id)) {
				const error = new Error('Record already exists');
				error.statusCode = 409;
				throw error;
			}
			jtis.set(record.id, { record, context });
		};
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: makeTable(clients, 'client_id'),
				mcp_auth_codes: makeTable(codes, 'code'),
				mcp_refresh_families: makeTable(new Map(), 'family_id'),
				harper_oauth_mcp_keys: makeTable(
					new Map([
						[
							SIGNING_KEY_ID,
							{
								kid: SIGNING_KEY_ID,
								alg: 'RS256',
								public_key_pem: signingKeypair.publicKey,
								private_key_pem: signingKeypair.privateKey,
								created_at: 1,
							},
						],
					]),
					'kid'
				),
				mcp_assertion_jtis: { create: (record, context) => jtiCreate(record, context) },
			},
		};
		served = { [ASSISTANT]: ASSISTANT_DOC, [FOREIGN]: FOREIGN_DOC, [PUBLIC_CIMD]: PUBLIC_DOC };
		served[ASSISTANT_JWKS] = { keys: [KEY_1.jwk] };
		served['https://keys.example.net/jwks.json'] = { keys: [KEY_1.jwk] };
		fetches = [];
		_setDnsLookup(async () => [{ address: '93.184.216.34', family: 4 }]);
		_setFetch(async (url) => {
			fetches.push(url);
			return jsonResponse(served[url]);
		});
	});

	afterEach(() => {
		_setDnsLookup(null);
		_setFetch(null);
		_setJwksNow(null);
	});

	function seedCode(code, clientId, redirectUri, method) {
		codes.set(code, {
			code,
			client_id: clientId,
			user: 'alice',
			resource: RESOURCE,
			code_challenge: CODE_CHALLENGE,
			code_challenge_method: 'S256',
			redirect_uri: redirectUri,
			client_auth_method: method,
		});
	}

	function exchange(body, { headers = {}, config = DEFAULT, code = 'code-1' } = {}) {
		return handleToken(
			{ headers },
			{ grant_type: 'authorization_code', code, code_verifier: CODE_VERIFIER, ...body },
			config,
			undefined,
			logger
		);
	}

	const basic = (id, secret) => ({ authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` });

	function assertInvalidClient(res, pattern) {
		assert.equal(res.status, 401, JSON.stringify(res.body));
		assert.equal(res.body.error, 'invalid_client');
		if (pattern) assert.match(res.body.error_description, pattern);
	}

	describe('partial, empty, duplicate and conflicting credentials', () => {
		beforeEach(() => seedCode('code-1', 'public-1', REDIRECT, 'none'));

		const publicBody = { client_id: 'public-1', redirect_uri: REDIRECT };
		const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

		it('rejects half an assertion pair', async () => {
			assertInvalidClient(await exchange({ ...publicBody, client_assertion: signAssertion() }), /presented together/);
			assertInvalidClient(await exchange({ ...publicBody, client_assertion_type: TYPE }), /presented together/);
		});

		it('rejects empty credential parameters', async () => {
			for (const name of ['client_assertion', 'client_assertion_type', 'client_secret']) {
				assertInvalidClient(
					await exchange({ ...publicBody, [name]: '' }),
					new RegExp(`${name} must be a single non-empty value`)
				);
			}
		});

		it('rejects repeated credential parameters and a repeated client_id', async () => {
			assertInvalidClient(await exchange({ ...publicBody, client_secret: ['a', 'b'] }), /single non-empty value/);
			assertInvalidClient(
				await exchange({
					...publicBody,
					client_assertion: [signAssertion(), signAssertion()],
					client_assertion_type: TYPE,
				}),
				/single non-empty value/
			);
			const dupId = await exchange({ ...publicBody, client_id: ['public-1', 'public-1'] });
			assert.equal(dupId.status, 400);
			assert.equal(dupId.body.error, 'invalid_request');
		});

		it('rejects an assertion alongside a secret or any Basic header, including an empty-secret one', async () => {
			const withAssertion = { ...publicBody, client_assertion: signAssertion(), client_assertion_type: TYPE };
			assertInvalidClient(
				await exchange({ ...withAssertion, client_secret: 'x' }),
				/Multiple client authentication methods/
			);
			assertInvalidClient(await exchange(withAssertion, { headers: basic('public-1', '') }), /Multiple/);
		});

		it('rejects an unknown assertion type', async () => {
			assertInvalidClient(
				await exchange({ ...publicBody, client_assertion: signAssertion(), client_assertion_type: 'urn:nope' }),
				/client_assertion_type must be/
			);
		});

		it('rejects malformed Basic credentials instead of ignoring them', async () => {
			for (const authorization of [
				'Basic !!!',
				`Basic ${Buffer.from('no-colon').toString('base64')}`,
				`Basic ${Buffer.from(':secret').toString('base64')}`,
			]) {
				assertInvalidClient(await exchange(publicBody, { headers: { authorization } }), /Malformed Basic/);
			}
		});

		it('consumes no code on any of these rejections', async () => {
			await exchange({ ...publicBody, client_assertion: signAssertion() });
			await exchange({ ...publicBody, client_secret: '' });
			assert.equal(codes.has('code-1'), true);
		});

		it('keeps the empty-secret Basic transport for public clients', async () => {
			const res = await exchange({ redirect_uri: REDIRECT }, { headers: basic('public-1', '') });
			assert.equal(res.status, 200, JSON.stringify(res.body));
		});
	});

	describe('assertions presented by clients permitted none are rejected, never ignored', () => {
		it('a stored public client', async () => {
			seedCode('code-1', 'public-1', REDIRECT, 'none');
			const res = await exchange({
				client_id: 'public-1',
				redirect_uri: REDIRECT,
				client_assertion: signAssertion(),
				client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			});
			assertInvalidClient(res, /Public client must not present a client assertion/);
			assert.equal(codes.has('code-1'), true);
		});

		it('a none-only CIMD client, and ChatGPT-shaped clients where private_key_jwt is not advertised', async () => {
			for (const [clientId, redirect] of [
				[PUBLIC_CIMD, 'https://public.example.com/cb'],
				[ASSISTANT, ASSISTANT_REDIRECT],
			]) {
				seedCode('code-1', clientId, redirect, 'none');
				const res = await exchange({
					client_id: clientId,
					redirect_uri: redirect,
					client_assertion: signAssertion(),
					client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				});
				assertInvalidClient(res, /Public client must not present a client assertion/);
			}
			assert.ok(!fetches.includes(ASSISTANT_JWKS), 'no keys are fetched for a rejected presentation');
		});
	});

	describe('interactive private_key_jwt where it is the permitted method', () => {
		const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
		const body = (assertion, extra = {}) => ({
			client_id: ASSISTANT,
			redirect_uri: ASSISTANT_REDIRECT,
			client_assertion: assertion,
			client_assertion_type: TYPE,
			...extra,
		});
		beforeEach(() => seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'private_key_jwt'));

		for (const [name, config] of [
			['a server advertising it for headless agents', MIXED],
			['the interactive setting', SETTING_ON],
		]) {
			it(`verifies the assertion against the client's jwks_uri keys (${name})`, async () => {
				const assertion = signAssertion();
				const res = await exchange(body(assertion), { config });
				assert.equal(res.status, 200, JSON.stringify(res.body));
				assert.ok(fetches.includes(ASSISTANT_JWKS));
				assert.ok(logLines.some((l) => /authenticated with private_key_jwt \(alg RS256, aud form issuer\)/.test(l)));
				const [, payloadSegment, signatureSegment] = assertion.split('.');
				assert.ok(
					!logLines.some((l) => l.includes(signatureSegment) || l.includes(payloadSegment)),
					'no log line carries the assertion'
				);
			});
		}

		it('rejects a missing assertion or a secret', async () => {
			assertInvalidClient(
				await exchange({ client_id: ASSISTANT, redirect_uri: ASSISTANT_REDIRECT }, { config: MIXED }),
				/must authenticate with a client_assertion/
			);
			assertInvalidClient(
				await exchange(
					{ client_id: ASSISTANT, redirect_uri: ASSISTANT_REDIRECT, client_secret: 's' },
					{ config: MIXED }
				),
				/must authenticate with a client_assertion/
			);
		});

		it('accepts the issuer as audience and rejects the token endpoint by default', async () => {
			assertInvalidClient(
				await exchange(body(signAssertion({ claims: { aud: TOKEN_ENDPOINT } })), { config: MIXED }),
				/aud does not match/
			);
		});

		describe('opt-in token-endpoint audience exception', () => {
			const exceptionFor = (clientIds, expiresAt, extra = {}) => ({
				...MIXED,
				clientIdMetadataDocuments: {
					privateKeyJwt: { tokenEndpointAudience: { clientIds, expiresAt }, ...extra },
				},
			});

			it('accepts the exact advertised token endpoint for a listed client and records the form', async () => {
				const config = exceptionFor([ASSISTANT], Date.now() + 60_000);
				const res = await exchange(body(signAssertion({ claims: { aud: TOKEN_ENDPOINT } })), { config });
				assert.equal(res.status, 200, JSON.stringify(res.body));
				assert.ok(logLines.some((l) => /aud form token_endpoint/.test(l)));
			});

			it('stops applying at its expiry, checked on the request', async () => {
				const config = exceptionFor([ASSISTANT], Date.now() - 1);
				assertInvalidClient(
					await exchange(body(signAssertion({ claims: { aud: TOKEN_ENDPOINT } })), { config }),
					/aud does not match/
				);
			});

			it('applies only to the listed client IDs', async () => {
				const config = exceptionFor(['https://other.example.com/client.json'], Date.now() + 60_000);
				assertInvalidClient(
					await exchange(body(signAssertion({ claims: { aud: TOKEN_ENDPOINT } })), { config }),
					/aud does not match/
				);
			});

			it('does not apply when the keys come from an allowlisted foreign origin', async () => {
				seedCode('code-2', FOREIGN, 'https://foreign.example.com/cb', 'private_key_jwt');
				const config = exceptionFor([FOREIGN], Date.now() + 60_000, {
					jwksUriAllowedOrigins: ['https://keys.example.net'],
				});
				const foreign = (aud) => signAssertion({ claims: { iss: FOREIGN, sub: FOREIGN, aud } });
				const viaTokenEndpoint = await exchange(
					{
						client_id: FOREIGN,
						redirect_uri: 'https://foreign.example.com/cb',
						client_assertion: foreign(TOKEN_ENDPOINT),
						client_assertion_type: TYPE,
					},
					{ config, code: 'code-2' }
				);
				assertInvalidClient(viaTokenEndpoint, /aud does not match/);
				const viaIssuer = await exchange(
					{
						client_id: FOREIGN,
						redirect_uri: 'https://foreign.example.com/cb',
						client_assertion: foreign(ISSUER),
						client_assertion_type: TYPE,
					},
					{ config, code: 'code-2' }
				);
				assert.equal(viaIssuer.status, 200, JSON.stringify(viaIssuer.body));
			});
		});

		it('rejects a replayed assertion and fails closed when the replay store fails', async () => {
			const assertion = signAssertion();
			assert.equal((await exchange(body(assertion), { config: MIXED })).status, 200);
			seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'private_key_jwt');
			assertInvalidClient(await exchange(body(assertion), { config: MIXED }), /jti has already been used/);
			jtiCreate = async () => {
				throw new Error('store unavailable');
			};
			const failed = await exchange(body(signAssertion()), { config: MIXED });
			assert.equal(failed.status, 500);
			assert.equal(codes.has('code-1'), true, 'no code consumed when the replay check cannot run');
		});

		it('retains the replay record past the assertion exp', async () => {
			assert.equal((await exchange(body(signAssertion()), { config: MIXED })).status, 200);
			const [{ record, context }] = [...jtis.values()];
			assert.ok(context.expiresAt >= (Math.floor(Date.now() / 1000) + 60 + 5) * 1000);
			assert.equal(record.expires_at, context.expiresAt);
		});

		it('rejects an algorithm other than the document pin', async () => {
			const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
			const ecJwk = { ...ec.publicKey.export({ format: 'jwk' }), kid: 'ec1' };
			served[ASSISTANT_JWKS] = { keys: [KEY_1.jwk, ecJwk] };
			const now = Math.floor(Date.now() / 1000);
			const h = b64url({ alg: 'ES256', kid: 'ec1' });
			const p = b64url({ iss: ASSISTANT, sub: ASSISTANT, aud: ISSUER, iat: now, exp: now + 60, jti: 'es' });
			const s = sign('sha256', Buffer.from(`${h}.${p}`), { key: ec.privateKey, dsaEncoding: 'ieee-p1363' }).toString(
				'base64url'
			);
			assertInvalidClient(await exchange(body(`${h}.${p}.${s}`), { config: MIXED }), /alg must be RS256/);
		});

		it('refetches keys once for an unknown kid after the client rotates', async () => {
			let now = Date.now();
			_setJwksNow(() => now);
			assert.equal((await exchange(body(signAssertion()), { config: MIXED })).status, 200);
			served[ASSISTANT_JWKS] = { keys: [KEY_1.jwk, KEY_2.jwk] };
			seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'private_key_jwt');
			now += 61_000;
			const rotated = await exchange(body(signAssertion({ key: KEY_2 })), { config: MIXED });
			assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
			assert.equal(fetches.filter((u) => u === ASSISTANT_JWKS).length, 2);
		});

		it('identifies the client from the assertion subject when client_id is omitted (RFC 7521 §4.2)', async () => {
			const res = await exchange(
				{ redirect_uri: ASSISTANT_REDIRECT, client_assertion: signAssertion(), client_assertion_type: TYPE },
				{ config: MIXED }
			);
			assert.equal(res.status, 200, JSON.stringify(res.body));
		});

		it('still enforces PKCE for a verified client', async () => {
			const res = await exchange(body(signAssertion(), { code_verifier: randomBytes(32).toString('base64url') }), {
				config: MIXED,
			});
			assert.equal(res.status, 400);
			assert.equal(res.body.error, 'invalid_grant');
		});
	});
});
