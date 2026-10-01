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
import { _resetGrantRateLimiter, handleToken } from '../../../dist/lib/mcp/token.js';
import { MAX_ASSERTION_LENGTH } from '../../../dist/lib/mcp/clientAssertion.js';
import { buildAuthorizationServerMetadata } from '../../../dist/lib/mcp/wellKnown.js';
import { resetMCPAssertionJtisTableCache } from '../../../dist/lib/mcp/assertionJtiStore.js';
import { resetMCPAuthCodesTableCache } from '../../../dist/lib/mcp/authCodeStore.js';
import { _clearCimdCache, _setDnsLookup, _setFetch } from '../../../dist/lib/mcp/cimd.js';
import { resetMCPClientsTableCache } from '../../../dist/lib/mcp/clientStore.js';
import { _clearJwksCache, _setJwksNow } from '../../../dist/lib/mcp/jwksFetcher.js';
import { resetMCPKeysTableCache, SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';
import {
	resetMCPRefreshFamiliesTableCache,
	makeRefreshToken,
	FAMILY_ID_PREFIX,
	BOUND_FAMILY_ID_PREFIX,
} from '../../../dist/lib/mcp/refreshTokenStore.js';
import {
	CAPTURE_REFRESH_OFFSETS_MS,
	CAPTURE_REQUEST_HEADERS,
	CHATGPT_CIMD_DOCUMENT,
	CHATGPT_CLIENT_ID,
	CHATGPT_JWKS_URI,
	CHATGPT_REDIRECT_URI,
	captureAssertion,
	captureCodeForm,
	captureRefreshForm,
	createCaptureSigner,
} from '../../helpers/cimdAuthCaptureFixtures.js';
import {
	UPSTREAM_FAMILY_ID_PREFIX,
	upstreamInteractiveDocumentMethod,
	upstreamCodeRedeemable,
	upstreamEncodeCode,
	upstreamEncodeFamily,
	upstreamRefreshOutcome,
} from '../../helpers/upstreamGrantFormats.js';

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
		// Harper's partial update: only the given fields, on top of the stored record.
		patch: async (id, update) => {
			const next = { ...map.get(id) };
			for (const [name, value] of Object.entries(update)) {
				next[name] = value?.__op__ === 'add' ? (Number(next[name]) || 0) + value.value : value;
			}
			map.set(id, next);
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
	let families;
	let jtis;
	let served;
	let fetches;
	let jtiPatch;
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
		families = new Map();
		jtis = new Map();
		jtiPatch = async (id, update, context) => {
			const record = { ...jtis.get(id)?.record };
			for (const [name, value] of Object.entries(update)) {
				record[name] = value?.__op__ === 'add' ? (Number(record[name]) || 0) + value.value : value;
			}
			jtis.set(id, { record, context });
		};
		global.databases = {
			oauth: {
				harper_oauth_mcp_clients: makeTable(clients, 'client_id'),
				mcp_auth_codes: makeTable(codes, 'code'),
				mcp_refresh_families: makeTable(families, 'family_id'),
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
				mcp_assertion_jtis: {
					get: async (id) => jtis.get(id)?.record ?? null,
					patch: (id, update, context) => jtiPatch(id, update, context),
				},
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

	function assertInvalidRequest(res, pattern) {
		assert.equal(res.status, 400, JSON.stringify(res.body));
		assert.equal(res.body.error, 'invalid_request');
		if (pattern) assert.match(res.body.error_description, pattern);
	}

	describe('partial, empty, duplicate and conflicting credentials', () => {
		beforeEach(() => seedCode('code-1', 'public-1', REDIRECT, 'none'));

		const publicBody = { client_id: 'public-1', redirect_uri: REDIRECT };
		const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

		it('rejects half an assertion pair (invalid_request)', async () => {
			assertInvalidRequest(await exchange({ ...publicBody, client_assertion: signAssertion() }), /presented together/);
			assertInvalidRequest(await exchange({ ...publicBody, client_assertion_type: TYPE }), /presented together/);
		});

		it('rejects empty credential parameters (invalid_request)', async () => {
			for (const name of ['client_assertion', 'client_assertion_type', 'client_secret', 'client_id']) {
				assertInvalidRequest(
					await exchange({ ...publicBody, [name]: '' }),
					new RegExp(`${name} must be a single non-empty value`)
				);
			}
		});

		it('rejects array-valued credential parameters and client_id as repeated parameters (invalid_request)', async () => {
			assertInvalidRequest(await exchange({ ...publicBody, client_secret: ['a', 'b'] }), /must not be repeated/);
			assertInvalidRequest(
				await exchange({
					...publicBody,
					client_assertion: [signAssertion(), signAssertion()],
					client_assertion_type: TYPE,
				}),
				/must not be repeated/
			);
			assertInvalidRequest(
				await exchange({ ...publicBody, client_id: ['public-1', 'public-1'] }),
				/must not be repeated/
			);
		});

		it('rejects an assertion alongside a secret or any Basic header, including an empty-secret one (invalid_request)', async () => {
			const withAssertion = { ...publicBody, client_assertion: signAssertion(), client_assertion_type: TYPE };
			assertInvalidRequest(
				await exchange({ ...withAssertion, client_secret: 'x' }),
				/Multiple client authentication methods/
			);
			assertInvalidRequest(await exchange(withAssertion, { headers: basic('public-1', '') }), /Multiple/);
		});

		it('rejects a detected repeat in a form body as Harper deserializes it (invalid_request)', async () => {
			// A body in the shape Harper's form deserializer builds for these inputs
			// (harper server/serverHelpers/contentTypes.ts, HarperFast/harper#2953).
			const harperForm = (query) => {
				const object = {};
				for (const [name, value] of new URLSearchParams(query)) {
					if (Object.hasOwn(object, name)) {
						const last = object[name];
						if (Array.isArray(last)) last.push(value);
						else object.key = [last, value];
					} else object[name] = value;
				}
				return object;
			};
			const form = `grant_type=authorization_code&code=code-1&code_verifier=${CODE_VERIFIER}&redirect_uri=${encodeURIComponent(REDIRECT)}`;
			for (const repeat of ['client_id=public-1&client_id=public-1', 'client_id=public-1&code=code-1']) {
				const body = harperForm(`${form}&${repeat}`);
				const res = await handleToken({ headers: {} }, body, DEFAULT, undefined, logger);
				assertInvalidRequest(res, /must not be repeated/);
			}
			assert.equal(codes.has('code-1'), true, 'no code consumed');
			const once = await handleToken(
				{ headers: {} },
				harperForm(`${form}&client_id=public-1`),
				DEFAULT,
				undefined,
				logger
			);
			assert.equal(once.status, 200, JSON.stringify(once.body));
		});

		describe('repeats and unrecognized parameters in the deserialized body, on every grant', () => {
			// The two deserialized shapes: a `key` array (HarperFast/harper#2953) and,
			// once that is fixed, an array under the parameter's own name. See the
			// harper#2953 note in docs/mcp-oauth.md.
			const SINGLE_VALUED = [
				'grant_type',
				'code',
				'redirect_uri',
				'code_verifier',
				'refresh_token',
				'client_id',
				'client_secret',
				'client_assertion',
				'client_assertion_type',
				'scope',
			];
			const HEADLESS = 'https://agents.example.com/fleet/agent-1.json';
			const OTHER_RESOURCE = 'https://other.example.com/mcp';
			const agent = generateKeyPairSync('ed25519');
			const config = { ...MIXED, clientIdMetadataDocuments: { allowedHosts: ['agents.example.com'] } };
			let familyCount = 0;

			beforeEach(() => {
				_resetGrantRateLimiter();
				served[HEADLESS] = {
					client_id: HEADLESS,
					client_name: 'Headless agent',
					grant_types: ['client_credentials'],
					token_endpoint_auth_method: 'private_key_jwt',
					jwks: { keys: [agent.publicKey.export({ format: 'jwk' })] },
				};
			});

			function headlessAssertion() {
				const now = Math.floor(Date.now() / 1000);
				const h = b64url({ alg: 'EdDSA', typ: 'JWT' });
				const p = b64url({
					iss: HEADLESS,
					sub: HEADLESS,
					aud: ISSUER,
					iat: now,
					exp: now + 30,
					jti: randomBytes(12).toString('hex'),
				});
				return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), agent.privateKey).toString('base64url')}`;
			}

			/** A fresh, otherwise valid request body for each grant (a new code, family and assertion). */
			function freshGrants() {
				seedCode('code-1', 'public-1', REDIRECT, 'none');
				const familyId = `${BOUND_FAMILY_ID_PREFIX}repeat-${++familyCount}`;
				const { token, hash } = makeRefreshToken(familyId);
				families.set(familyId, {
					family_id: familyId,
					current_token_hash: hash,
					revoked: false,
					client_id: 'public-1',
					user: 'alice',
					resource: RESOURCE,
					expires_at: Math.floor(Date.now() / 1000) + 3600,
					client_auth_method: 'none',
				});
				return {
					authorization_code: {
						...publicBody,
						grant_type: 'authorization_code',
						code: 'code-1',
						code_verifier: CODE_VERIFIER,
					},
					refresh_token: { grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
					client_credentials: {
						grant_type: 'client_credentials',
						client_id: HEADLESS,
						client_assertion_type: TYPE,
						client_assertion: headlessAssertion(),
					},
				};
			}

			const token = (body) => handleToken({ headers: {} }, body, config, undefined, logger);

			it('refuses a single-valued parameter repeated in either deserialized shape, consuming nothing', async () => {
				for (const [grant, body] of Object.entries(freshGrants())) {
					for (const name of SINGLE_VALUED) {
						const value = body[name] ?? `repeated-${name}`;
						for (const repeat of [{ [name]: [value, value] }, { [name]: value, key: [value, value] }]) {
							const res = await token({ ...body, ...repeat });
							const label = `${grant} ${JSON.stringify(repeat)}: ${JSON.stringify(res.body)}`;
							assert.equal(res.status, 400, label);
							assert.equal(res.body.error, 'invalid_request', label);
							assert.equal(res.body.error_description, `${name} must not be repeated`, label);
						}
					}
					// Nothing was consumed: the same request without the repeat succeeds.
					const once = await token(body);
					assert.equal(once.status, 200, `${grant}: ${JSON.stringify(once.body)}`);
				}
			});

			it('client_credentials: two resource values in the deserialized body are accepted when both are the MCP resource, invalid_target otherwise', async () => {
				const body = freshGrants().client_credentials;
				for (const refused of [
					{ resource: [RESOURCE, OTHER_RESOURCE] },
					{ resource: [OTHER_RESOURCE, RESOURCE] },
					{ resource: RESOURCE, key: [RESOURCE, OTHER_RESOURCE] },
					{ resource: OTHER_RESOURCE, key: [OTHER_RESOURCE, RESOURCE] },
				]) {
					const res = await token({ ...body, ...refused });
					const label = `${JSON.stringify(refused)}: ${JSON.stringify(res.body)}`;
					assert.equal(res.status, 400, label);
					assert.equal(res.body.error, 'invalid_target', label);
				}
				// The refusals consumed nothing: the same assertion is accepted with two allowed values.
				const accepted = await token({ ...body, resource: [RESOURCE, RESOURCE] });
				assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
				const pre2953 = await token({
					...freshGrants().client_credentials,
					resource: RESOURCE,
					key: [RESOURCE, RESOURCE],
				});
				assert.equal(pre2953.status, 200, JSON.stringify(pre2953.body));
			});

			it('ignores an unrecognized parameter: vendor_options as a JSON array, or vendor repeated in the pre-harper#2953 form shape', async () => {
				for (const unknown of [{ vendor_options: ['a', 'b'] }, { vendor: 'a', key: ['a', 'b'] }]) {
					for (const [grant, body] of Object.entries(freshGrants())) {
						const res = await token({ ...body, ...unknown });
						assert.equal(res.status, 200, `${grant} ${JSON.stringify(unknown)}: ${JSON.stringify(res.body)}`);
					}
				}
			});
		});

		it('answers invalid_request for an assertion with any Basic header, whatever its type, on both grants', async () => {
			const grants = [
				{ grant_type: 'authorization_code', code: 'code-1', code_verifier: CODE_VERIFIER, redirect_uri: REDIRECT },
				{ grant_type: 'refresh_token', refresh_token: 'p2-family.secret' },
			];
			const headers = [basic('public-1', 'x'), basic('public-1', ''), { authorization: 'Basic !!!' }];
			for (const grant of grants) {
				for (const header of headers) {
					for (const type of ['urn:nope', TYPE]) {
						const body = {
							...grant,
							client_id: 'public-1',
							client_assertion: signAssertion(),
							client_assertion_type: type,
						};
						const res = await handleToken({ headers: header }, body, DEFAULT, undefined, logger);
						assertInvalidRequest(res, /Multiple client authentication methods/);
					}
				}
			}
			assertInvalidRequest(
				await exchange({ ...publicBody, client_secret: 'x' }, { headers: { authorization: 'Basic !!!' } }),
				/Multiple client authentication methods/
			);
			assert.equal(codes.has('code-1'), true, 'no code consumed');
		});

		it('challenges for Basic on a 401 only when the request used Basic', async () => {
			const challenged = await exchange(publicBody, { headers: { authorization: 'Basic !!!' } });
			assertInvalidClient(challenged, /Malformed Basic/);
			assert.equal(challenged.headers['WWW-Authenticate'], 'Basic realm="oauth"');
			const wrongSecret = await exchange({ redirect_uri: REDIRECT }, { headers: basic('conf-1', 'not-the-secret') });
			assertInvalidClient(wrongSecret, /Invalid client credentials/);
			assert.equal(wrongSecret.headers['WWW-Authenticate'], 'Basic realm="oauth"');
			const withoutBasic = await exchange({ ...publicBody, client_secret: 'x' });
			assertInvalidClient(withoutBasic);
			assert.equal(withoutBasic.headers['WWW-Authenticate'], undefined);
			const notA401 = await exchange({ ...publicBody, client_secret: 'x' }, { headers: basic('public-1', 'y') });
			assertInvalidRequest(notA401, /Multiple/);
			assert.equal(notA401.headers['WWW-Authenticate'], undefined);
		});

		it('rejects an unknown assertion type', async () => {
			assertInvalidClient(
				await exchange({ ...publicBody, client_assertion: signAssertion(), client_assertion_type: 'urn:nope' }),
				/client_assertion_type must be/
			);
		});

		it('rejects malformed Basic credentials instead of ignoring them', async () => {
			for (const authorization of [
				'Basic',
				'basic',
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
			jtiPatch = async () => {
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

	describe('grant binding: codes and refresh families keep the method bound at authorization', () => {
		const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
		const withAssertion = (extra = {}) => ({
			client_id: ASSISTANT,
			redirect_uri: ASSISTANT_REDIRECT,
			client_assertion: signAssertion(),
			client_assertion_type: TYPE,
			...extra,
		});
		const asPublic = { client_id: ASSISTANT, redirect_uri: ASSISTANT_REDIRECT };

		function refresh(refreshToken, body, config) {
			return handleToken(
				{ headers: {} },
				{ grant_type: 'refresh_token', refresh_token: refreshToken, ...body },
				config,
				undefined,
				logger
			);
		}

		function seedFamily(familyId, clientId, method) {
			const { token, hash } = makeRefreshToken(familyId);
			families.set(familyId, {
				family_id: familyId,
				current_token_hash: hash,
				revoked: false,
				client_id: clientId,
				user: 'alice',
				resource: RESOURCE,
				expires_at: Math.floor(Date.now() / 1000) + 3600,
				...(method === undefined ? {} : { client_auth_method: method }),
			});
			return token;
		}

		it('rejects an unbound (pre-activation) code before consuming it', async () => {
			seedCode('code-1', 'public-1', REDIRECT, undefined);
			const res = await exchange({ client_id: 'public-1', redirect_uri: REDIRECT });
			assert.equal(res.status, 400);
			assert.equal(res.body.error, 'invalid_grant');
			assert.match(res.body.error_description, /predates client authentication binding/);
			assert.equal(codes.has('code-1'), true);
		});

		it('refuses a code bound to private_key_jwt once the configuration only permits none', async () => {
			// Authorized on a server advertising private_key_jwt; exchanged after it stopped.
			seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'private_key_jwt');
			const res = await exchange(asPublic, { config: DEFAULT });
			assert.equal(res.status, 400);
			assert.equal(res.body.error, 'invalid_grant');
			assert.match(res.body.error_description, /bound to a different client authentication method/);
			assert.equal(codes.has('code-1'), true);
		});

		it('refuses a code bound to none once private_key_jwt becomes the permitted method', async () => {
			seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'none');
			const res = await exchange(withAssertion(), { config: MIXED });
			assert.equal(res.status, 400);
			assert.match(res.body.error_description, /bound to a different client authentication method/);
			assert.equal(codes.has('code-1'), true);
		});

		it('copies the binding into a bound family and requires the same method on every refresh', async () => {
			seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'private_key_jwt');
			const minted = await exchange(withAssertion(), { config: MIXED });
			assert.equal(minted.status, 200, JSON.stringify(minted.body));
			const [family] = families.values();
			assert.ok(family.family_id.startsWith(BOUND_FAMILY_ID_PREFIX));
			assert.equal(family.client_auth_method, 'private_key_jwt');

			const first = await refresh(minted.body.refresh_token, withAssertion({ redirect_uri: undefined }), MIXED);
			assert.equal(first.status, 200, JSON.stringify(first.body));
			assert.equal(families.get(family.family_id).client_auth_method, 'private_key_jwt', 'binding survives rotation');

			// The document drops private_key_jwt: the client is now permitted (and presents) none.
			served[ASSISTANT] = {
				...ASSISTANT_DOC,
				token_endpoint_auth_method: 'none',
				token_endpoint_auth_methods_supported: ['none'],
			};
			_clearCimdCache();
			const before = families.get(family.family_id).current_token_hash;
			const weakened = await refresh(first.body.refresh_token, { client_id: ASSISTANT }, MIXED);
			assert.equal(weakened.status, 400);
			assert.equal(weakened.body.error, 'invalid_grant');
			assert.match(weakened.body.error_description, /bound to a different client authentication method/);
			assert.equal(families.get(family.family_id).current_token_hash, before, 'no rotation on a binding mismatch');
		});

		it('rejects a bare Basic scheme on refresh as malformed', async () => {
			const token = seedFamily(`${FAMILY_ID_PREFIX}bare-basic`, 'public-1', undefined);
			const res = await handleToken(
				{ headers: { authorization: 'Basic' } },
				{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
				DEFAULT,
				undefined,
				logger
			);
			assertInvalidClient(res, /Malformed Basic/);
			// The same request without the header refreshes: the header alone was refused.
			const ok = await handleToken(
				{ headers: {} },
				{ grant_type: 'refresh_token', refresh_token: token, client_id: 'public-1' },
				DEFAULT,
				undefined,
				logger
			);
			assert.equal(ok.status, 200, JSON.stringify(ok.body));
		});

		it('rejects a bound family whose binding an older writer dropped', async () => {
			const token = seedFamily(`${BOUND_FAMILY_ID_PREFIX}stripped`, 'public-1', undefined);
			const res = await refresh(token, { client_id: 'public-1' }, DEFAULT);
			assert.equal(res.status, 400);
			assert.match(res.body.error_description, /no client authentication binding/);
		});

		it('binds legacy families to the method clients used before the binding existed', async () => {
			// Stored clients: their registered method; CIMD clients: none.
			const stored = seedFamily(`${FAMILY_ID_PREFIX}legacy-dcr`, 'public-1', undefined);
			assert.equal((await refresh(stored, { client_id: 'public-1' }, DEFAULT)).status, 200);
			const cimdPublic = seedFamily(`${FAMILY_ID_PREFIX}legacy-cimd`, ASSISTANT, undefined);
			assert.equal((await refresh(cimdPublic, asPublic, DEFAULT)).status, 200);
			// The same legacy link cannot continue once private_key_jwt is required: reauthorize.
			const cimdUpgraded = seedFamily(`${FAMILY_ID_PREFIX}legacy-cimd-2`, ASSISTANT, undefined);
			const res = await refresh(cimdUpgraded, withAssertion({ redirect_uri: undefined }), MIXED);
			assert.equal(res.status, 400);
			assert.match(res.body.error_description, /bound to a different client authentication method/);
		});
	});

	describe('conformance: rejected before any client lookup, and storage failures', () => {
		const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
		beforeEach(() => seedCode('code-1', ASSISTANT, ASSISTANT_REDIRECT, 'private_key_jwt'));

		function oversized(length) {
			// A payload whose sub names a real client, so an unbounded parse would look it up.
			const real = signAssertion();
			const [h, p] = real.split('.');
			return `${h}.${p}.${'A'.repeat(length - h.length - p.length - 2)}`;
		}

		it('rejects an assertion over the verifier bound before parsing it or resolving any client', async () => {
			for (const withClientId of [false, true]) {
				const res = await exchange(
					{
						...(withClientId ? { client_id: ASSISTANT } : {}),
						redirect_uri: ASSISTANT_REDIRECT,
						client_assertion: oversized(MAX_ASSERTION_LENGTH + 1),
						client_assertion_type: TYPE,
					},
					{ config: MIXED }
				);
				assertInvalidClient(res, /exceeds the maximum allowed length/);
			}
			assert.deepEqual(fetches, [], 'no document or key fetch');
			assert.equal(codes.has('code-1'), true);
		});

		it('an assertion exactly at the bound still reaches client resolution', async () => {
			const res = await exchange(
				{
					redirect_uri: ASSISTANT_REDIRECT,
					client_assertion: oversized(MAX_ASSERTION_LENGTH),
					client_assertion_type: TYPE,
				},
				{ config: MIXED }
			);
			assertInvalidClient(res);
			assert.ok(fetches.includes(ASSISTANT), 'the subject was used to resolve the client');
		});

		it('rejects Basic credentials combined with a body client_secret as invalid_request', async () => {
			seedCode('code-2', 'conf-1', REDIRECT, 'client_secret_basic');
			const res = await exchange(
				{ redirect_uri: REDIRECT, client_secret: 'conf-secret' },
				{ headers: basic('conf-1', 'conf-secret'), code: 'code-2' }
			);
			assertInvalidRequest(res, /Multiple client authentication methods/);
			assert.equal(codes.has('code-2'), true);
		});

		it('answers server_error, not an authentication or grant error, when a store read fails', async () => {
			const failingGet = async () => {
				throw new Error('storage unavailable');
			};
			seedCode('code-2', 'public-1', REDIRECT, 'none');
			const table = global.databases.oauth;

			const realClients = table.harper_oauth_mcp_clients.get;
			table.harper_oauth_mcp_clients.get = failingGet;
			const client = await exchange({ client_id: 'public-1', redirect_uri: REDIRECT }, { code: 'code-2' });
			assert.equal(client.status, 500, JSON.stringify(client.body));
			assert.equal(client.body.error, 'server_error');
			table.harper_oauth_mcp_clients.get = realClients;

			const realCodes = table.mcp_auth_codes.get;
			table.mcp_auth_codes.get = failingGet;
			const code = await exchange({ client_id: 'public-1', redirect_uri: REDIRECT }, { code: 'code-2' });
			assert.equal(code.status, 500, JSON.stringify(code.body));
			assert.equal(code.body.error, 'server_error');
			table.mcp_auth_codes.get = realCodes;
			assert.equal(codes.has('code-2'), true, 'the code is not consumed');

			const minted = await exchange({ client_id: 'public-1', redirect_uri: REDIRECT }, { code: 'code-2' });
			assert.equal(minted.status, 200, JSON.stringify(minted.body));
			const [family] = families.values();
			const hashBefore = family.current_token_hash;
			table.mcp_refresh_families.get = failingGet;
			const refreshed = await handleToken(
				{ headers: {} },
				{ grant_type: 'refresh_token', refresh_token: minted.body.refresh_token, client_id: 'public-1' },
				DEFAULT,
				undefined,
				logger
			);
			assert.equal(refreshed.status, 500, JSON.stringify(refreshed.body));
			assert.equal(refreshed.body.error, 'server_error');
			assert.equal(families.get(family.family_id).current_token_hash, hashBefore, 'no rotation');
			assert.equal(families.get(family.family_id).revoked, false, 'no revocation');
		});

		it('still reports a missing client, code or family as a client or grant error', async () => {
			assertInvalidClient(await exchange({ client_id: 'nobody', redirect_uri: REDIRECT }), /Unknown client/);
			const noCode = await exchange({ client_id: 'public-1', redirect_uri: REDIRECT }, { code: 'no-such-code' });
			assert.equal(noCode.status, 400);
			assert.equal(noCode.body.error, 'invalid_grant');
			const noFamily = await handleToken(
				{ headers: {} },
				{
					grant_type: 'refresh_token',
					refresh_token: `${BOUND_FAMILY_ID_PREFIX}missing.secret`,
					client_id: 'public-1',
				},
				DEFAULT,
				undefined,
				logger
			);
			assert.equal(noFamily.status, 400);
			assert.equal(noFamily.body.error, 'invalid_grant');
		});
	});

	describe('ChatGPT requests in the recorded shape', () => {
		const signer = createCaptureSigner();
		const SCOPE = 'echo';
		const exceptionOn = (base, expiresAt = Date.now() + 86_400_000) => ({
			...base,
			clientIdMetadataDocuments: {
				...base.clientIdMetadataDocuments,
				privateKeyJwt: {
					...base.clientIdMetadataDocuments?.privateKeyJwt,
					tokenEndpointAudience: { clientIds: [CHATGPT_CLIENT_ID], expiresAt },
				},
			},
		});
		const interactiveOff = (base) => ({
			...base,
			clientIdMetadataDocuments: { ...base.clientIdMetadataDocuments, privateKeyJwt: { enabled: false } },
		});

		beforeEach(() => {
			served[CHATGPT_CLIENT_ID] = CHATGPT_CIMD_DOCUMENT;
			served[CHATGPT_JWKS_URI] = signer.jwks;
		});

		function seedChatGPTCode(code, method) {
			codes.set(code, {
				code,
				client_id: CHATGPT_CLIENT_ID,
				user: 'alice',
				resource: RESOURCE,
				scope: SCOPE,
				code_challenge: CODE_CHALLENGE,
				code_challenge_method: 'S256',
				redirect_uri: CHATGPT_REDIRECT_URI,
				client_auth_method: method,
			});
		}

		const post = (form, config) => handleToken({ headers: CAPTURE_REQUEST_HEADERS }, form, config, undefined, logger);

		/** Run `fn` with Date.now() pinned to `ms`. */
		async function atTime(ms, fn) {
			const realNow = Date.now;
			Date.now = () => ms;
			try {
				return await fn();
			} finally {
				Date.now = realNow;
			}
		}

		function claimsOf(jwt) {
			return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
		}

		function exchangeForm(code, assertion) {
			return captureCodeForm({ assertion, resource: RESOURCE, code, codeVerifier: CODE_VERIFIER });
		}

		for (const [variant, audience, config] of [
			['the recorded token-endpoint audience, with the exact-ID exception', TOKEN_ENDPOINT, exceptionOn(SETTING_ON)],
			['the issuer audience, under the default issuer-only policy', ISSUER, SETTING_ON],
			[
				'the recorded audience on a mixed server whose headless issuance limit is 2 per minute',
				TOKEN_ENDPOINT,
				exceptionOn({ ...MIXED, clientCredentials: { enabled: true, rateLimit: 2 } }),
			],
		]) {
			it(`chains the recorded burst: code exchange, then refreshes at 0.8, 3.6, 5.4 and 6.6 s (${variant})`, async () => {
				seedChatGPTCode('code-burst', 'private_key_jwt');
				const t0 = Date.now();
				const assertionAt = (ms) => captureAssertion(signer, { audience, nowMs: ms });
				const minted = await atTime(t0, () => post(exchangeForm('code-burst', assertionAt(t0)), config));
				assert.equal(minted.status, 200, JSON.stringify(minted.body));
				assert.equal(claimsOf(minted.body.access_token).aud, RESOURCE, 'the code-bound resource');
				const [family] = families.values();
				const original = { ...families.get(family.family_id) };
				assert.equal(original.client_auth_method, 'private_key_jwt');

				let current = minted.body.refresh_token;
				const presented = [current];
				for (const offset of CAPTURE_REFRESH_OFFSETS_MS) {
					const at = t0 + offset;
					const res = await atTime(at, () =>
						post(captureRefreshForm({ assertion: assertionAt(at), resource: RESOURCE, refreshToken: current }), config)
					);
					assert.equal(res.status, 200, `refresh at +${offset} ms: ${JSON.stringify(res.body)}`);
					assert.notEqual(res.body.refresh_token, current);
					assert.equal(claimsOf(res.body.access_token).aud, RESOURCE);
					current = res.body.refresh_token;
					presented.push(current);
				}
				const after = families.get(family.family_id);
				assert.equal(after.expires_at, original.expires_at, 'the family keeps its original expiry');
				assert.equal(after.resource, RESOURCE);
				assert.equal(after.scope, SCOPE);
				assert.equal(after.client_auth_method, 'private_key_jwt');
				assert.equal(after.revoked, false);
				assert.equal(fetches.filter((u) => u === CHATGPT_JWKS_URI).length, 1, 'keys fetched once for the burst');
				assert.equal(jtis.size, 5, 'five distinct assertions recorded');
				for (const { record, context } of jtis.values()) {
					assert.equal(record.expires_at, context.expiresAt);
				}
			});
		}

		it('refuses the same assertion presented again (invalid_client) without rotating', async () => {
			const config = exceptionOn(SETTING_ON);
			seedChatGPTCode('code-replay', 'private_key_jwt');
			const minted = await post(
				exchangeForm('code-replay', captureAssertion(signer, { audience: TOKEN_ENDPOINT })),
				config
			);
			assert.equal(minted.status, 200, JSON.stringify(minted.body));
			const assertion = captureAssertion(signer, { audience: TOKEN_ENDPOINT });
			const first = await post(
				captureRefreshForm({ assertion, resource: RESOURCE, refreshToken: minted.body.refresh_token }),
				config
			);
			assert.equal(first.status, 200, JSON.stringify(first.body));
			const [family] = families.values();
			const hash = families.get(family.family_id).current_token_hash;
			const replay = await post(
				captureRefreshForm({ assertion, resource: RESOURCE, refreshToken: first.body.refresh_token }),
				config
			);
			assertInvalidClient(replay, /jti has already been used/);
			assert.equal(families.get(family.family_id).current_token_hash, hash, 'no rotation');
			const fresh = await post(
				captureRefreshForm({
					assertion: captureAssertion(signer, { audience: TOKEN_ENDPOINT }),
					resource: RESOURCE,
					refreshToken: first.body.refresh_token,
				}),
				config
			);
			assert.equal(fresh.status, 200, 'the current token still refreshes with a fresh assertion');
		});

		it('refuses a superseded refresh token with a fresh assertion (invalid_grant) and revokes the family', async () => {
			const config = exceptionOn(SETTING_ON);
			seedChatGPTCode('code-superseded', 'private_key_jwt');
			const minted = await post(
				exchangeForm('code-superseded', captureAssertion(signer, { audience: TOKEN_ENDPOINT })),
				config
			);
			const rotated = await post(
				captureRefreshForm({
					assertion: captureAssertion(signer, { audience: TOKEN_ENDPOINT }),
					resource: RESOURCE,
					refreshToken: minted.body.refresh_token,
				}),
				config
			);
			assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
			const superseded = await post(
				captureRefreshForm({
					assertion: captureAssertion(signer, { audience: TOKEN_ENDPOINT }),
					resource: RESOURCE,
					refreshToken: minted.body.refresh_token,
				}),
				config
			);
			assert.equal(superseded.status, 400);
			assert.equal(superseded.body.error, 'invalid_grant');
			assert.match(superseded.body.error_description, /superseded; family revoked/);
			const [family] = families.values();
			assert.equal(families.get(family.family_id).revoked, true);
			const latest = await post(
				captureRefreshForm({
					assertion: captureAssertion(signer, { audience: TOKEN_ENDPOINT }),
					resource: RESOURCE,
					refreshToken: rotated.body.refresh_token,
				}),
				config
			);
			assert.equal(latest.status, 400, 'the latest token dies with its family');
			assert.equal(latest.body.error, 'invalid_grant');
		});

		it('never treats the resource form field as the assertion audience', async () => {
			seedChatGPTCode('code-resource', 'private_key_jwt');
			const res = await post(
				exchangeForm('code-resource', captureAssertion(signer, { audience: RESOURCE })),
				exceptionOn(SETTING_ON)
			);
			assertInvalidClient(res, /aud does not match/);
			assert.equal(codes.has('code-resource'), true);
		});

		it('never trusts the unverified subject: an assertion-only request with a forged signature is refused', async () => {
			seedChatGPTCode('code-forged', 'private_key_jwt');
			const forger = createCaptureSigner({ kid: signer.kid });
			const form = exchangeForm('code-forged', captureAssertion(forger, { audience: ISSUER }));
			delete form.client_id;
			assertInvalidClient(await post(form, SETTING_ON), /signature/);
			assert.equal(codes.has('code-forged'), true);
		});

		describe('mixed-server matrix: what the metadata advertises is what the token endpoint accepts', () => {
			// advertises: private_key_jwt in the metadata (and so the method ChatGPT is permitted).
			// Outcomes: the recorded request (token-endpoint aud), its issuer-audience variant, the none-only form.
			const MATRIX = [
				['CIMD on, interactive setting absent, headless off', DEFAULT, false, [401, 401, 200]],
				['interactive setting false, headless off', interactiveOff(DEFAULT), false, [401, 401, 200]],
				['interactive setting true', SETTING_ON, true, [401, 200, 401]],
				['headless on, interactive setting absent', MIXED, true, [401, 200, 401]],
				['headless on, interactive setting false', interactiveOff(MIXED), true, [401, 200, 401]],
				['interactive setting true, exact-ID exception', exceptionOn(SETTING_ON), true, [200, 200, 401]],
				[
					'headless on, interactive setting false, exact-ID exception',
					exceptionOn(interactiveOff(MIXED)),
					true,
					[200, 200, 401],
				],
				['interactive setting true, expired exception', exceptionOn(SETTING_ON, Date.now() - 1), true, [401, 200, 401]],
				[
					'interactive setting absent, exception configured (it enables nothing)',
					exceptionOn(DEFAULT),
					false,
					[401, 401, 200],
				],
			];

			for (const [name, config, advertises, [recorded, issuerAud, noneOnly]] of MATRIX) {
				it(name, async () => {
					const metadata = await buildAuthorizationServerMetadata({ headers: {} }, config);
					assert.equal(metadata.token_endpoint_auth_methods_supported.includes('private_key_jwt'), advertises);
					assert.equal((metadata.token_endpoint_auth_signing_alg_values_supported ?? []).includes('RS256'), advertises);
					const bound = advertises ? 'private_key_jwt' : 'none';
					const outcomes = [];
					for (const [code, assertion] of [
						['code-recorded', captureAssertion(signer, { audience: TOKEN_ENDPOINT })],
						['code-issuer', captureAssertion(signer, { audience: ISSUER })],
						['code-none', undefined],
					]) {
						seedChatGPTCode(code, bound);
						const res = await post(exchangeForm(code, assertion), config);
						outcomes.push(res.status);
						if (res.status !== 200) {
							assert.equal(res.body.error, 'invalid_client', `${code}: ${JSON.stringify(res.body)}`);
							assert.equal(codes.has(code), true, `${code}: no code consumed`);
						}
					}
					assert.deepEqual(outcomes, [recorded, issuerAud, noneOnly]);
				});
			}
		});
	});

	describe('migration: grant formats against 2.7.0 writers and readers', () => {
		const TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
		// Declares both methods without a singular preference: 2.6.0 and 2.7.0
		// resolve it as a public client, this version permits private_key_jwt
		// wherever it is advertised.
		const DUAL = 'https://dual.example.com/oauth/client.json';
		const DUAL_REDIRECT = 'https://dual.example.com/cb';
		const DUAL_DOC = {
			client_id: DUAL,
			client_name: 'Dual',
			redirect_uris: [DUAL_REDIRECT],
			grant_types: ['authorization_code', 'refresh_token'],
			token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
			jwks_uri: 'https://dual.example.com/oauth/jwks.json',
		};
		const dualAssertion = () => signAssertion({ claims: { iss: DUAL, sub: DUAL } });
		const withAssertion = (extra = {}) => ({
			client_id: DUAL,
			client_assertion: dualAssertion(),
			client_assertion_type: TYPE,
			...extra,
		});
		const refresh = (refreshToken, body, config) =>
			handleToken(
				{ headers: {} },
				{ grant_type: 'refresh_token', refresh_token: refreshToken, ...body },
				config,
				undefined,
				logger
			);
		const hashOf = (token) => createHash('sha256').update(token).digest('base64url');

		beforeEach(() => {
			served[DUAL] = DUAL_DOC;
			served[DUAL_DOC.jwks_uri] = { keys: [KEY_1.jwk] };
		});

		async function boundFamily() {
			seedCode('code-1', DUAL, DUAL_REDIRECT, 'private_key_jwt');
			const minted = await exchange(withAssertion({ redirect_uri: DUAL_REDIRECT }), { config: MIXED });
			assert.equal(minted.status, 200, JSON.stringify(minted.body));
			const [family] = families.values();
			assert.ok(family.family_id.startsWith(BOUND_FAMILY_ID_PREFIX));
			assert.equal(family.client_auth_method, 'private_key_jwt');
			return { token: minted.body.refresh_token, familyId: family.family_id };
		}

		it('documents whose singular method is private_key_jwt do not resolve on 2.6.0 or 2.7.0', () => {
			assert.equal(upstreamInteractiveDocumentMethod(ASSISTANT_DOC), null, 'requests routed there fail closed');
			assert.equal(upstreamInteractiveDocumentMethod(CHATGPT_CIMD_DOCUMENT), null);
			assert.equal(upstreamInteractiveDocumentMethod(DUAL_DOC), 'none', 'this one resolves there as public');
		});

		it('refuses a bound family after a binding-unaware node rotated it and dropped the binding', async () => {
			const { token, familyId } = await boundFamily();
			const { token: next, hash } = makeRefreshToken(familyId);
			const family = families.get(familyId);
			assert.equal(
				upstreamRefreshOutcome(family, { clientId: DUAL, presentedHash: hashOf(token), provenanceReader: false }),
				'rotate',
				'a 2.6.0 node rotates it'
			);
			families.set(familyId, upstreamEncodeFamily({ ...family, current_token_hash: hash }));
			assert.equal('client_auth_method' in families.get(familyId), false, 'its full-record put dropped the binding');
			const res = await refresh(next, withAssertion(), MIXED);
			assert.equal(res.status, 400);
			assert.match(res.body.error_description, /no client authentication binding/);
		});

		it('rolling back to 2.7.0 retires bound families (its reader accepts only p1- ids)', async () => {
			const { token, familyId } = await boundFamily();
			assert.equal(
				upstreamRefreshOutcome(families.get(familyId), { clientId: DUAL, presentedHash: hashOf(token) }),
				'retire'
			);
		});

		it('routing a bound grant to a binding-unaware node is unsafe: it accepts a weaker method', async () => {
			const { token, familyId } = await boundFamily();
			assert.equal(upstreamInteractiveDocumentMethod(DUAL_DOC), 'none', 'the bound method was private_key_jwt');
			assert.equal(
				upstreamRefreshOutcome(families.get(familyId), {
					clientId: DUAL,
					presentedHash: hashOf(token),
					provenanceReader: false,
				}),
				'rotate',
				'a 2.6.0 node rotates the family for a public-client request'
			);
			seedCode('code-9', DUAL, DUAL_REDIRECT, 'private_key_jwt');
			assert.equal(
				upstreamCodeRedeemable(upstreamEncodeCode(codes.get('code-9')), {
					clientId: DUAL,
					redirectUri: DUAL_REDIRECT,
				}),
				true,
				'a 2.6.0 or 2.7.0 node redeems a code bound to private_key_jwt without the assertion'
			);
		});

		it('a code written by a 2.7.0 node has no binding and is refused before it is consumed', async () => {
			codes.set(
				'code-old',
				upstreamEncodeCode({
					code: 'code-old',
					client_id: 'public-1',
					user: 'alice',
					resource: RESOURCE,
					code_challenge: CODE_CHALLENGE,
					code_challenge_method: 'S256',
					redirect_uri: REDIRECT,
					client_auth_method: 'none',
				})
			);
			const res = await exchange({ client_id: 'public-1', redirect_uri: REDIRECT }, { code: 'code-old' });
			assert.equal(res.status, 400);
			assert.match(res.body.error_description, /predates client authentication binding/);
			assert.equal(codes.has('code-old'), true);
		});

		it('families written by 2.7.0 keep its policy; unknown formats are retired, never read as bound', async () => {
			const legacy = (familyId, clientId) => {
				const { token, hash } = makeRefreshToken(familyId);
				families.set(
					familyId,
					upstreamEncodeFamily({
						family_id: familyId,
						current_token_hash: hash,
						revoked: false,
						client_id: clientId,
						user: 'alice',
						resource: RESOURCE,
						expires_at: Math.floor(Date.now() / 1000) + 3600,
					})
				);
				return token;
			};
			assert.equal(
				(await refresh(legacy(`${UPSTREAM_FAMILY_ID_PREFIX}dcr`, 'public-1'), { client_id: 'public-1' }, DEFAULT))
					.status,
				200
			);
			assert.equal(
				(await refresh(legacy(`${UPSTREAM_FAMILY_ID_PREFIX}cimd`, DUAL), { client_id: DUAL }, DEFAULT)).status,
				200,
				'a CIMD family from 2.7.0 stays bound to none'
			);
			const upgraded = await refresh(legacy(`${UPSTREAM_FAMILY_ID_PREFIX}cimd-2`, DUAL), withAssertion(), MIXED);
			assert.equal(upgraded.status, 400, 'once private_key_jwt is permitted, that link reauthorizes');
			assert.match(upgraded.body.error_description, /bound to a different client authentication method/);
			for (const unknown of ['p3-future', 'bare-uuid-family']) {
				const res = await refresh(legacy(unknown, 'public-1'), { client_id: 'public-1' }, DEFAULT);
				assert.equal(res.status, 400);
				assert.match(res.body.error_description, /predates provenance tracking/);
				assert.equal(families.get(unknown).revoked, true);
			}
		});

		it('ChatGPT grants bound to none need reauthorization once private_key_jwt is permitted', async () => {
			served[CHATGPT_CLIENT_ID] = CHATGPT_CIMD_DOCUMENT;
			const { token, hash } = makeRefreshToken(`${BOUND_FAMILY_ID_PREFIX}chatgpt-none`);
			families.set(`${BOUND_FAMILY_ID_PREFIX}chatgpt-none`, {
				family_id: `${BOUND_FAMILY_ID_PREFIX}chatgpt-none`,
				current_token_hash: hash,
				revoked: false,
				client_id: CHATGPT_CLIENT_ID,
				user: 'alice',
				resource: RESOURCE,
				expires_at: Math.floor(Date.now() / 1000) + 3600,
				client_auth_method: 'none',
			});
			// Permitted private_key_jwt now: presenting none is an authentication error...
			assertInvalidClient(await refresh(token, { client_id: CHATGPT_CLIENT_ID }, SETTING_ON), /client_assertion/);
			// ...and presenting the assertion does not satisfy the grant's binding.
			served[CHATGPT_JWKS_URI] = { keys: [KEY_1.jwk] };
			const withKey = await refresh(
				token,
				{
					client_id: CHATGPT_CLIENT_ID,
					client_assertion: signAssertion({ claims: { iss: CHATGPT_CLIENT_ID, sub: CHATGPT_CLIENT_ID } }),
					client_assertion_type: TYPE,
				},
				SETTING_ON
			);
			assert.equal(withKey.status, 400);
			assert.match(withKey.body.error_description, /bound to a different client authentication method/);
			// Under the configuration it was issued with, it still refreshes.
			assert.equal((await refresh(token, { client_id: CHATGPT_CLIENT_ID }, DEFAULT)).status, 200);
		});

		it('a stored secret client still authenticates after registration is disabled; discovery agrees', async () => {
			const noDcr = { ...DEFAULT, dynamicClientRegistration: { enabled: false } };
			const withDcr = { ...DEFAULT, dynamicClientRegistration: {} };
			seedCode('code-conf', 'conf-1', REDIRECT, 'client_secret_basic');
			const minted = await exchange(
				{ redirect_uri: REDIRECT },
				{ headers: basic('conf-1', 'conf-secret'), config: noDcr, code: 'code-conf' }
			);
			assert.equal(minted.status, 200, JSON.stringify(minted.body));
			const refreshed = await handleToken(
				{ headers: basic('conf-1', 'conf-secret') },
				{ grant_type: 'refresh_token', refresh_token: minted.body.refresh_token },
				noDcr,
				undefined,
				logger
			);
			assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
			const off = await buildAuthorizationServerMetadata({ headers: {} }, noDcr);
			const on = await buildAuthorizationServerMetadata({ headers: {} }, withDcr);
			assert.ok(off.token_endpoint_auth_methods_supported.includes('client_secret_basic'));
			assert.deepEqual(off.token_endpoint_auth_methods_supported, on.token_endpoint_auth_methods_supported);
			assert.equal(off.registration_endpoint, undefined);
			assert.ok(on.registration_endpoint);
		});
	});
});
