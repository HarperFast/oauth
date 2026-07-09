/**
 * Tests for verifyClientAssertion (RFC 7523 §3 private_key_jwt, EdDSA-only).
 *
 * Assertions are built by hand (base64url + node:crypto sign) rather than via
 * a JWT library so the tests can produce every malformed shape the verifier
 * must reject.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as signRaw } from 'node:crypto';
import { verifyClientAssertion, CLIENT_ASSERTION_TYPE_JWT_BEARER } from '../../../dist/lib/mcp/clientAssertion.js';

const CLIENT_ID = 'agent-client-1';
const TOKEN_ENDPOINT = 'https://mcp.example.com/oauth/mcp/token';

function makeKeyPair() {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	return { privateKey, jwk: publicKey.export({ format: 'jwk' }) };
}

function b64url(value) {
	return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
}

function nowSeconds() {
	return Math.floor(Date.now() / 1000);
}

function defaultPayload(overrides = {}) {
	const now = nowSeconds();
	return {
		iss: CLIENT_ID,
		sub: CLIENT_ID,
		aud: TOKEN_ENDPOINT,
		exp: now + 30,
		iat: now,
		jti: `jti-${Math.random().toString(36).slice(2)}`,
		...overrides,
	};
}

/** Build and sign an assertion, allowing every part to be overridden. */
function makeAssertion({ header = { alg: 'EdDSA' }, payload = defaultPayload(), privateKey, rawSignature } = {}) {
	const h = b64url(header);
	const p = b64url(payload);
	const sig = rawSignature ?? signRaw(null, Buffer.from(`${h}.${p}`), privateKey).toString('base64url');
	return `${h}.${p}.${sig}`;
}

function verify(assertion, jwks, extra = {}) {
	return verifyClientAssertion({
		assertion,
		clientId: CLIENT_ID,
		tokenEndpoint: TOKEN_ENDPOINT,
		jwks,
		...extra,
	});
}

describe('verifyClientAssertion', () => {
	describe('success paths', () => {
		it('verifies a well-formed EdDSA assertion and returns its claims', () => {
			const { privateKey, jwk } = makeKeyPair();
			const payload = defaultPayload();
			const result = verify(makeAssertion({ privateKey, payload }), [jwk]);
			assert.equal(result.valid, true);
			assert.equal(result.claims.iss, CLIENT_ID);
			assert.equal(result.claims.sub, CLIENT_ID);
			assert.equal(result.claims.aud, TOKEN_ENDPOINT);
			assert.equal(result.claims.jti, payload.jti);
			assert.equal(result.claims.exp, payload.exp);
			assert.equal(result.claims.iat, payload.iat);
		});

		it('accepts aud as a single-element array (RFC 7519), unwrapping it', () => {
			const { privateKey, jwk } = makeKeyPair();
			const payload = defaultPayload({ aud: [TOKEN_ENDPOINT] });
			const result = verify(makeAssertion({ privateKey, payload }), [jwk]);
			assert.equal(result.valid, true);
			assert.equal(result.claims.aud, TOKEN_ENDPOINT);
		});

		it('accepts typ: JWT case-insensitively and a passed nbf', () => {
			const { privateKey, jwk } = makeKeyPair();
			const payload = defaultPayload({ nbf: nowSeconds() - 10 });
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', typ: 'jwt' }, privateKey, payload }), [jwk]);
			assert.equal(result.valid, true);
		});

		it('selects the right key by kid among multiple registered keys', () => {
			const other = makeKeyPair();
			const { privateKey, jwk } = makeKeyPair();
			const keys = [
				{ ...other.jwk, kid: 'key-a' },
				{ ...jwk, kid: 'key-b' },
			];
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', kid: 'key-b' }, privateKey }), keys);
			assert.equal(result.valid, true);
		});

		it('exports the RFC 7523 client_assertion_type URN', () => {
			assert.equal(CLIENT_ASSERTION_TYPE_JWT_BEARER, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
		});
	});

	describe('structure and header', () => {
		it('rejects empty, non-JWT, and two-segment inputs', () => {
			const { jwk } = makeKeyPair();
			for (const bad of ['', 'not-a-jwt', 'aaaa.bbbb', 'a.b.c.d']) {
				const result = verify(bad, [jwk]);
				assert.equal(result.valid, false, `expected rejection for ${JSON.stringify(bad)}`);
			}
		});

		it('rejects an assertion over the 8KB length cap before any decode work', () => {
			const { privateKey, jwk } = makeKeyPair();
			const good = makeAssertion({ privateKey });
			const oversized = good + 'A'.repeat(8192);
			const result = verify(oversized, [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /maximum allowed length/);
		});

		it('rejects base64url segments containing invalid characters', () => {
			const { privateKey, jwk } = makeKeyPair();
			const good = makeAssertion({ privateKey });
			const [h, p, s] = good.split('.');
			const result = verify(`${h}.${p}+.${s}`, [jwk]);
			assert.equal(result.valid, false);
		});

		it('rejects alg: none even with an empty signature', () => {
			const { jwk } = makeKeyPair();
			const assertion = `${b64url({ alg: 'none' })}.${b64url(defaultPayload())}.`;
			const result = verify(assertion, [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /alg must be EdDSA/);
		});

		it('rejects any non-EdDSA alg before doing key work (no RS/HS confusion)', () => {
			const { privateKey, jwk } = makeKeyPair();
			for (const alg of ['RS256', 'HS256', 'ES256', 'EDDSA', 'eddsa']) {
				const result = verify(makeAssertion({ header: { alg }, privateKey }), [jwk]);
				assert.equal(result.valid, false, `expected rejection for alg ${alg}`);
				assert.match(result.reason, /alg must be EdDSA/);
			}
		});

		it('rejects a typ other than JWT', () => {
			const { privateKey, jwk } = makeKeyPair();
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', typ: 'JOSE' }, privateKey }), [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /typ must be JWT/);
		});

		it('rejects assertions carrying crit extensions', () => {
			const { privateKey, jwk } = makeKeyPair();
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', crit: ['exp'] }, privateKey }), [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /crit/);
		});
	});

	describe('key selection and key material', () => {
		it('rejects when the client has no registered keys', () => {
			const { privateKey } = makeKeyPair();
			for (const jwks of [[], undefined, null]) {
				const result = verify(makeAssertion({ privateKey }), jwks);
				assert.equal(result.valid, false);
			}
		});

		it('requires kid when multiple keys are registered', () => {
			const a = makeKeyPair();
			const b = makeKeyPair();
			const result = verify(makeAssertion({ privateKey: a.privateKey }), [a.jwk, b.jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /kid is required/);
		});

		it('rejects an unknown kid instead of falling back to other keys', () => {
			const { privateKey, jwk } = makeKeyPair();
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', kid: 'nope' }, privateKey }), [
				{ ...jwk, kid: 'key-a' },
			]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /does not match exactly one/);
		});

		it('rejects a kid that matches more than one registered key', () => {
			const a = makeKeyPair();
			const b = makeKeyPair();
			const keys = [
				{ ...a.jwk, kid: 'dup' },
				{ ...b.jwk, kid: 'dup' },
			];
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', kid: 'dup' }, privateKey: a.privateKey }), keys);
			assert.equal(result.valid, false);
		});

		it('rejects a registered JWK carrying private material (d)', () => {
			const { privateKey, jwk } = makeKeyPair();
			const withPrivate = { ...jwk, d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
			const result = verify(makeAssertion({ privateKey }), [withPrivate]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /not a public Ed25519 key/);
		});

		it('rejects null/primitive JWK Set entries without throwing (never-throws contract)', () => {
			const { privateKey, jwk } = makeKeyPair();
			// Single-entry sets on the no-kid path.
			for (const entry of [null, 42, 'key']) {
				const result = verify(makeAssertion({ privateKey }), [entry]);
				assert.equal(result.valid, false, `expected rejection for single entry ${JSON.stringify(entry)}`);
			}
			// Mixed sets on the kid path: the null entry must not throw during selection.
			const result = verify(makeAssertion({ header: { alg: 'EdDSA', kid: 'key-a' }, privateKey }), [
				null,
				{ ...jwk, kid: 'key-a' },
			]);
			assert.equal(result.valid, true);
		});

		it('rejects non-OKP and non-Ed25519 JWKs', () => {
			const { privateKey } = makeKeyPair();
			for (const jwk of [
				{ kty: 'RSA', n: 'abc', e: 'AQAB' },
				{ kty: 'OKP', crv: 'X25519', x: 'abc' },
				{ kty: 'OKP', crv: 'Ed25519' }, // missing x
				{ kty: 'OKP', crv: 'Ed25519', x: 'not!valid!base64url!!!' },
			]) {
				const result = verify(makeAssertion({ privateKey }), [jwk]);
				assert.equal(result.valid, false, `expected rejection for ${JSON.stringify(jwk)}`);
			}
		});
	});

	describe('signature', () => {
		it('rejects a signature from a different key', () => {
			const attacker = makeKeyPair();
			const { jwk } = makeKeyPair();
			const result = verify(makeAssertion({ privateKey: attacker.privateKey }), [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /signature verification failed/);
		});

		it('rejects a tampered payload', () => {
			const { privateKey, jwk } = makeKeyPair();
			const good = makeAssertion({ privateKey });
			const [h, , s] = good.split('.');
			const tampered = `${h}.${b64url(defaultPayload({ sub: 'someone-else' }))}.${s}`;
			const result = verify(tampered, [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /signature verification failed/);
		});

		it('rejects a signature that is not 64 bytes', () => {
			const { privateKey, jwk } = makeKeyPair();
			const result = verify(makeAssertion({ privateKey, rawSignature: b64url('short') }), [jwk]);
			assert.equal(result.valid, false);
			assert.match(result.reason, /signature is malformed/);
		});
	});

	describe('claims', () => {
		function rejectPayload(payload, reasonPattern, extra = {}) {
			const { privateKey, jwk } = makeKeyPair();
			const result = verify(makeAssertion({ privateKey, payload }), [jwk], extra);
			assert.equal(result.valid, false, `expected rejection for ${JSON.stringify(payload)}`);
			assert.match(result.reason, reasonPattern);
		}

		it('rejects iss/sub not matching client_id (RFC 7523: iss = sub = client_id)', () => {
			rejectPayload(defaultPayload({ iss: 'other' }), /iss does not match/);
			rejectPayload(defaultPayload({ sub: 'other' }), /sub does not match/);
			rejectPayload(defaultPayload({ iss: undefined }), /iss does not match/);
		});

		it('rejects aud mismatches, multi-audience arrays, and non-strings', () => {
			rejectPayload(defaultPayload({ aud: 'https://evil.example.com/token' }), /aud does not match/);
			rejectPayload(defaultPayload({ aud: [TOKEN_ENDPOINT, 'https://other.example.com'] }), /aud does not match/);
			rejectPayload(defaultPayload({ aud: [] }), /aud does not match/);
			rejectPayload(defaultPayload({ aud: undefined }), /aud does not match/);
			// Prefix of the real endpoint must not pass (no prefix matching).
			rejectPayload(defaultPayload({ aud: 'https://mcp.example.com/oauth/mcp' }), /aud does not match/);
		});

		it('rejects missing or expired exp', () => {
			rejectPayload(defaultPayload({ exp: undefined }), /exp is required/);
			rejectPayload(defaultPayload({ exp: 'soon' }), /exp is required/);
			rejectPayload(defaultPayload({ exp: nowSeconds() - 30 }), /has expired/);
		});

		it('rejects exp beyond the maximum window (default 60s)', () => {
			rejectPayload(defaultPayload({ exp: nowSeconds() + 300 }), /exceeds the maximum window/);
		});

		it('rejects an over-long self-declared lifetime (old iat, near-now exp)', () => {
			// exp is inside the now-relative window, but exp - iat advertises a
			// far-longer lifetime than the policy allows — strict verifier refuses it.
			rejectPayload(defaultPayload({ iat: nowSeconds() - 3600, exp: nowSeconds() + 30 }), /lifetime .* exceeds/);
		});

		it('honors a custom maxExpiresInSeconds', () => {
			rejectPayload(defaultPayload({ exp: nowSeconds() + 25 }), /exceeds the maximum window/, {
				maxExpiresInSeconds: 10,
				clockToleranceSeconds: 0,
			});
		});

		it('does not fail open when window options are NaN/Infinity/negative (falls back to defaults)', () => {
			const { privateKey, jwk } = makeKeyPair();
			const farFuture = () => defaultPayload({ exp: nowSeconds() + 3600 });
			const expired = () => defaultPayload({ exp: nowSeconds() - 3600, iat: nowSeconds() - 3630 });
			// A poisoned maxExpiresInSeconds must not let a far-future exp through.
			for (const bad of [NaN, Infinity, -Infinity, -5, 0]) {
				const result = verify(makeAssertion({ privateKey, payload: farFuture() }), [jwk], {
					maxExpiresInSeconds: bad,
				});
				assert.equal(result.valid, false, `far-future exp accepted with maxExpiresInSeconds=${bad}`);
				assert.match(result.reason, /exceeds the maximum window/);
			}
			// A poisoned clockToleranceSeconds must not let an expired assertion through.
			for (const bad of [NaN, Infinity, -1]) {
				const result = verify(makeAssertion({ privateKey, payload: expired() }), [jwk], {
					clockToleranceSeconds: bad,
				});
				assert.equal(result.valid, false, `expired assertion accepted with clockToleranceSeconds=${bad}`);
				assert.match(result.reason, /has expired/);
			}
		});

		it('accepts config-shaped numeric strings for the window options', () => {
			const { privateKey, jwk } = makeKeyPair();
			// exp within a string "10" window but tolerance "0" — mirrors YAML/${ENV} config.
			const result = verify(makeAssertion({ privateKey, payload: defaultPayload({ exp: nowSeconds() + 5 }) }), [jwk], {
				maxExpiresInSeconds: '10',
				clockToleranceSeconds: '0',
			});
			assert.equal(result.valid, true);
			// And the string window is still enforced as a bound.
			const tooFar = verify(makeAssertion({ privateKey, payload: defaultPayload({ exp: nowSeconds() + 25 }) }), [jwk], {
				maxExpiresInSeconds: '10',
				clockToleranceSeconds: '0',
			});
			assert.equal(tooFar.valid, false);
			assert.match(tooFar.reason, /exceeds the maximum window/);
		});

		it('rejects missing or future iat', () => {
			rejectPayload(defaultPayload({ iat: undefined }), /iat is required/);
			rejectPayload(defaultPayload({ iat: nowSeconds() + 120 }), /iat is in the future/);
		});

		it('rejects a future nbf', () => {
			rejectPayload(defaultPayload({ nbf: nowSeconds() + 120 }), /not yet valid/);
			rejectPayload(defaultPayload({ nbf: 'later' }), /nbf is invalid/);
		});

		it('rejects a missing, empty, or non-string jti as required', () => {
			rejectPayload(defaultPayload({ jti: undefined }), /jti is required/);
			rejectPayload(defaultPayload({ jti: '' }), /jti is required/);
			rejectPayload(defaultPayload({ jti: 42 }), /jti is required/);
		});

		it('rejects an oversized jti with a length-specific message (not "required")', () => {
			rejectPayload(defaultPayload({ jti: 'x'.repeat(257) }), /jti exceeds the maximum length/);
		});
	});
});
