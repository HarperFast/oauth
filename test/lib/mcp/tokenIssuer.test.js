/**
 * Tests for the MCP access-token issuer (sign / verify / JWK serialization).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import {
	signAccessToken,
	verifyAccessToken,
	verifyAccessTokenWithKeySet,
	publicKeyToJwk,
} from '../../../dist/lib/mcp/tokenIssuer.js';
import { SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
	modulusLength: 2048,
	publicKeyEncoding: { type: 'spki', format: 'pem' },
	privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const key = {
	kid: SIGNING_KEY_ID,
	alg: 'RS256',
	public_key_pem: publicKey,
	private_key_pem: privateKey,
	created_at: 1700000000,
};

const baseParams = {
	issuer: 'https://as.example.com',
	subject: 'alice@example.com',
	audience: 'https://app.example.com/mcp',
	clientId: 'client-123',
	scope: 'mcp:read',
	ttlSeconds: 3600,
};

describe('tokenIssuer', () => {
	it('signs and verifies an access token with the expected claims', () => {
		const { token, jti } = signAccessToken(baseParams, key);
		const claims = verifyAccessToken(token, key.public_key_pem, {
			audience: baseParams.audience,
			issuer: baseParams.issuer,
		});
		assert.equal(claims.iss, baseParams.issuer);
		assert.equal(claims.sub, baseParams.subject);
		assert.equal(claims.aud, baseParams.audience);
		assert.equal(claims.client_id, baseParams.clientId);
		assert.equal(claims.scope, baseParams.scope);
		assert.ok(claims.jti, 'jti present');
		assert.equal(claims.jti, jti, 'returned jti matches the JWT claim');
		assert.ok(claims.exp > claims.iat, 'exp after iat');
		assert.equal(claims.exp - claims.iat, 3600, 'exp derived from ttlSeconds');
	});

	it('puts the kid and RS256 alg in the JWT header', () => {
		const { token } = signAccessToken(baseParams, key);
		const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
		assert.equal(header.kid, SIGNING_KEY_ID);
		assert.equal(header.alg, 'RS256');
	});

	it('rejects a token verified against the wrong audience (RFC 8707 binding)', () => {
		const { token } = signAccessToken(baseParams, key);
		assert.throws(() => verifyAccessToken(token, key.public_key_pem, { audience: 'https://evil.example.com/mcp' }));
	});

	it('rejects a token verified against the wrong issuer', () => {
		const { token } = signAccessToken(baseParams, key);
		assert.throws(() => verifyAccessToken(token, key.public_key_pem, { issuer: 'https://evil.example.com' }));
	});

	it('omits scope when none is requested', () => {
		const { scope, ...noScope } = baseParams;
		void scope;
		const { token } = signAccessToken(noScope, key);
		const claims = verifyAccessToken(token, key.public_key_pem);
		assert.equal(claims.scope, undefined);
	});

	it('uses the caller-supplied jti when provided', () => {
		const { token, jti } = signAccessToken({ ...baseParams, jti: 'my-custom-jti' }, key);
		assert.equal(jti, 'my-custom-jti', 'returned jti matches the supplied value');
		const claims = verifyAccessToken(token, key.public_key_pem);
		assert.equal(claims.jti, 'my-custom-jti', 'JWT jti claim matches the supplied value');
	});

	it('serializes an RSA public key to a JWK with kid/use/alg', () => {
		const jwk = publicKeyToJwk(key.public_key_pem, key.kid);
		assert.equal(jwk.kty, 'RSA');
		assert.ok(jwk.n, 'modulus present');
		assert.equal(jwk.e, 'AQAB', 'standard RSA public exponent (65537)');
		assert.equal(jwk.use, 'sig');
		assert.equal(jwk.alg, 'RS256');
		assert.equal(jwk.kid, SIGNING_KEY_ID);
		assert.equal(jwk.d, undefined, 'private exponent must NOT be present');
	});
});

function makeRsaKey(kid) {
	const { publicKey, privateKey } = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	return { kid, alg: 'RS256', public_key_pem: publicKey, private_key_pem: privateKey, created_at: 1700000000 };
}

describe('verifyAccessTokenWithKeySet', () => {
	it('selects the key by kid and verifies aud + iss', () => {
		const { token } = signAccessToken(baseParams, key);
		const claims = verifyAccessTokenWithKeySet(token, [makeRsaKey('unrelated'), key], {
			audience: baseParams.audience,
			issuer: baseParams.issuer,
		});
		assert.equal(claims.sub, baseParams.subject);
		assert.equal(claims.client_id, baseParams.clientId);
	});

	it('throws on an empty key set', () => {
		const { token } = signAccessToken(baseParams, key);
		assert.throws(
			() => verifyAccessTokenWithKeySet(token, [], { audience: baseParams.audience, issuer: baseParams.issuer }),
			/no signing keys/
		);
	});

	it('throws on an unknown kid rather than falling back to another key', () => {
		// Signed with `key` (kid SIGNING_KEY_ID) but that kid is absent from the set.
		const { token } = signAccessToken(baseParams, key);
		assert.throws(
			() =>
				verifyAccessTokenWithKeySet(token, [makeRsaKey('different-kid')], {
					audience: baseParams.audience,
					issuer: baseParams.issuer,
				}),
			/unknown key id/
		);
	});

	it('uses the sole key when the token carries no kid', () => {
		// signAccessToken always sets a kid, so craft a no-kid token directly.
		const token = jwt.sign({ client_id: 'c' }, key.private_key_pem, {
			algorithm: 'RS256',
			issuer: baseParams.issuer,
			audience: baseParams.audience,
			subject: baseParams.subject,
		});
		const claims = verifyAccessTokenWithKeySet(token, [key], {
			audience: baseParams.audience,
			issuer: baseParams.issuer,
		});
		assert.equal(claims.sub, baseParams.subject);
	});

	it('throws when no kid and the set is ambiguous (>1 key)', () => {
		const token = jwt.sign({ client_id: 'c' }, key.private_key_pem, {
			algorithm: 'RS256',
			issuer: baseParams.issuer,
			audience: baseParams.audience,
			subject: baseParams.subject,
		});
		assert.throws(
			() =>
				verifyAccessTokenWithKeySet(token, [key, makeRsaKey('second')], {
					audience: baseParams.audience,
					issuer: baseParams.issuer,
				}),
			/key id required/
		);
	});

	it('throws on a malformed token', () => {
		assert.throws(
			() =>
				verifyAccessTokenWithKeySet('not-a-jwt', [key], { audience: baseParams.audience, issuer: baseParams.issuer }),
			/malformed token/
		);
	});
});

function makeEcKey(kid) {
	const { publicKey, privateKey } = generateKeyPairSync('ec', {
		namedCurve: 'P-256',
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	return { kid, alg: 'ES256', public_key_pem: publicKey, private_key_pem: privateKey, created_at: 1700000000 };
}

describe('tokenIssuer ES256', () => {
	const ecKey = makeEcKey('ec-key-1');

	it('signs and verifies an ES256 access token with the expected claims', () => {
		const { token, jti } = signAccessToken(baseParams, ecKey);
		const claims = verifyAccessToken(token, ecKey.public_key_pem, {
			audience: baseParams.audience,
			issuer: baseParams.issuer,
		});
		assert.equal(claims.sub, baseParams.subject);
		assert.equal(claims.client_id, baseParams.clientId);
		assert.equal(claims.jti, jti);
	});

	it('puts the kid and ES256 alg in the JWT header', () => {
		const { token } = signAccessToken(baseParams, ecKey);
		const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
		assert.equal(header.kid, 'ec-key-1');
		assert.equal(header.alg, 'ES256');
	});

	it('throws on a key record with an unsupported alg', () => {
		assert.throws(() => signAccessToken(baseParams, { ...ecKey, alg: 'EdDSA' }), /unsupported signing algorithm/);
	});

	it('serializes an EC public key to a JWK with crv/x/y and no private material', () => {
		const jwk = publicKeyToJwk(ecKey.public_key_pem, ecKey.kid, ecKey.alg);
		assert.equal(jwk.kty, 'EC');
		assert.equal(jwk.crv, 'P-256');
		assert.ok(jwk.x, 'x coordinate present');
		assert.ok(jwk.y, 'y coordinate present');
		assert.equal(jwk.n, undefined, 'no RSA modulus on an EC JWK');
		assert.equal(jwk.alg, 'ES256');
		assert.equal(jwk.use, 'sig');
		assert.equal(jwk.kid, 'ec-key-1');
		assert.equal(jwk.d, undefined, 'private scalar must NOT be present');
	});

	it('verifies against a mixed RS256/ES256 key set by kid', () => {
		const { token } = signAccessToken(baseParams, ecKey);
		const claims = verifyAccessTokenWithKeySet(token, [key, makeRsaKey('other-rsa'), ecKey], {
			audience: baseParams.audience,
			issuer: baseParams.issuer,
		});
		assert.equal(claims.sub, baseParams.subject);
	});

	it("rejects a token whose header alg does not match the selected key's declared alg", () => {
		// Signed ES256, but the key record in the set (same kid) claims RS256 —
		// verification must pin to the declared alg and fail.
		const { token } = signAccessToken(baseParams, ecKey);
		assert.throws(() =>
			verifyAccessTokenWithKeySet(token, [{ ...ecKey, alg: 'RS256' }], {
				audience: baseParams.audience,
				issuer: baseParams.issuer,
			})
		);
	});
});
