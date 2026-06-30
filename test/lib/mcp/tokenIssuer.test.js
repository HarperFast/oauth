/**
 * Tests for the MCP access-token issuer (sign / verify / JWK serialization).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { signAccessToken, verifyAccessToken, publicKeyToJwk } from '../../../dist/lib/mcp/tokenIssuer.js';
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
