/**
 * Tests for MCPKeyStore — first-boot generation, reuse, config-provided keys,
 * and JWKS publication.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { MCPKeyStore, resetMCPKeysTableCache, SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';

function asTrackedObject(plain) {
	return new Proxy(plain, {
		ownKeys() {
			return [];
		},
		getOwnPropertyDescriptor() {
			return undefined;
		},
	});
}

describe('MCPKeyStore', () => {
	let store;
	let originalDatabases;
	let stored;

	before(() => {
		originalDatabases = global.databases;
	});
	after(() => {
		global.databases = originalDatabases;
	});

	beforeEach(() => {
		resetMCPKeysTableCache();
		store = new MCPKeyStore();
		stored = new Map();
		global.databases = {
			oauth: {
				harper_oauth_mcp_keys: {
					get: async (id) => {
						const raw = stored.get(id);
						return raw ? asTrackedObject(raw) : null;
					},
					put: async (rec) => {
						stored.set(rec.kid, rec);
					},
					delete: async (id) => {
						stored.delete(id);
					},
				},
			},
		};
	});

	it('returns null and an empty JWKS set before any key exists', async () => {
		assert.equal(await store.get(), null);
		assert.deepEqual(await store.getAllPublicKeys(), []);
	});

	it('generates and persists an RS256 keypair on first use', async () => {
		const key = await store.getSigningKey();
		assert.equal(key.kid, SIGNING_KEY_ID);
		assert.equal(key.alg, 'RS256');
		assert.match(key.public_key_pem, /BEGIN PUBLIC KEY/);
		assert.match(key.private_key_pem, /BEGIN PRIVATE KEY/);
		assert.equal(stored.size, 1, 'persisted to the table');
	});

	it('reuses the persisted key on subsequent calls (cached)', async () => {
		const first = await store.getSigningKey();
		resetMCPKeysTableCache(); // drop the in-process cache; force a table read
		const second = await new MCPKeyStore().getSigningKey();
		assert.equal(second.public_key_pem, first.public_key_pem, 'same key reused, not regenerated');
		assert.equal(stored.size, 1);
	});

	it('uses a config-provided signing key instead of generating one', async () => {
		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const key = await store.getSigningKey({ signingKeyPem: privateKey });
		assert.equal(key.private_key_pem, privateKey);
		const expectedPublic = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
		assert.equal(key.public_key_pem, expectedPublic, 'public half derived from the provided private key');
	});

	it('publishes the public key in the JWKS set once a key exists', async () => {
		await store.getSigningKey();
		const keys = await store.getAllPublicKeys();
		assert.equal(keys.length, 1);
		assert.equal(keys[0].kid, SIGNING_KEY_ID);
	});
});
