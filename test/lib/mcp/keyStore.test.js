/**
 * Tests for MCPKeyStore — first-boot generation, reuse, config-provided keys,
 * multi-key JWKS publication, signing-key rotation, GC, and legacy compat.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { MCPKeyStore, resetMCPKeysTableCache, SIGNING_KEY_ID } from '../../../dist/lib/mcp/keyStore.js';
import { verifyAccessTokenWithKeySet, signAccessToken } from '../../../dist/lib/mcp/tokenIssuer.js';

// ---- Helpers ----

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

/** Build a minimal mock keys table backed by a Map. */
function makeKeysTable(stored) {
	return {
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
		// Async generator that yields all stored rows.
		search: async function* () {
			for (const rec of stored.values()) {
				yield asTrackedObject(rec);
			}
		},
	};
}

/** Pre-seed a keypair record into the stored map, returns the record. */
function seedKey(stored, overrides = {}) {
	const { privateKey, publicKey } = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	const rec = {
		kid: SIGNING_KEY_ID,
		alg: 'RS256',
		public_key_pem: publicKey,
		private_key_pem: privateKey,
		created_at: Math.floor(Date.now() / 1000),
		...overrides,
	};
	stored.set(rec.kid, rec);
	return rec;
}

// ---- Suite ----

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
				harper_oauth_mcp_keys: makeKeysTable(stored),
			},
		};
	});

	// ---- Existing behavior (updated for enumeration) ----

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

	it('reuses the persisted key on subsequent calls', async () => {
		const first = await store.getSigningKey();
		resetMCPKeysTableCache();
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

	// ---- Multi-key: two keys in table ----

	it('getAllPublicKeys returns all persisted keys', async () => {
		const oldKey = seedKey(stored, { kid: 'key-old', created_at: 1_000_000 });
		const newKey = seedKey(stored, { kid: 'key-new', created_at: 2_000_000 });
		const keys = await store.getAllPublicKeys();
		assert.equal(keys.length, 2, 'both keys published');
		const kids = keys.map((k) => k.kid).sort();
		assert.deepEqual(kids, [oldKey.kid, newKey.kid].sort());
	});

	it('selects the newest key as signer when two keys exist', async () => {
		seedKey(stored, { kid: 'key-old', created_at: 1_000_000 });
		const newKey = seedKey(stored, { kid: 'key-new', created_at: 2_000_000 });
		const signer = await store.getSigningKey();
		assert.equal(signer.kid, newKey.kid, 'newest key is the signer');
	});

	it('tie-breaks on kid descending when created_at is equal', async () => {
		const ts = Math.floor(Date.now() / 1000);
		seedKey(stored, { kid: 'aaa', created_at: ts });
		seedKey(stored, { kid: 'zzz', created_at: ts });
		const signer = await store.getSigningKey();
		assert.equal(signer.kid, 'zzz', 'lexicographically larger kid wins tie-break');
	});

	// ---- Rotation ----

	it('does NOT rotate when keyRotationInterval is unset (default: no rotation)', async () => {
		const original = seedKey(stored, { kid: 'original', created_at: 1_000_000 });
		const signer = await store.getSigningKey({ accessTokenTtl: 3600 });
		assert.equal(signer.kid, original.kid, 'original key is still the signer');
		assert.equal(stored.size, 1, 'no new key generated');
	});

	it('does NOT rotate when keyRotationInterval is 0', async () => {
		seedKey(stored, { kid: 'original', created_at: 1_000_000 });
		await store.getSigningKey({ keyRotationInterval: 0, accessTokenTtl: 3600 });
		assert.equal(stored.size, 1, 'no rotation when interval is 0');
	});

	it('rotates when the newest key is older than keyRotationInterval', async () => {
		const veryOldTs = Math.floor(Date.now() / 1000) - 10_000;
		seedKey(stored, { kid: 'old-key', created_at: veryOldTs });

		const signer = await store.getSigningKey({ keyRotationInterval: 60, accessTokenTtl: 3600 });
		assert.notEqual(signer.kid, 'old-key', 'a new key was generated');
		assert.equal(stored.size, 2, 'old key retained for JWKS overlap; new key added');
	});

	it('JWKS publishes both old and new key during rotation overlap', async () => {
		const veryOldTs = Math.floor(Date.now() / 1000) - 10_000;
		seedKey(stored, { kid: 'old-key', created_at: veryOldTs });

		await store.getSigningKey({ keyRotationInterval: 60, accessTokenTtl: 3600 });

		const allKeys = await store.getAllPublicKeys();
		assert.equal(allKeys.length, 2, 'both keys published during overlap window');
		const kids = allKeys.map((k) => k.kid);
		assert.ok(kids.includes('old-key'), 'old key still in JWKS');
	});

	it('a token signed by the old key still verifies against the full key set after rotation', async () => {
		const veryOldTs = Math.floor(Date.now() / 1000) - 10_000;
		const oldKey = seedKey(stored, { kid: 'old-key', created_at: veryOldTs });

		// Sign with the old key.
		const { token } = signAccessToken(
			{
				issuer: 'https://as.example.com',
				subject: 'alice',
				audience: 'https://app.example.com/mcp',
				clientId: 'client-1',
				ttlSeconds: 3600,
			},
			oldKey
		);

		// Rotate.
		await store.getSigningKey({ keyRotationInterval: 60, accessTokenTtl: 3600 });

		// Build the current JWKS (includes both keys).
		const allKeys = await store.getAllPublicKeys();

		// Old token MUST still verify against the full key set.
		assert.doesNotThrow(() =>
			verifyAccessTokenWithKeySet(token, allKeys, {
				audience: 'https://app.example.com/mcp',
				issuer: 'https://as.example.com',
			})
		);
	});

	it('does NOT rotate when the key is fresh (age < interval)', async () => {
		const recentTs = Math.floor(Date.now() / 1000) - 30;
		seedKey(stored, { kid: 'fresh-key', created_at: recentTs });

		const signer = await store.getSigningKey({ keyRotationInterval: 3600, accessTokenTtl: 3600 });
		assert.equal(signer.kid, 'fresh-key', 'fresh key is still the signer');
		assert.equal(stored.size, 1, 'no rotation when key is still fresh');
	});

	// ---- Pin wins ----

	it('pin wins on first boot: signingKeyPem is used to generate the first key', async () => {
		// Empty table — signingKeyPem is used for the first-boot key.
		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});

		const signer = await store.getSigningKey({
			signingKeyPem: privateKey,
			accessTokenTtl: 3600,
		});

		assert.equal(stored.size, 1, 'exactly one key persisted');
		assert.equal(signer.kid, SIGNING_KEY_ID, 'pinned key stored under legacy kid');
		assert.equal(signer.private_key_pem, privateKey, 'pinned key is the signer');
	});

	it('pin wins over rotation: signingKeyPem prevents rotation even with keyRotationInterval set', async () => {
		// Seed an aged key that would normally trigger rotation.
		const veryOldKey = seedKey(stored, { kid: 'old-key', created_at: 1_000_000 });

		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});

		await store.getSigningKey({
			signingKeyPem: privateKey,
			keyRotationInterval: 1, // would rotate if not pinned
			accessTokenTtl: 3600,
		});

		// No rotation key should have been added — pin skips the rotation path.
		assert.equal(stored.size, 1, 'no rotation key generated when pinned');
		// The existing key is still the signer (pin doesn't overwrite existing keys).
		assert.ok(stored.has(veryOldKey.kid), 'original key unchanged');
	});

	// ---- GC ----

	it('GC deletes a retired key once superseded time > 2× accessTokenTtl', async () => {
		// New key was created 8000 seconds ago (2× 3600 = 7200 — GC threshold passed).
		const nowSeconds = Math.floor(Date.now() / 1000);
		const newKeyTs = nowSeconds - 8_000;
		// Old key (superseded by newKey) — its exact age doesn't matter for GC;
		// what matters is how long ago newKey was created (newKey.created_at).
		seedKey(stored, { kid: 'retired-key', created_at: newKeyTs - 1_000 });
		seedKey(stored, { kid: 'current-key', created_at: newKeyTs });

		// No rotation needed (key is old but we're not rotating in this test).
		// getSigningKey selects newest (current-key) and GC fires asynchronously.
		await store.getSigningKey({ accessTokenTtl: 3600 });

		// Wait for GC microtask to complete.
		await new Promise((resolve) => setImmediate(resolve));

		assert.ok(!stored.has('retired-key'), 'retired key was GCd');
		assert.ok(stored.has('current-key'), 'current signer was preserved');
	});

	it('GC does NOT delete a retired key when superseded time < 2× accessTokenTtl', async () => {
		// New key was created only 100 seconds ago — well within the 7200s window.
		const nowSeconds = Math.floor(Date.now() / 1000);
		const newKeyTs = nowSeconds - 100;
		seedKey(stored, { kid: 'still-needed', created_at: newKeyTs - 5_000 });
		seedKey(stored, { kid: 'current-key', created_at: newKeyTs });

		await store.getSigningKey({ accessTokenTtl: 3600 });
		await new Promise((resolve) => setImmediate(resolve));

		assert.ok(stored.has('still-needed'), 'recently superseded key NOT deleted');
		assert.ok(stored.has('current-key'));
	});

	it('GC never deletes the current signer', async () => {
		// Only one key — nothing to GC.
		const nowSeconds = Math.floor(Date.now() / 1000);
		seedKey(stored, { kid: 'sole-key', created_at: nowSeconds - 100_000 });

		await store.getSigningKey({ accessTokenTtl: 1 }); // tiny TTL — would GC anything deletable
		await new Promise((resolve) => setImmediate(resolve));

		assert.ok(stored.has('sole-key'), 'sole signer never GCd');
	});

	it('GC error does not block minting (returns key despite GC failure)', async () => {
		const nowSeconds = Math.floor(Date.now() / 1000);
		// Superseded long enough ago to trigger GC.
		seedKey(stored, { kid: 'retired', created_at: nowSeconds - 20_000 });
		const currentKey = seedKey(stored, { kid: 'current', created_at: nowSeconds - 8_000 });

		// Make delete throw.
		global.databases.oauth.harper_oauth_mcp_keys.delete = async () => {
			throw new Error('simulated delete failure');
		};

		// Should resolve to the current signer without throwing.
		const signer = await store.getSigningKey({ accessTokenTtl: 3600 });
		assert.equal(signer.kid, currentKey.kid, 'minting still works despite GC failure');
	});

	// ---- Legacy compat ----

	it('legacy rs256-default row is honored as signer until rotation adds a newer key', async () => {
		const legacyKey = seedKey(stored, { kid: SIGNING_KEY_ID, created_at: 1_000_000 });

		// No rotation configured.
		const signer = await store.getSigningKey({ accessTokenTtl: 3600 });
		assert.equal(signer.kid, SIGNING_KEY_ID, 'legacy key is the signer');
		assert.equal(signer.public_key_pem, legacyKey.public_key_pem);
	});

	it('legacy rs256-default is superseded by a newer UUID key when one exists', async () => {
		const legacyTs = Math.floor(Date.now() / 1000) - 100;
		const newerTs = Math.floor(Date.now() / 1000) - 10;
		seedKey(stored, { kid: SIGNING_KEY_ID, created_at: legacyTs });
		const newerKey = seedKey(stored, { kid: 'uuid-key', created_at: newerTs });

		const signer = await store.getSigningKey({ accessTokenTtl: 3600 });
		assert.equal(signer.kid, newerKey.kid, 'UUID key supersedes legacy row');
	});
});
