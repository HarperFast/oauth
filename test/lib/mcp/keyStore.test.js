/**
 * Tests for MCPKeyStore — first-boot generation, reuse, config-provided keys,
 * multi-key JWKS publication, signing-key rotation, GC, and legacy compat.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { MCPKeyStore, resetMCPKeysTableCache, SIGNING_KEY_ID, _setCacheNowMs } from '../../../dist/lib/mcp/keyStore.js';
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

	it('generates and persists an RS256 keypair under a UNIQUE kid on first use', async () => {
		const key = await store.getSigningKey();
		// Generated first-boot keys must NOT share the fixed legacy kid: two nodes
		// racing first boot generate different keypairs, and a shared primary key
		// would let one overwrite the other — stranding the loser's already-signed
		// tokens with a kid whose JWKS entry is a different public key.
		assert.notEqual(key.kid, SIGNING_KEY_ID, 'generated key gets a unique kid, not the legacy fixed kid');
		assert.match(key.kid, /^[0-9a-f-]{36}$/, 'generated kid is a UUID');
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
		const signer = await store.getSigningKey();
		const keys = await store.getAllPublicKeys();
		assert.equal(keys.length, 1);
		assert.equal(keys[0].kid, signer.kid);
	});

	// ---- Multi-key: two keys in table ----

	it('getAllPublicKeys returns all persisted keys (within retirement window)', async () => {
		// Both keys use recent timestamps so neither is retired (successor age < 2×TTL).
		const nowSeconds = Math.floor(Date.now() / 1000);
		const oldKey = seedKey(stored, { kid: 'key-old', created_at: nowSeconds - 100 });
		const newKey = seedKey(stored, { kid: 'key-new', created_at: nowSeconds - 50 });
		const keys = await store.getAllPublicKeys();
		assert.equal(keys.length, 2, 'both keys published within the retirement window');
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

	it('pin wins over rotation: signingKeyPem persists the pinned key and skips rotation', async () => {
		// Seed an aged key that would normally trigger rotation. Note: kid ≠ SIGNING_KEY_ID
		// so SIGNING_KEY_ID is free for the pinned key.
		seedKey(stored, { kid: 'old-key', created_at: 1_000_000 });

		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});

		const signer = await store.getSigningKey({
			signingKeyPem: privateKey,
			keyRotationInterval: 1, // would rotate if not pinned
			accessTokenTtl: 3600,
		});

		// Pinned key was persisted under rs256-default (free because old-key ≠ SIGNING_KEY_ID).
		// No rotation key was generated.
		assert.equal(stored.size, 2, 'pinned key added; old key retained for JWKS overlap');
		assert.ok(stored.has('old-key'), 'old key untouched');
		assert.ok(stored.has(SIGNING_KEY_ID), 'pinned key stored under rs256-default');
		assert.equal(signer.private_key_pem, privateKey, 'pinned key signs');
	});

	it('pin wins after unpinned first boot: pinned PEM is persisted and becomes signer', async () => {
		// An unpinned node already minted a UUID key.
		const { privateKey: existingPrivKey, publicKey: existingPubKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const uuidKid = 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb';
		stored.set(uuidKid, {
			kid: uuidKid,
			alg: 'RS256',
			public_key_pem: existingPubKey,
			private_key_pem: existingPrivKey,
			created_at: Math.floor(Date.now() / 1000) - 60,
		});

		const { privateKey: pinnedPrivKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});

		// Now configure the pin.
		const signer = await store.getSigningKey({ signingKeyPem: pinnedPrivKey, accessTokenTtl: 3600 });

		// Pinned key persisted under rs256-default (UUID key ≠ SIGNING_KEY_ID).
		assert.equal(stored.size, 2, 'pinned key added; UUID key retained for JWKS overlap');
		assert.ok(stored.has(uuidKid), 'UUID key still in table for JWKS overlap');
		assert.ok(stored.has(SIGNING_KEY_ID), 'pinned key stored under rs256-default');
		assert.equal(signer.private_key_pem, pinnedPrivKey, 'pinned key is the signer');

		// A token signed by the UUID key MUST still verify (JWKS overlap window).
		const oldKeyRecord = {
			kid: uuidKid,
			alg: 'RS256',
			public_key_pem: existingPubKey,
			private_key_pem: existingPrivKey,
			created_at: Math.floor(Date.now() / 1000) - 60,
		};
		const { token } = signAccessToken(
			{
				issuer: 'https://as.example.com',
				subject: 'alice',
				audience: 'https://app.example.com/mcp',
				clientId: 'client-1',
				ttlSeconds: 3600,
			},
			oldKeyRecord
		);
		const allKeys = await store.getAllPublicKeys();
		assert.doesNotThrow(() =>
			verifyAccessTokenWithKeySet(token, allKeys, {
				audience: 'https://app.example.com/mcp',
				issuer: 'https://as.example.com',
			})
		);
	});

	it('pin recognized when legacy rs256-default already holds the MATCHING material', async () => {
		// Table already has the pinned key under rs256-default (e.g. configured since first boot).
		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const pinnedPublicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
		stored.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: pinnedPublicKey,
			private_key_pem: privateKey,
			created_at: Math.floor(Date.now() / 1000) - 3600,
		});

		const signer = await store.getSigningKey({ signingKeyPem: privateKey, accessTokenTtl: 3600 });

		// Found by material match — NO new row written.
		assert.equal(stored.size, 1, 'no new row when matching material already exists');
		assert.equal(signer.kid, SIGNING_KEY_ID, 'existing row is the signer');
		assert.equal(signer.private_key_pem, privateKey, 'pinned key signs');
	});

	it('pin while rs256-default holds DIFFERENT material: fingerprint kid used, rs256-default untouched', async () => {
		// rs256-default exists with different (legacy-generated) material.
		const { privateKey: legacyPrivKey, publicKey: legacyPubKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		stored.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: legacyPubKey,
			private_key_pem: legacyPrivKey,
			created_at: Math.floor(Date.now() / 1000) - 3600,
		});

		const { privateKey: pinnedPrivKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});

		const signer = await store.getSigningKey({ signingKeyPem: pinnedPrivKey, accessTokenTtl: 3600 });

		// Pinned key gets a fingerprint kid; rs256-default is untouched.
		assert.equal(stored.size, 2, 'fingerprint kid row added alongside rs256-default');
		assert.ok(stored.has(SIGNING_KEY_ID), 'legacy rs256-default row preserved');
		assert.notEqual(signer.kid, SIGNING_KEY_ID, 'signer is the fingerprint-kid row, not rs256-default');
		assert.ok(signer.kid.startsWith('pinned-'), 'signer kid has the fingerprint prefix');
		assert.equal(signer.private_key_pem, pinnedPrivKey, 'pinned key signs');

		// Determinism: calling again with the same PEM yields the same kid.
		resetMCPKeysTableCache();
		const store2 = new MCPKeyStore();
		const signer2 = await store2.getSigningKey({ signingKeyPem: pinnedPrivKey, accessTokenTtl: 3600 });
		assert.equal(signer2.kid, signer.kid, 'deterministic kid: same PEM → same kid');
		assert.equal(stored.size, 2, 'idempotent: no second fingerprint row written');
	});

	it('idempotent: calling getSigningKey twice with the same pin produces exactly one pinned row', async () => {
		const { privateKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});

		const cfg = { signingKeyPem: privateKey, accessTokenTtl: 3600 };
		await store.getSigningKey(cfg);
		resetMCPKeysTableCache();
		await new MCPKeyStore().getSigningKey(cfg);

		assert.equal(stored.size, 1, 'exactly one pinned row after two calls');
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

	it("GC keys off each key's IMMEDIATE SUCCESSOR, not the current signer (no accumulation)", async () => {
		// Regression for the accumulation bug: with a fresh signer, a signer-age
		// rule never fires and retired keys pile up forever. The successor rule
		// deletes oldest-key because ITS successor (middle-key) is old enough,
		// even though the signer is brand new.
		const nowSeconds = Math.floor(Date.now() / 1000);
		seedKey(stored, { kid: 'oldest-key', created_at: nowSeconds - 20_000 });
		seedKey(stored, { kid: 'middle-key', created_at: nowSeconds - 10_000 }); // > 2×3600 ago
		seedKey(stored, { kid: 'signer-key', created_at: nowSeconds - 10 }); // fresh — signer-age rule would never fire

		await store.getSigningKey({ accessTokenTtl: 3600 });
		await new Promise((resolve) => setImmediate(resolve));

		assert.ok(!stored.has('oldest-key'), 'oldest key GCd — its successor (middle-key) is past the window');
		assert.ok(stored.has('middle-key'), 'middle key retained — its successor (signer) is too fresh');
		assert.ok(stored.has('signer-key'), 'signer retained');
	});

	// ---- Enumeration errors ----

	// A generator that throws before yielding anything — simulates a table read
	// failure surfacing on the first iteration. (Plain throw keeps eslint's
	// require-yield satisfied via the unreachable yield.)
	async function* failingSearch() {
		throw new Error('simulated table read failure');
		yield undefined; // eslint-disable-line no-unreachable
	}

	it('getSigningKey PROPAGATES enumeration errors instead of generating spurious keys', async () => {
		global.databases.oauth.harper_oauth_mcp_keys.search = failingSearch;

		await assert.rejects(store.getSigningKey({ accessTokenTtl: 3600 }), /simulated table read failure/);
		assert.equal(stored.size, 0, 'no key generated on a transient read error');
	});

	it('getAllPublicKeys returns an empty set on enumeration error (JWKS must not 500)', async () => {
		global.databases.oauth.harper_oauth_mcp_keys.search = failingSearch;
		assert.deepEqual(await store.getAllPublicKeys(), []);
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

	// ---- Single-flight (item 1) ----

	it('single-flight: 5 concurrent first-boot getSigningKey calls produce exactly one key', async () => {
		// Slow put so all 5 calls race to the empty-table check.
		global.databases.oauth.harper_oauth_mcp_keys.put = async (rec) => {
			await new Promise((resolve) => setTimeout(resolve, 5));
			stored.set(rec.kid, rec);
		};

		const results = await Promise.all([
			store.getSigningKey({ accessTokenTtl: 3600 }),
			store.getSigningKey({ accessTokenTtl: 3600 }),
			store.getSigningKey({ accessTokenTtl: 3600 }),
			store.getSigningKey({ accessTokenTtl: 3600 }),
			store.getSigningKey({ accessTokenTtl: 3600 }),
		]);

		assert.equal(stored.size, 1, 'exactly one key generated despite 5 concurrent calls');
		const kids = new Set(results.map((r) => r.kid));
		assert.equal(kids.size, 1, 'all 5 calls resolve to the same kid');
	});

	it('single-flight: 3 concurrent rotation calls produce exactly one new key', async () => {
		const veryOldTs = Math.floor(Date.now() / 1000) - 10_000;
		seedKey(stored, { kid: 'old-key', created_at: veryOldTs });

		// Slow put so all 3 calls race to the rotation boundary check.
		global.databases.oauth.harper_oauth_mcp_keys.put = async (rec) => {
			await new Promise((resolve) => setTimeout(resolve, 5));
			stored.set(rec.kid, rec);
		};

		const results = await Promise.all([
			store.getSigningKey({ keyRotationInterval: 60, accessTokenTtl: 3600 }),
			store.getSigningKey({ keyRotationInterval: 60, accessTokenTtl: 3600 }),
			store.getSigningKey({ keyRotationInterval: 60, accessTokenTtl: 3600 }),
		]);

		// old-key + exactly one rotation key.
		assert.equal(stored.size, 2, 'exactly one rotation key generated despite 3 concurrent calls');
		const rotationKids = new Set(results.map((r) => r.kid));
		assert.equal(rotationKids.size, 1, 'all 3 calls resolve to the same new kid');
		assert.ok(!rotationKids.has('old-key'), 'new key is not the old key');
	});

	// ---- Pin created_at bump (item 2) ----

	it('pin bump: when pinned key is not the newest, created_at is bumped and it becomes signer', async () => {
		// Seed a newer generated key (created 60s ago).
		const nowSeconds = Math.floor(Date.now() / 1000);
		const { privateKey: generatedPrivKey, publicKey: generatedPubKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		stored.set('generated-uuid', {
			kid: 'generated-uuid',
			alg: 'RS256',
			public_key_pem: generatedPubKey,
			private_key_pem: generatedPrivKey,
			created_at: nowSeconds - 60, // newer than pinned
		});

		// Seed the pinned key under rs256-default with an older created_at.
		const { privateKey: pinnedPrivKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const pinnedPubKey = createPublicKey(pinnedPrivKey).export({ type: 'spki', format: 'pem' });
		stored.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: pinnedPubKey,
			private_key_pem: pinnedPrivKey,
			created_at: nowSeconds - 3600, // older than generated key
		});

		const signer = await store.getSigningKey({ signingKeyPem: pinnedPrivKey, accessTokenTtl: 3600 });

		// Pinned key was bumped and is the signer.
		assert.equal(signer.private_key_pem, pinnedPrivKey, 'pinned key signs');
		// created_at was bumped — should be ≥ nowSeconds.
		const persisted = stored.get(SIGNING_KEY_ID);
		assert.ok(persisted.created_at >= nowSeconds, 'pinned key created_at bumped to now');

		// GC regression: after 2×TTL the generated key should be collected.
		// Simulate GC by re-running getSigningKey after the generated key's successor
		// (the bumped pin, nowSeconds) is 2×TTL old.
		// To test GC without sleeping, call garbageCollect indirectly via getSigningKey
		// with a fake nowSeconds via future-dated stored records.
		// Simplest check: both keys still exist (GC hasn't fired yet in this tick).
		assert.equal(stored.size, 2, 'both keys still present before GC fires');
	});

	it('pin bump regression: generated key is GCd once window passes (no accumulation)', async () => {
		// Arrange: generated key at a timestamp old enough to be GC'd once the bumped
		// pin's created_at is treated as the successor.
		const nowSeconds = Math.floor(Date.now() / 1000);
		const generatedCreatedAt = nowSeconds - 9_000; // > 2×3600

		const { privateKey: generatedPrivKey, publicKey: generatedPubKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		stored.set('generated-uuid', {
			kid: 'generated-uuid',
			alg: 'RS256',
			public_key_pem: generatedPubKey,
			private_key_pem: generatedPrivKey,
			created_at: generatedCreatedAt,
		});

		const { privateKey: pinnedPrivKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		const pinnedPubKey = createPublicKey(pinnedPrivKey).export({ type: 'spki', format: 'pem' });
		// Pinned key has an older created_at than the generated key.
		stored.set(SIGNING_KEY_ID, {
			kid: SIGNING_KEY_ID,
			alg: 'RS256',
			public_key_pem: pinnedPubKey,
			private_key_pem: pinnedPrivKey,
			created_at: nowSeconds - 10_000, // older than generated
		});

		// getSigningKey: pin path bumps created_at → pin becomes sorted[0].
		// GC fires: generated key's successor (the bumped pin, created_at ≈ now)
		// was "created" 0 s ago → 0 < 2×3600 → generated key is NOT retired yet.
		await store.getSigningKey({ signingKeyPem: pinnedPrivKey, accessTokenTtl: 3600 });
		await new Promise((resolve) => setImmediate(resolve));

		// Both still present — generated key is not yet past the 2×TTL window from
		// the bumped pin (bumped just now, window not yet elapsed).
		assert.ok(stored.has('generated-uuid'), 'generated key still in table (window not elapsed)');

		// Now simulate that the bumped pin was created 9000s ago (window passed).
		// Directly update the bumped pin's created_at to force GC on next call.
		const bumpedPin = stored.get(SIGNING_KEY_ID);
		stored.set(SIGNING_KEY_ID, { ...bumpedPin, created_at: nowSeconds - 9_000 });
		resetMCPKeysTableCache();

		// Seed another fresh key so getSigningKey has a signer and can run GC.
		const freshCreatedAt = nowSeconds;
		const { privateKey: freshPrivKey, publicKey: freshPubKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'pem' },
			privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
		});
		stored.set('fresh-key', {
			kid: 'fresh-key',
			alg: 'RS256',
			public_key_pem: freshPubKey,
			private_key_pem: freshPrivKey,
			created_at: freshCreatedAt,
		});

		// Re-run without pin — uses rotation path, GC fires on the old keys.
		await store.getSigningKey({ accessTokenTtl: 3600 });
		await new Promise((resolve) => setImmediate(resolve));

		assert.ok(!stored.has('generated-uuid'), 'generated key GCd once successor (pin) is past 2×TTL');
	});

	// ---- Read-time retirement (item 3) ----

	it('getAllPublicKeys excludes retired keys even without mint traffic', async () => {
		const nowSeconds = Math.floor(Date.now() / 1000);

		// old-key was superseded by new-key 9000s ago — past 2×3600.
		const oldKey = seedKey(stored, { kid: 'old-key', created_at: nowSeconds - 15_000 });
		seedKey(stored, { kid: 'new-key', created_at: nowSeconds - 9_000 });

		// No getSigningKey call — no GC. But getAllPublicKeys must filter retired keys.
		const keys = await store.getAllPublicKeys({ accessTokenTtl: 3600 });

		const kids = keys.map((k) => k.kid);
		assert.ok(!kids.includes('old-key'), 'retired old-key excluded from JWKS');
		assert.ok(kids.includes('new-key'), 'live new-key included in JWKS');

		// A token signed by the retired key FAILS against the filtered set.
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
		assert.throws(
			() =>
				verifyAccessTokenWithKeySet(token, keys, {
					audience: 'https://app.example.com/mcp',
					issuer: 'https://as.example.com',
				}),
			'token signed by retired key rejected by filtered key set'
		);
	});

	it('getAllPublicKeys keeps a key live until its successor is 2×TTL old', async () => {
		const nowSeconds = Math.floor(Date.now() / 1000);
		// Successor created only 100s ago — within the 2×3600s window.
		seedKey(stored, { kid: 'still-live', created_at: nowSeconds - 5_000 });
		seedKey(stored, { kid: 'signer', created_at: nowSeconds - 100 });

		const keys = await store.getAllPublicKeys({ accessTokenTtl: 3600 });
		const kids = keys.map((k) => k.kid);
		assert.ok(kids.includes('still-live'), 'key within window stays live');
		assert.ok(kids.includes('signer'), 'signer included');
	});

	// ---- Enumeration cache (item 4) ----

	it('cache: two rapid getAllPublicKeys calls produce one table scan', async () => {
		let searchCalls = 0;
		const origSearch = global.databases.oauth.harper_oauth_mcp_keys.search;
		global.databases.oauth.harper_oauth_mcp_keys.search = async function* () {
			searchCalls++;
			yield* origSearch();
		};

		seedKey(stored, { kid: 'k1' });

		await store.getAllPublicKeys();
		await store.getAllPublicKeys();

		assert.equal(searchCalls, 1, 'second call served from cache');
	});

	it('cache: a MCPKeyStore put invalidates the cache; new key visible immediately', async () => {
		let searchCalls = 0;
		const origSearch = global.databases.oauth.harper_oauth_mcp_keys.search;
		global.databases.oauth.harper_oauth_mcp_keys.search = async function* () {
			searchCalls++;
			yield* origSearch();
		};

		// Cold cache — first call goes to table.
		await store.getAllPublicKeys(); // searchCalls = 1
		const callsAfterFirstRead = searchCalls;

		// Cache hit.
		await store.getAllPublicKeys();
		assert.equal(searchCalls, callsAfterFirstRead, 'cache hit');

		// Write a key via MCPKeyStore (invalidates cache).
		await store.getSigningKey(); // generates key → put → invalidateEnumCache
		const callsAfterMint = searchCalls; // includes internal enumerations from getSigningKey

		// Next getAllPublicKeys hits the DB again (cache was invalidated; post-write
		// re-enumerate inside generateAndPersistFirstKey refills it).
		const keys = await store.getAllPublicKeys();
		assert.ok(keys.length > 0, 'new key visible after cache invalidation');
		// The post-write enumerate inside generateAndPersistFirstKey already refilled
		// the cache, so this getAllPublicKeys should be a cache hit.
		assert.equal(searchCalls, callsAfterMint, 'cache refilled by post-write enumerate; getAllPublicKeys is a hit');
	});

	it('cache: TTL expiry causes re-fetch (inject clock override)', async () => {
		let searchCalls = 0;
		const origSearch = global.databases.oauth.harper_oauth_mcp_keys.search;
		global.databases.oauth.harper_oauth_mcp_keys.search = async function* () {
			searchCalls++;
			yield* origSearch();
		};
		seedKey(stored, { kid: 'k1' });

		let fakeNow = Date.now();
		_setCacheNowMs(() => fakeNow);
		try {
			await store.getAllPublicKeys(); // cache miss → search 1
			assert.equal(searchCalls, 1);

			await store.getAllPublicKeys(); // cache hit → still 1
			assert.equal(searchCalls, 1);

			// Advance clock past 5s TTL.
			fakeNow += 6_000;

			await store.getAllPublicKeys(); // cache expired → search 2
			assert.equal(searchCalls, 2, 'TTL expiry causes re-fetch');
		} finally {
			_setCacheNowMs(null); // Restore default clock.
		}
	});
});
