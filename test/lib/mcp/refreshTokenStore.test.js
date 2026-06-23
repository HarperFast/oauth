/**
 * Tests for the refresh-token family store and its token helpers.
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
	MCPRefreshFamilyStore,
	resetMCPRefreshFamiliesTableCache,
	makeRefreshToken,
	hashRefreshToken,
	parseRefreshToken,
	newFamilyId,
} from '../../../dist/lib/mcp/refreshTokenStore.js';

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

describe('refresh-token helpers', () => {
	it('hashes a token as base64url sha256', () => {
		const expected = createHash('sha256').update('abc.def').digest('base64url');
		assert.equal(hashRefreshToken('abc.def'), expected);
	});

	it('mints a token of the form <family_id>.<secret> with a matching hash', () => {
		const familyId = newFamilyId();
		const { token, hash } = makeRefreshToken(familyId);
		assert.ok(token.startsWith(`${familyId}.`));
		assert.equal(hash, hashRefreshToken(token));
		assert.deepEqual(parseRefreshToken(token), { familyId });
	});

	it('mints distinct secrets each call', () => {
		const familyId = newFamilyId();
		assert.notEqual(makeRefreshToken(familyId).token, makeRefreshToken(familyId).token);
	});

	it('rejects malformed refresh tokens', () => {
		assert.equal(parseRefreshToken(undefined), null);
		assert.equal(parseRefreshToken(42), null);
		assert.equal(parseRefreshToken('no-dot'), null);
		assert.equal(parseRefreshToken('.leading'), null);
		assert.equal(parseRefreshToken('trailing.'), null);
	});
});

describe('MCPRefreshFamilyStore', () => {
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
		resetMCPRefreshFamiliesTableCache();
		store = new MCPRefreshFamilyStore();
		stored = new Map();
		global.databases = {
			oauth: {
				mcp_refresh_families: {
					get: async (id) => {
						const raw = stored.get(id);
						return raw ? asTrackedObject(raw) : null;
					},
					put: async (rec) => {
						stored.set(rec.family_id, rec);
					},
					delete: async (id) => {
						stored.delete(id);
					},
				},
			},
		};
	});

	const sample = {
		family_id: 'fam-1',
		current_token_hash: 'hash-abc',
		revoked: false,
		client_id: 'client-123',
		user: 'alice@example.com',
		resource: 'https://app.example.com/mcp',
		scope: 'mcp:read',
		created_at: 1700000000,
		expires_at: 1700086400,
	};

	it('persists and retrieves a family through the tracked-object Proxy', async () => {
		await store.set(sample);
		const got = await store.get('fam-1');
		assert.ok(got);
		assert.equal(got.family_id, 'fam-1');
		assert.equal(got.current_token_hash, 'hash-abc');
		assert.equal(got.revoked, false);
		assert.equal(got.client_id, 'client-123');
		assert.equal(got.user, 'alice@example.com');
		assert.equal(got.resource, 'https://app.example.com/mcp');
		assert.equal(got.scope, 'mcp:read');
		assert.equal(got.expires_at, 1700086400);
	});

	it('returns null for an unknown family', async () => {
		assert.equal(await store.get('nope'), null);
	});

	it('decodes a missing revoked flag as false', async () => {
		const { revoked, ...withoutRevoked } = sample;
		void revoked;
		await store.set(withoutRevoked);
		const got = await store.get('fam-1');
		assert.equal(got.revoked, false);
	});

	it('propagates set() errors so the caller can fail the request', async () => {
		global.databases.oauth.mcp_refresh_families.put = async () => {
			throw new Error('db write failure');
		};
		await assert.rejects(() => store.set(sample));
	});
});
