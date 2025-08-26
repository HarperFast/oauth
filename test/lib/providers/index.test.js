/**
 * Tests for OAuth provider index and general functionality
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider, getProviderNames } from '../../../dist/lib/providers/index.js';

describe('Provider Index', () => {
	describe('getProvider', () => {
		it('should return null for unknown provider', () => {
			const unknown = getProvider('unknown-provider');
			assert.equal(unknown, null);
		});

		it('should handle case-insensitive provider names', () => {
			const github1 = getProvider('GitHub');
			const github2 = getProvider('github');
			assert.ok(github1);
			assert.equal(github1.provider, github2.provider);
		});

		it('should return a copy to prevent mutations', () => {
			const github1 = getProvider('github');
			const github2 = getProvider('github');
			assert.notStrictEqual(github1, github2, 'Should return different object instances');

			// Mutate one instance
			github1.clientId = 'mutated';

			// Other instance should not be affected
			assert.equal(github2.clientId, '');
		});

		it('should handle microsoft alias for azure', () => {
			const microsoft = getProvider('microsoft');
			const azure = getProvider('azure');
			assert.deepEqual(microsoft, azure);
		});
	});

	describe('getProviderNames', () => {
		it('should return all provider names', () => {
			const names = getProviderNames();
			assert.ok(Array.isArray(names));
			assert.ok(names.includes('github'));
			assert.ok(names.includes('google'));
			assert.ok(names.includes('azure'));
			assert.ok(names.includes('microsoft'));
			assert.ok(names.includes('auth0'));
		});
	});

	describe('Provider scope defaults', () => {
		it('should have appropriate scopes for each provider', () => {
			const github = getProvider('github');
			assert.equal(github.scope, 'read:user user:email');

			const google = getProvider('google');
			assert.equal(google.scope, 'openid profile email');

			const azure = getProvider('azure');
			assert.equal(azure.scope, 'openid profile email User.Read');

			const auth0 = getProvider('auth0');
			assert.equal(auth0.scope, 'openid profile email');
		});
	});
});
