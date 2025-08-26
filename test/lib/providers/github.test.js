/**
 * Tests for GitHub OAuth provider
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider } from '../../../dist/lib/providers/index.js';

describe('GitHub Provider', () => {
	it('should return GitHub provider config', () => {
		const github = getProvider('github');
		assert.ok(github);
		assert.equal(github.provider, 'github');
		assert.equal(github.authorizationUrl, 'https://github.com/login/oauth/authorize');
		assert.equal(github.tokenUrl, 'https://github.com/login/oauth/access_token');
		assert.equal(github.userInfoUrl, 'https://api.github.com/user');
		assert.equal(github.scope, 'read:user user:email');
		assert.equal(github.usernameClaim, 'login');
		// defaultRole is not in provider preset - it's added by the main config
	});

	it('should have custom getUserInfo for email fetching', async () => {
		const github = getProvider('github');
		assert.ok(github.getUserInfo);
		assert.equal(typeof github.getUserInfo, 'function');

		// Mock the helpers
		const mockHelpers = {
			getUserInfo: async (token) => ({
				login: 'testuser',
				name: 'Test User',
				email: null, // GitHub often returns null email
			}),
			logger: {
				info: () => {},
				debug: () => {},
			},
		};

		// Mock fetch for email endpoint
		const originalFetch = global.fetch;
		global.fetch = async (url, options) => {
			if (url === 'https://api.github.com/user/emails') {
				assert.equal(options.headers.Authorization, 'Bearer test-token');
				assert.equal(options.headers.Accept, 'application/json');
				return {
					ok: true,
					json: async () => [
						{ email: 'secondary@example.com', primary: false },
						{ email: 'primary@example.com', primary: true },
					],
				};
			}
			throw new Error('Unexpected URL: ' + url);
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			assert.equal(userInfo.email, 'primary@example.com');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should handle email fetch failure gracefully', async () => {
		const github = getProvider('github');

		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: null,
			}),
			logger: {
				info: () => {},
				debug: () => {},
				warn: () => {},
			},
		};

		// Mock fetch to fail
		const originalFetch = global.fetch;
		global.fetch = async () => {
			throw new Error('Network error');
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			// Should still return user info even if email fetch fails
			assert.equal(userInfo.login, 'testuser');
			assert.equal(userInfo.email, null);
		} finally {
			global.fetch = originalFetch;
		}
	});
});
