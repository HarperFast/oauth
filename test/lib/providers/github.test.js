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
			getUserInfo: async () => ({
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

	it('should have token validation support', () => {
		const github = getProvider('github');
		assert.ok(github.validateToken);
		assert.equal(typeof github.validateToken, 'function');
		assert.ok(github.tokenValidationInterval);
		assert.equal(github.tokenValidationInterval, 15 * 60 * 1000); // 15 minutes
	});

	it('should validate tokens with HEAD request', async () => {
		const github = getProvider('github');

		const originalFetch = global.fetch;
		global.fetch = async (url, options) => {
			assert.equal(url, 'https://api.github.com/user');
			assert.equal(options.method, 'HEAD');
			assert.equal(options.headers.Authorization, 'Bearer valid-token');
			return { ok: true, status: 200 };
		};

		try {
			const isValid = await github.validateToken('valid-token');
			assert.equal(isValid, true);
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should return false for invalid tokens', async () => {
		const github = getProvider('github');

		const originalFetch = global.fetch;
		global.fetch = async () => {
			return { ok: false, status: 401, statusText: 'Unauthorized' };
		};

		try {
			const isValid = await github.validateToken('invalid-token');
			assert.equal(isValid, false);
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should log debug message for invalid tokens', async () => {
		const github = getProvider('github');

		let debugCalled = false;
		const mockLogger = {
			debug: (msg) => {
				if (msg.includes('token validation failed') && msg.includes('401')) {
					debugCalled = true;
				}
			},
		};

		const originalFetch = global.fetch;
		global.fetch = async () => {
			return { ok: false, status: 401, statusText: 'Unauthorized' };
		};

		try {
			const isValid = await github.validateToken('invalid-token', mockLogger);
			assert.equal(isValid, false);
			assert.ok(debugCalled, 'Should call debug logger for invalid tokens');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should handle validation errors gracefully', async () => {
		const github = getProvider('github');

		const originalFetch = global.fetch;
		global.fetch = async () => {
			throw new Error('Network error');
		};

		try {
			const isValid = await github.validateToken('test-token');
			assert.equal(isValid, false); // Should return false on error
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should log warning on validation network errors', async () => {
		const github = getProvider('github');

		let warnCalled = false;
		const mockLogger = {
			warn: (msg, error) => {
				if (msg.includes('GitHub token validation error') && error.includes('Network error')) {
					warnCalled = true;
				}
			},
		};

		const originalFetch = global.fetch;
		global.fetch = async () => {
			throw new Error('Network error');
		};

		try {
			const isValid = await github.validateToken('test-token', mockLogger);
			assert.equal(isValid, false);
			assert.ok(warnCalled, 'Should call warn logger on network errors');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should handle when no primary email exists', async () => {
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

		// Mock fetch to return emails without primary
		const originalFetch = global.fetch;
		global.fetch = async (url) => {
			if (url === 'https://api.github.com/user/emails') {
				return {
					ok: true,
					json: async () => [
						{ email: 'secondary1@example.com', primary: false, verified: true },
						{ email: 'secondary2@example.com', primary: false, verified: false },
					],
				};
			}
			throw new Error('Unexpected URL: ' + url);
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			// Should return user info without email when no primary email found
			assert.equal(userInfo.login, 'testuser');
			assert.equal(userInfo.email, null);
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should handle when email API returns non-OK status', async () => {
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

		// Mock fetch to return 403 (permissions issue)
		const originalFetch = global.fetch;
		global.fetch = async (url) => {
			if (url === 'https://api.github.com/user/emails') {
				return {
					ok: false,
					status: 403,
					statusText: 'Forbidden',
				};
			}
			throw new Error('Unexpected URL: ' + url);
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			// Should return user info without email when API fails
			assert.equal(userInfo.login, 'testuser');
			assert.equal(userInfo.email, null);
		} finally {
			global.fetch = originalFetch;
		}
	});
});
