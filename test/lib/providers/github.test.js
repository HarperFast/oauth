/**
 * Tests for GitHub OAuth provider
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { getProvider } from '../../../dist/lib/providers/index.js';
import { ADAPTER_EMAIL_PROVENANCE } from '../../../dist/lib/emailProvenance.js';

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

	it('should surface email_verified for a public profile email (#174)', async () => {
		const github = getProvider('github');

		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: 'public@example.com', // public profile email — previously skipped /user/emails
			}),
			logger: { warn: () => {} },
		};

		const originalFetch = global.fetch;
		global.fetch = async (url) => {
			if (url === 'https://api.github.com/user/emails') {
				return {
					ok: true,
					json: async () => [
						{ email: 'other@example.com', primary: true, verified: false },
						{ email: 'public@example.com', primary: false, verified: true },
					],
				};
			}
			throw new Error('Unexpected URL: ' + url);
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			// The reported email must keep its own verified status (not the primary's)
			assert.equal(userInfo.email, 'public@example.com');
			assert.equal(userInfo.email_verified, true);
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should leave email_verified unset when the public email is not in /user/emails', async () => {
		const github = getProvider('github');

		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: 'public@example.com',
			}),
			logger: { warn: () => {} },
		};

		const originalFetch = global.fetch;
		global.fetch = async (url) => {
			if (url === 'https://api.github.com/user/emails') {
				return {
					ok: true,
					json: async () => [{ email: 'other@example.com', primary: true, verified: true }],
				};
			}
			throw new Error('Unexpected URL: ' + url);
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			assert.equal(userInfo.email, 'public@example.com', 'public email must be preserved');
			assert.equal(userInfo.email_verified, undefined, 'unknown status must not be guessed');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should preserve public email when the emails endpoint fails', async () => {
		const github = getProvider('github');

		let warned = false;
		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: 'public@example.com',
			}),
			logger: {
				warn: () => {
					warned = true;
				},
			},
		};

		const originalFetch = global.fetch;
		global.fetch = async () => {
			throw new Error('Network error');
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			assert.equal(userInfo.email, 'public@example.com');
			assert.equal(userInfo.email_verified, undefined);
			assert.ok(warned, 'failure should be logged');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should set email_verified when filling a non-public email from primary', async () => {
		const github = getProvider('github');

		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: null,
			}),
			logger: { warn: () => {} },
		};

		const originalFetch = global.fetch;
		global.fetch = async (url) => {
			if (url === 'https://api.github.com/user/emails') {
				return {
					ok: true,
					json: async () => [{ email: 'primary@example.com', primary: true, verified: true }],
				};
			}
			throw new Error('Unexpected URL: ' + url);
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			assert.equal(userInfo.email, 'primary@example.com');
			assert.equal(userInfo.email_verified, true);
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should bound the emails fetch with an abort signal and degrade gracefully on timeout', async () => {
		const github = getProvider('github');

		let warned = false;
		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: 'public@example.com',
			}),
			logger: {
				warn: () => {
					warned = true;
				},
			},
		};

		let sawSignal = false;
		const originalFetch = global.fetch;
		global.fetch = async (url, options) => {
			sawSignal = options.signal instanceof AbortSignal;
			const error = new Error('The operation was aborted due to timeout');
			error.name = 'TimeoutError';
			throw error;
		};

		try {
			const userInfo = await github.getUserInfo.call({ config: github }, 'test-token', mockHelpers);
			assert.ok(sawSignal, 'emails fetch must carry an AbortSignal');
			assert.equal(userInfo.email, 'public@example.com', 'timeout must not break the login');
			assert.equal(userInfo.email_verified, undefined);
			assert.ok(warned, 'timeout should be logged');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('should handle when email API returns non-OK status', async () => {
		const github = getProvider('github');

		let warned = false;
		const mockHelpers = {
			getUserInfo: async () => ({
				login: 'testuser',
				name: 'Test User',
				email: null,
			}),
			logger: {
				info: () => {},
				debug: () => {},
				warn: (msg) => {
					if (msg.includes('/user/emails returned 403')) warned = true;
				},
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
			assert.ok(warned, 'non-OK response (e.g. missing user:email scope) should warn');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('asserts github-authenticated via the provenance Symbol only on a successful fetch of a verified email', async () => {
		const github = getProvider('github');
		const mockHelpers = {
			getUserInfo: async () => ({ login: 'user', email: null }),
			logger: { warn: () => {} },
		};

		const originalFetch = global.fetch;

		// Success path: primary email found and verified → github-authenticated
		global.fetch = async () => ({
			ok: true,
			json: async () => [{ email: 'user@example.com', primary: true, verified: true }],
		});
		try {
			const info = await github.getUserInfo.call({ config: github }, 'token', mockHelpers);
			assert.equal(
				info[ADAPTER_EMAIL_PROVENANCE],
				'github-authenticated',
				'a successful fetch of a verified email must assert github-authenticated'
			);
			assert.equal(info._emailProvenance, undefined, 'the adapter must not set the string _emailProvenance');
		} finally {
			global.fetch = originalFetch;
		}

		// Successful fetch of an UNVERIFIED email → unauthenticated (verified is required)
		global.fetch = async () => ({
			ok: true,
			json: async () => [{ email: 'user@example.com', primary: true, verified: false }],
		});
		try {
			const info = await github.getUserInfo.call({ config: github }, 'token', mockHelpers);
			assert.equal(
				info[ADAPTER_EMAIL_PROVENANCE],
				'unauthenticated',
				'an unverified email must not earn github-authenticated even on a successful fetch'
			);
		} finally {
			global.fetch = originalFetch;
		}

		// GHES / custom userInfoUrl: the userinfo body claims email_verified:true but the
		// hard-coded api.github.com/user/emails fetch fails → must stay unauthenticated
		// (the trust signal is the authenticated fetch, never the body's claim).
		global.fetch = async () => {
			throw new Error('network error');
		};
		try {
			const info = await github.getUserInfo.call({ config: github }, 'token', {
				getUserInfo: async () => ({ login: 'user', email: 'victim@corp.example', email_verified: true }),
				logger: { warn: () => {} },
			});
			assert.equal(
				info[ADAPTER_EMAIL_PROVENANCE],
				'unauthenticated',
				'a failed fetch must yield unauthenticated even when the userinfo body claims email_verified'
			);
		} finally {
			global.fetch = originalFetch;
		}

		// Non-OK response → unauthenticated
		global.fetch = async () => ({
			ok: false,
			status: 403,
			statusText: 'Forbidden',
			body: { cancel: async () => {} },
		});
		try {
			const info = await github.getUserInfo.call({ config: github }, 'token', {
				...mockHelpers,
				logger: { warn: () => {} },
			});
			assert.equal(info[ADAPTER_EMAIL_PROVENANCE], 'unauthenticated', 'non-OK response must yield unauthenticated');
		} finally {
			global.fetch = originalFetch;
		}
	});

	it('sets the provenance assertion as a non-enumerable symbol a spread cannot carry', async () => {
		const github = getProvider('github');
		const originalFetch = global.fetch;
		global.fetch = async () => ({
			ok: true,
			json: async () => [{ email: 'user@example.com', primary: true, verified: true }],
		});
		try {
			const info = await github.getUserInfo.call({ config: github }, 'token', {
				getUserInfo: async () => ({ login: 'user', email: null }),
				logger: { warn: () => {} },
			});
			assert.equal(info[ADAPTER_EMAIL_PROVENANCE], 'github-authenticated', 'the adapter asserts via the symbol');
			// A spread onto a substituted email must not carry the assertion.
			const spread = { ...info, email: 'attacker@evil.example' };
			assert.equal(
				spread[ADAPTER_EMAIL_PROVENANCE],
				undefined,
				'a spread must not carry the assertion onto a substituted email'
			);
		} finally {
			global.fetch = originalFetch;
		}
	});

	describe('helpers.resolveEmail selection (#228)', () => {
		const originalFetch = global.fetch;
		const EMAILS = [
			{ email: 'secondary@example.com', primary: false, verified: true },
			{ email: 'primary@example.com', primary: true, verified: true },
			{ email: 'unverified@example.com', primary: false, verified: false },
		];

		function mockEmailsFetch() {
			global.fetch = async () => ({ ok: true, json: async () => EMAILS });
		}

		it('uses the hook-resolved email, with email_verified true and github-authenticated provenance', async () => {
			const github = getProvider('github');
			mockEmailsFetch();
			try {
				const info = await github.getUserInfo.call({ config: github }, 'token', {
					getUserInfo: async () => ({ login: 'user', email: null }),
					logger: { warn: () => {} },
					resolveEmail: async () => 'secondary@example.com',
				});
				assert.equal(info.email, 'secondary@example.com');
				assert.equal(info.email_verified, true);
				assert.equal(info[ADAPTER_EMAIL_PROVENANCE], 'github-authenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('falls back to the default (primary) selection when resolveEmail returns undefined', async () => {
			const github = getProvider('github');
			mockEmailsFetch();
			try {
				const info = await github.getUserInfo.call({ config: github }, 'token', {
					getUserInfo: async () => ({ login: 'user', email: null }),
					logger: { warn: () => {} },
					resolveEmail: async () => undefined,
				});
				assert.equal(info.email, 'primary@example.com');
				assert.equal(info[ADAPTER_EMAIL_PROVENANCE], 'github-authenticated');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('passes helpers.resolveEmail every fetched address, verified or not', async () => {
			const github = getProvider('github');
			mockEmailsFetch();
			let received;
			try {
				await github.getUserInfo.call({ config: github }, 'token', {
					getUserInfo: async () => ({ login: 'user', email: null }),
					logger: { warn: () => {} },
					resolveEmail: async (candidates) => {
						received = candidates;
						return undefined;
					},
				});
				assert.deepEqual(
					received,
					EMAILS.map((e) => ({ email: e.email, verified: e.verified, primary: e.primary }))
				);
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('is not called when the /user/emails fetch did not succeed', async () => {
			const github = getProvider('github');
			global.fetch = async () => ({
				ok: false,
				status: 403,
				statusText: 'Forbidden',
				body: { cancel: async () => {} },
			});
			let called = false;
			try {
				await github.getUserInfo.call({ config: github }, 'token', {
					getUserInfo: async () => ({ login: 'user', email: null }),
					logger: { warn: () => {} },
					resolveEmail: async () => {
						called = true;
						return undefined;
					},
				});
				assert.equal(called, false, 'resolveEmail must not be called without a successful candidate fetch');
			} finally {
				global.fetch = originalFetch;
			}
		});

		it('propagates a rejection from resolveEmail instead of falling back to the default (#228 wrong-account guard)', async () => {
			const github = getProvider('github');
			mockEmailsFetch();
			try {
				await assert.rejects(
					() =>
						github.getUserInfo.call({ config: github }, 'token', {
							getUserInfo: async () => ({ login: 'user', email: null }),
							logger: { warn: () => {} },
							resolveEmail: async () => {
								throw new Error('onResolveEmail hook returned an address that is not one of the verified candidates');
							},
						}),
					/onResolveEmail hook returned an address/
				);
			} finally {
				global.fetch = originalFetch;
			}
		});
	});
});
