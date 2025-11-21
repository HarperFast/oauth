/**
 * Tests for HookManager
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { HookManager } from '../../dist/lib/hookManager.js';
import { createMockFn, createMockLogger } from '../helpers/mockFn.js';

// Note: mock is imported and used by the helper, we only use createMockFn in tests

describe('HookManager', () => {
	let hookManager;
	let mockLogger;

	beforeEach(() => {
		mockLogger = createMockLogger();
		hookManager = new HookManager(mockLogger);
	});

	describe('register', () => {
		it('should register hooks', () => {
			const hooks = {
				onLogin: createMockFn(),
				onLogout: createMockFn(),
			};

			hookManager.register(hooks);
			assert.equal(hookManager.hasHooks(), true);
		});

		it('should log registered hooks', () => {
			const hooks = {
				onLogin: createMockFn(),
				onLogout: createMockFn(),
				onTokenRefresh: createMockFn(),
			};

			hookManager.register(hooks);
			assert.equal(mockLogger.debug.mock.calls.length, 1);
			const logMessage = mockLogger.debug.mock.calls[0].arguments[0];
			assert.ok(logMessage.includes('onLogin'));
			assert.ok(logMessage.includes('onLogout'));
			assert.ok(logMessage.includes('onTokenRefresh'));
		});
	});

	describe('hasHooks', () => {
		it('should return false when no hooks registered', () => {
			assert.equal(hookManager.hasHooks(), false);
		});

		it('should return true when hooks registered', () => {
			hookManager.register({ onLogin: createMockFn() });
			assert.equal(hookManager.hasHooks(), true);
		});
	});

	describe('callOnLogin', () => {
		it('should call onLogin hook with correct parameters', async () => {
			const onLoginMock = createMockFn(async () => ({ customData: 'test' }));
			hookManager.register({ onLogin: onLoginMock });

			const oauthUser = { username: 'testuser', email: 'test@example.com' };
			const tokenResponse = { access_token: 'token123', refresh_token: 'refresh456' };
			const session = { id: 'session123' };
			const request = { url: '/test' };
			const provider = 'github';

			const result = await hookManager.callOnLogin(oauthUser, tokenResponse, session, request, provider);

			assert.equal(onLoginMock.mock.calls.length, 1);
			assert.equal(onLoginMock.mock.calls[0].arguments[0], oauthUser);
			assert.equal(onLoginMock.mock.calls[0].arguments[1], tokenResponse);
			assert.equal(onLoginMock.mock.calls[0].arguments[2], session);
			assert.equal(onLoginMock.mock.calls[0].arguments[3], request);
			assert.equal(onLoginMock.mock.calls[0].arguments[4], provider);
			assert.deepEqual(result, { customData: 'test' });
		});

		it('should return undefined when no onLogin hook registered', async () => {
			const result = await hookManager.callOnLogin({}, {}, {}, {}, 'github');
			assert.equal(result, undefined);
		});

		it('should catch and log errors from onLogin hook', async () => {
			const onLoginMock = createMockFn(async () => {
				throw new Error('Hook error');
			});
			hookManager.register({ onLogin: onLoginMock });

			const result = await hookManager.callOnLogin({}, {}, {}, {}, 'github');

			assert.equal(result, undefined);
			assert.equal(mockLogger.error.mock.calls.length, 1);
			assert.ok(mockLogger.error.mock.calls[0].arguments[0].includes('onLogin hook failed'));
		});

		it('should log debug message when calling hook', async () => {
			hookManager.register({ onLogin: createMockFn(async () => {}) });
			await hookManager.callOnLogin({}, {}, {}, {}, 'github');

			assert.ok(mockLogger.debug.mock.calls.some((call) => call.arguments[0].includes('Calling onLogin hook')));
		});
	});

	describe('callOnLogout', () => {
		it('should call onLogout hook with correct parameters', async () => {
			const onLogoutMock = createMockFn(async () => {});
			hookManager.register({ onLogout: onLogoutMock });

			const session = { id: 'session123', user: 'testuser' };
			const request = { url: '/logout' };

			await hookManager.callOnLogout(session, request);

			assert.equal(onLogoutMock.mock.calls.length, 1);
			assert.equal(onLogoutMock.mock.calls[0].arguments[0], session);
			assert.equal(onLogoutMock.mock.calls[0].arguments[1], request);
		});

		it('should not throw when no onLogout hook registered', async () => {
			await hookManager.callOnLogout({}, {});
			// Should complete without error
		});

		it('should catch and log errors from onLogout hook', async () => {
			const onLogoutMock = createMockFn(async () => {
				throw new Error('Logout hook error');
			});
			hookManager.register({ onLogout: onLogoutMock });

			await hookManager.callOnLogout({}, {});

			assert.equal(mockLogger.error.mock.calls.length, 1);
			assert.ok(mockLogger.error.mock.calls[0].arguments[0].includes('onLogout hook failed'));
		});
	});

	describe('callOnTokenRefresh', () => {
		it('should call onTokenRefresh hook with correct parameters', async () => {
			const onTokenRefreshMock = createMockFn(async () => {});
			hookManager.register({ onTokenRefresh: onTokenRefreshMock });

			const session = { id: 'session123', oauth: { accessToken: 'token' } };
			const request = { url: '/api' };

			await hookManager.callOnTokenRefresh(session, true, request);

			assert.equal(onTokenRefreshMock.mock.calls.length, 1);
			assert.equal(onTokenRefreshMock.mock.calls[0].arguments[0], session);
			assert.equal(onTokenRefreshMock.mock.calls[0].arguments[1], true);
			assert.equal(onTokenRefreshMock.mock.calls[0].arguments[2], request);
		});

		it('should handle refreshed=false', async () => {
			const onTokenRefreshMock = createMockFn(async () => {});
			hookManager.register({ onTokenRefresh: onTokenRefreshMock });

			await hookManager.callOnTokenRefresh({}, false);

			assert.equal(onTokenRefreshMock.mock.calls[0].arguments[1], false);
		});

		it('should work without request parameter', async () => {
			const onTokenRefreshMock = createMockFn(async () => {});
			hookManager.register({ onTokenRefresh: onTokenRefreshMock });

			await hookManager.callOnTokenRefresh({}, true);

			assert.equal(onTokenRefreshMock.mock.calls.length, 1);
			assert.equal(onTokenRefreshMock.mock.calls[0].arguments[2], undefined);
		});

		it('should not throw when no onTokenRefresh hook registered', async () => {
			await hookManager.callOnTokenRefresh({}, true);
			// Should complete without error
		});

		it('should catch and log errors from onTokenRefresh hook', async () => {
			const onTokenRefreshMock = createMockFn(async () => {
				throw new Error('Refresh hook error');
			});
			hookManager.register({ onTokenRefresh: onTokenRefreshMock });

			await hookManager.callOnTokenRefresh({}, true);

			assert.equal(mockLogger.error.mock.calls.length, 1);
			assert.ok(mockLogger.error.mock.calls[0].arguments[0].includes('onTokenRefresh hook failed'));
		});

		it('should log debug message with refreshed status', async () => {
			hookManager.register({ onTokenRefresh: createMockFn(async () => {}) });
			await hookManager.callOnTokenRefresh({}, true);

			assert.ok(
				mockLogger.debug.mock.calls.some((call) => {
					const args = call.arguments || call;
					const message = args[0];
					return message.includes('Calling onTokenRefresh hook') && message.includes('refreshed: true');
				})
			);
		});
	});
});
