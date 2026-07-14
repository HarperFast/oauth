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

		it('should not throw and still logs when hook throws a non-Error string', async () => {
			hookManager.register({
				onLogin: async () => {
					throw 'string-error'; // eslint-disable-line no-throw-literal
				},
			});
			// Must resolve without throwing even though the hook threw a non-Error.
			const result = await hookManager.callOnLogin({}, {}, {}, {}, 'github');
			assert.equal(result, undefined);
			assert.equal(mockLogger.error.mock.calls.length, 1, 'error still logged');
		});

		it('should not throw and still logs when hook throws null', async () => {
			hookManager.register({
				onLogin: async () => {
					throw null; // eslint-disable-line no-throw-literal
				},
			});
			const result = await hookManager.callOnLogin({}, {}, {}, {}, 'github');
			assert.equal(result, undefined);
			assert.equal(mockLogger.error.mock.calls.length, 1, 'error still logged');
		});

		it('should pass a structured outcome through verbatim (#174)', async () => {
			const outcome = { status: 'denied', error: 'not_provisioned', redirect: '/denied' };
			hookManager.register({ onLogin: async () => outcome });

			const result = await hookManager.callOnLogin({}, {}, {}, {}, 'github');
			assert.equal(result, outcome);
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

		it('should not throw when hook throws a non-Error value (null)', async () => {
			hookManager.register({
				onLogout: async () => {
					throw null; // eslint-disable-line no-throw-literal
				},
			});
			await hookManager.callOnLogout({}, {});
			assert.equal(mockLogger.error.mock.calls.length, 1, 'error still logged');
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

		it('should not throw when hook throws a non-Error value (string)', async () => {
			hookManager.register({
				onTokenRefresh: async () => {
					throw 'non-error-string'; // eslint-disable-line no-throw-literal
				},
			});
			await hookManager.callOnTokenRefresh({}, true);
			assert.equal(mockLogger.error.mock.calls.length, 1, 'error still logged');
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

	describe('callOnMCPTokenIssued', () => {
		const SAMPLE_EVENT = {
			type: /** @type {const} */ ('access'),
			client_id: 'client-abc',
			sub: 'alice@example.com',
			aud: 'https://app.example.com/mcp',
			scope: 'mcp:read',
			jti: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
		};
		const SAMPLE_REQUEST = { headers: {} };

		// The hook is fire-and-forget (NOT awaited), so it runs detached on the
		// microtask queue. Drain it with a macrotask tick before asserting.
		const flushMicrotasks = () => new Promise((resolve) => setImmediate(resolve));

		it('should call onMCPTokenIssued hook with the correct event and request', async () => {
			const hookMock = createMockFn(async () => {});
			hookManager.register({ onMCPTokenIssued: hookMock });

			hookManager.callOnMCPTokenIssued(SAMPLE_EVENT, SAMPLE_REQUEST);
			await flushMicrotasks();

			assert.equal(hookMock.mock.calls.length, 1);
			const [eventArg, requestArg] = hookMock.mock.calls[0].arguments;
			assert.equal(eventArg.type, 'access');
			assert.equal(eventArg.client_id, SAMPLE_EVENT.client_id);
			assert.equal(eventArg.sub, SAMPLE_EVENT.sub);
			assert.equal(eventArg.aud, SAMPLE_EVENT.aud);
			assert.equal(eventArg.scope, SAMPLE_EVENT.scope);
			assert.equal(eventArg.jti, SAMPLE_EVENT.jti);
			assert.equal(requestArg, SAMPLE_REQUEST);
		});

		it('does not await the hook — a slow hook never blocks token issuance', async () => {
			let release;
			const gate = new Promise((resolve) => {
				release = resolve;
			});
			let hookCompleted = false;
			hookManager.register({
				onMCPTokenIssued: async () => {
					await gate;
					hookCompleted = true;
				},
			});

			// Returns synchronously (void) without waiting on the hook.
			const ret = hookManager.callOnMCPTokenIssued(SAMPLE_EVENT, SAMPLE_REQUEST);
			assert.equal(ret, undefined, 'returns void synchronously');
			assert.equal(hookCompleted, false, 'issuance does not wait for the hook to finish');

			// Once unblocked, the detached hook still runs to completion.
			release();
			await flushMicrotasks();
			assert.equal(hookCompleted, true);
		});

		it('is a no-op when no onMCPTokenIssued hook is registered', async () => {
			// No hook registered — returns without scheduling anything or throwing.
			hookManager.callOnMCPTokenIssued(SAMPLE_EVENT, SAMPLE_REQUEST);
			await flushMicrotasks();
		});

		it('swallows a throwing hook and logs the error (fire-and-forget contract)', async () => {
			const throwingHook = createMockFn(async () => {
				throw new Error('billing service unavailable');
			});
			hookManager.register({ onMCPTokenIssued: throwingHook });

			hookManager.callOnMCPTokenIssued(SAMPLE_EVENT, SAMPLE_REQUEST);
			await flushMicrotasks();

			assert.equal(mockLogger.error.mock.calls.length, 1, 'error is logged');
			assert.ok(
				mockLogger.error.mock.calls[0].arguments[0].includes('onMCPTokenIssued hook failed'),
				'error message mentions the hook name'
			);
		});

		it('handles the refresh type correctly', async () => {
			const hookMock = createMockFn(async () => {});
			hookManager.register({ onMCPTokenIssued: hookMock });

			const refreshEvent = { ...SAMPLE_EVENT, type: /** @type {const} */ ('refresh') };
			hookManager.callOnMCPTokenIssued(refreshEvent, SAMPLE_REQUEST);
			await flushMicrotasks();

			assert.equal(hookMock.mock.calls[0].arguments[0].type, 'refresh');
		});

		it('swallows a hook that throws a NON-Error value (null) without the catch itself throwing', async () => {
			// `(null).message` in the catch would itself throw and escape, breaking
			// the fire-and-forget contract — guards the `instanceof Error` handling.
			hookManager.register({
				onMCPTokenIssued: async () => {
					throw null;
				},
			});

			hookManager.callOnMCPTokenIssued(SAMPLE_EVENT, SAMPLE_REQUEST);
			await flushMicrotasks();
			assert.equal(mockLogger.error.mock.calls.length, 1, 'error is still logged');
		});

		it('shields the catch body — a throwing logger does not escape the detached chain', async () => {
			// The hook throws AND logger.error throws. Without the try/catch shield in
			// the catch body, the throw would become an unhandled rejection on the
			// detached (void) chain — which the test runner attributes as a failure
			// (and crashes Node >=15 in production). Surviving the flush is the proof.
			const throwingLogger = {
				debug() {},
				error() {
					throw new Error('logging subsystem down');
				},
			};
			const hm = new HookManager(throwingLogger);
			hm.register({
				onMCPTokenIssued: async () => {
					throw new Error('hook boom');
				},
			});

			hm.callOnMCPTokenIssued(SAMPLE_EVENT, SAMPLE_REQUEST);
			await flushMicrotasks();
			await flushMicrotasks();
			assert.ok(true, 'no unhandled rejection escaped the detached chain');
		});
	});
});
