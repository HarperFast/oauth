/**
 * Tests for the module-level dynamic-provider cache invalidation wiring in
 * src/index.ts: invalidateDynamicProvider(), clearDynamicProviderCache(), and
 * the set of active caches (added on handleApplication, removed on scope close).
 * The DynamicProviderCache class itself is covered in
 * test/lib/dynamicProviderCache.test.js — this exercises the handleApplication
 * wiring around it, including the multi-instance behavior that motivated tracking
 * a Set of caches rather than a single reference.
 *
 * The exported functions read module-level state (the active-cache set + active
 * hookManager) shared across the file; node --test isolates each file in its own
 * subprocess, and each test tears down the scopes it creates so the set is empty
 * between tests.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	handleApplication,
	registerHooks,
	invalidateDynamicProvider,
	clearDynamicProviderCache,
} from '../dist/index.js';

function makeScope() {
	const closeListeners = [];
	let middleware = null;
	const scope = {
		logger: { info: () => {}, error: () => {}, warn: () => {}, debug: () => {} },
		options: {
			_config: {
				// A static provider so the plugin registers the real OAuthResource
				// (not the no-providers error stub); the hook handles oac-* configs.
				providers: {
					github: { provider: 'github', clientId: 'gh-id', clientSecret: 'gh-secret' },
				},
			},
			getAll() {
				return this._config;
			},
			on() {},
		},
		server: {
			// The session-validation middleware registers with no options; the MCP
			// well-known handlers register with { urlPath }. Capture only the former.
			http(fn, opts) {
				if (!opts?.urlPath) middleware = fn;
				return fn;
			},
		},
		resources: {
			set() {},
		},
		on(event, listener) {
			if (event === 'close') closeListeners.push(listener);
		},
	};
	return { scope, getMiddleware: () => middleware, closeListeners };
}

/** A session whose token is far from expiry so the validator does no refresh/network. */
function oacSession(providerConfigId) {
	const future = Date.now() + 60 * 60 * 1000;
	return {
		oauth: {
			providerConfigId,
			accessToken: 'access-token',
			expiresAt: future,
			refreshThreshold: future,
		},
	};
}

describe('dynamic provider cache invalidation wiring', () => {
	it('invalidate/clear evict resolved providers, and close releases the active cache', async () => {
		// Before any plugin load there is no active cache → invalidate is a no-op.
		assert.strictEqual(invalidateDynamicProvider('oac-1'), false);

		let resolveCalls = 0;
		registerHooks({
			async onResolveProvider(providerName) {
				if (!providerName.startsWith('oac-')) return null;
				resolveCalls++;
				return {
					provider: 'generic',
					clientId: 'oac-client',
					clientSecret: 'oac-secret',
					authorizationUrl: 'https://idp.test/authorize',
					tokenUrl: 'https://idp.test/token',
					userInfoUrl: 'https://idp.test/userinfo',
					scope: 'openid',
				};
			},
		});

		const { scope, getMiddleware, closeListeners } = makeScope();
		await handleApplication(scope);
		const middleware = getMiddleware();
		assert.ok(typeof middleware === 'function', 'middleware should be registered');

		const next = (req) => req;

		// First request for oac-1 → cache miss → hook resolves and caches it.
		await middleware({ session: oacSession('oac-1') }, next);
		assert.strictEqual(resolveCalls, 1, 'hook resolves on first miss');

		// Second request → served from cache, hook not called again.
		await middleware({ session: oacSession('oac-1') }, next);
		assert.strictEqual(resolveCalls, 1, 'second request is a cache hit');

		// Invalidate the entry → evicts in this thread.
		assert.strictEqual(invalidateDynamicProvider('oac-1'), true, 'invalidate evicts a present entry');
		assert.strictEqual(invalidateDynamicProvider('oac-1'), false, 'invalidate is false once evicted');

		// Next request re-resolves via the hook (cache miss after eviction).
		await middleware({ session: oacSession('oac-1') }, next);
		assert.strictEqual(resolveCalls, 2, 'request after invalidate re-resolves');

		// clearDynamicProviderCache() drops everything → next request re-resolves.
		clearDynamicProviderCache();
		await middleware({ session: oacSession('oac-1') }, next);
		assert.strictEqual(resolveCalls, 3, 'request after clear re-resolves');

		// Scope close removes this cache from the active set → invalidate becomes a no-op.
		assert.strictEqual(closeListeners.length, 1, 'a close listener is registered');
		closeListeners[0]();
		assert.strictEqual(invalidateDynamicProvider('oac-1'), false, 'invalidate is a no-op after close');
	});

	it('invalidation reaches every plugin instance in the thread; closing one does not orphan the others', async () => {
		let resolveCalls = 0;
		const resolver = {
			async onResolveProvider(name) {
				if (!name.startsWith('oac-')) return null;
				resolveCalls++;
				return {
					provider: 'generic',
					clientId: 'oac-client',
					clientSecret: 'oac-secret',
					authorizationUrl: 'https://idp.test/authorize',
					tokenUrl: 'https://idp.test/token',
					userInfoUrl: 'https://idp.test/userinfo',
					scope: 'openid',
				};
			},
		};
		const next = (req) => req;
		const req = () => ({ session: oacSession('oac-x') });

		// Two plugin instances loaded in the same thread/module. Register the hook
		// after each handleApplication so it binds to that instance's hookManager.
		const a = makeScope();
		await handleApplication(a.scope);
		registerHooks(resolver);
		const midA = a.getMiddleware();
		await midA(req(), next); // A resolves + caches oac-x (resolveCalls: 1)

		const b = makeScope();
		await handleApplication(b.scope);
		registerHooks(resolver);
		const midB = b.getMiddleware();
		await midB(req(), next); // B resolves + caches oac-x (resolveCalls: 2)
		assert.strictEqual(resolveCalls, 2, 'each instance resolved and cached once');

		// invalidate must reach BOTH instances. (The old single-reference design
		// tracked only the last-loaded instance, so A's cache was never reachable.)
		assert.strictEqual(invalidateDynamicProvider('oac-x'), true);
		await midA(req(), next); // A re-resolves → proves A was cleared (3)
		await midB(req(), next); // B re-resolves → proves B was cleared (4)
		assert.strictEqual(resolveCalls, 4, 'invalidate reached both instances, not just the last-loaded one');

		// Close B — the LAST-loaded instance. With the old `=== ` single-ref guard
		// this nulled the shared reference and broke invalidation for every still-
		// active instance. With the Set, A stays invalidatable.
		b.closeListeners[0]();
		assert.strictEqual(
			invalidateDynamicProvider('oac-x'),
			true,
			'closing the last-loaded instance must not orphan invalidation for the still-active one'
		);

		// Tear down A too; with no active caches, invalidate is a no-op.
		a.closeListeners[0]();
		assert.strictEqual(invalidateDynamicProvider('oac-x'), false, 'no active caches after all instances close');
	});
});
