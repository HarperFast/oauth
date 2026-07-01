import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleApplication } from '../dist/index.js';
import { OAuthResource } from '../dist/lib/resource.js';

describe('OAuth Plugin Options Watcher', () => {
	let scope;
	let configChangeListeners;
	let closeListeners;
	let resources;
	let lastResourceSet;

	beforeEach(() => {
		// Reset listeners and resources
		configChangeListeners = [];
		closeListeners = [];
		resources = {};
		lastResourceSet = null;

		// Create mock scope
		scope = {
			logger: {
				info: () => {},
				error: () => {},
				warn: () => {},
				debug: () => {},
			},
			options: {
				_config: {
					debug: false,
					providers: {
						github: {
							provider: 'github',
							clientId: 'test-client-id',
							clientSecret: 'test-client-secret',
						},
					},
				},
				getAll() {
					return this._config;
				},
				on(event, listener) {
					if (event === 'change') {
						configChangeListeners.push(listener);
					}
				},
			},
			server: {
				http(middleware) {
					// Mock HTTP middleware registration
					return middleware;
				},
			},
			resources: {
				set(name, resource) {
					// If resource is a class with loadAsInstance = false (Resource API v2),
					// instantiate it to match Harper's behavior
					if (typeof resource === 'function' && resource.loadAsInstance === false) {
						resources[name] = new resource();
					} else {
						resources[name] = resource;
					}
					lastResourceSet = { name, resource };
				},
			},
			on(event, listener) {
				if (event === 'close') {
					closeListeners.push(listener);
				}
			},
		};
	});

	it('should initialize OAuth plugin and register change listener', async () => {
		await handleApplication(scope);

		// Should have registered the oauth resource
		assert.ok(resources.oauth, 'OAuth resource should be registered');

		// Should have registered a change listener
		assert.equal(configChangeListeners.length, 1, 'Should register one change listener');

		// Should have registered a close listener
		assert.equal(closeListeners.length, 1, 'Should register one close listener');
	});

	it('should fail to start when mcp.enabled but issuer is not pinned', async () => {
		scope.options._config.mcp = { enabled: true };
		await assert.rejects(handleApplication(scope), /mcp\.issuer is not set/);
	});

	it('should fail to start when only mcp.resource is pinned (issuer still Host-derived)', async () => {
		scope.options._config.mcp = { enabled: true, resource: 'https://app.example.com/mcp' };
		await assert.rejects(handleApplication(scope), /mcp\.issuer is not set/);
	});

	it('should start when mcp.enabled and mcp.issuer is a valid https origin', async () => {
		scope.options._config.mcp = { enabled: true, issuer: 'https://app.example.com' };
		await handleApplication(scope);
		assert.ok(resources.oauth, 'OAuth resource should be registered');
	});

	it('should start when mcp.issuer is an http origin (localhost)', async () => {
		scope.options._config.mcp = { enabled: true, issuer: 'http://localhost:9926' };
		await handleApplication(scope);
		assert.ok(resources.oauth, 'OAuth resource should be registered');
	});

	it('should start when mcp.issuer has a trailing slash (tolerated)', async () => {
		scope.options._config.mcp = { enabled: true, issuer: 'https://app.example.com/' };
		await handleApplication(scope);
		assert.ok(resources.oauth, 'OAuth resource should be registered');
	});

	it('should fail to start when mcp.issuer is schemeless', async () => {
		scope.options._config.mcp = { enabled: true, issuer: 'as.example.com' };
		await assert.rejects(handleApplication(scope), /mcp\.issuer must be an absolute http\(s\) origin/);
	});

	it('should fail to start when mcp.issuer includes a path', async () => {
		scope.options._config.mcp = { enabled: true, issuer: 'https://app.example.com/base' };
		await assert.rejects(handleApplication(scope), /mcp\.issuer must be an absolute http\(s\) origin/);
	});

	it('should start when mcp is disabled regardless of issuer/resource', async () => {
		scope.options._config.mcp = { enabled: false };
		await handleApplication(scope);
		assert.ok(resources.oauth, 'OAuth resource should be registered');
	});

	it('should start when mcp is disabled even with an invalid issuer (master switch off)', async () => {
		// `enabled: false` must not run issuer-format validation — a stale/placeholder
		// issuer left in config should not block startup when the feature is off.
		scope.options._config.mcp = { enabled: false, issuer: 'as.example.com' };
		await handleApplication(scope);
		assert.ok(resources.oauth, 'OAuth resource should be registered');
	});

	it('should update configuration when options change', async () => {
		await handleApplication(scope);

		// Initial setup should have github provider
		let response = await resources.oauth.get('', { headers: {} });
		assert.ok(response.body || response.message, 'Should have initial response');

		// Change configuration
		scope.options._config = {
			debug: true, // Enable debug mode
			providers: {
				google: {
					// Switch to google provider
					provider: 'google',
					clientId: 'google-client-id',
					clientSecret: 'google-client-secret',
				},
			},
		};

		// Trigger change event
		configChangeListeners[0]();

		// Resource should be updated
		assert.ok(lastResourceSet, 'Resource should be re-set after config change');
		assert.equal(lastResourceSet.name, 'oauth', 'OAuth resource should be updated');
	});

	it('should handle debug mode toggle', async () => {
		await handleApplication(scope);

		// Initially debug is false
		assert.equal(scope.options._config.debug, false, 'Debug should be false initially');

		// Enable debug mode
		scope.options._config = {
			...scope.options._config,
			debug: true,
		};

		// Trigger change event
		configChangeListeners[0]();

		// The resource should be updated with debug mode
		// Note: We can't easily test the debug mode behavior without a full Harper environment
		// but we can verify the resource was re-set
		assert.ok(lastResourceSet, 'Resource should be updated after debug mode change');
	});

	it('should handle provider removal', async () => {
		await handleApplication(scope);

		// Remove all providers
		scope.options._config = {
			debug: false,
			providers: {},
		};

		// Trigger change event and wait for async update
		configChangeListeners[0]();
		// Give async config update time to complete
		await new Promise((resolve) => setTimeout(resolve, 10));

		// Should set error resource when no providers
		assert.ok(resources.oauth, 'OAuth resource should still exist');
		const response = await resources.oauth.get();
		assert.equal(response.status, 503, 'Should return 503 when no providers configured');
		assert.ok(response.body.error.includes('No valid OAuth providers'), 'Should have appropriate error message');
	});

	it('should clear MCP config when a live reload drops all providers (fail closed)', async () => {
		// Start enabled with a valid provider so OAuthResource.mcpConfig is live.
		scope.options._config = {
			debug: false,
			providers: {
				github: { provider: 'github', clientId: 'test-client-id', clientSecret: 'test-client-secret' },
			},
			mcp: { enabled: true, issuer: 'https://app.example.com' },
		};
		await handleApplication(scope);
		assert.equal(OAuthResource.mcpConfig?.enabled, true, 'MCP config should be live while a provider is configured');

		// Reload to zero providers — the plugin is no longer validly configured.
		scope.options._config = { debug: false, providers: {} };
		configChangeListeners[0]();
		await new Promise((resolve) => setTimeout(resolve, 10));

		// Fail closed: the stale enabled MCP config must not survive, or withMCPAuth's
		// default getter (and the well-known handlers) would keep verifying tokens /
		// serving discovery against config the plugin no longer holds.
		assert.equal(
			OAuthResource.mcpConfig,
			undefined,
			'MCP config must be cleared on the zero-provider branch so the MCP surface fails closed'
		);
	});

	it('should handle adding new provider', async () => {
		await handleApplication(scope);

		// Add azure provider
		scope.options._config = {
			debug: false,
			providers: {
				github: {
					provider: 'github',
					clientId: 'test-client-id',
					clientSecret: 'test-client-secret',
				},
				azure: {
					provider: 'azure',
					clientId: 'azure-client-id',
					clientSecret: 'azure-client-secret',
					tenant: 'common',
				},
			},
		};

		// Trigger change event
		configChangeListeners[0]();

		// Resource should be updated with new providers
		assert.ok(lastResourceSet, 'Resource should be updated after adding provider');
		assert.equal(lastResourceSet.name, 'oauth', 'OAuth resource should be updated');
	});

	it('should handle config update errors gracefully', async () => {
		let errorLogged = false;
		scope.logger.error = (msg) => {
			if (msg.includes('Failed to update OAuth configuration') || msg.includes('Unexpected error')) {
				errorLogged = true;
			}
		};

		await handleApplication(scope);

		// Override getAll to throw an error
		scope.options.getAll = () => {
			throw new Error('Config error');
		};

		// Trigger change event
		configChangeListeners[0]();

		// Give async error handling time to complete
		await new Promise((resolve) => setTimeout(resolve, 10));

		// Should log error
		assert.ok(errorLogged, 'Should log config update errors');
	});

	it('should register HTTP middleware for session validation', async () => {
		let middlewareRegistered = false;
		scope.server.http = (middleware) => {
			middlewareRegistered = true;
			return middleware;
		};

		await handleApplication(scope);

		assert.ok(middlewareRegistered, 'Should register HTTP middleware');
	});

	it('should call close handler on scope close', async () => {
		let closeHandlerCalled = false;
		scope.logger.info = (msg) => {
			if (msg.includes('shutting down')) {
				closeHandlerCalled = true;
			}
		};

		await handleApplication(scope);

		// Trigger close event
		closeListeners[0]();

		assert.ok(closeHandlerCalled, 'Should call close handler');
	});

	it('should handle missing providers configuration', async () => {
		scope.options._config = {
			debug: false,
			// No providers key at all
		};

		await handleApplication(scope);

		// Should set error resource when providers missing
		assert.ok(resources.oauth, 'OAuth resource should exist');
		const response = await resources.oauth.get();
		assert.equal(response.status, 503, 'Should return 503 when providers missing');
	});

	it('should handle invalid provider configuration', async () => {
		scope.options._config = {
			debug: false,
			providers: {
				invalid: {
					// Missing required fields
					provider: 'github',
					// No clientId or clientSecret
				},
			},
		};

		await handleApplication(scope);

		// Should set error resource when all providers are invalid
		assert.ok(resources.oauth, 'OAuth resource should exist');
		const response = await resources.oauth.get();
		assert.equal(response.status, 503, 'Should return 503 when all providers invalid');
	});

	// Harper v5's Scope type marks resources and server as optional, but the
	// Scope constructor always assigns them. handleApplication() guards against
	// the invariant being violated — these tests exercise the guard so any
	// future regression surfaces at startup rather than as scattered failures.
	it('should throw when scope.resources is missing', async () => {
		scope.resources = undefined;

		await assert.rejects(
			handleApplication(scope),
			(err) => /scope\.resources or scope\.server is unavailable/.test(err.message),
			'expected an error citing the missing scope field'
		);
	});

	it('should throw when scope.server is missing', async () => {
		scope.server = undefined;

		await assert.rejects(
			handleApplication(scope),
			(err) => /scope\.resources or scope\.server is unavailable/.test(err.message),
			'expected an error citing the missing scope field'
		);
	});
});
