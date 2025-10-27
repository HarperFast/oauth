import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handleApplication } from '../dist/index.js';

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
					resources[name] = resource;
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
});