/**
 * Tests for OAuth configuration and lazy initialization
 */

import { describe, it, before, after, mock } from 'node:test';
import assert from 'node:assert';
import { buildProviderConfig, getOrInitializeProvider, initializeProviders } from '../dist/lib/config.js';

describe('Lazy Environment Variable Expansion', () => {
	const originalEnv = { ...process.env };

	after(() => {
		// Restore original env vars
		process.env = originalEnv;
	});

	it('should expand env vars when accessed, not at config build time', () => {
		// Start without env var
		delete process.env.TEST_CLIENT_ID;

		const providerConfig = {
			provider: 'github',
			clientId: '${TEST_CLIENT_ID}',
			clientSecret: 'secret123',
		};

		const config = buildProviderConfig(providerConfig, 'github');

		// At this point, env var isn't set - config should have placeholder
		assert.strictEqual(config.clientId, '${TEST_CLIENT_ID}');

		// Now set the env var
		process.env.TEST_CLIENT_ID = 'actual-client-id';

		// Access the value again - should now return the env var value
		assert.strictEqual(config.clientId, 'actual-client-id');
	});

	it('should return placeholder if env var is empty string', () => {
		process.env.TEST_CLIENT_ID = '';

		const providerConfig = {
			clientId: '${TEST_CLIENT_ID}',
		};

		const config = buildProviderConfig(providerConfig, 'github');

		// Empty string should be treated as "not set"
		assert.strictEqual(config.clientId, '${TEST_CLIENT_ID}');
	});

	it('should handle non-env-var values normally', () => {
		const providerConfig = {
			clientId: 'hardcoded-id',
			scope: 'openid profile',
		};

		const config = buildProviderConfig(providerConfig, 'github');

		assert.strictEqual(config.clientId, 'hardcoded-id');
		assert.strictEqual(config.scope, 'openid profile');
	});

	it('should handle multiple env vars in same config', () => {
		delete process.env.TEST_CLIENT_ID;
		delete process.env.TEST_CLIENT_SECRET;

		const providerConfig = {
			clientId: '${TEST_CLIENT_ID}',
			clientSecret: '${TEST_CLIENT_SECRET}',
		};

		const config = buildProviderConfig(providerConfig, 'github');

		// Both should have placeholders
		assert.strictEqual(config.clientId, '${TEST_CLIENT_ID}');
		assert.strictEqual(config.clientSecret, '${TEST_CLIENT_SECRET}');

		// Set one env var
		process.env.TEST_CLIENT_ID = 'id-123';

		// Only the set one should expand
		assert.strictEqual(config.clientId, 'id-123');
		assert.strictEqual(config.clientSecret, '${TEST_CLIENT_SECRET}');

		// Set the other
		process.env.TEST_CLIENT_SECRET = 'secret-456';

		// Both should now expand
		assert.strictEqual(config.clientId, 'id-123');
		assert.strictEqual(config.clientSecret, 'secret-456');
	});
});

describe('getOrInitializeProvider', () => {
	const originalEnv = { ...process.env };
	let mockLogger;

	before(() => {
		mockLogger = {
			debug: mock.fn(),
			info: mock.fn(),
			warn: mock.fn(),
			error: mock.fn(),
		};
	});

	after(() => {
		process.env = originalEnv;
	});

	it('should return existing provider if already initialized', () => {
		const mockProvider = { provider: {}, config: { provider: 'github' } };
		const providers = {
			github: mockProvider,
		};

		const options = {
			providers: {
				github: {
					clientId: 'id',
					clientSecret: 'secret',
				},
			},
		};

		const result = getOrInitializeProvider('github', providers, options, mockLogger);

		assert.strictEqual(result, mockProvider);
		assert.strictEqual(mockLogger.info.mock.calls.length, 0); // Should not log initialization
	});

	it('should return null if provider not defined in config', () => {
		const providers = {};
		const options = {
			providers: {
				github: {},
			},
		};

		const result = getOrInitializeProvider('gitlab', providers, options, mockLogger);

		assert.strictEqual(result, null);
	});

	it('should return null if required fields still have placeholders', () => {
		delete process.env.TEST_CLIENT_ID;

		const providers = {};
		const options = {
			providers: {
				github: {
					provider: 'github',
					clientId: '${TEST_CLIENT_ID}',
					clientSecret: 'secret',
				},
			},
		};

		const result = getOrInitializeProvider('github', providers, options, mockLogger);

		assert.strictEqual(result, null);
		assert.ok(mockLogger.debug.mock.calls.length > 0); // Should log debug message about missing fields
	});

	it('should initialize provider when env vars become available', () => {
		// Start without env var
		delete process.env.TEST_CLIENT_ID;
		delete process.env.TEST_CLIENT_SECRET;

		const providers = {};
		const options = {
			providers: {
				github: {
					provider: 'github',
					clientId: '${TEST_CLIENT_ID}',
					clientSecret: '${TEST_CLIENT_SECRET}',
				},
			},
		};

		// First attempt - should fail
		let result = getOrInitializeProvider('github', providers, options, mockLogger);
		assert.strictEqual(result, null);

		// Now set env vars
		process.env.TEST_CLIENT_ID = 'test-id';
		process.env.TEST_CLIENT_SECRET = 'test-secret';

		// Second attempt - should succeed
		result = getOrInitializeProvider('github', providers, options, mockLogger);

		assert.ok(result !== null);
		assert.ok(result.provider);
		assert.strictEqual(result.config.provider, 'github');
		assert.ok(mockLogger.info.mock.calls.length > 0); // Should log initialization
	});

	it('should add initialized provider to registry', () => {
		process.env.TEST_CLIENT_ID = 'test-id';
		process.env.TEST_CLIENT_SECRET = 'test-secret';

		const providers = {};
		const options = {
			providers: {
				github: {
					provider: 'github',
					clientId: '${TEST_CLIENT_ID}',
					clientSecret: '${TEST_CLIENT_SECRET}',
				},
			},
		};

		const result = getOrInitializeProvider('github', providers, options, mockLogger);

		// Should be added to providers registry
		assert.ok(providers.github);
		assert.strictEqual(providers.github, result);
	});
});

describe('initializeProviders', () => {
	const originalEnv = { ...process.env };
	let mockLogger;

	before(() => {
		mockLogger = {
			debug: mock.fn(),
			info: mock.fn(),
			warn: mock.fn(),
			error: mock.fn(),
		};
	});

	after(() => {
		process.env = originalEnv;
	});

	it('should skip providers with missing env vars', () => {
		delete process.env.TEST_CLIENT_ID;

		const options = {
			providers: {
				github: {
					provider: 'github',
					clientId: '${TEST_CLIENT_ID}',
					clientSecret: 'secret',
				},
			},
		};

		const providers = initializeProviders(options, mockLogger);

		assert.strictEqual(Object.keys(providers).length, 0);
		assert.ok(mockLogger.warn.mock.calls.length > 0); // Should warn about missing fields
	});

	it('should initialize providers when env vars are available', () => {
		process.env.TEST_CLIENT_ID = 'test-id';
		process.env.TEST_CLIENT_SECRET = 'test-secret';

		const options = {
			providers: {
				github: {
					provider: 'github',
					clientId: '${TEST_CLIENT_ID}',
					clientSecret: '${TEST_CLIENT_SECRET}',
				},
			},
		};

		const providers = initializeProviders(options, mockLogger);

		assert.strictEqual(Object.keys(providers).length, 1);
		assert.ok(providers.github);
		assert.strictEqual(providers.github.config.provider, 'github');
	});

	it('should handle mix of ready and not-ready providers', () => {
		process.env.GITHUB_CLIENT_ID = 'github-id';
		process.env.GITHUB_CLIENT_SECRET = 'github-secret';
		delete process.env.GOOGLE_CLIENT_ID;

		const options = {
			providers: {
				github: {
					provider: 'github',
					clientId: '${GITHUB_CLIENT_ID}',
					clientSecret: '${GITHUB_CLIENT_SECRET}',
				},
				google: {
					provider: 'google',
					clientId: '${GOOGLE_CLIENT_ID}',
					clientSecret: 'secret',
				},
			},
		};

		const providers = initializeProviders(options, mockLogger);

		// Only github should be initialized
		assert.strictEqual(Object.keys(providers).length, 1);
		assert.ok(providers.github);
		assert.strictEqual(providers.google, undefined);
	});
});
