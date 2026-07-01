/**
 * Tests for SENSITIVE_KEY_PATTERN and redactSecrets
 *
 * Verifies that secret-bearing config keys are redacted in all casing conventions
 * (camelCase, snake_case, kebab-case) and that non-secret keys remain intact.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { redactSecrets, SENSITIVE_KEY_PATTERN } from '../dist/lib/redact.js';

describe('redactSecrets', () => {
	describe('redacts camelCase secret keys', () => {
		it('redacts clientSecret', () => {
			assert.deepEqual(redactSecrets({ clientSecret: 'abc123' }), { clientSecret: '[REDACTED]' });
		});

		it('redacts signingKeyPem', () => {
			assert.deepEqual(redactSecrets({ signingKeyPem: 'pem-data' }), { signingKeyPem: '[REDACTED]' });
		});

		it('redacts initialAccessToken', () => {
			assert.deepEqual(redactSecrets({ initialAccessToken: 'tok' }), { initialAccessToken: '[REDACTED]' });
		});

		it('redacts privateKey', () => {
			assert.deepEqual(redactSecrets({ privateKey: 'key-data' }), { privateKey: '[REDACTED]' });
		});

		it('redacts apiKey', () => {
			assert.deepEqual(redactSecrets({ apiKey: 'k' }), { apiKey: '[REDACTED]' });
		});

		it('redacts password', () => {
			assert.deepEqual(redactSecrets({ password: 'hunter2' }), { password: '[REDACTED]' });
		});

		it('redacts passphrase', () => {
			assert.deepEqual(redactSecrets({ passphrase: 'secret phrase' }), { passphrase: '[REDACTED]' });
		});

		it('redacts credential', () => {
			assert.deepEqual(redactSecrets({ credential: 'cred' }), { credential: '[REDACTED]' });
		});
	});

	describe('redacts snake_case secret keys', () => {
		it('redacts client_secret', () => {
			assert.deepEqual(redactSecrets({ client_secret: 'abc123' }), { client_secret: '[REDACTED]' });
		});

		it('redacts signing_key_pem', () => {
			assert.deepEqual(redactSecrets({ signing_key_pem: 'pem-data' }), { signing_key_pem: '[REDACTED]' });
		});

		it('redacts initial_access_token', () => {
			assert.deepEqual(redactSecrets({ initial_access_token: 'tok' }), { initial_access_token: '[REDACTED]' });
		});

		it('redacts private_key', () => {
			assert.deepEqual(redactSecrets({ private_key: 'key-data' }), { private_key: '[REDACTED]' });
		});

		it('redacts api_key', () => {
			assert.deepEqual(redactSecrets({ api_key: 'k' }), { api_key: '[REDACTED]' });
		});

		it('redacts passphrase (snake already single word)', () => {
			assert.deepEqual(redactSecrets({ passphrase: 'secret phrase' }), { passphrase: '[REDACTED]' });
		});

		it('redacts credential (snake already single word)', () => {
			assert.deepEqual(redactSecrets({ credential: 'cred' }), { credential: '[REDACTED]' });
		});
	});

	describe('redacts nested objects (recursion)', () => {
		it('redacts secret nested under mcp.dynamicClientRegistration.initialAccessToken', () => {
			const input = {
				mcp: {
					enabled: true,
					dynamicClientRegistration: {
						initialAccessToken: 'secret-token',
					},
				},
			};
			const result = redactSecrets(input);
			assert.equal(result.mcp.dynamicClientRegistration.initialAccessToken, '[REDACTED]');
			assert.equal(result.mcp.enabled, true);
		});

		it('redacts secret nested under providers.myProvider.clientSecret', () => {
			const input = {
				providers: {
					myProvider: {
						clientId: 'id-123',
						clientSecret: 'shh',
					},
				},
			};
			const result = redactSecrets(input);
			assert.equal(result.providers.myProvider.clientSecret, '[REDACTED]');
			assert.equal(result.providers.myProvider.clientId, 'id-123');
		});
	});

	describe('redacts secrets inside arrays', () => {
		it('redacts secrets in array elements', () => {
			const input = [{ clientSecret: 'abc' }, { enabled: true }];
			const result = redactSecrets(input);
			assert.equal(result[0].clientSecret, '[REDACTED]');
			assert.equal(result[1].enabled, true);
		});
	});

	describe('does NOT redact non-secret keys', () => {
		it('preserves issuer', () => {
			assert.deepEqual(redactSecrets({ issuer: 'https://as.example.com' }), {
				issuer: 'https://as.example.com',
			});
		});

		it('preserves enabled', () => {
			assert.deepEqual(redactSecrets({ enabled: true }), { enabled: true });
		});

		it('preserves clientId', () => {
			assert.deepEqual(redactSecrets({ clientId: 'app-client-id' }), { clientId: 'app-client-id' });
		});

		it('preserves redirectUri', () => {
			assert.deepEqual(redactSecrets({ redirectUri: 'https://app.example.com/cb' }), {
				redirectUri: 'https://app.example.com/cb',
			});
		});

		it('preserves resource', () => {
			assert.deepEqual(redactSecrets({ resource: 'https://app.example.com/mcp' }), {
				resource: 'https://app.example.com/mcp',
			});
		});

		it('preserves refreshTokenTtl', () => {
			assert.deepEqual(redactSecrets({ refreshTokenTtl: 86400 }), { refreshTokenTtl: 86400 });
		});

		it('preserves accessTokenTtl', () => {
			assert.deepEqual(redactSecrets({ accessTokenTtl: 3600 }), { accessTokenTtl: 3600 });
		});
	});

	describe('case-insensitivity', () => {
		it('redacts CLIENT_SECRET (upper case)', () => {
			assert.deepEqual(redactSecrets({ CLIENT_SECRET: 'val' }), { CLIENT_SECRET: '[REDACTED]' });
		});

		it('redacts Password (mixed case)', () => {
			assert.deepEqual(redactSecrets({ Password: 'val' }), { Password: '[REDACTED]' });
		});
	});

	describe('preserves non-object scalar values', () => {
		it('returns strings unchanged', () => {
			assert.equal(redactSecrets('hello'), 'hello');
		});

		it('returns numbers unchanged', () => {
			assert.equal(redactSecrets(42), 42);
		});

		it('returns null unchanged', () => {
			assert.equal(redactSecrets(null), null);
		});
	});

	describe('non-plain-object guard — returns non-plain objects as-is', () => {
		it('returns a Date unchanged (same reference)', () => {
			const d = new Date('2024-01-01');
			assert.strictEqual(redactSecrets(d), d);
		});

		it('returns a RegExp unchanged (same reference)', () => {
			const r = /foo/i;
			assert.strictEqual(redactSecrets(r), r);
		});

		it('returns a Map unchanged (same reference)', () => {
			const m = new Map([['clientSecret', 'shh']]);
			assert.strictEqual(redactSecrets(m), m);
		});

		it('still redacts secrets in plain objects alongside non-plain values', () => {
			const d = new Date('2024-01-01');
			const input = { clientSecret: 'shh', createdAt: d };
			const result = redactSecrets(input);
			assert.equal(result.clientSecret, '[REDACTED]');
			assert.strictEqual(result.createdAt, d, 'Date value must not be converted to {}');
		});
	});
});

describe('SENSITIVE_KEY_PATTERN', () => {
	it('matches secret', () => assert.ok(SENSITIVE_KEY_PATTERN.test('clientSecret')));
	it('matches signing_key', () => assert.ok(SENSITIVE_KEY_PATTERN.test('signing_key_pem')));
	it('matches signingKey', () => assert.ok(SENSITIVE_KEY_PATTERN.test('signingKey')));
	it('matches initial_access_token', () => assert.ok(SENSITIVE_KEY_PATTERN.test('initial_access_token')));
	it('matches initialAccessToken', () => assert.ok(SENSITIVE_KEY_PATTERN.test('initialAccessToken')));
	it('matches private_key', () => assert.ok(SENSITIVE_KEY_PATTERN.test('private_key')));
	it('matches api-key (kebab)', () => assert.ok(SENSITIVE_KEY_PATTERN.test('api-key')));
	it('does NOT match refreshTokenTtl', () => assert.ok(!SENSITIVE_KEY_PATTERN.test('refreshTokenTtl')));
	it('does NOT match accessTokenTtl', () => assert.ok(!SENSITIVE_KEY_PATTERN.test('accessTokenTtl')));
	it('does NOT match clientId', () => assert.ok(!SENSITIVE_KEY_PATTERN.test('clientId')));
	it('does NOT match issuer', () => assert.ok(!SENSITIVE_KEY_PATTERN.test('issuer')));
	it('does NOT match kid', () => assert.ok(!SENSITIVE_KEY_PATTERN.test('kid')));
	it('does NOT match resource', () => assert.ok(!SENSITIVE_KEY_PATTERN.test('resource')));
});
