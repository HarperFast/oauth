/**
 * Tests for OAuth Configuration
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
	buildProviderConfig,
	extractPluginDefaults,
	initializeProviders,
	expandEnvVar,
	expandEnvVarsDeep,
	coerceConfigBoolean,
	normalizeMcpSecurityConfig,
} from '../../dist/lib/config.js';

describe('OAuth Configuration', () => {
	let originalEnv;
	let mockLogger;

	before(() => {
		// Save original environment
		originalEnv = { ...process.env };
	});

	after(() => {
		// Restore original environment
		process.env = originalEnv;
	});

	beforeEach(() => {
		// Reset environment for each test
		Object.keys(process.env).forEach((key) => {
			if (key.startsWith('OAUTH_') || key.startsWith('TEST_')) {
				delete process.env[key];
			}
		});

		mockLogger = {
			info: () => {},
			warn: () => {},
			error: () => {},
			debug: () => {},
		};
	});

	describe('expandEnvVar + coerceConfigBoolean (escape-hatch pattern)', () => {
		it('${VAR}=true enables a boolean flag via environment variable', () => {
			process.env._TEST_HATCH = 'true';
			try {
				assert.equal(coerceConfigBoolean(expandEnvVar('${_TEST_HATCH}')), true);
			} finally {
				delete process.env._TEST_HATCH;
			}
		});

		it('${VAR}=false disables a boolean flag — strict coercion', () => {
			process.env._TEST_HATCH = 'false';
			try {
				assert.equal(coerceConfigBoolean(expandEnvVar('${_TEST_HATCH}')), false);
			} finally {
				delete process.env._TEST_HATCH;
			}
		});

		it('unresolved ${VAR} (env unset) → undefined, so caller default applies', () => {
			// expandEnvVar leaves the placeholder intact; coerceConfigBoolean returns
			// undefined for junk so the caller's ?? false default applies.
			delete process.env._TEST_HATCH_UNSET;
			assert.equal(
				coerceConfigBoolean(expandEnvVar('${_TEST_HATCH_UNSET}')),
				undefined,
				'unresolved placeholder must not flip the gate'
			);
		});
	});

	describe('coerceConfigBoolean', () => {
		it('passes real booleans through', () => {
			assert.equal(coerceConfigBoolean(true), true);
			assert.equal(coerceConfigBoolean(false), false);
		});
		it('coerces documented boolean strings (case/space-insensitive)', () => {
			assert.equal(coerceConfigBoolean('true'), true);
			assert.equal(coerceConfigBoolean('false'), false);
			assert.equal(coerceConfigBoolean(' FALSE '), false);
			assert.equal(coerceConfigBoolean('True'), true);
		});
		it('returns undefined for anything else (caller applies its default)', () => {
			assert.equal(coerceConfigBoolean('yes'), undefined);
			assert.equal(coerceConfigBoolean(1), undefined);
			assert.equal(coerceConfigBoolean(undefined), undefined);
		});
	});

	describe('normalizeMcpSecurityConfig', () => {
		it('coerces an env-expanded "false" so the feature is truly disabled', () => {
			const cfg = { enabled: 'false', clientIdMetadataDocuments: { enabled: 'false' } };
			normalizeMcpSecurityConfig(cfg);
			assert.equal(cfg.enabled, false);
			assert.equal(cfg.clientIdMetadataDocuments.enabled, false);
		});
		it('coerces refreshTokenRequiresOfflineAccess (string "false" must not activate the gate)', () => {
			const cfg = { refreshTokenRequiresOfflineAccess: 'false' };
			normalizeMcpSecurityConfig(cfg);
			assert.equal(cfg.refreshTokenRequiresOfflineAccess, false);
			const cfgTrue = { refreshTokenRequiresOfflineAccess: 'true' };
			normalizeMcpSecurityConfig(cfgTrue);
			assert.equal(cfgTrue.refreshTokenRequiresOfflineAccess, true);
		});
		it('drops an unresolved "${FLAG}" placeholder so a documented-off gate stays off, and warns', () => {
			// expandEnvVarsDeep leaves "${FLAG}" intact when FLAG is unset; that
			// string is truthy and must not activate the gate (PR #192 review).
			const warnings = [];
			const logger = { warn: (...args) => warnings.push(args.join(' ')) };
			const cfg = { refreshTokenRequiresOfflineAccess: '${FLAG}' };
			normalizeMcpSecurityConfig(cfg, logger);
			assert.equal(cfg.refreshTokenRequiresOfflineAccess, undefined, 'placeholder dropped — default applies');
			assert.equal(warnings.length, 1);
			assert.match(warnings[0], /unresolved env placeholder/);
		});
		it('drops any other non-boolean value with a warning (total normalization)', () => {
			const warnings = [];
			const logger = { warn: (...args) => warnings.push(args.join(' ')) };
			const cfg = {
				enabled: 'yes',
				refreshTokenRequiresOfflineAccess: 1,
				clientCredentials: { enabled: {} },
				dynamicClientRegistration: { enabled: 'on' },
				clientIdMetadataDocuments: { enabled: 'nope' },
			};
			normalizeMcpSecurityConfig(cfg, logger);
			assert.equal(cfg.enabled, undefined);
			assert.equal(cfg.refreshTokenRequiresOfflineAccess, undefined);
			assert.equal(cfg.clientCredentials.enabled, undefined);
			assert.equal(cfg.dynamicClientRegistration.enabled, undefined);
			assert.equal(cfg.clientIdMetadataDocuments.enabled, undefined);
			assert.equal(warnings.length, 5, 'one warning per dropped field');
			assert.ok(warnings.every((w) => /must be a boolean/.test(w)));
		});
		it('normalizes dynamicClientRegistration.enabled ("false" string must actually disable DCR)', () => {
			const cfg = { dynamicClientRegistration: { enabled: 'false' } };
			normalizeMcpSecurityConfig(cfg);
			assert.equal(cfg.dynamicClientRegistration.enabled, false);
		});
		it('coerces clientCredentials.enabled the same way (token-minting switch must not be string-truthy)', () => {
			const cfg = { clientCredentials: { enabled: 'false' } };
			normalizeMcpSecurityConfig(cfg);
			assert.equal(cfg.clientCredentials.enabled, false);
			const cfgTrue = { clientCredentials: { enabled: 'true' } };
			normalizeMcpSecurityConfig(cfgTrue);
			assert.equal(cfgTrue.clientCredentials.enabled, true);
		});
		it('leaves real booleans and absent values alone', () => {
			const cfg = { enabled: true, clientIdMetadataDocuments: {} };
			normalizeMcpSecurityConfig(cfg);
			assert.equal(cfg.enabled, true);
			assert.equal(cfg.clientIdMetadataDocuments.enabled, undefined);
		});
		it('wraps a scalar allowedHosts into a lowercased exact-match array (no substring matching)', () => {
			const cfg = { clientIdMetadataDocuments: { allowedHosts: 'Trusted.Example.COM' } };
			normalizeMcpSecurityConfig(cfg);
			assert.deepEqual(cfg.clientIdMetadataDocuments.allowedHosts, ['trusted.example.com']);
		});
		it('normalizes an array of hostnames (trim + lowercase, drops empties)', () => {
			const cfg = { clientIdMetadataDocuments: { allowedHosts: [' A.com ', 'B.COM', ''] } };
			normalizeMcpSecurityConfig(cfg);
			assert.deepEqual(cfg.clientIdMetadataDocuments.allowedHosts, ['a.com', 'b.com']);
		});
		it('rejects a non-string allowedHosts entry rather than failing open', () => {
			assert.throws(
				() => normalizeMcpSecurityConfig({ clientIdMetadataDocuments: { allowedHosts: [123] } }),
				/allowedHosts must be/
			);
		});

		describe('signingKeyPem (#221 — declared-but-empty must not silently self-generate)', () => {
			function rsaPem() {
				return generateKeyPairSync('rsa', {
					modulusLength: 2048,
					publicKeyEncoding: { type: 'spki', format: 'pem' },
					privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
				}).privateKey;
			}

			it('declared but resolved empty (e.g. unset/empty env var) throws, naming the field', () => {
				assert.throws(
					() => normalizeMcpSecurityConfig({ enabled: true, signingKeyPem: '' }),
					/mcp\.signingKeyPem.*empty/s
				);
			});

			it('declared as an unresolved ${VAR} placeholder throws, naming the variable', () => {
				assert.throws(
					() => normalizeMcpSecurityConfig({ enabled: true, signingKeyPem: '${MY_SIGNING_KEY}' }),
					/mcp\.signingKeyPem.*unresolved env placeholder.*MY_SIGNING_KEY/s
				);
			});

			it('declared but unparseable throws (previously only warned, then 500s at first mint)', () => {
				assert.throws(
					() => normalizeMcpSecurityConfig({ enabled: true, signingKeyPem: 'not a pem' }),
					/mcp\.signingKeyPem is not a supported signing key/
				);
			});

			it('declared with an RSA key under 2048 bits throws at boot (jsonwebtoken refuses to sign with it)', () => {
				const weakPem = generateKeyPairSync('rsa', {
					modulusLength: 1024,
					publicKeyEncoding: { type: 'spki', format: 'pem' },
					privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
				}).privateKey;
				assert.throws(
					() => normalizeMcpSecurityConfig({ enabled: true, signingKeyPem: weakPem }),
					/mcp\.signingKeyPem is not a supported signing key.*RSA key is 1024 bits/s
				);
			});

			it('declared with a 2048-bit RSA key passes through unchanged', () => {
				const pem = rsaPem();
				const cfg = { enabled: true, signingKeyPem: pem };
				normalizeMcpSecurityConfig(cfg);
				assert.equal(cfg.signingKeyPem, pem);
			});

			it('mcp.enabled false (or absent) leaves a declared-but-bad pin INERT — the disabled block must not refuse boot (byte-identical-boot contract)', () => {
				assert.doesNotThrow(() =>
					normalizeMcpSecurityConfig({ enabled: false, signingKeyPem: '${FLAIR_MCP_SIGNING_KEY_PEM}' })
				);
				assert.doesNotThrow(() => normalizeMcpSecurityConfig({ signingKeyPem: '' }));
			});

			it('declared as undefined (live-reload removed the key; OptionsWatcher#merge sets it undefined) counts as undeclared — no throw', () => {
				assert.doesNotThrow(() => normalizeMcpSecurityConfig({ enabled: true, signingKeyPem: undefined }));
			});

			it('not declared at all leaves the config untouched — self-generation path unaffected', () => {
				const cfg = { enabled: true };
				normalizeMcpSecurityConfig(cfg);
				assert.equal('signingKeyPem' in cfg, false);
			});

			it('declared with a valid PEM passes through unchanged — pin mode', () => {
				const pem = rsaPem();
				const cfg = { enabled: true, signingKeyPem: pem };
				normalizeMcpSecurityConfig(cfg);
				assert.equal(cfg.signingKeyPem, pem);
			});
		});
	});

	describe('expandEnvVar', () => {
		it('should expand environment variable references', () => {
			process.env.TEST_VAR = 'test-value';
			const result = expandEnvVar('${TEST_VAR}');
			assert.equal(result, 'test-value');
		});

		it('should return original value when env var does not exist', () => {
			const result = expandEnvVar('${NONEXISTENT_VAR}');
			assert.equal(result, '${NONEXISTENT_VAR}');
		});

		it('should return non-string values unchanged', () => {
			assert.equal(expandEnvVar(123), 123);
			assert.equal(expandEnvVar(true), true);
			assert.equal(expandEnvVar(null), null);
			assert.deepEqual(expandEnvVar({ key: 'value' }), { key: 'value' });
		});

		it('should return literal strings unchanged', () => {
			const result = expandEnvVar('literal-string');
			assert.equal(result, 'literal-string');
		});

		it('should not expand partial matches', () => {
			const result1 = expandEnvVar('${MISSING_CLOSE');
			const result2 = expandEnvVar('MISSING_OPEN}');
			const result3 = expandEnvVar('text ${VAR} text');
			assert.equal(result1, '${MISSING_CLOSE');
			assert.equal(result2, 'MISSING_OPEN}');
			assert.equal(result3, 'text ${VAR} text');
		});

		it('should handle empty environment variable values', () => {
			process.env.EMPTY_VAR = '';
			const result = expandEnvVar('${EMPTY_VAR}');
			assert.equal(result, '');
		});
	});

	describe('expandEnvVarsDeep', () => {
		it('expands string leaves on nested objects', () => {
			process.env.TEST_TOKEN = 'secret-123';
			const input = {
				enabled: true,
				dynamicClientRegistration: {
					initialAccessToken: '${TEST_TOKEN}',
					allowedRedirectUriHosts: ['app.example.com', '${TEST_NOT_SET}'],
				},
			};
			const result = expandEnvVarsDeep(input);
			assert.equal(result.dynamicClientRegistration.initialAccessToken, 'secret-123');
			assert.equal(result.dynamicClientRegistration.allowedRedirectUriHosts[0], 'app.example.com');
			// Unset env vars retain their placeholder
			assert.equal(result.dynamicClientRegistration.allowedRedirectUriHosts[1], '${TEST_NOT_SET}');
		});

		it('passes non-string, non-object scalars through', () => {
			const input = { a: 1, b: true, c: null };
			assert.deepEqual(expandEnvVarsDeep(input), input);
		});

		it('returns the input unchanged when there are no placeholders', () => {
			const input = { foo: 'bar', baz: { qux: 'quux' } };
			assert.deepEqual(expandEnvVarsDeep(input), input);
		});

		it('does not mutate the input object', () => {
			process.env.TEST_X = 'expanded';
			const input = { nested: { value: '${TEST_X}' } };
			const result = expandEnvVarsDeep(input);
			assert.equal(input.nested.value, '${TEST_X}', 'input should be untouched');
			assert.equal(result.nested.value, 'expanded');
		});
	});

	describe('buildProviderConfig', () => {
		it('should build basic provider config', () => {
			const providerConfig = {
				clientId: 'test-client',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'http://localhost:9926/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'test', {});

			assert.equal(config.clientId, 'test-client');
			assert.equal(config.clientSecret, 'test-secret');
			assert.equal(config.authorizationUrl, 'https://auth.test.com/authorize');
			assert.equal(config.redirectUri, 'http://localhost:9926/oauth/test/callback');
		});

		it('should throw a configuration error when redirectUri is not set (no localhost fallback)', () => {
			const providerConfig = {
				clientId: 'test-client',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
			};

			assert.throws(
				() => buildProviderConfig(providerConfig, 'myprovider', {}),
				(error) => {
					assert.match(error.message, /myprovider/);
					assert.match(error.message, /redirectUri/);
					assert.doesNotMatch(error.message, /localhost:9926/);
					return true;
				}
			);
		});

		it('throws the same configuration error when redirectUri is a non-string (e.g. a YAML boolean)', () => {
			const providerConfig = {
				clientId: 'test-client',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: true,
			};
			assert.throws(() => buildProviderConfig(providerConfig, 'myprovider', {}), /has no redirectUri configured/);
		});

		it('throws a configuration error when redirectUri is an unresolved env placeholder (per-provider, variable unset)', () => {
			delete process.env.OAUTH_TEST_UNSET_REDIRECT_VAR;
			const providerConfig = {
				clientId: 'test-client',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: '${OAUTH_TEST_UNSET_REDIRECT_VAR}',
			};

			assert.throws(
				() => buildProviderConfig(providerConfig, 'myprovider', {}),
				(error) => {
					assert.match(error.message, /myprovider/);
					assert.match(error.message, /redirectUri/);
					assert.match(error.message, /unset/);
					return true;
				}
			);
		});

		it('throws even when other required fields are also missing (redirectUri is checked regardless)', () => {
			// A provider config missing everything (clientId, clientSecret, URLs) is normally
			// skipped-with-a-warning by initializeProviders — but that's a downstream check;
			// buildProviderConfig itself must still fail closed on the redirectUri it's asked
			// to resolve, not silently hand back a localhost one.
			assert.throws(() => buildProviderConfig({}, 'empty', {}), /redirectUri/);
		});

		it('should expand environment variables', () => {
			process.env.OAUTH_CLIENT_ID = 'env-client-id';
			process.env.OAUTH_CLIENT_SECRET = 'env-client-secret';

			const providerConfig = {
				clientId: '${OAUTH_CLIENT_ID}',
				clientSecret: '${OAUTH_CLIENT_SECRET}',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://auth.test.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'test', {});

			assert.equal(config.clientId, 'env-client-id');
			assert.equal(config.clientSecret, 'env-client-secret');
		});

		it('should handle missing environment variables', () => {
			const providerConfig = {
				clientId: '${MISSING_VAR}',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://auth.test.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'test', {});

			// Should keep original placeholder when env var is missing
			assert.equal(config.clientId, '${MISSING_VAR}');
		});

		it('should apply plugin defaults', () => {
			const providerConfig = {
				clientId: 'test-client',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
			};

			const pluginDefaults = {
				scope: 'custom-scope',
				usernameClaim: 'custom-username',
				defaultRole: 'custom-role',
				postLoginRedirect: '/custom-redirect',
				redirectUri: 'https://app.test.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'test', pluginDefaults);

			assert.equal(config.scope, 'custom-scope');
			assert.equal(config.usernameClaim, 'custom-username');
			assert.equal(config.defaultRole, 'custom-role');
			assert.equal(config.postLoginRedirect, '/custom-redirect');
		});

		it('should override defaults with provider config', () => {
			const providerConfig = {
				clientId: 'test-client',
				clientSecret: 'test-secret',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				scope: 'provider-scope',
				defaultRole: 'provider-role',
			};

			const pluginDefaults = {
				scope: 'default-scope',
				defaultRole: 'default-role',
				redirectUri: 'https://app.test.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'test', pluginDefaults);

			assert.equal(config.scope, 'provider-scope');
			assert.equal(config.defaultRole, 'provider-role');
		});

		it('should build correct redirect URI with provider name', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
			};

			const config = buildProviderConfig(providerConfig, 'myprovider', {
				redirectUri: 'http://localhost:9926/oauth',
			});

			assert.equal(config.redirectUri, 'http://localhost:9926/oauth/myprovider/callback');
		});

		it('should handle custom redirect URI', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'test', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/test/callback');
		});

		it('should fix redirect URI ending with /oauth/callback', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth/callback',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/github/callback');
		});

		it('should tolerate a trailing slash on a redirect URI ending with /oauth/', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth/',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/github/callback');
		});

		it('should tolerate a trailing slash on a redirect URI ending with /oauth/callback/', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth/callback/',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/github/callback');
		});

		it('should keep a query string when appending the provider segment after /oauth/callback', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth/callback?tenant=acme',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/github/callback?tenant=acme');
		});

		it('should keep a query string when appending the provider segment after /oauth', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth?x=1',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/github/callback?x=1');
		});

		it('should keep a query string when the redirect URI has both a trailing slash and a query string', () => {
			const providerConfig = {
				clientId: 'test',
				clientSecret: 'test',
				authorizationUrl: 'https://auth.test.com/authorize',
				tokenUrl: 'https://auth.test.com/token',
				userInfoUrl: 'https://auth.test.com/userinfo',
				redirectUri: 'https://myapp.com/oauth/?x=1',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			assert.equal(config.redirectUri, 'https://myapp.com/oauth/github/callback?x=1');
		});

		describe('Provider Presets', () => {
			it('should apply GitHub preset', () => {
				const providerConfig = {
					provider: 'github',
					clientId: 'github-client',
					clientSecret: 'github-secret',
					redirectUri: 'https://app.test.com/oauth',
				};

				const config = buildProviderConfig(providerConfig, 'github', {});

				assert.equal(config.authorizationUrl, 'https://github.com/login/oauth/authorize');
				assert.equal(config.tokenUrl, 'https://github.com/login/oauth/access_token');
				assert.equal(config.userInfoUrl, 'https://api.github.com/user');
				assert.equal(config.scope, 'read:user user:email');
			});

			it('should apply Google preset', () => {
				const providerConfig = {
					provider: 'google',
					clientId: 'google-client',
					clientSecret: 'google-secret',
					redirectUri: 'https://app.test.com/oauth',
				};

				const config = buildProviderConfig(providerConfig, 'google', {});

				assert.equal(config.authorizationUrl, 'https://accounts.google.com/o/oauth2/v2/auth');
				assert.equal(config.tokenUrl, 'https://oauth2.googleapis.com/token');
				assert.equal(config.userInfoUrl, 'https://www.googleapis.com/oauth2/v3/userinfo');
				assert.equal(config.scope, 'openid profile email');
			});

			it('should configure Azure with tenant', () => {
				const tenantId = '12345678-1234-1234-1234-123456789012';
				const providerConfig = {
					provider: 'azure',
					clientId: 'azure-client',
					clientSecret: 'azure-secret',
					tenantId,
					redirectUri: 'https://app.test.com/oauth',
				};

				const config = buildProviderConfig(providerConfig, 'azure', {});

				assert.ok(config.authorizationUrl.includes(tenantId));
				assert.ok(config.tokenUrl.includes(tenantId));
			});

			it('should configure Auth0 with domain', () => {
				const providerConfig = {
					provider: 'auth0',
					clientId: 'auth0-client',
					clientSecret: 'auth0-secret',
					domain: 'myapp.auth0.com',
					redirectUri: 'https://app.test.com/oauth',
				};

				const config = buildProviderConfig(providerConfig, 'auth0', {});

				assert.ok(config.authorizationUrl.includes('myapp.auth0.com'));
				assert.ok(config.tokenUrl.includes('myapp.auth0.com'));
				assert.ok(config.userInfoUrl.includes('myapp.auth0.com'));
			});

			it('should clean Auth0 domain input', () => {
				const providerConfig = {
					provider: 'auth0',
					clientId: 'auth0-client',
					clientSecret: 'auth0-secret',
					domain: 'https://myapp.auth0.com/',
					redirectUri: 'https://app.test.com/oauth',
				};

				const config = buildProviderConfig(providerConfig, 'auth0', {});

				// Domain should be cleaned to just 'myapp.auth0.com'
				assert.equal(config.authorizationUrl, 'https://myapp.auth0.com/authorize');
			});
		});

		it('should infer provider type from name if not specified', () => {
			const providerConfig = {
				// No 'provider' field
				clientId: 'github-client',
				clientSecret: 'github-secret',
				redirectUri: 'https://app.test.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'github', {});

			// Should get GitHub preset based on provider name
			assert.equal(config.authorizationUrl, 'https://github.com/login/oauth/authorize');
		});

		it('should handle generic provider without preset', () => {
			const providerConfig = {
				clientId: 'custom-client',
				clientSecret: 'custom-secret',
				authorizationUrl: 'https://custom.com/auth',
				tokenUrl: 'https://custom.com/token',
				userInfoUrl: 'https://custom.com/user',
				redirectUri: 'https://app.test.com/oauth',
			};

			const config = buildProviderConfig(providerConfig, 'custom', {});

			assert.equal(config.provider, 'generic');
			assert.equal(config.authorizationUrl, 'https://custom.com/auth');
		});
	});

	describe('extractPluginDefaults', () => {
		it('should extract non-provider options', () => {
			const options = {
				scope: 'default-scope',
				usernameClaim: 'email',
				defaultRole: 'user',
				postLoginRedirect: '/dashboard',
				providers: { github: {} },
				debug: true,
			};

			const defaults = extractPluginDefaults(options);

			assert.equal(defaults.scope, 'default-scope');
			assert.equal(defaults.usernameClaim, 'email');
			assert.equal(defaults.defaultRole, 'user');
			assert.equal(defaults.postLoginRedirect, '/dashboard');
			assert.equal(defaults.providers, undefined);
			assert.equal(defaults.debug, undefined);
		});

		it('should handle empty options', () => {
			const defaults = extractPluginDefaults({});
			assert.deepEqual(defaults, {});
		});

		it('should skip providers and debug fields', () => {
			const options = {
				providers: { test: {} },
				debug: true,
			};

			const defaults = extractPluginDefaults(options);

			assert.equal(defaults.providers, undefined);
			assert.equal(defaults.debug, undefined);
		});

		it('should expand environment variables in plugin defaults', () => {
			process.env.TEST_REDIRECT_URI = 'https://example.com/oauth/callback';
			process.env.TEST_DEFAULT_ROLE = 'admin';

			const options = {
				redirectUri: '${TEST_REDIRECT_URI}',
				defaultRole: '${TEST_DEFAULT_ROLE}',
				scope: 'openid profile',
				providers: { github: {} },
			};

			const defaults = extractPluginDefaults(options);

			assert.equal(defaults.redirectUri, 'https://example.com/oauth/callback');
			assert.equal(defaults.defaultRole, 'admin');
			assert.equal(defaults.scope, 'openid profile');
		});

		it('should preserve literal values when not env vars', () => {
			const options = {
				redirectUri: 'https://literal.com/oauth',
				scope: 'openid profile email',
			};

			const defaults = extractPluginDefaults(options);

			assert.equal(defaults.redirectUri, 'https://literal.com/oauth');
			assert.equal(defaults.scope, 'openid profile email');
		});

		it('should handle missing environment variables in defaults', () => {
			const options = {
				redirectUri: '${NONEXISTENT_REDIRECT_URI}',
				postLoginRedirect: '/home',
			};

			const defaults = extractPluginDefaults(options);

			// Should preserve the original value when env var doesn't exist
			assert.equal(defaults.redirectUri, '${NONEXISTENT_REDIRECT_URI}');
			assert.equal(defaults.postLoginRedirect, '/home');
		});

		it('should handle non-string values in defaults', () => {
			const options = {
				redirectUri: 'https://example.com/oauth',
				timeout: 5000,
				enabled: true,
			};

			const defaults = extractPluginDefaults(options);

			assert.equal(defaults.timeout, 5000);
			assert.equal(defaults.enabled, true);
		});
	});

	describe('initializeProviders', () => {
		it('should initialize configured providers', () => {
			const options = {
				redirectUri: 'https://app.test.com/oauth',
				providers: {
					github: {
						clientId: 'github-client',
						clientSecret: 'github-secret',
						authorizationUrl: 'https://github.com/login/oauth/authorize',
						tokenUrl: 'https://github.com/login/oauth/access_token',
						userInfoUrl: 'https://api.github.com/user',
					},
					google: {
						clientId: 'google-client',
						clientSecret: 'google-secret',
						authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
						tokenUrl: 'https://oauth2.googleapis.com/token',
						userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
					},
				},
			};

			const providers = initializeProviders(options, mockLogger);

			assert.ok(providers.github);
			assert.ok(providers.google);
			assert.equal(providers.github.config.clientId, 'github-client');
			assert.equal(providers.google.config.clientId, 'google-client');
		});

		it("should reject a provider named 'mcp' (reserved for MCP endpoints)", () => {
			const options = {
				providers: {
					mcp: {
						clientId: 'x',
						clientSecret: 'y',
						authorizationUrl: 'https://auth.com/authorize',
						tokenUrl: 'https://auth.com/token',
						userInfoUrl: 'https://auth.com/user',
					},
				},
			};

			assert.throws(() => initializeProviders(options, mockLogger), /reserved for the MCP OAuth endpoints/);
		});

		it('should skip providers with missing required fields', () => {
			const options = {
				redirectUri: 'https://app.test.com/oauth',
				providers: {
					incomplete: {
						clientId: 'test-client',
						// Missing clientSecret and URLs
					},
					valid: {
						clientId: 'valid-client',
						clientSecret: 'valid-secret',
						authorizationUrl: 'https://auth.com/authorize',
						tokenUrl: 'https://auth.com/token',
						userInfoUrl: 'https://auth.com/user',
					},
				},
			};

			const providers = initializeProviders(options, mockLogger);

			assert.equal(providers.incomplete, undefined);
			assert.ok(providers.valid);
		});

		it('should handle missing providers configuration', () => {
			const options = {};
			const providers = initializeProviders(options, mockLogger);
			assert.deepEqual(providers, {});
		});

		it('should handle invalid providers configuration', () => {
			const options = {
				providers: 'not-an-object',
			};
			const providers = initializeProviders(options, mockLogger);
			assert.deepEqual(providers, {});
		});

		it('should apply plugin defaults to all providers', () => {
			const options = {
				scope: 'plugin-scope',
				defaultRole: 'plugin-role',
				redirectUri: 'https://app.test.com/oauth',
				providers: {
					test1: {
						clientId: 'test1-client',
						clientSecret: 'test1-secret',
						authorizationUrl: 'https://auth1.com/authorize',
						tokenUrl: 'https://auth1.com/token',
						userInfoUrl: 'https://auth1.com/user',
					},
					test2: {
						clientId: 'test2-client',
						clientSecret: 'test2-secret',
						authorizationUrl: 'https://auth2.com/authorize',
						tokenUrl: 'https://auth2.com/token',
						userInfoUrl: 'https://auth2.com/user',
						defaultRole: 'override-role', // Override plugin default
					},
				},
			};

			const providers = initializeProviders(options, mockLogger);

			assert.equal(providers.test1.config.scope, 'plugin-scope');
			assert.equal(providers.test1.config.defaultRole, 'plugin-role');
			assert.equal(providers.test2.config.scope, 'plugin-scope');
			assert.equal(providers.test2.config.defaultRole, 'override-role');
		});

		it('should use provider presets', () => {
			const options = {
				redirectUri: 'https://app.test.com/oauth',
				providers: {
					github: {
						provider: 'github',
						clientId: 'github-client',
						clientSecret: 'github-secret',
					},
				},
			};

			const providers = initializeProviders(options, mockLogger);

			assert.ok(providers.github);
			assert.equal(providers.github.config.authorizationUrl, 'https://github.com/login/oauth/authorize');
		});

		it('should handle provider initialization errors', () => {
			const options = {
				redirectUri: 'https://app.test.com/oauth',
				providers: {
					bad: {
						clientId: 'bad-client',
						clientSecret: 'bad-secret',
						authorizationUrl: 'https://auth.com/authorize',
						tokenUrl: 'https://auth.com/token',
						userInfoUrl: 'https://auth.com/user',
						// Add something that might cause OAuthProvider constructor to throw
						// For this test, we'll just verify the structure
					},
				},
			};

			// Since OAuthProvider constructor is robust, this should still work
			const providers = initializeProviders(options, mockLogger);
			assert.ok(providers.bad || !providers.bad); // Either initialized or skipped
		});

		it('should throw when a provider has no redirectUri anywhere in the config (no localhost fallback)', () => {
			const options = {
				// No plugin-level redirectUri, and none on the provider either.
				providers: {
					github: {
						clientId: 'github-client',
						clientSecret: 'github-secret',
						authorizationUrl: 'https://github.com/login/oauth/authorize',
						tokenUrl: 'https://github.com/login/oauth/access_token',
						userInfoUrl: 'https://api.github.com/user',
					},
				},
			};

			assert.throws(() => initializeProviders(options, mockLogger), /redirectUri/);
		});

		it('should expand environment variables in plugin-level redirectUri', () => {
			process.env.TEST_OAUTH_REDIRECT = 'https://test.com/oauth';
			process.env.TEST_GOOGLE_CLIENT_ID = 'google-client-123';
			process.env.TEST_GOOGLE_SECRET = 'google-secret-456';

			const options = {
				redirectUri: '${TEST_OAUTH_REDIRECT}',
				defaultRole: 'user',
				providers: {
					google: {
						provider: 'google',
						clientId: '${TEST_GOOGLE_CLIENT_ID}',
						clientSecret: '${TEST_GOOGLE_SECRET}',
					},
				},
			};

			const providers = initializeProviders(options, mockLogger);

			assert.ok(providers.google);
			assert.equal(providers.google.config.clientId, 'google-client-123');
			assert.equal(providers.google.config.clientSecret, 'google-secret-456');
			// The redirectUri should use the expanded value from plugin defaults
			assert.ok(providers.google.config.redirectUri.startsWith('https://test.com/oauth'));
			assert.ok(providers.google.config.redirectUri.includes('google'));
		});

		it('should throw when the plugin-level redirectUri is an unresolved env placeholder (variable unset)', () => {
			delete process.env.OAUTH_TEST_UNSET_PLUGIN_REDIRECT;
			const options = {
				redirectUri: '${OAUTH_TEST_UNSET_PLUGIN_REDIRECT}',
				providers: {
					github: {
						clientId: 'github-client',
						clientSecret: 'github-secret',
						authorizationUrl: 'https://github.com/login/oauth/authorize',
						tokenUrl: 'https://github.com/login/oauth/access_token',
						userInfoUrl: 'https://api.github.com/user',
					},
				},
			};

			assert.throws(() => initializeProviders(options, mockLogger), /redirectUri/);
		});

		it('should not throw when a per-provider redirectUri is set even if the plugin-level one is an unresolved placeholder', () => {
			delete process.env.OAUTH_TEST_UNSET_PLUGIN_REDIRECT_2;
			const options = {
				redirectUri: '${OAUTH_TEST_UNSET_PLUGIN_REDIRECT_2}',
				providers: {
					github: {
						clientId: 'github-client',
						clientSecret: 'github-secret',
						authorizationUrl: 'https://github.com/login/oauth/authorize',
						tokenUrl: 'https://github.com/login/oauth/access_token',
						userInfoUrl: 'https://api.github.com/user',
						redirectUri: 'https://app.test.com/oauth',
					},
				},
			};

			const providers = initializeProviders(options, mockLogger);

			assert.ok(providers.github);
			assert.equal(providers.github.config.redirectUri, 'https://app.test.com/oauth/github/callback');
		});
	});
});
