/**
 * Tests for token-endpoint authentication method selection
 * (clientAuthMethod.ts): what the server advertises, and the one method it
 * permits per client, including the opt-in and headless paths.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	advertisedTokenEndpointAuthMethods,
	advertisedAssertionSigningAlgorithms,
	permittedAuthMethod,
	interactiveAllowedAlgorithms,
	isClientAuthMethod,
	headlessPrivateKeyJwtActive,
	interactivePrivateKeyJwtActive,
	headlessAssertionPolicy,
} from '../../../dist/lib/mcp/clientAuthMethod.js';
import { CHATGPT_CLIENT_ID } from '../../helpers/cimdFixtures.js';

const DEFAULT = { enabled: true };
const SETTING_OFF = { enabled: true, clientIdMetadataDocuments: { privateKeyJwt: { enabled: false } } };
const MIXED = { enabled: true, clientCredentials: { enabled: true } };
const SETTING_ON = { enabled: true, clientIdMetadataDocuments: { privateKeyJwt: { enabled: true } } };

function interactive(auth, extra = {}) {
	return {
		client_id: CHATGPT_CLIENT_ID,
		client_id_issued_at: 0,
		grant_types: ['authorization_code', 'refresh_token'],
		redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
		_cimd: true,
		_cimdAuth: auth,
		...extra,
	};
}

// An interactive client with no signing-alg pin: accepts every interactive algorithm.
const interactive_unpinned = {
	client_id: 'https://unpinned.example.com/client.json',
	_cimd: true,
	grant_types: ['authorization_code'],
	_cimdAuth: { declared: ['private_key_jwt'] },
};

const CHATGPT = interactive(
	{ declared: ['none', 'private_key_jwt'], preferred: 'private_key_jwt', signingAlg: 'RS256' },
	{ jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }
);

describe('advertised methods and algorithms', () => {
	it('omits interactive private_key_jwt when the setting is absent', () => {
		assert.deepEqual(advertisedTokenEndpointAuthMethods(DEFAULT), [
			'none',
			'client_secret_basic',
			'client_secret_post',
		]);
		assert.equal(advertisedAssertionSigningAlgorithms(DEFAULT), undefined);
	});

	it('omits private_key_jwt when explicitly disabled without headless agents', () => {
		assert.deepEqual(advertisedTokenEndpointAuthMethods(SETTING_OFF), [
			'none',
			'client_secret_basic',
			'client_secret_post',
		]);
		assert.equal(advertisedAssertionSigningAlgorithms(SETTING_OFF), undefined);
	});

	it('adds private_key_jwt for headless agents, with the interactive algorithms they steer to', () => {
		assert.ok(advertisedTokenEndpointAuthMethods(MIXED).includes('private_key_jwt'));
		assert.deepEqual(advertisedAssertionSigningAlgorithms(MIXED), ['RS256', 'ES256', 'EdDSA']);
	});

	it('advertises exactly the union of the algorithms each enabled verification path accepts', () => {
		const HEADLESS_ONLY = { ...MIXED, clientIdMetadataDocuments: { enabled: false } };
		const BOTH = { ...MIXED, clientIdMetadataDocuments: { privateKeyJwt: { enabled: true } } };
		const SETTING_CIMD_OFF = {
			enabled: true,
			clientIdMetadataDocuments: { enabled: false, privateKeyJwt: { enabled: true } },
		};
		const cases = [
			[DEFAULT, false, false],
			[SETTING_OFF, false, false],
			[HEADLESS_ONLY, true, false],
			[MIXED, true, true],
			[BOTH, true, true],
			[SETTING_ON, false, true],
			[SETTING_CIMD_OFF, false, false],
		];
		for (const [config, headless, interactive] of cases) {
			assert.equal(headlessPrivateKeyJwtActive(config), headless, JSON.stringify(config));
			assert.equal(interactivePrivateKeyJwtActive(config), interactive, JSON.stringify(config));
			// The union of what the enabled paths' own policies accept.
			const expected = new Set([
				...(headless
					? headlessAssertionPolicy(config, 'https://as.example.com', 'https://as.example.com/t').algorithms
					: []),
				...(interactive ? interactiveAllowedAlgorithms(interactive_unpinned) : []),
			]);
			const advertised = advertisedAssertionSigningAlgorithms(config);
			if (expected.size === 0) {
				assert.equal(advertised, undefined, JSON.stringify(config));
				assert.ok(!advertisedTokenEndpointAuthMethods(config).includes('private_key_jwt'));
			} else {
				assert.deepEqual(new Set(advertised), expected, JSON.stringify(config));
				assert.equal(advertised.length, expected.size, 'no duplicates');
				assert.ok(advertisedTokenEndpointAuthMethods(config).includes('private_key_jwt'));
			}
		}
	});

	it('adds private_key_jwt with RS256, ES256 and EdDSA when interactive private_key_jwt is on', () => {
		assert.ok(advertisedTokenEndpointAuthMethods(SETTING_ON).includes('private_key_jwt'));
		assert.deepEqual(advertisedAssertionSigningAlgorithms(SETTING_ON), ['RS256', 'ES256', 'EdDSA']);
	});
});

describe('permittedAuthMethod — ChatGPT document', () => {
	it('resolves to none when interactive private_key_jwt is absent or explicitly disabled', () => {
		assert.deepEqual(permittedAuthMethod(CHATGPT, DEFAULT), { method: 'none' });
		assert.deepEqual(permittedAuthMethod(CHATGPT, SETTING_OFF), { method: 'none' });
	});

	it('resolves to private_key_jwt where headless agents already advertise it', () => {
		assert.deepEqual(permittedAuthMethod(CHATGPT, MIXED), { method: 'private_key_jwt' });
	});

	it('resolves to private_key_jwt when interactive private_key_jwt is on', () => {
		assert.deepEqual(permittedAuthMethod(CHATGPT, SETTING_ON), { method: 'private_key_jwt' });
	});
});

describe('permittedAuthMethod — selection rules', () => {
	it('uses the singular preference only when it is in the intersection', () => {
		const preferNone = interactive(
			{ declared: ['none', 'private_key_jwt'], preferred: 'none' },
			{ jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }
		);
		assert.deepEqual(permittedAuthMethod(preferNone, SETTING_ON), { method: 'none' });
	});

	it('prefers private_key_jwt when both are available and no preference is declared', () => {
		const noPreference = interactive(
			{ declared: ['none', 'private_key_jwt'] },
			{ jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }
		);
		assert.deepEqual(permittedAuthMethod(noPreference, SETTING_ON), { method: 'private_key_jwt' });
		assert.deepEqual(permittedAuthMethod(noPreference, DEFAULT), { method: 'none' });
		assert.deepEqual(permittedAuthMethod(noPreference, SETTING_OFF), { method: 'none' });
	});

	it('never downgrades a private_key_jwt preference whose keys are unusable', () => {
		const crossOrigin = { ...CHATGPT, jwks_uri: 'https://keys.example.net/jwks.json' };
		assert.match(
			permittedAuthMethod(crossOrigin, SETTING_ON).error,
			/keys are unusable: jwks_uri must be on the client ID origin/
		);
		const allowed = {
			...SETTING_ON,
			clientIdMetadataDocuments: {
				privateKeyJwt: { enabled: true, jwksUriAllowedOrigins: ['https://keys.example.net'] },
			},
		};
		assert.deepEqual(permittedAuthMethod(crossOrigin, allowed), { method: 'private_key_jwt' });
		// Where private_key_jwt is not advertised, the client is expected to use none.
		assert.deepEqual(permittedAuthMethod(crossOrigin, SETTING_OFF), { method: 'none' });
		const unsupportedPin = interactive({
			...CHATGPT._cimdAuth,
			signingAlg: undefined,
			signingAlgIssue: 'PS256 unsupported',
		});
		assert.match(permittedAuthMethod(unsupportedPin, MIXED).error, /PS256 unsupported/);
		const noKeys = interactive({ declared: ['none', 'private_key_jwt'], preferred: 'private_key_jwt' });
		assert.match(permittedAuthMethod(noKeys, MIXED).error, /neither jwks nor jwks_uri/);
	});

	it('refuses a client with no mutually supported method', () => {
		const pkjwtOnly = interactive(
			{ declared: ['private_key_jwt'], preferred: 'private_key_jwt' },
			{ jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }
		);
		assert.match(permittedAuthMethod(pkjwtOnly, SETTING_OFF).error, /no token endpoint authentication method/);
		const unknownOnly = interactive({ declared: ['tls_client_auth'] });
		assert.match(permittedAuthMethod(unknownOnly, SETTING_ON).error, /no token endpoint authentication method/);
	});

	it('keeps none-only documents public in every configuration', () => {
		const codexLike = interactive({ declared: ['none'], preferred: 'none' });
		for (const config of [DEFAULT, MIXED, SETTING_ON]) {
			assert.deepEqual(permittedAuthMethod(codexLike, config), { method: 'none' });
		}
	});

	it('passes stored (DCR) methods through and pins headless clients to private_key_jwt', () => {
		assert.deepEqual(
			permittedAuthMethod({ client_id: 'c', token_endpoint_auth_method: 'client_secret_basic' }, DEFAULT),
			{
				method: 'client_secret_basic',
			}
		);
		assert.deepEqual(permittedAuthMethod({ client_id: 'c' }, DEFAULT), { method: 'none' });
		assert.match(
			permittedAuthMethod({ client_id: 'c', token_endpoint_auth_method: 'tls_client_auth' }, DEFAULT).error,
			/unsupported/
		);
		const headless = {
			client_id: 'https://agents.example.com/a.json',
			_cimd: true,
			grant_types: ['client_credentials'],
		};
		assert.deepEqual(permittedAuthMethod(headless, DEFAULT), { method: 'private_key_jwt' });
	});
});

describe('interactiveAllowedAlgorithms and isClientAuthMethod', () => {
	it('narrows to the document pin, else allows every interactive algorithm', () => {
		assert.deepEqual(interactiveAllowedAlgorithms(CHATGPT), ['RS256']);
		assert.deepEqual(interactiveAllowedAlgorithms(interactive({ declared: ['private_key_jwt'] })), [
			'RS256',
			'ES256',
			'EdDSA',
		]);
	});

	it('recognises only the four supported methods', () => {
		for (const method of ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt']) {
			assert.equal(isClientAuthMethod(method), true);
		}
		for (const value of ['client_secret_jwt', 'tls_client_auth', '', undefined, 1]) {
			assert.equal(isClientAuthMethod(value), false);
		}
	});
});
