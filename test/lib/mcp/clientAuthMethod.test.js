/**
 * Tests for token-endpoint authentication method selection
 * (clientAuthMethod.ts): what the server advertises, and the one method it
 * permits per client — including the PR A safety matrix: without the
 * interactive setting, a server that does not advertise private_key_jwt
 * resolves ChatGPT to `none`, and a server that already advertises it for
 * headless agents resolves ChatGPT to private_key_jwt (verified).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
	advertisedTokenEndpointAuthMethods,
	advertisedAssertionSigningAlgorithms,
	permittedAuthMethod,
	interactiveAllowedAlgorithms,
	isClientAuthMethod,
} from '../../../dist/lib/mcp/clientAuthMethod.js';
import { CHATGPT_CLIENT_ID } from '../../helpers/cimdFixtures.js';

const DEFAULT = { enabled: true };
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

const CHATGPT = interactive(
	{ declared: ['none', 'private_key_jwt'], preferred: 'private_key_jwt', signingAlg: 'RS256' },
	{ jwks_uri: 'https://chatgpt.com/oauth/jwks.json' }
);

describe('advertised methods and algorithms', () => {
	it('keeps the default metadata unchanged', () => {
		assert.deepEqual(advertisedTokenEndpointAuthMethods(DEFAULT), [
			'none',
			'client_secret_basic',
			'client_secret_post',
		]);
		assert.equal(advertisedAssertionSigningAlgorithms(DEFAULT), undefined);
	});

	it('adds private_key_jwt with EdDSA for headless agents', () => {
		assert.ok(advertisedTokenEndpointAuthMethods(MIXED).includes('private_key_jwt'));
		assert.deepEqual(advertisedAssertionSigningAlgorithms(MIXED), ['EdDSA']);
	});

	it('adds private_key_jwt with RS256, ES256 and EdDSA when interactive private_key_jwt is on', () => {
		assert.ok(advertisedTokenEndpointAuthMethods(SETTING_ON).includes('private_key_jwt'));
		assert.deepEqual(advertisedAssertionSigningAlgorithms(SETTING_ON), ['RS256', 'ES256', 'EdDSA']);
	});
});

describe('permittedAuthMethod — PR A safety matrix for the ChatGPT document', () => {
	it('resolves to none where private_key_jwt is not advertised', () => {
		assert.deepEqual(permittedAuthMethod(CHATGPT, DEFAULT), { method: 'none' });
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
		assert.deepEqual(permittedAuthMethod(crossOrigin, DEFAULT), { method: 'none' });
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
		assert.match(permittedAuthMethod(pkjwtOnly, DEFAULT).error, /no token endpoint authentication method/);
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
