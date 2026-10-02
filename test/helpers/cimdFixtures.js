/**
 * Client ID Metadata Document fixtures captured from real MCP clients.
 *
 * Embedded verbatim and never fetched at test time, so the tests pin the exact
 * shape a client publishes rather than whatever it serves today.
 */

export const CHATGPT_CLIENT_ID = 'https://chatgpt.com/oauth/client.json';
export const CHATGPT_REDIRECT_URI = 'https://chatgpt.com/connector_platform_oauth_redirect';

/**
 * ChatGPT's CIMD document, as served at https://chatgpt.com/oauth/client.json
 * (captured 2026-09-29). It lists every method it can use in the multi-valued
 * `token_endpoint_auth_methods_supported` (OpenID Connect RP Metadata Choices
 * 1.0; MCP SEP-3149) and keeps `private_key_jwt` as its singular,
 * backwards-compatible preference.
 */
export const CHATGPT_CIMD_DOCUMENT = Object.freeze({
	client_id: CHATGPT_CLIENT_ID,
	client_uri: 'https://chatgpt.com/',
	redirect_uris: [CHATGPT_REDIRECT_URI],
	token_endpoint_auth_method: 'private_key_jwt',
	token_endpoint_auth_methods_supported: ['none', 'private_key_jwt'],
	grant_types: ['authorization_code', 'refresh_token'],
	response_types: ['code'],
	client_name: 'ChatGPT',
	logo_uri: 'https://persistent.oaistatic.com/sonic/misc/openai-logo.png',
	token_endpoint_auth_signing_alg: 'RS256',
	jwks_uri: 'https://chatgpt.com/oauth/jwks.json',
});
