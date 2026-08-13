/**
 * Shared client metadata validators
 *
 * Used by both DCR (dcr.ts) and CIMD (cimd.ts). Both paths require
 * authorization_code in the supported-grant intersection; extra grants this AS
 * doesn't implement are silently filtered rather than treated as errors.
 */

export const SUPPORTED_GRANT_TYPES = new Set(['authorization_code', 'refresh_token']);
export const SUPPORTED_RESPONSE_TYPES = new Set(['code']);
/** Auth methods supported for DCR clients. CIMD clients in v1 are restricted to 'none'. */
export const SUPPORTED_AUTH_METHODS = new Set(['none', 'client_secret_basic', 'client_secret_post']);
export const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

export function validateOptionalString(value: unknown, fieldName: string): string | null {
	if (value === undefined) return null;
	if (typeof value !== 'string') return `${fieldName} must be a string`;
	return null;
}

/**
 * Validate a single redirect URI against RFC 7591 + RFC 8252 rules.
 * Returns an error message on failure, null on success.
 */
export function validateRedirectUri(uri: unknown, allowedHosts: string[] | undefined): string | null {
	if (typeof uri !== 'string' || uri.length === 0) {
		return 'redirect_uris must contain non-empty strings';
	}
	let parsed: URL;
	try {
		parsed = new URL(uri);
	} catch {
		return `redirect_uri is not a valid URL: ${uri}`;
	}
	if (parsed.hash) {
		return `redirect_uri must not contain a fragment: ${uri}`;
	}
	const isLocal = LOCAL_HOSTS.has(parsed.hostname);
	// HTTPS is required except for loopback addresses (RFC 8252 §8.3).
	if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocal)) {
		return `redirect_uri must use https (or http to a loopback address): ${uri}`;
	}
	if (allowedHosts && allowedHosts.length > 0 && !isLocal && !allowedHosts.includes(parsed.hostname)) {
		return `redirect_uri host not in allowlist: ${parsed.hostname}`;
	}
	return null;
}

export function validateStringArray(value: unknown, fieldName: string): string | null {
	if (value === undefined) return null;
	if (!Array.isArray(value)) return `${fieldName} must be an array of strings`;
	for (const item of value) {
		if (typeof item !== 'string') return `${fieldName} must be an array of strings`;
	}
	return null;
}

/**
 * Whether the client's registered grant_types permit the requested grant.
 * Absent/undefined grant_types is treated as the legacy default
 * ['authorization_code', 'refresh_token'], matching the CIMD and DCR paths.
 */
export function allowsGrant(client: { grant_types?: string[] }, grant: string): boolean {
	return (client.grant_types ?? ['authorization_code', 'refresh_token']).includes(grant);
}

/** Returns an error if authorization_code is absent from the declared grants. */
export function validateGrantTypes(grantTypes: string[]): string | null {
	if (!grantTypes.includes('authorization_code')) {
		return 'Missing required grant_type: authorization_code';
	}
	return null;
}

/** Returns the subset of `grantTypes` that this AS supports. */
export function filterGrantTypes(grantTypes: string[]): string[] {
	return grantTypes.filter((g) => SUPPORTED_GRANT_TYPES.has(g));
}

export function validateResponseTypes(responseTypes: string[]): string | null {
	for (const responseType of responseTypes) {
		if (!SUPPORTED_RESPONSE_TYPES.has(responseType)) {
			return `Unsupported response_type: ${responseType}`;
		}
	}
	return null;
}

export function validateAuthMethod(method: string): string | null {
	if (!SUPPORTED_AUTH_METHODS.has(method)) {
		return `Unsupported token_endpoint_auth_method: ${method}`;
	}
	return null;
}
