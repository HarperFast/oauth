/**
 * Secret redaction for config logging
 *
 * Config can carry literal secrets (provider clientSecret/client_secret,
 * mcp.signingKeyPem/signing_key_pem, mcp.dynamicClientRegistration.initialAccessToken/
 * initial_access_token, and generic private_key/api_key/passphrase/credential).
 * Redact them before logging — logs are frequently shipped/retained outside the
 * trust boundary.
 *
 * Deny-list by key-name substring; over-redaction in a log is safe. Patterns use
 * optional [_-]? separators to catch camelCase, snake_case, and kebab-case variants
 * in one pass. Bare `token` and `key` are intentionally excluded — they would redact
 * non-secret values like refreshTokenTtl or kid.
 */

/**
 * Pattern matched against config object key names to identify secrets.
 * Covers camelCase, snake_case, and kebab-case forms of each term.
 */
export const SENSITIVE_KEY_PATTERN =
	/secret|signing[_-]?key|private[_-]?key|api[_-]?key|initial[_-]?access[_-]?token|password|passphrase|credential/i;

/**
 * Recursively walk a JSON-ish value and replace the string value of any key
 * matching SENSITIVE_KEY_PATTERN with `[REDACTED]`. Non-plain objects (Date,
 * RegExp, Map, class instances, etc.) are returned as-is — only plain objects
 * and arrays are recursed into. Primitive values are returned unchanged.
 */
export function redactSecrets(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(redactSecrets);
	if (value !== null && typeof value === 'object') {
		const proto = Object.getPrototypeOf(value);
		if (proto !== Object.prototype && proto !== null) {
			// Not a plain object — return as-is (Date, RegExp, Map, class instance, etc.)
			return value;
		}
		const out: Record<string, unknown> = {};
		for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
			out[key] = SENSITIVE_KEY_PATTERN.test(key) ? '[REDACTED]' : redactSecrets(val);
		}
		return out;
	}
	return value;
}
