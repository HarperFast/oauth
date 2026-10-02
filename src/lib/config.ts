/**
 * OAuth Configuration
 *
 * Provider configuration and initialization utilities
 */

import { OAuthProvider } from './OAuthProvider.ts';
import { getProvider } from './providers/index.ts';
import { redactSecrets } from './redact.ts';
import { algFromPrivateKeyPem } from './mcp/keyStore.ts';
import { isCimdClientId, cimdEnabled } from './mcp/cimd.ts';
import { resolveAzureIssuerBinding, isAzureJwksUri } from './azureIssuer.ts';
import type { OAuthProviderConfig, OAuthPluginConfig, ProviderRegistry, Logger } from '../types.ts';

/**
 * Expand environment variable in a string value
 *
 * If the value is a string in the format `${VAR_NAME}`, it will be replaced
 * with the value of the environment variable. Non-string values are returned unchanged.
 *
 * @example
 * expandEnvVar('${MY_VAR}') // Returns process.env.MY_VAR or '${MY_VAR}' if undefined
 * expandEnvVar('literal')   // Returns 'literal'
 * expandEnvVar(123)         // Returns 123
 * expandEnvVar(true)        // Returns true
 */
export function expandEnvVar(value: any): any {
	if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
		// Extract environment variable name
		const envVar = value.slice(2, -1);
		const envValue = process.env[envVar];
		// Only use env value if it exists (even if empty string)
		return envValue !== undefined ? envValue : value;
	}
	return value;
}

/**
 * Recursively expand `${ENV_VAR}` placeholders on every string leaf of a value.
 *
 * Used for structured config blocks (like `mcp`) where sensitive leaves
 * (e.g., `mcp.dynamicClientRegistration.initialAccessToken`) still need
 * env-var expansion but the block itself isn't a flat property bag.
 */
export function expandEnvVarsDeep<T>(value: T): T {
	if (typeof value === 'string') {
		return expandEnvVar(value);
	}
	if (Array.isArray(value)) {
		return value.map(expandEnvVarsDeep) as unknown as T;
	}
	if (value !== null && typeof value === 'object') {
		const expanded: Record<string, any> = {};
		for (const [key, item] of Object.entries(value as Record<string, any>)) {
			expanded[key] = expandEnvVarsDeep(item);
		}
		return expanded as T;
	}
	return value;
}

/**
 * True when `value` has the shape of an unexpanded `${VAR_NAME}` placeholder
 * (surrounding whitespace tolerated). This is a SHAPE check only — it cannot
 * distinguish a placeholder {@link expandEnvVar} left untouched because the
 * variable was unset from a resolved value that genuinely IS that literal
 * text (e.g. an environment variable deliberately set to the string
 * `${X}`). Callers rely on the former being the overwhelmingly common case
 * when this runs on output that has already passed through
 * `expandEnvVar`/`expandEnvVarsDeep`.
 */
export function isUnresolvedEnvPlaceholder(value: unknown): boolean {
	return typeof value === 'string' && /^\$\{[^}]*\}$/.test(value.trim());
}

/**
 * Coerce a config value that documents a boolean but may arrive as an
 * env-expanded string (`enabled: ${FLAG}` → `"false"`). Returns the boolean
 * for `true`/`false` (case-insensitive), otherwise `undefined` (so callers
 * apply their own default). A real boolean passes through unchanged.
 */
export function coerceConfigBoolean(value: unknown): boolean | undefined {
	if (typeof value === 'boolean') return value;
	if (typeof value === 'string') {
		const v = value.trim().toLowerCase();
		if (v === 'true') return true;
		if (v === 'false') return false;
	}
	return undefined;
}

/**
 * Normalize one documented-boolean config field in place, TOTALLY: after this
 * call the field is either a real boolean or absent. Coercible values
 * (booleans, "true"/"false" strings) are coerced; a non-boolean, non-
 * placeholder junk value (e.g. `"yes"`, `1`, `{}`) is DELETED with a warning,
 * so the field's documented default applies.
 *
 * An unresolved `${ENV_VAR}` placeholder left by expandEnvVarsDeep when the
 * variable is unset THROWS instead, when `failOnPlaceholder` is true (#207):
 * dropping it to the documented default silently picks a direction the
 * operator never chose — e.g. `mcp.dynamicClientRegistration.enabled: ${FLAG}`
 * with `FLAG` unset dropping to "absent" resolves to DCR's default-ENABLED
 * state (a block with no explicit `enabled: false` is on), the opposite of
 * what dropping a gate is supposed to achieve. A security gate with a value
 * the operator can't read back has no safe direction to guess; fail loudly
 * and name the variable instead, exactly like `mcp.signingKeyPem` and
 * `redirectUri` do for the same placeholder shape.
 *
 * `failOnPlaceholder` defaults to true. The four feature-scoped fields pass
 * `mcpConfig.enabled === true`, so they stay inert while MCP overall is off
 * (byte-identical-boot contract) and fail closed once it's on. `mcp.enabled`
 * itself passes `false` explicitly — see {@link normalizeMcpSecurityConfig}
 * for why that one field keeps the pre-#207 warn-and-drop behavior.
 * `requireBoolean` is used by the interactive private_key_jwt gate: while
 * MCP is active, a declared value other than a boolean is refused rather than
 * silently dropped. Placeholders and empty strings retain their specific errors.
 */
function normalizeBooleanField(
	obj: Record<string, any>,
	field: string,
	path: string,
	logger?: Logger,
	failOnPlaceholder = true,
	requireBoolean = false
): void {
	const value = obj[field];
	if (value === undefined && (!requireBoolean || !Object.prototype.hasOwnProperty.call(obj, field))) {
		return; // Omitted field uses its default; a declared undefined fails the strict boolean gate.
	}
	if (value === null && !requireBoolean) return; // Bare YAML key keeps the existing absent-value behavior.
	const isUnresolvedPlaceholder = isUnresolvedEnvPlaceholder(value);
	const isEmptyString = typeof value === 'string' && value.trim() === '';
	if (requireBoolean && typeof value !== 'boolean' && !isUnresolvedPlaceholder && !isEmptyString) {
		throw new Error(`${path} must be true or false when MCP is enabled.`);
	}
	const coerced = coerceConfigBoolean(value);
	if (coerced !== undefined) {
		obj[field] = coerced;
		return;
	}
	// Not every substitution mechanism leaves the placeholder text behind when
	// its variable is unset — docker-compose's `X=${X}` resolves to "" (not the
	// literal "${X}") for an unset X. That's the same operator-unreadable gate
	// value as an unresolved placeholder; treat it identically rather than
	// letting it fall through to "must be a boolean" and get silently dropped.
	if ((isUnresolvedPlaceholder || isEmptyString) && failOnPlaceholder) {
		throw new Error(
			isUnresolvedPlaceholder
				? `${path} is the unresolved env placeholder ${JSON.stringify(value)} (variable unset). ` +
						`Set the variable to "true" or "false", or remove ${path} to use its documented default.`
				: `${path} resolved to an empty value (likely an unset environment variable substitution — ` +
						`e.g. docker-compose's "\${VAR}" resolves to "" when VAR is unset). ` +
						`Set the variable to "true" or "false", or remove ${path} to use its documented default.`
		);
	}
	logger?.warn?.(
		isUnresolvedPlaceholder
			? `MCP: ${path} is the unresolved env placeholder ${JSON.stringify(value)} (variable unset). ` +
					'Treating the option as absent — its documented default applies.'
			: `MCP: ${path} must be a boolean; got ${JSON.stringify(value)}. ` +
					'Treating the option as absent — its documented default applies.'
	);
	delete obj[field];
}

/**
 * Normalize a list of https origins (a scalar string is wrapped): each entry
 * must be an https URL with no path, query, fragment or userinfo; it is stored
 * as its exact `URL.origin`. Anything else throws, naming the option.
 */
function normalizeHttpsOrigins(value: unknown, path: string): string[] {
	const raw = Array.isArray(value) ? value : [value];
	return raw.map((entry: unknown) => {
		let url: URL | undefined;
		if (typeof entry === 'string') {
			try {
				url = new URL(entry.trim());
			} catch {
				url = undefined;
			}
		}
		const valid =
			url !== undefined &&
			url.protocol === 'https:' &&
			url.username === '' &&
			url.password === '' &&
			(url.pathname === '' || url.pathname === '/') &&
			url.search === '' &&
			url.hash === '';
		if (!valid) {
			throw new Error(
				`${path} entries must be https origins like "https://keys.example.com"; got ${JSON.stringify(entry)}`
			);
		}
		return url!.origin;
	});
}

/**
 * Normalize `mcp.clientIdMetadataDocuments.privateKeyJwt.tokenEndpointAudience`:
 * `clientIds` must be a non-empty list of exact CIMD client IDs, and
 * `expiresAt` must parse as a date (normalized to epoch ms). An exception with
 * no usable expiry is refused rather than left open-ended.
 */
function normalizeTokenEndpointAudience(value: unknown, logger?: Logger): { clientIds: string[]; expiresAt: number } {
	const path = 'mcp.clientIdMetadataDocuments.privateKeyJwt.tokenEndpointAudience';
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error(`${path} must be an object with clientIds and expiresAt`);
	}
	const { clientIds, expiresAt } = value as { clientIds?: unknown; expiresAt?: unknown };
	if (
		!Array.isArray(clientIds) ||
		clientIds.length === 0 ||
		clientIds.some((id) => typeof id !== 'string' || !isCimdClientId(id))
	) {
		throw new Error(`${path}.clientIds must be a non-empty list of exact CIMD client IDs (https URLs with a path)`);
	}
	const expiresAtMs =
		typeof expiresAt === 'number' ? expiresAt : typeof expiresAt === 'string' ? Date.parse(expiresAt) : Number.NaN;
	if (!Number.isFinite(expiresAtMs)) {
		throw new Error(`${path}.expiresAt must be an ISO 8601 date-time; the exception requires an expiry`);
	}
	if (expiresAtMs <= Date.now()) {
		logger?.warn?.(`MCP: ${path} expired at ${new Date(expiresAtMs).toISOString()}; the exception no longer applies.`);
	}
	return { clientIds: [...clientIds] as string[], expiresAt: expiresAtMs };
}

/**
 * Normalize a declared hostname allowlist (`dcr.allowedRedirectUriHosts`,
 * `cimd.allowedHosts`): wrap a scalar into a single-element array, trim,
 * lowercase, and drop blanks. While `guard` is true (caller-determined: the
 * surface this list gates is active), a result with zero usable hosts, or
 * any unresolved `${VAR}` entry, throws naming `path` instead of silently
 * reading as "no restriction" downstream (#249) — `guard` false leaves both
 * checks inert so a disabled block can carry stale config.
 */
function normalizeHostAllowlist(value: unknown, path: string, guard: boolean): string[] {
	const raw: unknown[] = Array.isArray(value) ? value : [value];
	if (raw.some((h) => typeof h !== 'string')) {
		throw new Error(`${path} must be a hostname string or an array of hostname strings`);
	}
	const entries = raw as string[];
	if (guard) {
		const placeholder = entries.find((h) => isUnresolvedEnvPlaceholder(h));
		if (placeholder !== undefined) {
			throw new Error(
				`${path} contains the unresolved env placeholder ${JSON.stringify(placeholder)} (variable unset). ` +
					`Set the variable, remove that entry, or omit ${path} entirely to allow any host.`
			);
		}
	}
	const normalized = entries.map((h) => h.trim().toLowerCase()).filter((h) => h.length > 0);
	if (guard && normalized.length === 0) {
		throw new Error(
			`${path} is configured but resolved to an empty list (e.g. blank entries or an unset environment ` +
				`variable substitution). Provide at least one hostname, or omit ${path} entirely to allow any host.`
		);
	}
	return normalized;
}

/**
 * Validate `mcp.signingKeyPem` when the operator DECLARED it — i.e. the field
 * is present on the config object at all, regardless of what it resolved to.
 * Unlike the documented booleans above, an unresolved/empty pin does NOT get
 * a safe default to fall back to: `MCPKeyStore.getSigningKey` branches on
 * truthiness (pin present → pin wins; falsy → self-generate), so a pin that
 * resolves empty — e.g. `signingKeyPem: ${KEY}` with `KEY` unset-or-empty —
 * would silently swap the trust model to a self-generated key instead of the
 * operator-provisioned one (#221). That must fail loudly at boot instead:
 * - declared + unresolved `${VAR}` placeholder → throw naming the variable.
 * - declared + resolves empty (env var set-but-empty, or a literal `""`) →
 *   throw.
 * - declared + resolves to a value that isn't a parseable RSA/EC P-256 PEM →
 *   throw (previously this only warned at startup and threw at first mint).
 * - declared + a valid PEM → passes through untouched; pin mode as documented.
 * - NOT declared at all → this function takes no action; self-generation
 *   proceeds exactly as before.
 */
function validateSigningKeyPem(mcpConfig: Record<string, any>): void {
	// `undefined` is undeclared. YAML never yields undefined for a present key
	// (an empty YAML value is null, which IS declared-and-empty and falls
	// through to the checks below) — the real source is `OptionsWatcher#merge`
	// setting a removed key to undefined on live config reload. Self-generation
	// is the documented result of removing the pin that way; throwing here
	// would turn "unpin on reload" into a boot-validation failure.
	if (!('signingKeyPem' in mcpConfig) || mcpConfig.signingKeyPem === undefined) return;
	const value = mcpConfig.signingKeyPem;
	if (isUnresolvedEnvPlaceholder(value)) {
		throw new Error(
			`mcp.signingKeyPem is the unresolved env placeholder ${JSON.stringify(value)} (variable unset). ` +
				'Set the variable to a PEM-encoded private key, or remove mcp.signingKeyPem to use a self-generated key.'
		);
	}
	if (!value) {
		throw new Error(
			'mcp.signingKeyPem is configured but resolved to an empty value (e.g. an unset or empty ' +
				'environment variable). Provide a PEM-encoded private key, or remove mcp.signingKeyPem to use a ' +
				'self-generated key.'
		);
	}
	if (typeof value !== 'string') {
		throw new Error(`mcp.signingKeyPem must be a PEM-encoded string; got ${typeof value}.`);
	}
	try {
		algFromPrivateKeyPem(value);
	} catch (error) {
		throw new Error(
			`mcp.signingKeyPem is not a supported signing key (RSA or EC P-256): ` +
				(error instanceof Error ? error.message : String(error)),
			{ cause: error }
		);
	}
}

/**
 * Validate `mcp.dynamicClientRegistration.initialAccessToken` when the
 * operator DECLARED it and DCR is enabled. `checkInitialAccessToken` (dcr.ts)
 * gates purely on the configured value's truthiness, so two misconfigurations
 * turn the gate into no gate at all (#240):
 * - An unresolved `${VAR}` placeholder (the variable is unset) is a non-empty
 *   string — it IS the "configured" value, and becomes the accepted bearer
 *   secret. Anyone who can read the committed config (placeholders routinely
 *   are) can then register MCP clients.
 * - A set-but-empty value is falsy, so `checkInitialAccessToken` treats the
 *   token as entirely absent: open registration, silently.
 * Neither is a deliberate "I want open registration" choice — that's only
 * expressed by omitting the key. Fail loudly at boot instead:
 * - declared + unresolved `${VAR}` placeholder → throw naming the variable.
 * - declared + resolves to an empty or all-whitespace string → throw.
 * - NOT declared at all (field absent, or `undefined` from a live-reload
 *   removal) → this function takes no action; open registration proceeds
 *   exactly as before.
 */
function validateDcrInitialAccessToken(dcr: Record<string, any>): void {
	if (!('initialAccessToken' in dcr) || dcr.initialAccessToken === undefined) return;
	const value = dcr.initialAccessToken;
	if (isUnresolvedEnvPlaceholder(value)) {
		throw new Error(
			`mcp.dynamicClientRegistration.initialAccessToken is the unresolved env placeholder ${JSON.stringify(value)} ` +
				'(variable unset). Set the variable to the DCR bearer token, or remove initialAccessToken to allow ' +
				'open registration.'
		);
	}
	if (typeof value !== 'string') {
		throw new Error(
			`mcp.dynamicClientRegistration.initialAccessToken must be a string; got ${typeof value}. ` +
				'Provide a non-empty bearer token, or remove initialAccessToken to allow open registration.'
		);
	}
	if (value.trim() === '') {
		throw new Error(
			'mcp.dynamicClientRegistration.initialAccessToken is configured but resolved to an empty or ' +
				'whitespace-only value. Provide a non-empty bearer token, or remove initialAccessToken to allow ' +
				'open registration.'
		);
	}
}

/**
 * Normalize the security-relevant fields of the `mcp` config block in place,
 * so a mis-typed value can never silently flip a gate:
 * - The feature-scoped documented booleans
 *   (`mcp.refreshTokenRequiresOfflineAccess`, `mcp.clientCredentials.enabled`,
 *   `mcp.clientCredentials.acceptTokenEndpointAudience`,
 *   `mcp.clientIdMetadataDocuments.enabled`,
 *   `mcp.dynamicClientRegistration.enabled`) are normalized totally via
 *   {@link normalizeBooleanField}: coerced to a real boolean; a non-boolean,
 *   non-placeholder value is removed with a warning so the documented default
 *   applies; an unresolved `${VAR}` placeholder throws naming the variable
 *   (#207) while the surface it gates is active (`mcp.enabled === true`) —
 *   while it's inactive, the placeholder still drops with a warning so a
 *   disabled block stays inert. Consumers may therefore gate on plain
 *   truthiness / `!== false` without re-validating types.
 * - `mcp.enabled` itself keeps the pre-#207 warn-and-drop behavior (does not
 *   throw) — see {@link normalizeBooleanField}'s doc for why this one field
 *   is the exception.
 * - `mcp.clientIdMetadataDocuments.allowedHosts` and
 *   `mcp.dynamicClientRegistration.allowedRedirectUriHosts` are normalized via
 *   {@link normalizeHostAllowlist}; the latter is read by both DCR and CIMD
 *   (cimd.ts), so its guard covers either block being active, not DCR alone.
 * - `mcp.clientIdMetadataDocuments.privateKeyJwt`: `enabled` is opt-in.
 *   With MCP active, a declared non-boolean throws; with MCP off it keeps
 *   its previous coercion and warn-and-drop behavior. `jwksUriAllowedOrigins` is
 *   normalized to exact https origins;
 *   `tokenEndpointAudience` needs exact CIMD client IDs and a parseable
 *   `expiresAt` (normalized to epoch ms). Invalid values throw.
 * - `mcp.signingKeyPem`, if declared, must resolve to a parseable key — see
 *   {@link validateSigningKeyPem}. This one throws instead of dropping with a
 *   warning: unlike the booleans above, there is no safe default to fall back
 *   to for a declared-but-broken pin.
 * - `mcp.dynamicClientRegistration.initialAccessToken`, if declared and DCR is
 *   enabled, must resolve to a non-empty value — see
 *   {@link validateDcrInitialAccessToken}. Also throws rather than dropping:
 *   there is no safe default gate value to fall back to either (open
 *   registration is only ever chosen by omitting the key).
 */
export function normalizeMcpSecurityConfig(mcpConfig: Record<string, any>, logger?: Logger): void {
	// mcp.enabled is the one field kept on the pre-#207 warn-and-drop path (see
	// normalizeBooleanField's doc); the feature-scoped booleans below fail closed.
	normalizeBooleanField(mcpConfig, 'enabled', 'mcp.enabled', logger, false);
	// Feature-scoped fields below only fail closed on their own placeholder when
	// the surface they gate is actually active (mcp.enabled === true) — a
	// disabled block must stay inert (byte-identical-boot contract) even if a
	// placeholder is still sitting in its unused config.
	const mcpActive = mcpConfig.enabled === true;
	normalizeBooleanField(
		mcpConfig,
		'refreshTokenRequiresOfflineAccess',
		'mcp.refreshTokenRequiresOfflineAccess',
		logger,
		mcpActive
	);

	const clientCredentials = mcpConfig.clientCredentials;
	if (clientCredentials && typeof clientCredentials === 'object') {
		normalizeBooleanField(clientCredentials, 'enabled', 'mcp.clientCredentials.enabled', logger, mcpActive);
		normalizeBooleanField(
			clientCredentials,
			'acceptTokenEndpointAudience',
			'mcp.clientCredentials.acceptTokenEndpointAudience',
			logger,
			mcpActive
		);
	}

	// CIMD's enabled state is normalized here, ahead of the DCR block below,
	// so cimdActive (used by DCR's allowedRedirectUriHosts guard) reflects the
	// coerced value — e.g. an env-substituted `enabled: "false"` must count as
	// disabled, not as the still-truthy raw string.
	const cimd = mcpConfig.clientIdMetadataDocuments;
	if (cimd !== undefined && cimd !== null && (typeof cimd !== 'object' || Array.isArray(cimd))) {
		// Same non-mapping guard as dynamicClientRegistration below (arrays
		// included): CIMD's own `cimdConfig?.enabled !== false` predicate
		// (cimd.ts) also falls through to its default — for CIMD that default
		// is already "enabled", so a block meant to disable it would otherwise
		// be silently ignored rather than taking effect.
		if (mcpActive) {
			throw new Error('mcp.clientIdMetadataDocuments must be a mapping; use enabled: false to disable');
		}
	} else if (cimd && typeof cimd === 'object' && !Array.isArray(cimd)) {
		normalizeBooleanField(cimd, 'enabled', 'mcp.clientIdMetadataDocuments.enabled', logger, mcpActive);
	}

	// CIMD reads allowedRedirectUriHosts independently of dcr.enabled (cimd.ts);
	// precompute its active state here (shared `cimdEnabled` predicate — also
	// used at request time by `resolveClient`) for the DCR guard below.
	const cimdActive = cimdEnabled(cimd);

	const dcr = mcpConfig.dynamicClientRegistration;
	if (dcr !== undefined && dcr !== null && (typeof dcr !== 'object' || Array.isArray(dcr))) {
		// A non-mapping value (`false`, `0`, an unresolved placeholder string, an
		// array, ...) must not reach dcrEnabled()'s `dcrConfig != null &&
		// dcrConfig.enabled !== false` predicate — `.enabled` on a non-mapping is
		// always `undefined` (arrays included), so that check falls through to
		// its default-ENABLED result and silently turns a would-be "disable DCR"
		// value into open registration. Fail loudly instead of guessing.
		if (mcpActive) {
			throw new Error('mcp.dynamicClientRegistration must be a mapping; use enabled: false to disable');
		}
	} else if (dcr && typeof dcr === 'object' && !Array.isArray(dcr)) {
		normalizeBooleanField(dcr, 'enabled', 'mcp.dynamicClientRegistration.enabled', logger, mcpActive);
		// Only when MCP itself is enabled and DCR isn't explicitly disabled — a
		// disabled block must stay inert, matching mcp.signingKeyPem's gating
		// below and dcrEnabled()'s own predicate (dcr.ts).
		if (mcpActive && dcr.enabled !== false) {
			validateDcrInitialAccessToken(dcr);
		}
		if (dcr.allowedRedirectUriHosts !== undefined) {
			dcr.allowedRedirectUriHosts = normalizeHostAllowlist(
				dcr.allowedRedirectUriHosts,
				'mcp.dynamicClientRegistration.allowedRedirectUriHosts',
				mcpActive && (dcr.enabled !== false || cimdActive)
			);
		}
	}

	// cimd's non-mapping guard and `enabled` normalization already ran above,
	// before the DCR block; this continues processing the same mapping (if
	// it is one) for its other fields.
	if (cimd && typeof cimd === 'object' && !Array.isArray(cimd)) {
		if (cimd.allowedHosts !== undefined) {
			cimd.allowedHosts = normalizeHostAllowlist(
				cimd.allowedHosts,
				'mcp.clientIdMetadataDocuments.allowedHosts',
				mcpActive && cimd.enabled !== false
			);
		}

		const privateKeyJwt = cimd.privateKeyJwt;
		if (privateKeyJwt !== undefined) {
			if (!privateKeyJwt || typeof privateKeyJwt !== 'object' || Array.isArray(privateKeyJwt)) {
				throw new Error('mcp.clientIdMetadataDocuments.privateKeyJwt must be an object');
			}
			normalizeBooleanField(
				privateKeyJwt,
				'enabled',
				'mcp.clientIdMetadataDocuments.privateKeyJwt.enabled',
				logger,
				true,
				mcpActive
			);
			if (privateKeyJwt.jwksUriAllowedOrigins !== undefined) {
				privateKeyJwt.jwksUriAllowedOrigins = normalizeHttpsOrigins(
					privateKeyJwt.jwksUriAllowedOrigins,
					'mcp.clientIdMetadataDocuments.privateKeyJwt.jwksUriAllowedOrigins'
				);
			}
			if (privateKeyJwt.tokenEndpointAudience !== undefined) {
				privateKeyJwt.tokenEndpointAudience = normalizeTokenEndpointAudience(
					privateKeyJwt.tokenEndpointAudience,
					logger
				);
			}
		}
	}

	// Only when the MCP surface is actually enabled: a disabled block must
	// stay inert (the byte-identical-boot contract downstream components
	// rely on — e.g. a shipped config carrying `${VAR}` placeholders with
	// the surface off must not refuse boot). Mirrors the enabled-gating of
	// the other MCP startup checks in src/index.ts.
	if (mcpActive) {
		validateSigningKeyPem(mcpConfig);
	}
}

/**
 * Shallow-copy an object, dropping keys whose value is `undefined`. `null` and
 * `''` are explicit values and are kept as-is — only `undefined` means "not
 * specified", so a passed-through unset field can't clobber a preset/default
 * it's spread onto.
 */
export function skipUndefined(source: Record<string, any> | null | undefined): Record<string, any> {
	const result: Record<string, any> = {};
	if (!source) return result;
	for (const [key, value] of Object.entries(source)) {
		if (value === undefined) continue;
		result[key] = value;
	}
	return result;
}

/**
 * Build configuration for a specific provider.
 *
 * `providerConfig` keys with value `undefined` are treated as "not specified"
 * and are skipped, so they never override a plugin default or preset value —
 * this matters for a dynamically resolved config (e.g. from `onResolveProvider`)
 * that passes through an unset field such as `scope: row.scope`. `null` and
 * `''` are explicit values and are kept as-is.
 *
 * `enforceIssuerForJwks` runs {@link validateIssuerForJwks} (#231 §4) — pass
 * `true` only from a static, startup-time build (`initializeProviders`), never
 * from a request-path dynamic resolution (`onResolveProvider`): throwing there
 * would fail every request for a misconfigured tenant instead of just leaving
 * it non-adoption-eligible. `logger`, when passed, only reaches advisory
 * warnings (`checkGraphProfileScope`) and `resolveAzureIssuerBinding`'s own
 * info log — nothing here throws because of a missing logger.
 */
export function buildProviderConfig(
	providerConfig: Record<string, any>,
	providerName: string,
	pluginDefaults: Partial<OAuthProviderConfig> = {},
	enforceIssuerForJwks = false,
	logger?: Logger
): OAuthProviderConfig {
	const options = providerConfig || {};

	const expandedOptions: Record<string, any> = {};
	for (const [key, value] of Object.entries(skipUndefined(options))) {
		expandedOptions[key] = expandEnvVar(value);
	}

	// Accept jwksUrl as an alias for jwksUri (the docs used both names historically).
	if (expandedOptions.jwksUrl && !expandedOptions.jwksUri) {
		expandedOptions.jwksUri = expandedOptions.jwksUrl;
	}

	// Normalize `provider` to lowercase only when it matches a preset (#242); a custom
	// identifier with no preset, or an explicit '', is left untouched.
	const providerType = expandedOptions.provider || providerName;
	const providerPreset = providerType ? getProvider(providerType) : null;
	if (typeof expandedOptions.provider === 'string' && expandedOptions.provider !== '' && providerPreset) {
		expandedOptions.provider = expandedOptions.provider.toLowerCase();
	}

	// Build redirect URI with provider name in path. No loopback fallback: a missing
	// redirectUri used to default to http://localhost:9926/oauth, which some IdPs
	// (unlike GitHub) accept for native-app-style loopback flows — silently handing
	// the authorization code to whatever is listening on the end user's own
	// localhost:9926 instead of failing the login. Fail closed at config-resolution
	// time instead (see HarperFast/oauth#208).
	const baseRedirectUri = expandedOptions.redirectUri || pluginDefaults.redirectUri;
	if (typeof baseRedirectUri !== 'string' || baseRedirectUri.trim() === '') {
		throw new Error(
			`OAuth provider '${providerName}' has no redirectUri configured. Set the plugin-level ` +
				`'redirectUri' option (or a per-provider 'redirectUri' on '${providerName}') to your app's ` +
				`public origin plus '/oauth', e.g. redirectUri: 'https://your-app.example.com/oauth' — the plugin ` +
				`appends '/${providerName}/callback'. See docs/configuration.md#understanding-redirects.`
		);
	}
	// expandEnvVar leaves an unresolved `${VAR}` placeholder as-is when the
	// variable is unset, so a config like `redirectUri: ${OAUTH_REDIRECT_URI}`
	// (the pattern every doc example uses) would otherwise pass the blank
	// check above as a non-empty string, match neither rewrite below, and get
	// sent to the IdP verbatim. Fail closed here too (see HarperFast/oauth#208).
	if (isUnresolvedEnvPlaceholder(baseRedirectUri)) {
		throw new Error(
			`OAuth provider '${providerName}' has an unresolved 'redirectUri' environment variable placeholder ` +
				`(${JSON.stringify(baseRedirectUri)}) — the variable is unset. Set the plugin-level 'redirectUri' ` +
				`option (or a per-provider 'redirectUri' on '${providerName}') to your app's public origin plus ` +
				`'/oauth', e.g. redirectUri: 'https://your-app.example.com/oauth' — the plugin appends ` +
				`'/${providerName}/callback'. See docs/configuration.md#understanding-redirects.`
		);
	}
	const redirectUri = baseRedirectUri
		.replace(/\/oauth\/callback\/?(?=[?#]|$)/, `/oauth/${providerName}/callback`)
		.replace(/\/oauth\/?(?=[?#]|$)/, `/oauth/${providerName}/callback`);

	// Merge configurations: plugin defaults -> preset -> options
	const config: OAuthProviderConfig = {
		// Plugin defaults
		scope: pluginDefaults.scope || 'openid profile email',
		usernameClaim: pluginDefaults.usernameClaim || 'email',
		defaultRole: pluginDefaults.defaultRole || 'user',
		postLoginRedirect: pluginDefaults.postLoginRedirect || '/',

		// Provider type
		provider: 'generic',

		// Required fields (will be overridden if present)
		clientId: '',
		clientSecret: '',
		authorizationUrl: '',
		tokenUrl: '',
		userInfoUrl: '',

		// Provider preset (if available)
		...providerPreset,

		// Provider-specific options (with expanded env vars)
		...expandedOptions,

		// Ensure redirect URI includes provider name (override any previous value)
		redirectUri,
	};

	// Handle provider-specific configuration. Dispatches on the *resolved
	// preset's own* `provider` field, not `config.provider` — an explicit
	// `provider: 'microsoft'` option overwrites `config.provider` with that
	// alias string (via the `...expandedOptions` spread above) even though
	// `getProvider('microsoft')` already resolved the Azure preset; switching
	// on `config.provider` would silently skip `configure()` for that case.
	// Gated on `config.provider` being non-empty, though: an explicit
	// `provider: ''` is a deliberate escape hatch (keep the preset's other
	// defaults but never run its `configure()`), and must still suppress
	// dispatch even though `providerPreset` still resolved.
	if (config.provider && providerPreset?.configure) {
		let derivedConfig;

		switch (providerPreset.provider) {
			case 'azure':
				if (expandedOptions.tenantId) {
					derivedConfig = providerPreset.configure(expandedOptions.tenantId);
				}
				break;
			case 'auth0':
			case 'okta':
				if (expandedOptions.domain) {
					derivedConfig = providerPreset.configure(expandedOptions.domain, expandedOptions.authServer);
				}
				break;
		}

		if (derivedConfig) {
			// An explicit, usable operator `issuer` wins over a shortcut-derived
			// one (#264) — narrowly: every other `configure()`-returned field
			// (the endpoint URLs) keeps today's unconditional-overwrite behavior,
			// so a `domain`/`tenantId` shortcut's endpoints stay mutually
			// coherent rather than mixing a stale explicit endpoint with
			// freshly-derived others. "Usable" excludes `null`/`''`/an
			// all-empty array (same as `hasUsableIssuer` below) and an
			// unresolved `${VAR}` placeholder left by `expandEnvVar` when the
			// variable is unset — otherwise that literal placeholder string would
			// win over the shortcut-derived issuer and fail every login.
			const pinnedIssuer = expandedOptions.issuer;
			Object.assign(config, derivedConfig);
			if (isPinnedIssuerUsable(pinnedIssuer)) {
				config.issuer = pinnedIssuer;
			}
		}
	}

	// Azure issuer binding (#264): a real tenant GUID's issuer is fully
	// determined by its own jwksUri; a shared alias authority (/common,
	// /organizations, /consumers) only becomes usable when the operator pins
	// a single Azure-shaped tenant issuer, in which case verification is
	// redirected to that tenant's own, non-shared endpoint. A no-op for any
	// non-Azure-shaped jwksUri. Throws for an unsafe/malformed combination.
	resolveAzureIssuerBinding(config, providerName, logger);

	if (enforceIssuerForJwks) {
		validateIssuerForJwks(config, providerName);
		checkGraphProfileScope(config, providerName, logger);
	}

	return config;
}

/**
 * True when `issuer` is a value `jwt.verify`/`verifyIdTokenClaims` will actually
 * check against — a non-empty string, or a non-empty array (an empty array
 * normalizes to "no issuer configured", same as OAuthProvider.verifyIdToken).
 */
function hasUsableIssuer(issuer: OAuthProviderConfig['issuer']): boolean {
	if (Array.isArray(issuer)) return issuer.some((value) => typeof value === 'string' && value !== '');
	return typeof issuer === 'string' && issuer !== '';
}

/**
 * {@link hasUsableIssuer}, plus rejecting an unresolved `${VAR}` placeholder
 * (string, or any array element) — used only for the explicit-pin-wins-over-
 * shortcut check above, so a placeholder `expandEnvVar` left untouched
 * because the variable is unset can't win over a `domain`/`tenantId`
 * shortcut's derived issuer and then fail every login against that literal
 * placeholder text.
 */
function isPinnedIssuerUsable(issuer: OAuthProviderConfig['issuer']): boolean {
	const values = Array.isArray(issuer) ? issuer : [issuer];
	return values.some((value) => typeof value === 'string' && value !== '' && !isUnresolvedEnvPlaceholder(value));
}

/**
 * True when a JWKS-enabled, issuer-less provider is a candidate for
 * background OIDC discovery (HarperFast/oauth#264): `jwksUri` is set, no
 * usable `issuer` resulted (from a preset shortcut or an explicit pin —
 * includes the Azure cases `resolveAzureIssuerBinding` already resolved),
 * `authorizationUrl` parses as `https:` (discovery must not depend on the
 * network for a config that's wrong independent of it — a non-https
 * `authorizationUrl` can never be fixed by a fetch), and the endpoint isn't
 * Azure's own host (an *unpinned* alias authority is intentionally
 * issuer-less — generic discovery must never probe it; see `azureIssuer.ts`).
 */
export function needsIssuerDiscovery(config: OAuthProviderConfig): boolean {
	if (!config.jwksUri) return false;
	if (hasUsableIssuer(config.issuer)) return false;
	if (isAzureJwksUri(config.jwksUri)) return false;
	try {
		return new URL(config.authorizationUrl).protocol === 'https:';
	} catch {
		return false;
	}
}

/**
 * A JWKS-enabled provider (so `issuerValidated` can in principle be `true` —
 * HarperFast/oauth#231 §4) with no usable `issuer` would otherwise deny
 * adoption silently at login, forever. `domain`/`tenantId` already derive
 * `issuer` for Okta/Auth0/Azure; `resolveAzureIssuerBinding` derives it for
 * a pinned Azure alias or a real tenant GUID (HarperFast/oauth#264); this
 * only fires when all of that is bypassed.
 *
 * Boot must not depend on the network: a provider `needsIssuerDiscovery`
 * defers to that background attempt (`src/index.ts` starts it once this
 * provider is published) instead of throwing — only a config that's wrong
 * *independent* of the network (no `authorizationUrl`, or a non-`https` one)
 * still hard-fails here, exactly as before #264.
 *
 * Excluded by `jwksUri` shape, not declared provider type: any Azure-host
 * `jwksUri` that still has no usable `issuer` at this point can only be an
 * *unpinned* alias authority — `resolveAzureIssuerBinding` above already
 * resolved a pinned alias or a real tenant GUID to a usable issuer, or
 * thrown for anything unsafe/malformed. An unpinned alias is intentionally
 * issuer-less (HarperFast/oauth#264 §"adoption requires a pin") and must not
 * hard-fail here — regardless of whether the config says `provider: azure`,
 * uses the `microsoft` alias, or is a `generic`/explicit-endpoint provider
 * manually pointed at the same host.
 */
function validateIssuerForJwks(config: OAuthProviderConfig, providerName: string): void {
	if (!config.jwksUri) return;
	if (hasUsableIssuer(config.issuer)) return;
	if (isAzureJwksUri(config.jwksUri)) return;
	if (needsIssuerDiscovery(config)) return;

	throw new Error(
		`OAuth provider '${providerName}' (${config.provider}) has a 'jwksUri' but no usable 'issuer', and OIDC ` +
			`discovery cannot run for it (its 'authorizationUrl' is missing or not https). Without a validated ` +
			`issuer, ID token signature verification still runs but 'issuerValidated' is always false, so this ` +
			`provider's logins can never satisfy the account-adoption gate. Set 'issuer' explicitly on provider ` +
			`'${providerName}' (e.g. your OIDC server's issuer URI), or use the preset's 'domain'/'tenantId' ` +
			`shortcut if you're not already, which derives it for you.`
	);
}

/**
 * The exact condition `OAuthProvider`'s private `isAzureGraphUserInfo` checks
 * — `config.provider === 'azure'`, **or** `userInfoUrl`'s host is
 * `graph.microsoft.com` — duplicated here (deliberately, not imported: it's
 * a private method) so this startup check warns for exactly the same
 * configs that method's alternate `id`/`oid` correlation applies to.
 */
function isAzureGraphUserInfoConfig(config: OAuthProviderConfig): boolean {
	if (config.provider === 'azure') return true;
	try {
		return new URL(config.userInfoUrl).hostname === 'graph.microsoft.com';
	} catch {
		return false;
	}
}

/**
 * Warns (never throws) when a statically configured provider's `fetchEmail`
 * correlation against Microsoft Graph's non-OIDC `/v1.0/me` can never
 * succeed: that correlation needs the ID token's `oid` claim, which Azure
 * only includes when the `profile` scope was requested (#263; the Azure
 * preset's default `scope` already includes it). A custom `scope` that
 * drops `profile` silently loses the correlation at login time with no
 * indication why — this surfaces it at startup instead. Advisory only: it
 * degrades a UserInfo correlation, not the account-adoption gate's safety,
 * so a throwing logger must not abort provider initialization either.
 */
function checkGraphProfileScope(config: OAuthProviderConfig, providerName: string, logger?: Logger): void {
	if (!config.fetchEmail) return;
	if (!isAzureGraphUserInfoConfig(config)) return;
	const scopes = (config.scope ?? '').split(/\s+/).filter(Boolean);
	if (scopes.includes('profile')) return;
	try {
		logger?.warn?.(
			`OAuth provider '${providerName}': 'fetchEmail' is enabled against a Microsoft Graph UserInfo endpoint, ` +
				`but 'scope' does not include 'profile'. Azure only includes the 'oid' claim on the ID token when ` +
				`'profile' is requested, and 'oid' is required to correlate Graph's '/v1.0/me' response (which has ` +
				`no 'sub') with the ID token — without it, that fallback discards the UserInfo response instead of ` +
				`merging the email. Add 'profile' to provider '${providerName}''s 'scope'.`
		);
	} catch {
		/* a throwing logger must not abort provider initialization */
	}
}

/**
 * Re-derive OIDC discovery targets from an *already-built* provider
 * registry (HarperFast/oauth#264) — a pure function with no side effects.
 * Call only after the registry is confirmed published (see `src/index.ts`);
 * this function itself never starts a fetch.
 */
export function collectDiscoveryTargets(
	providers: ProviderRegistry
): Array<{ authorizationUrl: string; jwksUri: string; tokenUrl: string; providerName: string }> {
	const targets: Array<{ authorizationUrl: string; jwksUri: string; tokenUrl: string; providerName: string }> = [];
	for (const [providerName, { config }] of Object.entries(providers)) {
		if (needsIssuerDiscovery(config)) {
			targets.push({
				authorizationUrl: config.authorizationUrl,
				jwksUri: config.jwksUri!,
				tokenUrl: config.tokenUrl,
				providerName,
			});
		}
	}
	return targets;
}

/**
 * Extract plugin-level defaults from options
 */
export function extractPluginDefaults(options: OAuthPluginConfig): Partial<OAuthProviderConfig> {
	const pluginDefaults: Partial<OAuthProviderConfig> = {};

	// Copy all non-provider config to defaults, expanding environment variables.
	// `mcp` and `allowUnverifiedClaimInheritance` are plugin-level options that
	// do not apply per-provider and are excluded from the provider defaults copy.
	for (const [key, value] of Object.entries(options)) {
		if (key !== 'providers' && key !== 'debug' && key !== 'mcp' && key !== 'allowUnverifiedClaimInheritance') {
			pluginDefaults[key as keyof OAuthProviderConfig] = expandEnvVar(value);
		}
	}

	return pluginDefaults;
}

function isUnsetCredential(expandedValue: unknown): boolean {
	if (expandedValue === undefined || expandedValue === null) return true;
	if (typeof expandedValue === 'string' && expandedValue.trim() === '') return true;
	return isUnresolvedEnvPlaceholder(expandedValue);
}

function describeUnsetCredential(field: string, expandedValue: unknown): string {
	if (isUnresolvedEnvPlaceholder(expandedValue)) {
		return `'${field}' references environment variable ${String(expandedValue).trim()}, which is not set`;
	}
	return `'${field}' is not set`;
}

/**
 * Initialize OAuth providers from configuration
 */
export function initializeProviders(options: OAuthPluginConfig, logger?: Logger): ProviderRegistry {
	const providers: ProviderRegistry = {};

	// Providers configuration is required
	if (!options.providers || typeof options.providers !== 'object') {
		return providers;
	}

	// Extract plugin-level defaults
	const pluginDefaults = extractPluginDefaults(options);
	logger?.debug?.('Plugin defaults:', redactSecrets(pluginDefaults));

	// Initialize each provider
	for (const [providerName, providerConfig] of Object.entries(options.providers)) {
		// `mcp` is a reserved path segment for the MCP OAuth endpoints
		// (/oauth/mcp/*). A provider keyed `mcp` is shadowed by the MCP dispatcher
		// (resource.ts) and would silently 404 at request time, so reject the
		// collision loudly at config load instead.
		if (providerName === 'mcp') {
			throw new Error(
				"OAuth provider name 'mcp' is reserved for the MCP OAuth endpoints (/oauth/mcp/*). Rename this provider."
			);
		}

		// Must run before buildProviderConfig (#238's redirectUri checks) so an unconfigured
		// provider's redirectUri is never evaluated (#259).
		const expandedClientId = expandEnvVar(providerConfig?.clientId);
		const expandedClientSecret = expandEnvVar(providerConfig?.clientSecret);
		const clientIdUnset = isUnsetCredential(expandedClientId);
		const clientSecretUnset = isUnsetCredential(expandedClientSecret);

		if (clientIdUnset && clientSecretUnset) {
			logger?.warn?.(`OAuth provider '${providerName}' not configured. Missing: clientId, clientSecret`);
			continue;
		}
		if (clientIdUnset || clientSecretUnset) {
			const unsetField = clientIdUnset ? 'clientId' : 'clientSecret';
			const unsetValue = clientIdUnset ? expandedClientId : expandedClientSecret;
			logger?.error?.(
				`OAuth provider '${providerName}' is half configured — ${describeUnsetCredential(unsetField, unsetValue)} ` +
					`while the other credential is set. Skipping until both 'clientId' and 'clientSecret' are set.`
			);
			continue;
		}

		// enforceIssuerForJwks (#231 §4) only runs here, after the configured-ness
		// precheck above (#259/#260) — an unconfigured or half-configured provider
		// is already skipped and never reaches the issuer check.
		const config = buildProviderConfig(
			providerConfig,
			providerName,
			pluginDefaults,
			/* enforceIssuerForJwks */ true,
			logger
		);

		// Check if this provider is properly configured
		const requiredFields = ['clientId', 'clientSecret', 'authorizationUrl', 'tokenUrl', 'userInfoUrl'];
		const missingFields = requiredFields.filter((key) => !config[key as keyof OAuthProviderConfig]);

		if (missingFields.length > 0) {
			logger?.warn?.(`OAuth provider '${providerName}' not configured. Missing: ${missingFields.join(', ')}`);
			continue;
		}

		try {
			const provider = new OAuthProvider(config, logger);
			providers[providerName] = { provider, config };
			logger?.info?.(`OAuth provider '${providerName}' initialized (${config.provider})`);
		} catch (error) {
			logger?.error?.(`Failed to initialize OAuth provider '${providerName}':`, error);
		}
	}

	return providers;
}
