/**
 * Azure AD / Entra ID issuer resolution (HarperFast/oauth#264).
 *
 * `/common`, `/organizations` and `/consumers` are shared, tenant-independent
 * authorities with no single fixed issuer and no key set exclusive to one
 * tenant — a signature alone cannot prove which tenant a token belongs to.
 * A real tenant GUID, by contrast, is a tenant-exclusive authority: its
 * issuer and its JWKS response are both specific to that one tenant.
 *
 * This module gives every alias authority exactly one way to become usable:
 * the operator pins `issuer` to a single Azure tenant-GUID issuer string.
 * `resolveAzureIssuerBinding` then rewrites the effective `jwksUri` to that
 * same tenant's own, non-shared endpoint and sets `issuer` to its canonical
 * form — collapsing the pinned-alias case into the already-safe, already-
 * simple tenant-GUID case, with no new verification branch, resolver, or
 * cache: `OAuthProvider` ends up with an ordinary single-tenant config.
 * Left unpinned, an alias authority is untouched (byte-identical to today).
 *
 * Called from both `buildProviderConfig` (surfacing a misconfiguration as a
 * startup error as early as possible) and `OAuthProvider`'s own constructor
 * (the one point every construction path — including `TenantManager`, which
 * builds its config without going through `buildProviderConfig` at all —
 * is guaranteed to cross). Safe to call twice: once the rewrite has already
 * happened, the config simply looks like a real-tenant-GUID config, and a
 * second call is a no-op.
 */

import type { Logger, OAuthProviderConfig } from '../types.ts';

/** Entra ID's documented, permanent nickname for the "personal Microsoft accounts" tenant. */
export const AZURE_CONSUMERS_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad';

/**
 * A configured, but invalid, Azure `issuer` pin — distinguished from any
 * other `buildProviderConfig` failure so `initializeProviders` (#259/#260's
 * "skip the bad provider, keep the others" pattern) can treat it the same
 * way: this one provider's own pin is wrong, which says nothing about
 * whether every OTHER declared provider is safe to start.
 */
export class AzureIssuerBindingError extends Error {}

const AZURE_HOST = 'login.microsoftonline.com';
const AZURE_STS_HOST = 'sts.windows.net';
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALIAS_SEGMENTS = new Set(['common', 'organizations', 'consumers']);

function azureTenantUri(kind: 'issuer' | 'keys', guid: string): string {
	return kind === 'issuer' ? `https://${AZURE_HOST}/${guid}/v2.0` : `https://${AZURE_HOST}/${guid}/discovery/v2.0/keys`;
}

/**
 * The `{segment}` of an exact `https://login.microsoftonline.com/{segment}/discovery/v2.0/keys`
 * URL — full-URL match: exact host, no port/userinfo/query/fragment, exactly
 * one path segment before the fixed suffix. `null` for anything else,
 * including a lookalike with extra path segments or a different host.
 */
function azureJwksSegment(jwksUri: string | null | undefined): string | null {
	if (!jwksUri) return null;
	let url: URL;
	try {
		url = new URL(jwksUri);
	} catch {
		return null;
	}
	if (url.protocol !== 'https:') return null;
	if (url.hostname !== AZURE_HOST) return null;
	if (url.port !== '' || url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
		return null;
	}
	const match = /^\/([^/]+)\/discovery\/v2\.0\/keys$/.exec(url.pathname);
	return match ? match[1] : null;
}

/** True when `issuer` is a value `jwt.verify` would actually check against. */
function hasUsableIssuer(issuer: OAuthProviderConfig['issuer']): boolean {
	if (Array.isArray(issuer)) return issuer.some((value) => typeof value === 'string' && value !== '');
	return typeof issuer === 'string' && issuer !== '';
}

/**
 * The tenant GUID of a single Azure v1 (`https://sts.windows.net/{guid}/`)
 * or v2 (`https://login.microsoftonline.com/{guid}/v2.0`) tenant-exclusive
 * issuer string, lowercased. `null` for anything else — a different host,
 * an alias segment, or a malformed value.
 */
function azureIssuerGuidAnyVersion(value: unknown): string | null {
	if (typeof value !== 'string' || value === '') return null;
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return null;
	}
	if (url.protocol !== 'https:') return null;
	if (url.port !== '' || url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
		return null;
	}
	let match: RegExpExecArray | null = null;
	if (url.hostname === AZURE_HOST) match = /^\/([^/]+)\/v2\.0\/?$/.exec(url.pathname);
	else if (url.hostname === AZURE_STS_HOST) match = /^\/([^/]+)\/?$/.exec(url.pathname);
	if (!match) return null;
	const guid = match[1].toLowerCase();
	return GUID_RE.test(guid) ? guid : null;
}

/**
 * True when every value of a usable `issuer` (string or array) names the
 * same tenant `guid`, in either Azure issuer form
 * (`login.microsoftonline.com/.../v2.0` or `sts.windows.net/...`). Case and
 * a trailing slash are tolerated — `jwt.verify` itself does exact string
 * comparison, so this is what lets a pin in either acceptable shape or
 * casing be canonicalized rather than rejected or left to fail later.
 */
function azureIssuerNamesOnlyTenant(issuer: OAuthProviderConfig['issuer'], guid: string): boolean {
	const values = Array.isArray(issuer) ? issuer : [issuer];
	return values.every((value) => azureIssuerGuidAnyVersion(value) === guid);
}

const V1_AUTHORIZE_SUFFIX = '/oauth2/authorize';
const V2_AUTHORIZE_SUFFIX = '/oauth2/v2.0/authorize';

/**
 * Which Azure authorize-endpoint shape `authorizationUrl` is — the thing
 * that actually determines a real token's `iss` host (v1 `/oauth2/authorize`
 * issues `sts.windows.net` tokens; v2 `/oauth2/v2.0/authorize` issues
 * `login.microsoftonline.com` ones). Neither the pin's own form nor the
 * jwksUri's shape says anything about this — the Azure preset, for example,
 * always generates a v2 `authorizationUrl` regardless of what the operator
 * pins. `null` for a non-Azure host, or an authorize shape this function
 * doesn't recognize (e.g. a B2C custom-policy URL) — callers must not
 * additionally constrain the pin's form in that case, only its tenant.
 */
function azureAuthorizeIssuerHost(authorizationUrl: string | null | undefined): string | null {
	if (!authorizationUrl) return null;
	let url: URL;
	try {
		url = new URL(authorizationUrl);
	} catch {
		return null;
	}
	if (url.hostname !== AZURE_HOST) return null;
	if (url.pathname.endsWith(V2_AUTHORIZE_SUFFIX)) return AZURE_HOST;
	if (url.pathname.endsWith(V1_AUTHORIZE_SUFFIX)) return AZURE_STS_HOST;
	return null;
}

/**
 * True when every value of a usable `issuer` is in the one form a real
 * token from `authorizationUrl` would actually carry — or when
 * `authorizationUrl`'s shape isn't recognized, in which case this imposes
 * no additional constraint (see {@link azureAuthorizeIssuerHost}).
 */
function azureIssuerMatchesAuthorizeForm(issuer: OAuthProviderConfig['issuer'], authorizationUrl: string): boolean {
	const expectedHost = azureAuthorizeIssuerHost(authorizationUrl);
	if (!expectedHost) return true;
	const values = Array.isArray(issuer) ? issuer : [issuer];
	return values.every((value) => {
		if (typeof value !== 'string') return false;
		try {
			return new URL(value).hostname === expectedHost;
		} catch {
			return false;
		}
	});
}

/**
 * Canonicalize one already-validated (`azureIssuerGuidAnyVersion(value) ===
 * guid`) issuer value to its own form's exact string — case and a trailing
 * slash only. Which `iss` form a real token carries depends on the
 * *authorize* endpoint, not the JWKS URL (a v1 `/oauth2/authorize` issues
 * `sts.windows.net` tokens; v2 issues `login.microsoftonline.com` tokens),
 * so a v1 pin must stay v1 and a v2 pin must stay v2 — collapsing both to
 * one form would silently break whichever form the operator's real tokens
 * actually use.
 */
function azureCanonicalIssuerForm(value: string, guid: string): string {
	return new URL(value).hostname === AZURE_HOST ? azureTenantUri('issuer', guid) : `https://${AZURE_STS_HOST}/${guid}/`;
}

/** {@link azureCanonicalIssuerForm}, applied to every value of a string-or-array issuer, preserving its shape. */
function normalizeAzureIssuerPin(issuer: OAuthProviderConfig['issuer'], guid: string): OAuthProviderConfig['issuer'] {
	if (Array.isArray(issuer)) return issuer.map((value) => azureCanonicalIssuerForm(value as string, guid));
	return azureCanonicalIssuerForm(issuer as string, guid);
}

/**
 * True only for the exact Azure v2.0 keys-endpoint shape
 * (`https://login.microsoftonline.com/{segment}/discovery/v2.0/keys`) —
 * the one shape `resolveAzureIssuerBinding` above actually recognizes and
 * resolves (or safely leaves alone/throws for). Generic OIDC discovery
 * (`discovery.ts`) must never run against THAT shape: a config this
 * function excludes either already has a usable issuer (handled above) or
 * is an intentionally unpinned alias authority (byte-identical to today).
 *
 * Deliberately NOT a bare Azure-hostname check: a `login.microsoftonline.com`
 * `jwksUri` in a DIFFERENT shape (e.g. the older, non-`v2.0` `/discovery/keys`
 * path) is a shape `resolveAzureIssuerBinding` never touches at all — for
 * that case, falling through to the normal #231 §4 issuer-required check (or
 * to generic OIDC discovery, which Azure also supports at the standard
 * `.well-known/openid-configuration` path) is the useful, actionable outcome;
 * exempting it here would instead boot it silently, with `issuerValidated`
 * permanently `false` and no error, defeating the point of that check.
 */
export function isAzureJwksUri(jwksUri: string | null | undefined): boolean {
	return azureJwksSegment(jwksUri) !== null;
}

/**
 * Resolve (and validate) an Azure issuer binding on `config`, in place.
 * A no-op for any `jwksUri` that isn't the exact Azure v2.0 keys-endpoint
 * shape. Throws naming the provider for an unsafe or malformed combination
 * (an array/non-Azure pin on an alias authority, or a pin naming a different
 * tenant than a real-tenant-GUID `jwksUri`) — never silently builds a config
 * that could widen trust or that could never validate anything.
 */
export function resolveAzureIssuerBinding(config: OAuthProviderConfig, providerName: string, logger?: Logger): void {
	const segment = azureJwksSegment(config.jwksUri);
	if (!segment) return;
	const lowerSegment = segment.toLowerCase();

	if (GUID_RE.test(lowerSegment)) {
		// A real, tenant-exclusive authority: the issuer is fully determined by
		// the URL itself. An operator-pinned issuer must name only that same
		// tenant (in either Azure issuer form, string or array) — Azure's
		// signing keys are not guaranteed exclusive to one tenant-specific
		// endpoint over time, so a pin naming a different tenant could otherwise
		// accept a different tenant's token. A same-tenant pin is canonicalized
		// (case, trailing slash) within its OWN form rather than left as-is —
		// `jwt.verify` compares issuer strings exactly, so a differently-cased
		// GUID or a trailing slash would otherwise fail verification for a
		// real, correctly signed token — but never rewritten to a DIFFERENT
		// form: which `iss` a real token carries depends on the authorize
		// endpoint (v1 `/oauth2/authorize` issues `sts.windows.net` tokens, v2
		// issues `login.microsoftonline.com` ones), so collapsing a v1 pin to
		// v2 (or vice versa) would break verification for whichever form the
		// operator's real tokens actually use.
		if (hasUsableIssuer(config.issuer)) {
			if (!azureIssuerNamesOnlyTenant(config.issuer, lowerSegment)) {
				throw new AzureIssuerBindingError(
					`OAuth provider '${providerName}' (azure) has a jwksUri for tenant '${lowerSegment}' but an ` +
						`explicit 'issuer' naming a different tenant, or an unrecognized value, ` +
						`(${JSON.stringify(config.issuer)}). Every value of the pinned issuer's tenant and the jwksUri's ` +
						`tenant must be the same GUID.`
				);
			}
			// Naming the right tenant is necessary but not sufficient: the pin's
			// FORM must also match what `authorizationUrl` actually issues (e.g.
			// the Azure preset always generates a v2 authorizationUrl, regardless
			// of what the operator pins) — otherwise every real token's `iss`
			// fails `jwt.verify`'s exact-string comparison against the wrong form.
			if (!azureIssuerMatchesAuthorizeForm(config.issuer, config.authorizationUrl)) {
				throw new AzureIssuerBindingError(
					`OAuth provider '${providerName}' (azure) pins 'issuer' to ${JSON.stringify(config.issuer)}, which ` +
						`names the right tenant but the wrong Azure issuer form for its 'authorizationUrl' ` +
						`(${JSON.stringify(config.authorizationUrl)}). A v2 authorize endpoint ` +
						`('.../oauth2/v2.0/authorize') issues '${AZURE_HOST}' tokens; a v1 one ('.../oauth2/authorize') ` +
						`issues '${AZURE_STS_HOST}' tokens. Pin the form that matches 'authorizationUrl'.`
				);
			}
			config.issuer = normalizeAzureIssuerPin(config.issuer, lowerSegment);
			return;
		}
		config.issuer = azureTenantUri('issuer', lowerSegment);
		return;
	}

	if (!ALIAS_SEGMENTS.has(lowerSegment)) return; // Not a recognized Azure shape; leave it alone.

	// Shared, tenant-independent authority (/common, /organizations, /consumers):
	// adoption-eligible only when the operator pins exactly one tenant-GUID
	// issuer. Unpinned, this is byte-identical to today (plain jwks-rsa against
	// the shared endpoint, issuer never set, issuerValidated always false).
	if (!hasUsableIssuer(config.issuer)) return;

	if (Array.isArray(config.issuer)) {
		throw new AzureIssuerBindingError(
			`OAuth provider '${providerName}' (azure) pins 'issuer' to an array on a shared authority ` +
				`('${lowerSegment}'). Pin exactly one Azure tenant issuer (e.g. ` +
				`'https://login.microsoftonline.com/<tenant-guid>/v2.0') — an array would make every listed tenant ` +
				`adoption-eligible through one provider, re-opening the cross-tenant adoption question account-level ` +
				`identity binding (not issuer validation) is meant to answer. Configure a separate provider entry ` +
				`per tenant if more than one tenant needs to be trusted.`
		);
	}

	// Either Azure issuer form is accepted here, same as the real-tenant-GUID
	// case above: which form a real token's `iss` carries depends on the
	// authorize endpoint (v1 vs v2), not on this jwksUri being the shared v2
	// alias endpoint, and Azure signs v1 and v2 tokens with the same keys —
	// so a v1-authorize operator pinning a v1 (`sts.windows.net`) issuer is
	// exactly as safe as a v2 pin, and rejecting it would leave that
	// combination permanently unable to adopt. The pin's form must still
	// match `authorizationUrl`'s own shape when that shape is recognized
	// (checked below) — otherwise every real token's `iss` fails `jwt.verify`.
	const pinnedGuid = azureIssuerGuidAnyVersion(config.issuer);
	if (!pinnedGuid) {
		throw new AzureIssuerBindingError(
			`OAuth provider '${providerName}' (azure) pins 'issuer' to ${JSON.stringify(config.issuer)} on a shared ` +
				`authority ('${lowerSegment}'), which is not a usable Azure tenant issuer. Set 'issuer' to exactly one ` +
				`tenant issuer URI, e.g. 'https://login.microsoftonline.com/<tenant-guid>/v2.0' or ` +
				`'https://sts.windows.net/<tenant-guid>/' (use '${AZURE_CONSUMERS_TENANT_ID}' for the ` +
				`personal-Microsoft-account tenant).`
		);
	}
	if (!azureIssuerMatchesAuthorizeForm(config.issuer, config.authorizationUrl)) {
		throw new AzureIssuerBindingError(
			`OAuth provider '${providerName}' (azure) pins 'issuer' to ${JSON.stringify(config.issuer)}, which names a ` +
				`usable tenant but the wrong Azure issuer form for its 'authorizationUrl' ` +
				`(${JSON.stringify(config.authorizationUrl)}). A v2 authorize endpoint ('.../oauth2/v2.0/authorize') ` +
				`issues '${AZURE_HOST}' tokens; a v1 one ('.../oauth2/authorize') issues '${AZURE_STS_HOST}' tokens. ` +
				`Pin the form that matches 'authorizationUrl'.`
		);
	}

	// Collapse into the tenant-exclusive case above: verify against that one
	// tenant's own, non-shared JWKS endpoint — never the shared alias pool.
	// Advisory only: a throwing logger must not abort issuer binding.
	try {
		logger?.info?.(
			`OAuth provider '${providerName}' (azure): pinned issuer resolves to tenant '${pinnedGuid}'; verifying ` +
				`against that tenant's own JWKS endpoint instead of the shared '${lowerSegment}' key set.`
		);
	} catch {
		/* advisory log only */
	}
	config.jwksUri = azureTenantUri('keys', pinnedGuid);
	// Canonicalized WITHIN the pin's own form (case, trailing slash) — never
	// rewritten to the other form, same rationale as the real-tenant-GUID
	// case above.
	config.issuer = azureCanonicalIssuerForm(config.issuer as string, pinnedGuid);
}
