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
 * True when `url`'s query string is either empty, or consists of exactly
 * one `appid` parameter with a non-empty value — Azure's documented form
 * for identifying the calling application on these shared keys endpoints
 * (https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens).
 * Any other query (extra/duplicate/renamed params, or an empty `appid`)
 * is NOT accepted — callers treat that the same as before this existed.
 */
function hasEmptyOrAppIdOnlyQuery(url: URL): boolean {
	if (url.search === '') return true;
	const keys = [...url.searchParams.keys()];
	return keys.length === 1 && keys[0] === 'appid' && url.searchParams.get('appid') !== '';
}

/** The `appid` query parameter's value on `jwksUri`, or `null` if it has no query. Call only once the shape is already confirmed valid. */
function azureJwksAppId(jwksUri: string): string | null {
	const url = new URL(jwksUri);
	return url.search === '' ? null : url.searchParams.get('appid');
}

/**
 * The `{segment}` of an exact `https://login.microsoftonline.com/{segment}/discovery/v2.0/keys`
 * URL — full-URL match: exact host, no port/userinfo/fragment, exactly one
 * path segment before the fixed suffix, and a query that's either empty or
 * exactly Azure's documented `?appid=<client-id>` form. `null` for anything
 * else, including a lookalike with extra path segments, a different host,
 * or any other query.
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
	if (url.port !== '' || url.username !== '' || url.password !== '' || url.hash !== '') return null;
	if (!hasEmptyOrAppIdOnlyQuery(url)) return null;
	const match = /^\/([^/]+)\/discovery\/v2\.0\/keys$/.exec(url.pathname);
	return match ? match[1] : null;
}

/**
 * The `{segment}` of an exact Azure v1 JWKS keys-endpoint URL
 * (`https://login.microsoftonline.com/{segment}/discovery/keys` — no
 * `v2.0`; Azure's actual v1 metadata `jwks_uri` for a shared alias
 * authority), when `{segment}` is one of the shared aliases. `null` for
 * anything else, including the same path shape for a real tenant GUID —
 * out of scope here; this module's GUID branch only recognizes the v2 JWKS
 * shape (`azureJwksSegment`), and a v1-shaped GUID `jwksUri` is unaffected
 * by this function.
 */
function azureV1AliasJwksSegment(jwksUri: string | null | undefined): string | null {
	if (!jwksUri) return null;
	let url: URL;
	try {
		url = new URL(jwksUri);
	} catch {
		return null;
	}
	if (url.protocol !== 'https:') return null;
	if (url.hostname !== AZURE_HOST) return null;
	if (url.port !== '' || url.username !== '' || url.password !== '' || url.hash !== '') return null;
	if (!hasEmptyOrAppIdOnlyQuery(url)) return null;
	const match = /^\/([^/]+)\/discovery\/keys$/.exec(url.pathname);
	if (!match) return null;
	const segment = match[1].toLowerCase();
	return ALIAS_SEGMENTS.has(segment) ? segment : null;
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
 * The `{segment}` of an Azure authorize URL's path — either the v1
 * (`/{segment}/oauth2/authorize`) or v2 (`/{segment}/oauth2/v2.0/authorize`)
 * shape, lowercased. `null` for a non-Azure host or an unrecognized shape
 * (e.g. a B2C custom-policy URL) — callers must not warn on `null`; there is
 * no information to compare.
 */
function azureAuthorizeTenantSegment(authorizationUrl: string | null | undefined): string | null {
	if (!authorizationUrl) return null;
	let url: URL;
	try {
		url = new URL(authorizationUrl);
	} catch {
		return null;
	}
	if (url.hostname !== AZURE_HOST) return null;
	const match =
		/^\/([^/]+)\/oauth2\/v2\.0\/authorize$/.exec(url.pathname) ?? /^\/([^/]+)\/oauth2\/authorize$/.exec(url.pathname);
	return match ? match[1].toLowerCase() : null;
}

/**
 * The issuer to DERIVE (no pin given) for tenant `guid`, in the form
 * `authorizationUrl` actually issues — v1 (`sts.windows.net`) when it's a
 * recognized v1 authorize endpoint, v2 otherwise (including an unrecognized
 * shape, matching this function's behavior before v1 derivation existed).
 * Mirrors the pinned branch's `azureIssuerMatchesAuthorizeForm` check — a
 * real-tenant-GUID config with NO pin must derive the same form that one
 * would have been required to match.
 *
 * Also warns (never throws — advisory only) when `authorizationUrl` names a
 * DIFFERENT tenant (an alias, or another real GUID) than `jwksUri`'s `guid`:
 * deriving an issuer here is still the right, secure direction (it collapses
 * this config into the already-safe tenant-exclusive case, same as the
 * pinned branch), but it is also a silent behavior change — on `main`, this
 * exact shape (e.g. `authorizationUrl` pointed at the shared `/common`
 * endpoint, `jwksUri` pointed at one real tenant) had no issuer check at
 * all, so any tenant whose token verified against those keys could sign in;
 * now only `guid`'s tokens can. The warning exists so an operator who relied
 * on that (deliberately or not) finds out at startup, not from a wave of
 * `jwt issuer invalid` login failures.
 *
 * Only fires when `authorizeSegment` is something we can actually compare
 * against `guid`: an alias (`common`/`organizations`/`consumers`) or another
 * real tenant GUID. A verified-domain segment (e.g. `contoso.onmicrosoft.com`)
 * is neither — Azure accepts a tenant's registered domain name here, and we
 * have no offline way to map that domain to a GUID, so warning on it would be
 * a guess, not a finding; staying silent there is deliberate, not an
 * oversight.
 */
function azureDerivedIssuer(
	guid: string,
	authorizationUrl: string | null | undefined,
	providerName: string,
	logger?: Logger
): string {
	const rawAuthorizeSegment = azureAuthorizeTenantSegment(authorizationUrl);
	const authorizeSegment =
		rawAuthorizeSegment !== null && (ALIAS_SEGMENTS.has(rawAuthorizeSegment) || GUID_RE.test(rawAuthorizeSegment))
			? rawAuthorizeSegment
			: null;
	// 'consumers' and AZURE_CONSUMERS_TENANT_ID name the SAME tenant (Azure's
	// fixed GUID for personal Microsoft accounts) — not a mismatch, even
	// though the alias string and the GUID string are never equal.
	const isConsumersAliasMatch = authorizeSegment === 'consumers' && guid === AZURE_CONSUMERS_TENANT_ID;
	if (authorizeSegment && authorizeSegment !== guid && !isConsumersAliasMatch) {
		try {
			logger?.warn?.(
				`OAuth provider '${providerName}' (azure) has a jwksUri for tenant '${guid}' but an 'authorizationUrl' ` +
					`naming a different tenant ('${authorizeSegment}'). This provider now accepts sign-ins from '${guid}' ` +
					`only — a real token from any other tenant now fails ID-token verification outright, where it ` +
					`previously had no issuer check at all. If that's not intentional, point 'authorizationUrl' and ` +
					`'jwksUri' at the same tenant. If it is, pin 'issuer' explicitly to '${guid}'s issuer to make this ` +
					`startup-time derivation explicit in your config.`
			);
		} catch {
			/* advisory log only */
		}
	}
	return azureAuthorizeIssuerHost(authorizationUrl) === AZURE_STS_HOST
		? `https://${AZURE_STS_HOST}/${guid}/`
		: azureTenantUri('issuer', guid);
}

/**
 * True only for an UNPINNED shared alias authority's exact v2.0 keys-endpoint
 * shape (`https://login.microsoftonline.com/common|organizations|consumers/
 * discovery/v2.0/keys`) — the one case `resolveAzureIssuerBinding` above
 * deliberately leaves issuer-less by design (byte-identical to today; see
 * its own comments). Generic OIDC discovery (`discovery.ts`) and the #231 §4
 * issuer-required check must both skip only THAT case — every caller already
 * runs `hasUsableIssuer(config.issuer)` first, so this is only ever reached
 * once that's already `false`.
 *
 * Deliberately NOT "any shape `resolveAzureIssuerBinding` recognizes": a
 * real-tenant-GUID segment never reaches here at all (that function always
 * either sets a usable issuer or throws for it, so `hasUsableIssuer` above
 * already short-circuited), and a tenant-DOMAIN segment (e.g.
 * `contoso.onmicrosoft.com` — Azure accepts a verified domain name here, not
 * only a GUID), or the older, non-`v2.0` `/discovery/keys` shape on a real
 * tenant GUID, is not a case `resolveAzureIssuerBinding` touches at all.
 * Exempting either of those too (an earlier, broader version of this check
 * did) would boot them silently, `issuerValidated` permanently `false` and
 * no error — defeating the point of the check this guards. Falling through
 * instead lets the normal startup error fire, or lets generic discovery run
 * (Azure supports the standard `.well-known/openid-configuration` path for
 * these shapes too).
 *
 * The v1 alias shape (`.../common/discovery/keys`, no `v2.0`) IS included
 * here, alongside the v2 one: it is the same shared, tenant-independent key
 * pool under an older URL, and `resolveAzureIssuerBinding` handles it the
 * same way (byte-identical when unpinned; throws when pinned, below) — not
 * exempting it would route an unpinned one into generic discovery (which
 * fails for it) and tell the operator to pin, landing on the pinned case
 * that would otherwise bind an issuer to the unvalidated shared pool.
 */
export function isAzureJwksUri(jwksUri: string | null | undefined): boolean {
	const segment = azureJwksSegment(jwksUri);
	if (segment !== null) return ALIAS_SEGMENTS.has(segment.toLowerCase());
	return azureV1AliasJwksSegment(jwksUri) !== null;
}

/**
 * Resolve (and validate) an Azure issuer binding on `config`, in place.
 * A no-op for any `jwksUri` that isn't a recognized Azure JWKS shape (the
 * v2 keys endpoint for any segment, or the v1 keys endpoint for a shared
 * alias specifically). Throws naming the provider for an unsafe or
 * malformed combination (an array/non-Azure pin on an alias authority, a
 * pin naming a different tenant than a real-tenant-GUID `jwksUri`, or ANY
 * pin on a v1-shaped shared alias) — never silently builds a config that
 * could widen trust or that could never validate anything.
 */
export function resolveAzureIssuerBinding(config: OAuthProviderConfig, providerName: string, logger?: Logger): void {
	const segment = azureJwksSegment(config.jwksUri);
	if (!segment) {
		// Not the v2 shape at all — the only other case this module
		// recognizes is the v1 shared-alias shape. A v1-shaped real-tenant-GUID
		// `jwksUri` is NOT recognized (falls through, untouched, same as
		// before): this module's GUID handling only ever operates on the v2
		// JWKS shape.
		const v1AliasSegment = azureV1AliasJwksSegment(config.jwksUri);
		if (!v1AliasSegment) return;
		if (!hasUsableIssuer(config.issuer)) return; // Byte-identical to today — same as an unpinned v2 alias.
		throw new AzureIssuerBindingError(
			`OAuth provider '${providerName}' (azure) pins 'issuer' on a shared v1 authority ('${v1AliasSegment}', ` +
				`jwksUri '.../${v1AliasSegment}/discovery/keys') — a pinned issuer can't be bound to Azure's shared v1 ` +
				`key pool. Use the tenant's own keys ('https://login.microsoftonline.com/<tenant-guid>/discovery/keys') ` +
				`or the v2 endpoint ('https://login.microsoftonline.com/<tenant-guid>/discovery/v2.0/keys') instead.`
		);
	}
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
		config.issuer = azureDerivedIssuer(lowerSegment, config.authorizationUrl, providerName, logger);
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
	// Preserve the shared alias URL's own `?appid=` (if any, see
	// `hasEmptyOrAppIdOnlyQuery` above) on the rewritten tenant-exclusive
	// URL — it identifies the calling application to Azure, not the tenant,
	// so it still applies once `jwksUri` is redirected.
	const appId = azureJwksAppId(config.jwksUri as string);
	config.jwksUri = appId
		? `${azureTenantUri('keys', pinnedGuid)}?appid=${encodeURIComponent(appId)}`
		: azureTenantUri('keys', pinnedGuid);
	// Canonicalized WITHIN the pin's own form (case, trailing slash) — never
	// rewritten to the other form, same rationale as the real-tenant-GUID
	// case above.
	config.issuer = azureCanonicalIssuerForm(config.issuer as string, pinnedGuid);
}
