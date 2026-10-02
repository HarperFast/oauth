# Changelog

All notable changes to `@harperfast/oauth` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries prior to 2.2.0 were backfilled from the [GitHub release notes](https://github.com/HarperFast/oauth/releases).

## [Unreleased]

### Fixed

- **A statically configured JWKS-enabled provider now requires a usable `issuer`, checked at startup** (#231 §4): a custom OIDC/JWKS provider configured with explicit endpoints — e.g. an Okta custom authorization server, or a `generic` provider with `jwksUri` set — but no `issuer` left `issuerValidated` always `false` (see 2.6.0's account-adoption gate). Its ID token signature still verified, but a hookless login that should have adopted an existing Harper account was silently denied, with nothing in the logs pointing at `issuer`. Config building for a provider declared in `providers:` now throws at startup, naming the provider and the `issuer` key, whenever it has `jwksUri` set but no usable `issuer` (empty string, `null`, or an array with no non-empty entry). Okta/Auth0's `domain` shortcut (and Azure's `tenantId` shortcut) already derive `issuer` for you — this only affects a provider bypassing that shortcut with explicit endpoints. Azure's multi-tenant `/common` default is unaffected: it ships `issuer: null` deliberately (no single issuer exists for `/common`) and remains not-adoption-eligible exactly as before, not a startup error. A dynamically resolved provider (`onResolveProvider`) is also unaffected — enforcing this on the request path would repeatedly fail every request for a misconfigured tenant instead of just leaving it non-adoption-eligible, so the check runs only for statically declared providers. **Upgrade note:** an instance with a statically declared provider that sets `jwksUri` and no `issuer` — Okta/Auth0/`generic` only, not Azure — now fails to start; the same config applied via a live reload is rejected and the previous configuration keeps serving. Set `issuer` explicitly, or use the `domain`/`tenantId` shortcut.
- **UserInfo `sub` must match the ID token's `sub` on the `fetchEmail` fallback path** (#231 §5a, OIDC Core 5.3.2/5.3.4): when an ID token lacks an `email` claim and `fetchEmail` is configured, the plugin fetches the UserInfo endpoint to resolve it. A UserInfo response whose `sub` differs from (or omits, which OIDC Core 5.3.2 also disallows) the verified ID token's `sub` describes an uncorrelated subject — previously its fields (email, name, and any other claim not present on the ID token) were still merged into the login. The fetched UserInfo is now discarded entirely on a `sub` mismatch or absence, falling back to the ID token's own claims only, exactly as on a UserInfo fetch failure. This was not an adoption-gate bypass (that merge was always tagged `unauthenticated`, which the gate already denies for adoption), but it could still attach a different subject's profile fields to the session.
- **A transient `hdb_user` read error during account adoption now quarantines the login instead of denying it** (#231 §5b): the adoption gate's existence check previously treated a lookup error the same as a confirmed existing account, denying any login with an unverified claim. The quarantine principal it would otherwise use is unpredictable and can never match any `hdb_user` name, confirmed-existing or not, so quarantining on an unknown lookup result is exactly as secure as denying — and more available, since a transient error on a login that was never going to adopt anything no longer fails it outright. A trusted claim (signed-oidc / github-authenticated) is unaffected either way.
- **Disabling `allowUnverifiedClaimInheritance` is applied independently of provider (re)initialization on a live config reload** (#231 §5c): a reload snapshot that both disabled the escape hatch and had an unrelated provider config error (e.g. the new issuer check above) previously aborted before the escape-hatch flag was ever re-applied, leaving the _previous_ snapshot's value — possibly still enabled — in effect, contrary to the operator's intent in the snapshot that failed. A _disabling_ value is now applied to the running configuration immediately, before provider initialization can throw. An _enabling_ value still waits for the reload to fully succeed, so a rejected reload can never turn the hatch on for the still-serving (old) providers.
- **`_emailProvenance` is no longer stamped `signed-oidc` on the no-JWKS fallback** (#231 §5d): `OAuthProvider.getUserInfo` labeled any present `idTokenClaims` `signed-oidc` regardless of whether the ID token's signature was actually verified via JWKS — including the no-JWKS fallback, which only decodes claims. The account-adoption gate was not exploitable by this (it independently re-checks `signatureVerified`/`issuerValidated` before trusting `signed-oidc`), but the label overstated its own contract for any other consumer. `getUserInfo` now takes the verified-signature flag and only stamps `signed-oidc` when it is `true`.

## [2.8.0] - 2026-10-01

### Added

- **Interactive CIMD clients can authenticate with `private_key_jwt`**: the token endpoint verifies client assertions from interactive Client ID Metadata Document clients.
  - Algorithms: RS256, ES256 or EdDSA, narrowed to the document's `token_endpoint_auth_signing_alg`.
  - Keys come from inline `jwks` or from `jwks_uri`. A `jwks_uri` is fetched with the same controls as the document (validated and pinned addresses, no redirects, size and time limits) and must be on the client ID's origin unless `mcp.clientIdMetadataDocuments.privateKeyJwt.jwksUriAllowedOrigins` admits another. Only key material is cached, per client; a fetched key set is assigned a TTL of at least 60 seconds, whatever its caching directives.
  - The server permits one method per client: the document's preference when this server advertises it. Selection checks the inline key set or the `jwks_uri` location policy and any signing-algorithm pin. For `jwks_uri`, the fetched keys are validated during token exchange. The ChatGPT-shaped test document resolves to `none` when the interactive setting is omitted and headless agents are off, and to `private_key_jwt` when `privateKeyJwt.enabled: true` or headless agents advertise it. In one session recorded against a test authorization server that offered both methods, ChatGPT authenticated its code exchange and four refreshes with `private_key_jwt` (`RS256`, a 60-second lifetime) and the token endpoint URL as `aud`, which the issuer-only policy refuses unless an unexpired `privateKeyJwt.tokenEndpointAudience` exception lists its client ID. In a second session, offered only `none`, it used `none`. The recording was not made against this plugin.
  - The interactive assertion audience is the issuer. `privateKeyJwt.tokenEndpointAudience` is an opt-in exception with a required expiry that also accepts the advertised token endpoint for listed client IDs.
- **The client-authentication method is bound to the grant**: the method permitted at `/oauth/mcp/authorize` must be used for the code exchange and for every refresh of that grant. A request that authenticates under current policy but conflicts with a bound code or family returns `invalid_grant`; a currently unpermitted presentation returns `invalid_client` before grant lookup. The client then reauthorizes.

### Changed

- **Compatibility:** Interactive CIMD `private_key_jwt` remains opt-in: set `mcp.clientIdMetadataDocuments.privateKeyJwt.enabled: true` to advertise it when headless agents are off. When headless agents are off, omitting the flag or setting it to `false` preserves the prior public-client advertisement. Interactive clients selected for `private_key_jwt` must present a verified assertion on code exchange and refresh. Explicitly enabling the setting requires CIMD resolution and an `https:` issuer (loopback `http:` is allowed); these startup checks do not apply to an omitted or false setting. With MCP enabled, a declared non-boolean value, including an own `undefined` property, `"true"`, `"false"` or `null`, fails config normalization. Unresolved placeholders and empty strings retain their specific startup errors. With MCP off, prior coercion and warn-and-drop behavior is unchanged.
- **Token-request resource validation:** for `authorization_code` and `refresh_token`, a verified client assertion is recorded before grant and resource checks, including when `resource` is present. On a redeemable `authorization_code` or current `refresh_token` with a stored resource, every parsed `resource` must match both it and the current MCP resource; otherwise `400 invalid_target` precedes code consumption or refresh rotation. Superseded refresh replay precedes resource validation. Omitting `resource` is unchanged; a valid grant without a stored resource still returns `server_error` at signing.
- **Compatibility:** CIMD documents containing `client_secret*` members are rejected with `invalid_client` (for example `client_secret` or `client_secret_expires_at`), in either document shape.
- **Compatibility:** a `client_credentials` request in which `grant_type`, `code`, `redirect_uri`, `code_verifier`, `refresh_token`, `client_id`, `client_secret`, `client_assertion`, `client_assertion_type` or `scope` is an array now receives `400 invalid_request` before client authentication or token issuance. Every value of a `resource` array must be the configured MCP resource, otherwise the request receives `400 invalid_target`; previously a `resource` array was not checked. On Harper's old form deserializer (including 5.1.9), a repeated listed single-valued parameter or `resource` keeps its first value under its own name; later values are not checked there.
- **Client credentials presented at the token endpoint are verified or rejected** (`authorization_code` and `refresh_token`). An array value for a parameter listed in the compatibility note above, a `client_id` or credential parameter that is empty or not a single string, half an assertion pair, or more than one authentication mechanism (any `Basic` header counts as one) is rejected with `invalid_request` (400); otherwise, malformed `Basic` credentials are rejected with `invalid_client` (401). A `401` answering a request that used `Basic` carries `WWW-Authenticate: Basic`. A client permitted `none` that sends assertion parameters is rejected. **Compatibility:** assertion parameters that were previously ignored are now verified or rejected.
- **Interactive CIMD documents are validated for their declared authentication.** A document is rejected with `invalid_client` when:
  - `token_endpoint_auth_method` is present but not a string;
  - `token_endpoint_auth_methods_supported` is not an array of strings, or omits the singular value;
  - it declares `client_secret_basic`, `client_secret_post` or `client_secret_jwt`;
  - it has both `jwks` and `jwks_uri`, or inline keys with private key material.
- **Advertised signing algorithms are the union of what the enabled verification paths accept.** A server with `client_credentials` enabled now lists `RS256`, `ES256` and `EdDSA` in `token_endpoint_auth_signing_alg_values_supported` (previously `EdDSA` only), because interactive CIMD assertions are verified there as well.
- **`client_credentials` assertions also accept the issuer as `aud`.** The token endpoint URL stays accepted unless `mcp.clientCredentials.acceptTokenEndpointAudience` is `false`. `typ: client-authentication+jwt` is accepted, and `jku`, `jwk`, `x5u` and `x5c` headers are rejected.
- **Fetched documents' media type is compared exactly.** The response media type, excluding parameters, must be exactly `application/json` or `application/jwk-set+json`. CIMD documents accept `application/json` only; a type that merely contains it, such as `text/plain; x=application/json`, is rejected.
- **Client-assertion replay records carry an explicit per-record expiry** instead of the table's fixed 120 seconds. Expires at the later of assertion `exp` and insertion time, plus 60 seconds.
- **Upgrade note:**
  - Flow states and authorization codes created before this version are rejected; the client restarts authorization.
  - New refresh families use `p2-` ids and carry the binding; `p1-` families are treated as bound to `none` for CIMD clients and to the registered method (default `none`) for stored clients. A different currently permitted method requires reauthorization.
  - Drain older nodes before issuing bound grants and never route bound grants to versions before 2.7. Version 2.7.x retires `p2-` families.
  - Every new authorization code and refresh family is bound, whether or not `private_key_jwt` is advertised, so drain older nodes before this version serves any grant. On rollback to 2.7.x, `p2-` families are retired and those clients re-authorize; codes in flight can be redeemed without the binding check. Routing bound grants to a version below 2.7 is unsafe.
  - With MCP and CIMD enabled and headless agents off, omitting `privateKeyJwt.enabled` preserves the prior advertisement: a document declaring both `none` and `private_key_jwt` selects `none`, and a document declaring only `private_key_jwt` has no permitted method. When an operator opts in with `privateKeyJwt.enabled: true`, selection takes the singular preference in the declared, advertised and permitted intersection; otherwise the sole member wins, or `private_key_jwt` wins when both it and `none` remain. A client newly selected for `private_key_jwt` that keeps presenting `none` is refused with `invalid_client`, and its `p1-` families, bound to `none`, can no longer be refreshed; the client reauthorizes.
  - For key-authenticated ChatGPT now, set `mcp.clientIdMetadataDocuments.privateKeyJwt.enabled: true` and `mcp.clientIdMetadataDocuments.privateKeyJwt.tokenEndpointAudience: { clientIds: ["https://chatgpt.com/oauth/client.json"], expiresAt: "<operator-chosen ISO 8601 date-time>" }`. Headless agents also advertise `private_key_jwt` even when the interactive flag is omitted or false; add `chatgpt.com` to `clientIdMetadataDocuments.allowedHosts` when that allowlist is set (required for headless) and to `dynamicClientRegistration.allowedRedirectUriHosts` if set, then reauthorize ChatGPT links bound to `none`. This exception accepts the token-endpoint audience for that exact client until expiry. RFC 7523bis forbids that audience by default because a malicious authorization server can inject our token endpoint URL as its own and obtain a replayable assertion; use an expiry you choose and renew only while needed.

### Fixed

- **Interactive CIMD token-endpoint-audience refusals can give an operator warning** when a warning logger is available: with keys on the client-ID origin, an unconfigured exception gets the full exact-ID setting with a future expiry, while an existing exception gets every needed field edit, including both expiry and client ID when both fail; off-origin keys get an explanation that the exception cannot apply, without a setting. The client response and acceptance policy are unchanged. Each node warns at most once per client ID per five minutes. When its 1,024 slots are full, it suppresses warnings for new IDs until an expired slot is cleared by a later refusal.
- **`mcp.dynamicClientRegistration.initialAccessToken` fails closed on an unresolved placeholder or empty value** (#240): a declared `initialAccessToken` that resolved to an unresolved `${VAR}` placeholder (the variable is unset) previously became the accepted bearer secret itself — anyone who could read the committed config (placeholders routinely are) could register MCP clients — and a set-but-empty value silently enabled open registration behind a warning worded like the legitimate RFC 7591 open mode. Both now throw at startup, naming the key, whenever DCR is enabled (`mcp.enabled` is `true` and `dynamicClientRegistration.enabled` is not `false`). Open registration remains available only by omitting `initialAccessToken` entirely. **Upgrade note:** an instance with DCR enabled and a declared-but-unresolved/empty `initialAccessToken` now fails to start; applying the same bad value via a live config reload is rejected and the previous configuration keeps serving. Also closed here: Harper's `OptionsWatcher` applies a multi-key config edit one key at a time, emitting a `change` event synchronously per key. The config-update loop had no synchronization on that batch, so a reload that flipped `dynamicClientRegistration.enabled` to `true` in one key and set `initialAccessToken` in a second key could read and publish the config after only the first key landed — briefly serving open DCR before the batch's final, correctly-rejected snapshot was ever evaluated. The update loop now yields once before reading the config, so a synchronous burst of per-key `change` events is fully applied before any snapshot is read.
- **An unresolved `${VAR}` placeholder on a feature-scoped `mcp` boolean now throws instead of silently dropping to the documented default** (#207): `mcp.refreshTokenRequiresOfflineAccess`, `mcp.clientCredentials.enabled`, `mcp.clientIdMetadataDocuments.enabled`, and `mcp.dynamicClientRegistration.enabled` previously treated an unset environment variable's leftover placeholder as absent (warn and drop to the documented default) — introduced in 2.5.0 but never called out here. That's safe when the default is off, but `dynamicClientRegistration`'s default is _on_ (a declared block with no explicit `enabled: false` is enabled), so the identical mistake could silently re-enable a gate the operator meant to turn off. These four still drop to their default while the surface they gate is inactive (`mcp.enabled` isn't `true`), so a disabled block with a stray placeholder still boots unchanged. `mcp.enabled` itself keeps its original 2.5.0 warn-and-drop behavior rather than joining the other four in failing closed: dropping it already lands on the safe direction (MCP off), and there's no outer flag to hide an ambiguous value behind — failing closed here would stop the whole plugin, including every provider's browser OAuth login, over one unset variable. **Upgrade note:** a config with `mcp.enabled: true` and an unresolved placeholder on any of the four feature-scoped fields above now fails to start; the same value applied via a live config reload is rejected and the previous configuration keeps serving. An unresolved placeholder (or empty value) on `mcp.enabled` itself still only warns and boots with MCP off. Set the variable, or replace the placeholder with a literal `true`/`false`. Also closed here: not every substitution mechanism leaves the placeholder text behind when its variable is unset — docker-compose's `VAR=${VAR}` resolves to an empty string (not the literal `${VAR}`) for an unset `VAR`. An empty string left on one of the four feature-scoped boolean fields now fails closed the same way an unresolved placeholder does, instead of falling through to "must be a boolean" and getting silently dropped; `mcp.enabled` treats an empty string the same (warn and drop) as a placeholder.
- **A non-mapping `dynamicClientRegistration` or `clientIdMetadataDocuments` block no longer silently enables the feature it was supposed to disable**: `dynamicClientRegistration: false` (or `0`, an unresolved `${VAR}` placeholder, or an array — a YAML list is still `typeof 'object'`) skipped the block's validation entirely and fell through to the feature's runtime enabled-check, where `.enabled` on a non-mapping value reads as `undefined` — `!== false` resolved to `true`, so DCR opened for registration anyway (CIMD, whose block defaults to enabled, had the same gap for an operator trying to disable it with a scalar or array value). Both blocks now require an actual mapping whenever `mcp.enabled` is `true`: a non-mapping, non-null value throws at startup naming the field (`mcp.dynamicClientRegistration must be a mapping; use enabled: false to disable`, and the `clientIdMetadataDocuments` equivalent). `dcrEnabled()` and CIMD's own enabled check are hardened with the same type guard as defense in depth. A bare YAML key (parses as `null`) is unaffected and still means absent/disabled.
- **A scalar `dynamicClientRegistration.allowedRedirectUriHosts` is no longer matched by substring**: the redirect-uri allowlist check (shared by the DCR and CIMD redirect-uri validators) runs `Array.prototype.includes`, but a scalar string value ran `String.prototype.includes` instead — `allowedRedirectUriHosts: "example.com"` would accept `evil-example.com.attacker.net` as a substring match. It's now normalized to a one-element, lowercased array at startup, exactly like `clientIdMetadataDocuments.allowedHosts` already was.
- **Over-length client assertions are rejected before any client lookup.** The verifier's 8192-character bound is applied at the token endpoint before an assertion is parsed for its client ID or any client is looked up, on every grant that accepts assertions.
- **A client assertion presented concurrently is accepted at most once per node**, on every grant that accepts assertions. Replay records (`mcp_assertion_jtis`) gain a `uses` counter: each presentation adds 1 atomically, and only the one that reads back 1 is accepted, so concurrent presentations can all be refused. Previously they could all be accepted.
- **A refresh-family revocation is no longer undone by a concurrent refresh.** Rotation and revocation now write only their own field (`current_token_hash`, `revoked`), so a revocation committed while another request rotates the family stays in force.
- **A quoted `max-age` (`max-age="600"`) in a CIMD or JWKS response's `Cache-Control` is read** instead of falling back to the default lifetime.
- **A `client_credentials` request refused with `invalid_target` is no longer counted against `mcp.clientCredentials.rateLimit`.**
- **Client, authorization-code and refresh-family read failures return `server_error`** (500) instead of being reported as an unknown client or an invalid grant. A missing record still gives `invalid_client` or `invalid_grant`.
- **A superseded refresh token whose family revocation cannot be written no longer claims the revocation.** A superseded refresh token is refused with `invalid_grant` and revokes the family; if the revocation write fails, the token is still refused with `invalid_grant`, as before, and nothing is issued. The response no longer claims the revocation: its `error_description` is "Refresh token has been superseded" (without "; family revoked"). The token endpoint's handler no longer logs the error text followed by a "revoked family" line; it logs one line naming the family and failure, without the error text or the token. The refresh-family store's own write-error log, unchanged, still carries the underlying error. The family stays live until a later presentation retires or revokes it, or it expires.
- **A mixed-case `provider` value (e.g. `'GitHub'`) now gets the same GitHub-authenticated evidence as the lowercase preset** (#242): preset resolution (`getProvider`) has always matched provider names case-insensitively, but the 2.7.0 evidence path compared `config.provider === 'github'` case-sensitively, so a config with `provider: 'GitHub'` kept `emailProvenance: 'unauthenticated'` and `emailAuthenticated: false` even after a successful authenticated GitHub email fetch — denying account adoption, and any `onLogin` hook gating on `authEvidence.emailAuthenticated`, for a genuine GitHub login. `buildProviderConfig` now lowercases `provider` only when it matches a known preset (so `'GitHub'` → `'github'`): a custom provider identifier with no preset (e.g. `'AcmeOIDC'`) keeps its original case — it flows into hooks, session metadata, and any binding keyed on it — and an explicit `provider: ''` under a preset's registry key (e.g. `auth0`) stays `''`, so the preset's `configure()` switch is not triggered by the registry-key fallback and the operator's custom endpoints are preserved. `TenantManager.registerTenant` normalizes `tenant.provider` the same way once its preset is resolved, so the `configure()` switch, its error messages, and the stored `provider` all see one case — e.g. `'Okta'` now hits the domain-required check and is stored as `provider: 'okta'` even if `additionalConfig` also sets a mixed-case `provider`. **Upgrade note:** a static or `onResolveProvider` config written as `'Okta'`, `'Auth0'`, or `'Azure'` (mixed case) previously skipped that preset's `configure()` step entirely; it now runs, so a config that also sets `domain`/`tenantId` gets (or must already have) the same domain-derived endpoints a lowercase `'okta'`/`'auth0'`/`'azure'` config has always gotten.
- **An `undefined` provider option no longer overwrites its preset default** (#243): `buildProviderConfig` copied every key of the caller's provider options into the final config, including keys whose value was `undefined` — the common case for a dynamically resolved provider (e.g. from `onResolveProvider`) that passes through an unset database field such as `scope: row.scope`. For the Google preset this silently replaced `scope: 'openid profile email'` with `undefined`, and `OAuthProvider` then sent an empty `scope` to Google, which rejects the authorization request. `undefined` values are now skipped when building the provider config, so the preset (or plugin default) applies; `null` and `''` remain explicit values a caller can still use to blank a field.
- **`TenantManager.registerTenant`'s `additionalConfig` no longer wipes a preset default with an `undefined` value** (#248): the same "pass through an unset DB column" pattern #243 fixed in `buildProviderConfig` was still present on the multi-tenant path — `additionalConfig` was spread onto the provider config last with no `undefined` skip, so a tenant registered with `additionalConfig: { scope: undefined }` silently discarded the preset's default scope (e.g. Okta's `openid profile email groups`), and the resulting authorize request went out with no scope. `buildProviderConfig`'s undefined-skip is now a shared `skipUndefined` helper used by both call sites; `null` and `''` remain explicit values, and the normalized-`provider` pin added in #246 still wins regardless. **Upgrade note:** `additionalConfig: { field: undefined }` previously cleared whatever the preset/base provider had set for `field`; it now leaves the preset's value in place, matching #243's `buildProviderConfig` behavior. A caller that relied on `undefined` to blank a preset-set field should pass `null` or `''` instead.
- **A declared redirect-host allowlist that resolves empty no longer silently means "no restriction"** (#249): `mcp.dynamicClientRegistration.allowedRedirectUriHosts` and `mcp.clientIdMetadataDocuments.allowedHosts` are filtered down to non-empty, trimmed, lowercased entries, but `validateRedirectUri` and CIMD's own gate both read an empty or absent list as "no allowlist" — so a declared value whose entries all resolved blank (an env placeholder expanding to `""`, or whitespace-only entries) silently opened the exact restriction the operator thought they'd pinned, the same fail-open shape #240 and #207 closed for `initialAccessToken` and the MCP feature booleans. Both lists now throw at startup, naming the key, when the block(s) that read them are active and the declared list resolves to zero usable hosts — including an explicit `allowedHosts: []`, treated as declared-but-empty rather than an intentional "deny every host": neither validator has a mode where an empty list means "deny," so a present-but-empty array can't express that choice, and omitting the key entirely remains the only way to get the documented no-allowlist default. A single unresolved `${VAR}` placeholder entry inside an otherwise non-empty list also now throws instead of surviving as a literal, unmatchable hostname. `allowedRedirectUriHosts` is read by both the DCR and CIMD redirect-uri checks, so its guard fires whenever either is active — disabling DCR alone does not make a declared-but-empty list inert while CIMD (default-enabled) still reads it. **Upgrade note:** an instance with MCP enabled and a declared allowlist that resolves empty (or contains an unresolved placeholder) now fails to start; applying the same value via a live config reload is rejected and the previous configuration keeps serving.

## [2.7.0] - 2026-09-25

### Added

- **`onLogin` hooks receive authenticated-source evidence** (`oauthUser.authEvidence`): a frozen, hook-only snapshot exposing the plugin's own trust determination — `emailProvenance` (`'signed-oidc'` / `'github-authenticated'` / `'unauthenticated'`, normalized), `emailAuthenticated`, `signatureVerified`, `issuerValidated`, `emailVerified`, `email` (populated regardless of trust — verified only when `emailAuthenticated` is `true`), and the validated `idTokenIssuer` / `idTokenSubject`. A hook that adopts an existing account should base the decision on `authEvidence.emailAuthenticated` (resolve from `authEvidence.email`, or bind on the `idTokenIssuer`+`idTokenSubject` pair), not on the spoofable `emailVerified`. The new `OAuthAuthEvidence` and `EmailProvenance` types are exported. Does not change the built-in account-adoption gate.

### Changed

- **`redirectUri` is required; the `http://localhost:9926/oauth` fallback is removed** (#208): a missing, empty, or unresolved-`${VAR}` `redirectUri` (plugin-level or per-provider) now fails at startup naming the key, instead of silently sending a loopback redirect that some IdPs accept and that would hand the authorization code to whatever is listening on the end user's own machine. The provider segment is appended for `…/oauth`, `…/oauth/callback` (with or without a trailing slash) and a query string is preserved. **Upgrade note:** any app that relied on the default, including local-dev setups, must set `redirectUri` to its public origin plus `/oauth` before the plugin will load.
- **MCP refresh-token families minted before this version are retired at their next refresh** (#229): a refresh presenting a valid token for a family created by an earlier version is rejected with `invalid_grant`, the family is revoked, and an `oauth.mcp.token.retired` audit event is emitted; the client re-authorizes once. New families carry their provenance in the `family_id` (`p1-` prefix), which rotation preserves, so a mixed-version rollout cannot strip it. Access tokens already issued keep working until they expire. **Upgrade note:** every MCP client holding a pre-upgrade refresh token re-authorizes once at its next refresh; after a rollback, only families minted while rolled back re-authorize after re-upgrading. Browser login sessions are unaffected.

### Fixed

- **A declared `mcp.signingKeyPem` that cannot be used now fails at startup** (#221): when `mcp.enabled` is true, an empty value, an unresolved `${VAR}` placeholder, an unparseable PEM, or an RSA key under 2048 bits (which `jsonwebtoken` refuses at signing time) throws naming the key, instead of silently self-generating a key or returning 500 at token mint. Omitting the key still self-generates, and removing it on a live config reload still switches to self-generation. **Upgrade note:** the startup throw stops the whole plugin from loading, so on an instance with an unusable declared key, browser OAuth login is down as well as MCP token grants until the key is fixed or removed (a bad value applied by live reload is rejected and the previous config keeps serving; only a restart with it fails).

## [2.6.0] - 2026-09-14

### Security

- **Harden OAuth account adoption to require a verified identity claim** (GHSA-vf58-5v5f-mvpm): an OAuth login adopts an existing Harper `hdb_user` only when the claim is a verified email from an authenticated source — a JWKS-signature-verified OIDC id token with a validated issuer, or GitHub's authenticated email fetch. This closes an edge case in which a login could otherwise inherit an existing account from an **unverified or non-email claim** — e.g. an unsigned userinfo `email`, or a reassignable handle/username. Typical deployments (Google or GitHub keyed on the account's verified email) were already on the trusted path and are unaffected; a login resolved by an `onLogin` hook is likewise unchanged (the hook is authoritative). An _untrusted_ login (unverified/non-email claim) with no matching account gets a non-resolvable quarantine principal instead of the raw claim, so an account provisioned later under that name can't be adopted either; a verified login keeps its real identity. An escape hatch (`allowUnverifiedClaimInheritance`, default off) restores the previous behavior for deployments that intentionally adopt on an unverified/handle claim. GitHub's verified email is asserted through an in-process channel a remote userinfo body cannot forge, so a custom `userInfoUrl` (GHES/proxy) returning `email_verified: true` cannot earn adoption trust without a successful authenticated email fetch.

  **Upgrade note (protects new logins only):** the gate does not retract sessions established before the upgrade — Harper does not expire sessions by default, so they persist. Typical Google/GitHub verified-email deployments have nothing to retract. Any deployment that _could_ have accepted an unverified or non-email claim (intentionally or not) should, on upgrade, revoke pre-2.6 OAuth sessions fleet-wide by clearing `system.hdb_session` — an administrator action. A user re-login is **not** sufficient: it only replaces that user's own session cookie and leaves any other (e.g. attacker-held) session active. Automatic neutralization of pre-existing sessions is a tracked follow-up.

### Changed

- **`IOAuthProvider.verifyIdToken` returns `{ claims, signatureVerified, issuerValidated }`** (previously the bare claims): the adoption gate needs the verification result, not only the decoded claims. A custom provider that implements this method should return the new shape.
- **`oauthUser.email` now reflects the configured `emailClaim`** (previously always `userInfo.email`): the mapped email is read from `emailClaim` for consistency with the gate's verification. A deployment that sets a custom `emailClaim` — and an `onLogin` hook that reads `oauthUser.email` — now sees that claim's value rather than the standard `email` field.

### Fixed

- **Google logins carrying the bare `accounts.google.com` issuer are no longer denied adoption**: Google issues the OIDC `iss` claim as either `https://accounts.google.com` or `accounts.google.com`; the issuer check now accepts both forms. Provider `issuer` configuration accepts a single value or a list.
- **The MCP callback log no longer prints the quarantine principal's random suffix**: an untrusted no-account login's info-level log line redacts the unpredictable suffix (`unverified:<claim>#<redacted>`) instead of printing it in full.

## [2.5.1] - 2026-09-01

### Fixed

- **Periodic OAuth token validation no longer throws on Harper v5 frozen sessions** (#222, #223): on Harper v5 the `session.oauth` record is a read-only tracked object, so the periodic-validation path's in-place `lastValidated` update threw `Cannot assign to read only property 'lastValidated'`, breaking long-lived (non-expiring, e.g. GitHub) OAuth sessions once the validation interval elapsed. `validateAndRefreshSession` now rebuilds `session.oauth` with the updated timestamp instead of mutating it in place — mirroring the token-refresh path — and preserves all token fields.

## [2.5.0] - 2026-08-13

### Security

- **All browser-initiated OAuth flows are bound to the initiating browser** (#203): human login and every MCP authorize path set a `__Host-` binding cookie — a **stable per-browser secret** (#205) — whose hash travels in the flow's server-side state; the callback requires the cookie back before any upstream code exchange or session write. This closes the login-CSRF / authorization-code-injection class where an attacker-initiated flow (or a state delivered into a victim's browser) could otherwise complete against the victim. Included in the same change: request headers are now read through a runtime-wrapper-safe helper — the live Harper runtime exposes headers only via `.asObject`, so the binding (and the pre-existing CIMD consent binding) would otherwise fail closed in production; `error`/`error_description` are CRLF-encoded before logging (CWE-117) on the callback and DCR paths; `Basic`/`Bearer` scheme matching is case-insensitive (RFC 9110 / RFC 6750); and `Basic` credentials are `application/x-www-form-urlencoded`-decoded (RFC 6749 §2.3.1) so URL-shaped CIMD client IDs authenticate. **⚠️ Requires HTTPS:** the `__Host-`/`Secure` binding cookie is dropped by browsers on plain-HTTP non-localhost origins, so OAuth must be served over TLS (already the recommended posture; most browsers still trust `http://localhost` for development).

### Added

- **ES256 signing for MCP access tokens** (#191): set `mcp.signingAlgorithm: ES256` for EC P-256; RS256 remains the default. The JWKS publishes each key's `alg` — verify by `kid`.
- **`offline_access` refresh-token opt-in** (SEP-2207, #192): the authorization-server metadata advertises `offline_access` in `scopes_supported`; set `mcp.refreshTokenRequiresOfflineAccess: true` to withhold refresh tokens unless the granted scope carries it.

### Fixed

- **CIMD accepts unknown grant types; DCR filters to the supported intersection** (#199, #200): a Client ID Metadata Document that declares an unsupported `grant_type` (e.g. claude.ai's `urn:ietf:params:oauth:grant-type:jwt-bearer`) no longer fails the entire client resolution — unblocking claude.ai custom connectors. `authorization_code` is still required, and only supported grants are stored.

### Docs

- **MCP OAuth docs aligned to the 2026-07-28 authorization spec** (#193, #204): Client ID Metadata Documents reframed as the primary registration path (Dynamic Client Registration is deprecated in 2026-07-28), the flow diagram updated for the POST-based Streamable HTTP transport, and `iss` / scope step-up noted. Adds a requirement→code→test **conformance traceability matrix** (`docs/mcp-oauth-conformance.md`).

## [2.4.0] - 2026-07-20

### Security

- **OAuth callbacks are bound to the initiating session** (#181, #183): `handleCallback` rejects a state token minted in a different browser session — the RFC 6749 §10.12 login-CSRF class, and the load-bearing prerequisite for authenticated account-linking flows (an attacker-initiated state delivered into a victim's session could otherwise bind the attacker's provider identity to the victim's account). Enforced whenever the state carries the initiating session id — all states minted from this version do, including MCP flows: the MCP authorize path now records the session at the single upstream-state mint site, covering both direct authorize and post-CIMD confirm. Pre-upgrade tokens pass through, so in-flight logins survive the deploy. Rejection happens before the code exchange: no upstream calls, no session write; MCP flows get an `access_denied` error redirect to the client.
- **⚠️ MCP Dynamic Client Registration is now disabled unless configured** (#182, #184): an absent — or bare-null (`dynamicClientRegistration:` with no children) — `mcp.dynamicClientRegistration` block means `/oauth/mcp/register` returns 404 and the RFC 8414 metadata omits `registration_endpoint` (both driven by the same predicate, so discovery never points at an endpoint that 404s). Previously an absent block meant **open, ungated registration**: unauthenticated client creation on every deployment that never touched the block. **Migration for deployments that relied on the implicit default:** add `dynamicClientRegistration: {}` (open registration, now with a once-per-process ungated warning) or `dynamicClientRegistration: { initialAccessToken: '…' }` (gated) to the `mcp` config. Deployments that already wrote the block — any shape — are unchanged. CIMD-based client identity needs no DCR at all.

## [2.3.0] - 2026-07-14

### Added

- **`onLogin` controls the login outcome** (#174): the hook may return `{ status: 'denied', error?, redirect? }` or `{ status: 'needs_confirmation', redirect }` to stop a session from being created (deny the login, or defer it to an onboarding/confirmation step). Plain-object and `undefined` returns behave exactly as before; `{ status: 'ok', ... }` is the explicit equivalent. In MCP flows a gated login fails the authorization cleanly with `access_denied` to the MCP client. New exported types: `OnLoginResult`, `OnLoginResultOk`, `OnLoginResultDenied`, `OnLoginResultNeedsConfirmation`.
  - ⚠️ **Compatibility edge:** the status values `denied` and `needs_confirmation` are newly reserved. A hook that previously returned `status` with exactly one of those values as ordinary session-enrichment data now gates the login instead. Any other `status` value keeps the legacy merge-into-session behavior (with a warning logged, since it may be a typo'd gating attempt).
  - ⚠️ **Migration note — throw-to-deny never worked:** earlier docs suggested throwing from `onLogin` to prevent a login (e.g. suspended accounts). Thrown errors have **always** been caught and logged with the login proceeding — that pattern was fail-open in every release, and it still is. If your hook throws to deny, it is not denying anything: migrate to `return { status: 'denied', ... }`, which is the first mechanism that actually gates.
- **`oauthUser.emailVerified`** (#174 follow-up): normalized boolean on the mapped user (from the provider's `email_verified` claim); `undefined` when the provider didn't attest. Replaces digging through `metadata.oauthClaims.email_verified`.

### Fixed

- **GitHub provider: `email_verified` is now dependable** (#174): `/user/emails` is always consulted, so the claim is populated for users with a public profile email too (previously it was only set when the email had to be fetched). Hook consumers can gate provisioning on `email_verified` consistently across providers. The request is bounded by a 5s timeout, and a non-OK response (e.g. missing `user:email` scope) logs a warning while degrading gracefully.

## [2.2.1] - 2026-07-11

Docs-only patch — refreshes the README (and therefore the npm package page), which predated 2.2.0's MCP features.

### Changed

- README: documented headless-agent (`client_credentials`) authentication and CIMD in the MCP section, added the CIMD default-on security caveat, corrected the Database Schema section to the actual table set (`schema/oauth.graphql`), retired the closed #86 pointer in favor of #156, and linked this changelog.

## [2.2.0] - 2026-07-11

Minor release — headless-agent (machine-to-machine) MCP authentication, plus signing-key rotation.

### Added

- **Signing-key rotation + multi-key JWKS publication** (#158, closes #128). Rotate the MCP signing key without invalidating in-flight tokens; the JWKS publishes current + retiring keys.
- **Client-assertion primitives** (#165): strict RFC 7523 `private_key_jwt` verification — EdDSA/Ed25519 via built-in `node:crypto` (no new dependency), `jti` replay store, ≤60s `exp` window.
- **Client ID Metadata Documents (CIMD)** (#167): URL-shaped `client_id`s are resolved by fetching the client's metadata document through an SSRF-guarded, pinned-connection fetch, with a consent interstitial for interactive flows.
  - ⚠️ **Default-on when `mcp.enabled`** — URL client_ids are now accepted. Disable with `mcp.clientIdMetadataDocuments.enabled: false`, or restrict with `mcp.clientIdMetadataDocuments.allowedHosts`.
  - ⚠️ Interactive CIMD authorization requires browser cookies (a per-flow `__Host-` consent cookie binds the interstitial).
- **`client_credentials` grant** (#170, closes #161/#162): headless agents authenticate as themselves with `private_key_jwt` — no browser, no human. CIMD-first client resolution; short-TTL audience-bound tokens; every issuance audit-logged.
- **Rate limiting** (#171, closes #163): token issuance is limited per **verified** `client_id` (`mcp.clientCredentials.rateLimit`, default 30 req/min, `false`/`0` disables — debited post-authentication so unauthenticated requests can't drain a client's quota), and CIMD document fetches are limited at a fixed 10 attempts/min per URL. Over-limit responses are `429` `slow_down` with `Retry-After`.

### Fixed

- Client records use Harper's `@createdTime` instead of a hand-rolled `created_at` (#169).

## [2.1.2] - 2026-07-02

Patch release — MCP OAuth hardening batch. All fixes, no features.

### Fixed

- **Validate `mcp.issuer` is a full http(s) origin at config load** (#139). Fail-fast on schemeless / path / query / fragment / credential-bearing values. Only enforced when `mcp.enabled` is true.
  - ⚠️ A deployment with `mcp.enabled: true` and a malformed `mcp.issuer` that previously started (with broken discovery/endpoint URLs) now refuses to start, with an error naming the bad value.
- **Secret redaction hardening** (#140). Snake_case/kebab secret keys (`signing_key_pem`, `initial_access_token`, `private_key`, …) are now redacted from option logging; the `pluginDefaults` debug log is redacted too; non-plain objects pass through redaction unmangled.
- **Non-Error catch safety** (#142, #147). All remaining `(error as Error).message` catch sites are now safe against thrown strings/null; the wrapped ID-token verification error chains the original via `cause`.

## [2.1.1] - 2026-07-01

Patch release.

### Added

- **RFC 9207** — emit the `iss` parameter on all MCP OAuth authorization responses (success + error redirects) and advertise `authorization_response_iss_parameter_supported: true` in the AS metadata (#150, closes #149). Mitigates OAuth mix-up attacks; additive and backward-compatible.

## [2.1.0] - 2026-07-01

MCP OAuth v1 — experimental, opt-in (`mcp.enabled`). `@harperfast/oauth` can now act as a complete OAuth 2.1 authorization server for **Model Context Protocol** clients (Claude Desktop, Cursor, `mcp-remote`), authenticating them against your existing upstream providers. Completes the MCP OAuth v1 epic (#86).

### Added

- **`withMCPAuth`** — bearer-token guard for app-owned MCP routes: RS256 verification against the published JWKS, audience binding (RFC 8707), and the RFC 9728 `WWW-Authenticate: Bearer resource_metadata` challenge on failure. Attaches verified claims as `request.mcp`.
- **Audit logging + `onMCPTokenIssued` hook** — secret-free `oauth.mcp.token.issued` / `refreshed` / `rejected` audit events, plus a fire-and-forget lifecycle hook for reacting to token issuance.
- **End-to-end conformance test** — the full discovery → DCR → authorize → token → bearer-authenticated round-trip, validated on CI against a booted Harper.
- **User-facing docs** — [`docs/mcp-oauth.md`](https://github.com/HarperFast/oauth/blob/main/docs/mcp-oauth.md) plus a refreshed README and configuration reference.

## [2.0.0] - 2026-06-23

First **GA** of the Harper v5 line.

### Breaking

- Requires **Harper v5** — `peerDependencies: harper >=5.0.0` (the `harperdb` v4 → `harper` v5 package move). Harper v4 users stay on the 1.x line: `npm install @harperfast/oauth@1`.

### Added

- **MCP OAuth (experimental, opt-in via `mcp.enabled`)** — RFC 7591 Dynamic Client Registration, discovery metadata (`/.well-known/*`), `/oauth/mcp/authorize` (PKCE-S256), and `/oauth/mcp/token` (audience-bound RS256 JWT issuance).
- **Mature human-OAuth core** — multi-provider (GitHub, Google, Azure AD, Auth0, Okta, custom OIDC), automatic token refresh, lifecycle hooks, CSRF protection, multi-tenant SSO.

## [1.5.0] - 2026-06-02

### Changed

- Dynamic-provider cache now defaults to a bounded **300s TTL** instead of caching forever. Providers resolved via the `onResolveProvider` hook are re-resolved once their cache entry expires, so a config change takes effect within one TTL window instead of persisting until restart. Configure with `cacheDynamicProviders`: seconds (number), `false` to disable caching, or `true` for the previous cache-forever behavior. Freshness is TTL-only — there is no manual invalidation API.

## [1.2.1] - 2026-02-10

### Security

- Open redirect prevention on all callback redirect paths (error and success) via `sanitizeRedirect()`.
- Error reason codes in redirect URLs use safe constants instead of raw error messages.

### Fixed

- Disambiguated session OAuth fields — added `providerConfigId` and `providerType` alongside existing `provider` (#26).
- Provider errors (e.g. GitHub 500 HTML pages) no longer leak raw response bodies to the browser — callback redirects with `?error=auth_failed&reason=token_exchange` instead.
- Response bodies drained in error paths to prevent undici socket/connection pool leaks.
- Error redirect URLs correctly place query params before hash fragments via `buildErrorRedirect()`.
- JSON parse failures in token exchange/refresh fall back gracefully to status code instead of crashing.

## [1.2.0] - 2026-02-06

### Changed

- Moved npm orgs: `@harperdb/oauth` → `@harperfast/oauth`.

## [1.1.0] - 2025-11-07

Initial published release, as `@harperdb/oauth` — multi-provider human OAuth for Harper: provider configuration, session management, live config reload, and minimal lifecycle hooks (e.g. adding/modifying user records on authentication).

[2.4.0]: https://github.com/HarperFast/oauth/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/HarperFast/oauth/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/HarperFast/oauth/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/HarperFast/oauth/compare/v2.1.2...v2.2.0
[2.1.2]: https://github.com/HarperFast/oauth/compare/v2.1.1...v2.1.2
[2.1.1]: https://github.com/HarperFast/oauth/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/HarperFast/oauth/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/HarperFast/oauth/compare/v1.5.0...v2.0.0
[1.5.0]: https://github.com/HarperFast/oauth/compare/v1.2.1...v1.5.0
[1.2.1]: https://github.com/HarperFast/oauth/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/HarperFast/oauth/compare/release_1.1.0...v1.2.0
[1.1.0]: https://github.com/HarperFast/oauth/releases/tag/release_1.1.0
