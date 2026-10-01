# Changelog

All notable changes to `@harperfast/oauth` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries prior to 2.2.0 were backfilled from the [GitHub release notes](https://github.com/HarperFast/oauth/releases).

## [Unreleased]

### Added

- **Interactive CIMD clients can authenticate with `private_key_jwt`**: the token endpoint verifies client assertions from interactive Client ID Metadata Document clients.
  - Algorithms: RS256, ES256 or EdDSA, narrowed to the document's `token_endpoint_auth_signing_alg`.
  - Keys come from inline `jwks` or from `jwks_uri`. A `jwks_uri` is fetched with the same controls as the document (validated and pinned addresses, no redirects, size and time limits) and must be on the client ID's origin unless `mcp.clientIdMetadataDocuments.privateKeyJwt.jwksUriAllowedOrigins` admits another. Only key material is cached, per client.
  - The server permits one method per client: the document's preference when this server advertises it. Selection checks the inline key set or the `jwks_uri` location policy and any signing-algorithm pin. For `jwks_uri`, the fetched keys are validated during token exchange. The ChatGPT-shaped test document resolves to `private_key_jwt` on a server that advertises `private_key_jwt` (headless agents enabled, or the new, off-by-default `mcp.clientIdMetadataDocuments.privateKeyJwt.enabled`), and to `none` otherwise. In one session recorded against a test authorization server that offered both methods, ChatGPT authenticated its code exchange and four refreshes with `private_key_jwt` (`RS256`, a 60-second lifetime) and the token endpoint URL as `aud`, which the issuer-only policy refuses unless an unexpired `privateKeyJwt.tokenEndpointAudience` exception lists its client ID. In a second session, offered only `none`, it used `none`. The recording was not made against this plugin.
  - The interactive assertion audience is the issuer. `privateKeyJwt.tokenEndpointAudience` is an opt-in exception with a required expiry that also accepts the advertised token endpoint for listed client IDs.
- **The client-authentication method is bound to the grant**: the method permitted at `/oauth/mcp/authorize` must be used for the code exchange and for every refresh of that grant. A request that authenticates under current policy but conflicts with a bound code or family returns `invalid_grant`; a currently unpermitted presentation returns `invalid_client` before grant lookup. The client then reauthorizes.

### Changed

- **Client credentials presented at the token endpoint are verified or rejected** (`authorization_code` and `refresh_token`). Half an assertion pair, an empty or repeated credential parameter, malformed `Basic` credentials, or an assertion alongside another mechanism is rejected with `invalid_client`. A client permitted `none` that sends assertion parameters is rejected. **Compatibility:** assertion parameters that were previously ignored now cause `invalid_client`.
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
  - New refresh families use `p2-` ids and carry the binding; `p1-` families stay bound to the method used when they were issued.
  - Drain older nodes before issuing bound grants and never route bound grants to versions before 2.7. Version 2.7.x retires `p2-` families.
  - Every new authorization code and refresh family is bound, whether or not `private_key_jwt` is advertised, so drain older nodes before this version serves any grant. Versions before this one do not check a code's binding when redeeming it; roll back only to a version that reads the binding.
  - With headless agents enabled, `private_key_jwt` is advertised and interactive assertions are verified, so ChatGPT, which prefers `private_key_jwt`, must present one; setting `privateKeyJwt.enabled: false` does not restore its public-client flow. Before the cutover, configure the exact-ID `privateKeyJwt.tokenEndpointAudience` exception for `https://chatgpt.com/oauth/client.json` with an expiry you choose, add `chatgpt.com` to `clientIdMetadataDocuments.allowedHosts` (which headless agents require) and to `dynamicClientRegistration.allowedRedirectUriHosts` if that is set, then reauthorize ChatGPT links bound to `none`. When the exception expires, ChatGPT's token-endpoint-audience assertions are refused again.

### Fixed

- **CIMD documents containing `client_secret*` members are rejected** with `invalid_client` (for example `client_secret` or `client_secret_expires_at`), in either document shape.
- **Over-length client assertions are rejected before any client lookup.** The verifier's 8192-character bound is applied at the token endpoint before an assertion is parsed for its client ID or any client is looked up, on every grant that accepts assertions.
- **Conflicting `Basic` and body `client_secret` authentication returns `invalid_client`** (401) instead of `invalid_request` on the `authorization_code` and `refresh_token` grants.
- **A refresh-family revocation is no longer undone by a concurrent refresh.** Rotation and revocation now write only their own field (`current_token_hash`, `revoked`), so a revocation committed while another request rotates the family stays in force.
- **Client, authorization-code and refresh-family read failures return `server_error`** (500) instead of being reported as an unknown client or an invalid grant. A missing record still gives `invalid_client` or `invalid_grant`.
- **A superseded refresh token whose family revocation cannot be written no longer claims the revocation.** A superseded refresh token is refused with `invalid_grant` and revokes the family; if the revocation write fails, the token is still refused with `invalid_grant`, as before, and nothing is issued. The response no longer claims the revocation: its `error_description` is "Refresh token has been superseded" (without "; family revoked"). The token endpoint's handler no longer logs the error text followed by a "revoked family" line; it logs one fixed line naming the failure, without the error text or the token, and claims no revocation. The refresh-family store's own write-error log, unchanged, still carries the underlying error. The family stays live until a later presentation retires or revokes it, or it expires.

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
