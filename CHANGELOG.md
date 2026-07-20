# Changelog

All notable changes to `@harperfast/oauth` are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries prior to 2.2.0 were backfilled from the [GitHub release notes](https://github.com/HarperFast/oauth/releases).

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
