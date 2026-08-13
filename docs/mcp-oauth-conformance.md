# MCP OAuth — conformance traceability

This matrix maps each normative requirement the plugin's MCP OAuth surface
implements to **the code that satisfies it** and **the test that asserts it**.
It exists so a requirement can't quietly lose its assertion in a refactor: if a
row's test disappears, the gap is visible here rather than in a client's failed
handshake.

**Target spec:** [MCP authorization specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
built on OAuth 2.1 ([draft-ietf-oauth-v2-1-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13))
and the RFCs in [mcp-oauth.md](./mcp-oauth.md). Keep this file in step with that doc.

**How to read it:** every row is a MUST/SHOULD the module implements. `Test`
cites the file and a representative assertion; most rows have several — open the
file to see the full set. Status is ✅ (asserted) or ⚠️ (see [Known deltas](#known-deltas)).

Test files (all under `test/lib/mcp/` unless noted): `wellKnown` · `authorize` ·
`token` · `tokenAuditHook` · `dcr` · `cimd` · `clientAssertion` · `tokenIssuer` ·
`withMCPAuth` · `consentBinding` · `refreshTokenStore` · `callback` · `assertionJtiStore` ·
`index` · `rateLimit`; `handlers` under `test/lib/`; **e2e** =
`integrationTests/mcp-oauth-e2e.test.ts` (suite _MCP OAuth Stage 7: full round-trip e2e_).

---

## Discovery (RFC 9728 PRM · RFC 8414 AS metadata)

| Requirement                                                                                                  | Implemented in                                                         | Test                                                                                                               |     |
| ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | --- |
| RFC 9728 §3.1 — PRM has `resource` + `authorization_servers`; header-only bearer                             | `wellKnown.ts:buildProtectedResourceMetadata`                          | `wellKnown` "includes required fields…"; e2e step 2                                                                | ✅  |
| RFC 9728 §3.1 — path-appended PRM at `/.well-known/oauth-protected-resource/<path>`                          | `wellKnown.ts:wellKnownPathMatches` / `protectedResourceMetadataUrl`   | `wellKnown` "serves the path-appended PRM…"                                                                        | ✅  |
| RFC 9728 §5.1 — `401 + WWW-Authenticate: Bearer resource_metadata="…"` on deny                               | `withMCPAuth.ts:withMCPAuth` (deny path)                               | `withMCPAuth` "rejects a request with no Authorization header"; e2e step 1; `mcp-auth.test.ts`                     | ✅  |
| RFC 8414 — AS metadata: issuer, endpoint URLs, S256, `code`, auth methods, algs                              | `wellKnown.ts:buildAuthorizationServerMetadata`                        | `wellKnown` "includes spec-required endpoints", "advertises PKCE S256 only (no plain)"; e2e step 3                 | ✅  |
| RFC 8414 — advertise `registration_endpoint` only when DCR enabled (#182)                                    | `wellKnown.ts` (via `dcrEnabled`)                                      | `wellKnown` "omits registration_endpoint when the DCR block is absent…"                                            | ✅  |
| RFC 8707 — AS metadata declares `resource_parameter_supported`                                               | `wellKnown.ts`                                                         | `wellKnown` "signals RFC 8707 resource-parameter support"                                                          | ✅  |
| RFC 9207 — AS metadata declares `authorization_response_iss_parameter_supported`                             | `wellKnown.ts`                                                         | `wellKnown` "signals RFC 9207 authorization_response_iss_parameter_supported"                                      | ✅  |
| MCP CIMD — AS metadata declares `client_id_metadata_document_supported` when CIMD on                         | `wellKnown.ts`                                                         | `wellKnown` "advertises client_id_metadata_document_supported when CIMD is enabled"                                | ✅  |
| SEP-2207 — `offline_access` in `scopes_supported` (AS metadata), never in PRM                                | `wellKnown.ts`                                                         | `wellKnown` "advertises offline_access…" + "does not advertise scopes_supported… in PRM"                           | ✅  |
| Routing — three handlers at exact paths; sub-paths 404; falls through when MCP disabled; JWKS empty pre-mint | `wellKnown.ts:registerWellKnownHandlers` / `makeHandler` / `buildJWKS` | `wellKnown` "registers three handlers…", "falls through to next when MCP is disabled", "returns an empty key set…" | ✅  |

## Authorization endpoint (OAuth 2.1 + PKCE + RFC 8707 + RFC 9207)

| Requirement                                                                                                                    | Implemented in                                         | Test                                                                                                                       |     |
| ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | --- |
| OAuth 2.1 §3.1.2.5 — two-phase validation: `client_id`+`redirect_uri` verify pre-redirect (400 JSON), else redirect with error | `authorize.ts:handleAuthorize`                         | `authorize` "rejects unknown client_id with 400 invalid_client", "rejects unregistered redirect_uri with 400…"             | ✅  |
| OAuth 2.1 — `response_type` must be `code`                                                                                     | `authorize.ts`                                         | `authorize` "redirects with unsupported_response_type…"                                                                    | ✅  |
| OAuth 2.1 §4.1.2 / RFC 7636 — PKCE required; `S256` only, `plain` rejected                                                     | `authorize.ts`                                         | `authorize` "…code_challenge_method is \"plain\" (OAuth 2.1 forbids)"; e2e "negative: code_challenge_method=plain…"        | ✅  |
| RFC 7636 §4.2 — `code_challenge` charset/length (43–128 unreserved)                                                            | `authorize.ts:CODE_CHALLENGE_PATTERN`                  | `authorize` "…too short", "…too long", "…outside the unreserved set"                                                       | ✅  |
| RFC 8707 — `resource` required, no fragment, exact canonical match                                                             | `authorize.ts:validateCanonicalResource`               | `authorize` "invalid_target when resource is missing / has a fragment / does not match"; e2e "negative: missing resource…" | ✅  |
| RFC 9207 — `iss` on every Phase-2 error redirect; absent on Phase-1 400 JSON                                                   | `authorize.ts:buildClientErrorRedirect`                | `authorize` "includes iss…on a Phase-2 error redirect", "does NOT include iss on Phase-1 errors"                           | ✅  |
| RFC 9207 — `iss` on the success redirect                                                                                       | `callback.ts:buildSuccessRedirect`                     | `callback` "includes iss on the success redirect (RFC 9207)"; e2e asserts `iss` on success                                 | ✅  |
| State ↔ browser-session binding (#181) — reject a callback in a different session                                              | `authorize.ts:performUpstreamRedirect` + `handlers.ts` | `handlers` "rejects a callback processed in a different session…"                                                          | ✅  |

## Token endpoint (RFC 6749 · 7636 · 8707 · 9068)

| Requirement                                                                                                 | Implemented in                                                   | Test                                                                                                                                  |     |
| ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `authorization_code` exchange + PKCE verify + single-use code                                               | `token.ts:handleAuthorizationCodeGrant` / `pkceMatches`          | `token` "exchanges an authorization code…", "rejects a failed PKCE verification", "rejects a code issued to a different client"       | ✅  |
| Client auth methods `none` / `client_secret_basic` / `client_secret_post`                                   | `token.ts:authenticateClient` / `parseBasicAuth`                 | `token` "rejects a public client that presents a secret", "authenticates…via client_secret_basic", "…via client_secret_post"          | ✅  |
| RFC 6749 §5.1 — `Cache-Control: no-store` on token responses                                                | `token.ts:NO_STORE_HEADERS`                                      | `token` "sets no-store cache headers on a successful token response" (⚠️ error-path untested)                                         | ⚠️  |
| Refresh-token family rotation (single-use)                                                                  | `token.ts:handleRefreshTokenGrant` / `refreshTokenStore.ts`      | `token` "rotates a refresh token…"; e2e refresh rotation                                                                              | ✅  |
| Refresh reuse detection — replay of a superseded token revokes the family                                   | `token.ts:handleRefreshTokenGrant`                               | `token` "detects replay of a superseded refresh token and revokes the family"; e2e replay → `invalid_grant`                           | ✅  |
| Refresh issuance gating on `grant_types` + SEP-2207 `offline_access`                                        | `token.ts:shouldIssueRefresh` / `allowsRefresh`                  | `token` "omits the refresh token when the client did not register…", "withholds…unless…offline_access"                                | ✅  |
| RFC 8707 — access-token `aud` = canonical resource                                                          | `tokenIssuer.ts:signAccessToken`                                 | `tokenIssuer` "rejects a token verified against the wrong audience"                                                                   | ✅  |
| Reject unknown/missing `grant_type`; 404 when MCP disabled                                                  | `token.ts:handleToken` / `index.ts:handleMCPPost`                | `token` "rejects an unsupported grant_type"; `index` "returns 404 when mcpConfig.enabled is false"                                    | ✅  |
| RFC 9068 — JWT AT claims (`iss/sub/aud/exp/iat/jti/client_id/scope`); `kid`+`alg` header; alg-pinned verify | `tokenIssuer.ts:signAccessToken` / `verifyAccessTokenWithKeySet` | `tokenIssuer` "signs and verifies…with the expected claims", "puts the kid and RS256 alg in the JWT header" (⚠️ `typ:at+jwt` not set) | ⚠️  |
| Audit + `onMCPTokenIssued` hook — emit issued/refreshed events (no token material), fire post-persist       | `token.ts:mintTokenPair` / `audit.ts:emitMCPAuditEvent`          | `tokenAuditHook` "emits oauth.mcp.token.issued…", "audit event…contains no token material"                                            | ✅  |

## Client registration — CIMD (primary) & DCR (RFC 7591, deprecated compat)

| Requirement                                                                                                  | Implemented in                                              | Test                                                                                                                                         |     |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| DCR enable gating (#182) — endpoint exists only when block present & not disabled; else 404                  | `dcr.ts:dcrEnabled` / `handleRegister`                      | `dcr` "returns 404 when DCR is explicitly disabled / block absent / bare null"                                                               | ✅  |
| RFC 7591 — initial access token (constant-time Bearer match)                                                 | `dcr.ts:checkInitialAccessToken`                            | `dcr` "returns 401…missing / does not start with Bearer / does not match; accepts a matching Bearer token"                                   | ✅  |
| RFC 7591 §3 — metadata validation (redirect_uris, scalars, grant/response/auth-method/application_type)      | `dcr.ts:buildClientFromRequest`                             | `dcr` "rejects non-string client_name", "rejects unsupported grant_types / application_type"                                                 | ✅  |
| RFC 7591 — MCP defaults (public `none` + `code` + authz_code/refresh) + 201 issuance                         | `dcr.ts:buildClientFromRequest` / `handleRegister`          | `dcr` "applies MCP-context defaults (public client, code flow)", "issues a client_secret for confidential clients"                           | ✅  |
| RFC 8252 §8.3 — redirect_uris require https except http-to-loopback; no fragment                             | `clientValidator.ts:validateRedirectUri`                    | `dcr` "rejects http URIs to non-loopback hosts", "accepts http URIs to localhost/127.0.0.1", "rejects URIs with a fragment"                  | ✅  |
| RFC 8252 §7.3 — any port on loopback registered redirect                                                     | `authorize.ts:redirectUriMatches`                           | `authorize` "accepts any port for 127.0.0.1 / [::1] / localhost"                                                                             | ✅  |
| CIMD — `client_id` URL shape (https, non-root path, no userinfo/fragment/query/dot-segments/IP-literal)      | `cimd.ts:isCimdClientId`                                    | `cimd` "accepts https URLs with a non-root path", "rejects non-https / root-only / IP-literal / dot path segments"                           | ✅  |
| CIMD — document fetch + validation (self-matching client_id, required fields, 200/json only, size cap)       | `cimd.ts:fetchAndValidateCimd` / `validateCimdDocument`     | `cimd` "rejects when client_id in doc does not match the URL", "rejects oversized responses", "rejects redirect responses"                   | ✅  |
| CIMD — SSRF protection (DNS gate, pinned-connect rebind-safe, fail-closed, no detail leak)                   | `cimd.ts:checkHostSsrf` / `pinnedHttpsFetch`                | `cimd` "rejects non-global IPv4/IPv6…", "pins the fetch to the SSRF-validated addresses", "fails closed on an unexpected DNS address family" | ✅  |
| CIMD — per-URL fetch rate limit, bounded concurrency, LRU cache, failures uncached, live-policy revalidation | `cimd.ts:resolveCimdClient` / `rateLimit.ts`                | `cimd` "rejects the 11th fetch attempt…", "dedups concurrent resolutions…", "failures are never cached"                                      | ✅  |
| CIMD — `allowedHosts` gate (null = not-found, no leak); credentials docs require pinned allowlist            | `cimd.ts:resolveCimdClient` / `validateCredentialsDocument` | `cimd` "returns null (not found) when host is not in allowedHosts", "fails closed when allowedHosts is not configured"                       | ✅  |
| CIMD → DCR routing — URL-shaped → CIMD, else DCR store; CIMD-disable respected                               | `cimd.ts:resolveClient`                                     | `cimd` "routes URL-shaped client_ids to CIMD", "routes non-URL client_ids to DCR store", "skips CIMD when…disabled"                          | ✅  |

## CIMD consent interstitial & browser binding

| Requirement                                                                                                                                                        | Implemented in                                                                 | Test                                                                                                                                                                                         |     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| Consent interstitial — 200 HTML (not 302), shows authoritative `client_id` host + redirect hostname + loopback warning; HTML-escaped; anti-clickjacking + no-store | `authorize.ts:handleAuthorize` (CIMD) / `buildInterstitialPage` / `escapeHtml` | `authorize` "returns 200 HTML interstitial…", "displays the authoritative client_id hostname…", "escapes XSS in client_name"                                                                 | ✅  |
| Browser binding — `__Host-` per-flow nonce cookie; confirm requires hash-match; callback re-checks; one-time confirm token                                         | `consentBinding.ts` / `authorize.ts:handleAuthorizeConfirm` / `handlers.ts`    | `authorize` "rejects a confirm without the consent cookie…"; `handlers` "rejects when the consent cookie is missing…"; `consentBinding` "buildConsentCookie uses a \_\_Host- per-flow name…" | ✅  |

## Bearer guard & no-passthrough (RFC 6750 · 8707)

| Requirement                                                                                     | Implemented in                               | Test                                                                                                                                          |     |
| ----------------------------------------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| RFC 8707 — resource server enforces `aud`==resource, `iss`==issuer; reject cross-audience token | `withMCPAuth.ts:withMCPAuth`                 | `withMCPAuth` "rejects a token whose audience does not match mcp.resource", "…issuer does not match"                                          | ✅  |
| RFC 6750 §2.1 — bearer read from `Authorization` header only; query/body ignored                | `withMCPAuth.ts:extractBearerToken`          | `withMCPAuth` "ignores a query-string token"; e2e "negative: Authorization in query string → 401"                                             | ✅  |
| Fail-closed guard + rejected-token audit (no audit for missing-token probes)                    | `withMCPAuth.ts:withMCPAuth`                 | `withMCPAuth` "fails closed when MCP is disabled / no signing keys", "does NOT audit a missing-token request"                                 | ✅  |
| No upstream-token passthrough — IdP token never in MCP redirect / token response                | `callback.ts:handleMCPCallback` / `token.ts` | `callback` "never includes upstream provider token in the redirect URL"; `handlers` "does NOT include upstream IdP token in MCP redirect URL" | ✅  |

## Client credentials / private_key_jwt (RFC 7523 · 9068 §2.2)

| Requirement                                                                                                                                                     | Implemented in                                                                    | Test                                                                                                                                                    |     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| RFC 7523 §3 — `client_assertion` verify (EdDSA-only; `iss=sub=client_id`; `aud`=token endpoint; exp window; `jti` required; kid selection; public-Ed25519-only) | `clientAssertion.ts:verifyClientAssertion`                                        | `clientAssertion` "rejects alg: none…", "rejects any non-EdDSA alg…", "rejects iss/sub not matching client_id", "rejects exp beyond the maximum window" | ✅  |
| RFC 7523 grant integration (#162) — assertion-only (no secret/Basic); CIMD-pinned; `jti` replay guard; short TTL, no refresh; post-auth issuance rate limit     | `token.ts:handleClientCredentialsGrant` / `assertionJtiStore.ts` / `rateLimit.ts` | `token` "rejects a replayed jti", "rejects a Basic header or client_secret riding along", "rate-limits issuance per client — 429 + slow_down"           | ✅  |
| RFC 9068 §2.2 — `sub` = client identity (no end user) on client_credentials                                                                                     | `token.ts:handleClientCredentialsGrant`                                           | `token` "issues a short-TTL token with no refresh token (sub = client identity)"                                                                        | ✅  |

---

## Known deltas

Two requirements are implemented-but-partial or documented-not-yet; both are
tracked, neither is a security gap:

1. **RFC 9068 `typ: at+jwt` access-token header — not set.** `signAccessToken`
   emits `alg`+`kid` but leaves `typ` as the default `JWT`. The _claims_ shape is
   fully RFC 9068-conformant (and tested); only the media-type header is missing.
   Low impact — `withMCPAuth` verifies by `alg`/`kid`/claims, not `typ`. Candidate
   fix for the 2026-07-28 code re-verification ([#156](https://github.com/HarperFast/oauth/issues/156)).
2. **Token _error_-response `no-store` — untested.** `errorResponse()` applies the
   same `NO_STORE_HEADERS` constant as the success path, but only the success path
   has an asserting test. Same constant, so low risk; add an error-path assertion.

Documented-not-yet (see [mcp-oauth.md → Not yet supported](./mcp-oauth.md#not-yet-supported-v11)):
the 2026-07-28 **step-up authorization flow** (SEP-2350, `403 insufficient_scope` / `scope` challenge) and per-operation scope enforcement are v1.1 forward-work.

---

## Keeping this current

- When you add or change an MCP OAuth requirement, add/adjust its row here in the
  same PR — a new MUST with no `Test` cell is a red flag.
- When a test's title changes, update the citation (they're copied verbatim so
  they're greppable).
- On a spec-revision bump, re-verify against the new revision's normative
  requirements and reconcile [mcp-oauth.md](./mcp-oauth.md)'s version reference.
