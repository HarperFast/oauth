# Configuration Reference

Complete configuration options for the `@harperfast/oauth` plugin.

## Basic Configuration

```yaml
'@harperfast/oauth':
  package: '@harperfast/oauth'
  redirectUri: ${OAUTH_REDIRECT_URI} # your public origin + /oauth/callback — required on any deployed app
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
    google:
      clientId: ${OAUTH_GOOGLE_CLIENT_ID}
      clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
```

## Configuration Options

### Global Options

| Option                  | Type              | Default                   | Description                                                                                                                                                                                                                                                                                                                            |
| ----------------------- | ----------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `debug`                 | boolean           | `false`                   | Enable debug endpoints and logging                                                                                                                                                                                                                                                                                                     |
| `redirectUri`           | string            | _(required — no default)_ | **Required.** Base OAuth callback URL providers redirect back to; the plugin appends the provider name. An app that omits it (and has no per-provider `redirectUri`) fails to start with a configuration error, rather than silently sending providers a `localhost` callback. See [Understanding Redirects](#understanding-redirects) |
| `postLoginRedirect`     | string            | `/`                       | Default URL to redirect users after successful OAuth login                                                                                                                                                                                                                                                                             |
| `cacheDynamicProviders` | boolean \| number | `300`                     | TTL (seconds) for providers resolved via the `onResolveProvider` hook. Number = seconds; `false` = never cache (call the hook every request); `true` = cache forever. Default 300s; freshness is controlled by this TTL (there is no manual invalidation).                                                                             |
| `mcp`                   | object            | (off)                     | MCP OAuth flow configuration. See [MCP OAuth](#mcp-oauth) below                                                                                                                                                                                                                                                                        |

### Provider Configuration

Each provider requires:

| Option         | Type   | Required | Description                               |
| -------------- | ------ | -------- | ----------------------------------------- |
| `clientId`     | string | Yes      | OAuth client ID from provider             |
| `clientSecret` | string | Yes      | OAuth client secret from provider         |
| `scope`        | string | No       | OAuth scopes (provider-specific defaults) |

### Provider-Specific Options

#### Azure AD

- `tenantId` - Azure AD tenant ID (required)

#### Auth0

- `domain` - Auth0 domain, e.g., `yourapp.auth0.com` (required)

#### Custom OIDC Provider

- `authorizationUrl` - Authorization endpoint URL (required)
- `tokenUrl` - Token endpoint URL (required)
- `userInfoUrl` - User info endpoint URL (required)
- `jwksUri` - JWKS endpoint URL (required for ID token verification). The alias `jwksUrl` is also accepted for backwards compatibility.

### MCP OAuth

Opt-in support for the Model Context Protocol authorization flow ([issue #86](https://github.com/HarperFast/oauth/issues/86)). The plugin serves Dynamic Client Registration at `POST /oauth/mcp/register` (RFC 7591), the discovery documents under `/.well-known/*` (RFCs 8414, 9728) so MCP clients (Claude Desktop, Cursor, `mcp-remote`) can find and register themselves, the authorization endpoint `GET /oauth/mcp/authorize` (OAuth 2.1 + PKCE-S256), the `POST /oauth/mcp/token` exchange (audience-bound signed JWTs — RS256 by default, ES256 opt-in), and the `withMCPAuth` route guard that verifies those tokens on your MCP endpoint.

> This section is the configuration reference. For the end-to-end flow, the `withMCPAuth` wrapper (registration models + options), the `onMCPTokenIssued` hook, the production checklist, and troubleshooting, see **[MCP OAuth](./mcp-oauth.md)**. The feature is **experimental and opt-in** (`mcp.enabled`).

```yaml
'@harperfast/oauth':
  mcp:
    enabled: true
    # Required when enabled: pin the authorization-server identity. The plugin
    # refuses to start if `issuer` is unset — otherwise `iss` (and the `aud`,
    # which defaults to `<issuer>/mcp`) is derived from the client-controlled
    # Host header, letting a client influence the advertised identity and the
    # audience bound into the authorization code (audience confusion once tokens
    # are signed). Pinning `resource` alone is NOT enough — `iss` still floats.
    issuer: https://my-app.example.com
    # Canonical resource URI advertised in PRM and used as the `aud` claim
    # on issued tokens (RFC 8707). Defaults to `<issuer>/mcp` when unset.
    resource: https://my-app.example.com/mcp
    dynamicClientRegistration:
      # Optional: require Authorization: Bearer <token> on /register.
      # Without this, registration is OPEN per RFC 7591 — anyone can register.
      initialAccessToken: ${OAUTH_MCP_REGISTRATION_TOKEN}
      # Optional: restrict redirect_uri hosts (localhost always allowed).
      allowedRedirectUriHosts:
        - app.example.com
```

| Option                                                  | Type            | Default         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------- | --------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mcp.enabled`                                           | boolean         | `false`         | Master switch for the MCP OAuth endpoints                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mcp.issuer`                                            | string          | (none)          | Authorization-server URI advertised in AS metadata. **Required when `mcp.enabled`** — startup fails otherwise, to prevent a Host-header-driven `iss`/`aud`                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mcp.resource`                                          | string          | `<issuer>/mcp`  | Canonical resource URI advertised in PRM (RFC 9728) and validated as `aud` on issued tokens (RFC 8707). Optional override; defaults safely from the pinned `issuer`                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mcp.providers`                                         | string[]        | (all providers) | Subset of upstream providers eligible for the MCP auth flow. **v1 requires exactly one** resolved provider — set this when more than one provider is configured globally, otherwise `/oauth/mcp/authorize` returns `server_error`                                                                                                                                                                                                                                                                                                                                                                             |
| `mcp.dynamicClientRegistration.enabled`                 | boolean         | `true`          | Enable the `/register` endpoint when `mcp.enabled` is true                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mcp.dynamicClientRegistration.initialAccessToken`      | string          | (none)          | If set, registration requires `Authorization: Bearer <token>`. Otherwise open per RFC 7591                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mcp.dynamicClientRegistration.allowedRedirectUriHosts` | string[]        | (none)          | Allowlist for redirect_uri hosts. Localhost always allowed per RFC 8252                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `mcp.clientIdMetadataDocuments.enabled`                 | boolean         | `true`          | Enable CIMD resolution for URL-shaped `client_id` values. Disable with `false` to reject all CIMD clients; see [Client ID Metadata Documents](./mcp-oauth.md#client-id-metadata-documents-cimd)                                                                                                                                                                                                                                                                                                                                                                                                               |
| `mcp.clientIdMetadataDocuments.allowedHosts`            | string[]        | (none)          | If set, only CIMD `client_id` URLs whose hostname is in this list are resolved. Others are silently rejected (`invalid_client`) without revealing the allowlist                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `mcp.clientIdMetadataDocuments.fetchTimeoutMs`          | number          | `5000`          | Deadline for CIMD document retrieval covering DNS, connect, and body read (milliseconds). Non-finite or non-positive values fall back to the default                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `mcp.clientIdMetadataDocuments.maxDocumentBytes`        | number          | `65536`         | Maximum CIMD document size in bytes (64 KB default). Responses exceeding this limit are rejected. Non-finite or non-positive values fall back to the default                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mcp.clientCredentials.enabled`                         | boolean         | `false`         | Enable the RFC 7523 `client_credentials` grant (`private_key_jwt`, EdDSA) for headless agents. Explicit opt-in; requires a non-empty `mcp.clientIdMetadataDocuments.allowedHosts` allowlist, CIMD enabled, and an `https:` `mcp.issuer` (RFC 6749 §3.2 — the token endpoint must be TLS; `http:` is permitted only for loopback development issuers) — all enforced at startup. See [Headless agents](./mcp-oauth.md#headless-agents-client_credentials)                                                                                                                                                      |
| `mcp.clientCredentials.accessTokenTtl`                  | number          | `300`           | Access-token lifetime in seconds for the `client_credentials` grant. No refresh token is ever issued — agents re-mint on 401. Non-finite or non-positive values fall back to the default                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `mcp.clientCredentials.rateLimit`                       | number \| false | `30`            | Issuance rate limit in requests/minute per `client_id` (token bucket, per node, and in fact per worker thread — N threads means an N× effective ceiling; a shared counter table would be a replication hot-write anti-pattern, and the assertion replay guard + 60s window bound cross-node abuse). Over-limit requests get `429` with `error: "slow_down"` and a `Retry-After` header. `false` or `0` disables; non-finite/non-positive values fall back to the default. CIMD metadata fetches are separately limited at a fixed 10 attempts/min per client_id URL (not configurable)                        |
| `mcp.signingKeyPem`                                     | string          | (generated)     | PEM-encoded private key (PKCS#8; RSA or EC P-256 — the signing algorithm is derived from the key material, overriding `mcp.signingAlgorithm`) used to sign access tokens. When set, this key **always** wins as the signer — it is found in the key set by material match, or persisted on first use (under a deterministic kid so concurrent cluster nodes are idempotent). When unset, a UUID-kid keypair is generated on first boot. Because all persisted keys are published in the JWKS, tokens signed by any node verify everywhere — pinning is **recommended** for clusters but not strictly required |
| `mcp.keyRotationInterval`                               | number          | `0` (disabled)  | Signing-key rotation period in seconds. When `> 0`, a fresh UUID-kid keypair is generated at token-mint time once the current signer is older than this interval. Old keys are kept in the JWKS and deleted lazily once `2 × accessTokenTtl` has passed since their immediate successor was created (covering replication lag). Rotation is skipped while `signingKeyPem` is set — setting both emits a startup warning                                                                                                                                                                                       |
| `mcp.signingAlgorithm`                                  | string          | `RS256`         | JWT signing algorithm for generated signing keys: `RS256` or `ES256` (EC P-256, [#127](https://github.com/HarperFast/oauth/issues/127)). Changing it on a running deployment rotates in a new key under the new algorithm (once the current key is ≥ 5 minutes old — an age floor so nodes with briefly-disagreeing configs during a rolling rollout don't rotate against each other; update all nodes together); old keys stay in the JWKS until retired, so outstanding tokens keep verifying. Ignored while `signingKeyPem` is set (the pin's key material decides). EdDSA is not supported                |
| `mcp.accessTokenTtl`                                    | number          | `3600`          | Access-token lifetime in seconds (default 1 hour)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `mcp.refreshTokenTtl`                                   | number          | `2592000`       | Refresh-token (family) lifetime in seconds (default 30 days)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mcp.refreshTokenRequiresOfflineAccess`                 | boolean         | `false`         | When `true`, the `authorization_code` exchange only issues a refresh token when the granted scope includes `offline_access` (the [SEP-2207](https://modelcontextprotocol.io/specification/draft/basic/authorization) OIDC-flavored opt-in). Off by default because most MCP clients never request `offline_access` — withholding refresh tokens from them would force re-auth every `accessTokenTtl`. Flipping this on does not revoke existing refresh-token families. The AS metadata always advertises `offline_access` in `scopes_supported` so clients know they may request it                          |

Sensitive leaves inside `mcp` support `${ENV_VAR}` expansion (e.g., `initialAccessToken: ${OAUTH_MCP_REGISTRATION_TOKEN}`), the same way provider credentials do.

**Discovery endpoints** (served when `mcp.enabled: true`):

| Path                                      | Spec     | Purpose                                                                                          |
| ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------ |
| `/.well-known/oauth-protected-resource`   | RFC 9728 | Tells MCP clients where to find the authorization server                                         |
| `/.well-known/oauth-authorization-server` | RFC 8414 | Advertises authorize / token / register / JWKS endpoints and supported methods                   |
| `/.well-known/jwks.json`                  | —        | Public keys for verifying issued JWTs (returns an empty key set until the first token is minted) |

All three documents include `Access-Control-Allow-Origin: *` so browser-based MCP clients and discovery tools can fetch them cross-origin.

#### Protecting your MCP route — `withMCPAuth`

Your app owns the MCP endpoint; wrap your handler with `withMCPAuth` to verify the issued tokens on it — fail-closed bearer-token validation that emits the RFC 9728 `WWW-Authenticate` challenge on rejection and attaches `request.mcp = { sub, client_id, aud, scope }` on success. Registration matters (Harper's core auth otherwise consumes the bearer token), so see **[MCP OAuth → The `withMCPAuth` wrapper](./mcp-oauth.md#the-withmcpauth-wrapper)** for the registration models, the full options reference, and using the wrapper from a separate component.

**Security:** before exposing MCP OAuth publicly, work through the [production-deployment checklist](./mcp-oauth.md#production-deployment) — pin `issuer`, gate Dynamic Client Registration, restrict redirect-URI hosts, and serve over HTTPS. For clusters, all nodes share the JWKS automatically (multi-key publication); optionally pin `signingKeyPem` for a single authoritative signer, or enable `keyRotationInterval` for automatic rotation.

## Environment Variables

All configuration options can be set via environment variables:

### Provider Credentials

**GitHub:**

```bash
OAUTH_GITHUB_CLIENT_ID=your_client_id
OAUTH_GITHUB_CLIENT_SECRET=your_client_secret
OAUTH_GITHUB_SCOPE="user:email"  # Optional
```

**Google:**

```bash
OAUTH_GOOGLE_CLIENT_ID=your_client_id
OAUTH_GOOGLE_CLIENT_SECRET=your_client_secret
OAUTH_GOOGLE_SCOPE="openid profile email"  # Optional
```

**Azure:**

```bash
OAUTH_AZURE_CLIENT_ID=your_client_id
OAUTH_AZURE_CLIENT_SECRET=your_client_secret
OAUTH_AZURE_TENANT_ID=your_tenant_id
OAUTH_AZURE_SCOPE="openid profile email"  # Optional
```

**Auth0:**

```bash
OAUTH_AUTH0_DOMAIN=yourapp.auth0.com
OAUTH_AUTH0_CLIENT_ID=your_client_id
OAUTH_AUTH0_CLIENT_SECRET=your_client_secret
OAUTH_AUTH0_SCOPE="openid profile email"  # Optional
```

### Global Options

```bash
OAUTH_DEBUG=true  # Enable debug mode
OAUTH_REDIRECT_URI=https://yourdomain.com/oauth/callback  # OAuth callback URL
OAUTH_POST_LOGIN_REDIRECT=/dashboard  # Where to send users after login
```

## Understanding Redirects

The OAuth plugin uses two different redirect configurations that serve distinct purposes. Understanding the difference is critical for proper OAuth integration.

### 1. OAuth Callback URL (`redirectUri`)

**Purpose:** Tells OAuth providers (GitHub, Google, etc.) where to send users after they authenticate with the provider.

**Configuration:**

```yaml
'@harperfast/oauth':
  redirectUri: ${OAUTH_REDIRECT_URI}
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

**Example:** `https://yourdomain.com/oauth/callback`

**How it works:**

- The plugin automatically appends the provider name to create the full callback path
- `redirectUri: https://yourdomain.com/oauth/callback` becomes:
  - `https://yourdomain.com/oauth/github/callback` (for GitHub)
  - `https://yourdomain.com/oauth/google/callback` (for Google)
- This URL **must be registered** in your OAuth provider's application settings

**Important:**

- Must be a fully-qualified URL (protocol + domain + path)
- Must match exactly what's registered with the OAuth provider
- Used only during the OAuth handshake - users briefly visit this URL but don't stay there

**If you don't set it:** the plugin fails to start, with an error naming the provider and the `redirectUri` option to set. There is no `localhost` fallback — a missing `redirectUri` used to default to `http://localhost:9926/oauth/callback`, which silently sent providers a loopback callback instead of failing loudly (and, with an IdP that accepts loopback redirects more permissively than GitHub does, could hand the authorization code to whatever is listening on the end user's own machine). Registering the callback URL with your provider is **not** sufficient; the plugin only sends what `redirectUri` is set to. Set it explicitly on every deployed app, and [verify it](./providers.md#verifying-the-authorization-request) after deploying. For local development, set it explicitly to your loopback origin, e.g. `redirectUri: 'http://localhost:9926/oauth'`.

### 2. Post-Login Redirect (`postLoginRedirect`)

**Purpose:** Where to redirect users **in your application** after successful OAuth login.

**Configuration:**

```yaml
'@harperfast/oauth':
  postLoginRedirect: ${OAUTH_POST_LOGIN_REDIRECT} # Default: '/'
```

**Examples:**

- `/dashboard` - Simple path
- `/app?view=settings` - With query parameters
- `/app#welcome` - With URL fragment for SPAs

**How it works:**

- After OAuth completes successfully, users are redirected to this path
- Supports relative paths, query parameters, and URL fragments
- For SPAs, you can include the hash/fragment: `/app#dashboard`

**Default:** `/` (application root)

### Dynamic Redirect per Login Request

Override `postLoginRedirect` on a per-request basis using the `redirect` query parameter:

```javascript
// Redirect to specific page after login
window.location.href = '/oauth/github/login?redirect=/dashboard';

// Redirect with query parameters
window.location.href = '/oauth/github/login?redirect=/app?view=settings';

// Redirect with URL fragment (for SPAs)
window.location.href = '/oauth/github/login?redirect=' + encodeURIComponent('/app#welcome');
```

**Redirect Priority (highest to lowest):**

1. `redirect` query parameter
2. `Referer` header (where the user came from)
3. `postLoginRedirect` config setting
4. `/` (fallback)

**Security:** The `redirect` parameter is automatically sanitized to prevent open redirect attacks. Only the path portion (pathname + search + hash) is preserved - any protocol, host, or port is stripped.

```javascript
// Safe - these all work as expected
'/dashboard'                    → '/dashboard'
'/app?view=settings'            → '/app?view=settings'
'/app#section'                  → '/app#section'

// Sanitized - protocol and host stripped for security
'https://evil.com/phishing'     → '/phishing'
'http://attacker.com/steal'     → '/steal'
'//evil.com/bad'                → '/bad'
```

### Single-Page Application (SPA) Integration

**Recommended:** Configure `postLoginRedirect` with your SPA route including the fragment:

```yaml
'@harperfast/oauth':
  postLoginRedirect: '/app#home' # Always land on SPA home view
```

Or use environment variables for flexibility:

```bash
OAUTH_POST_LOGIN_REDIRECT=/app#dashboard
```

**Dynamic routing:** For user-specific or context-aware redirects, use the redirect parameter:

```javascript
// Direct user to their specific page
const userId = getCurrentUserId();
const destination = `/app#profile/${userId}`;
window.location.href = `/oauth/github/login?redirect=${encodeURIComponent(destination)}`;
```

**State management:** For complex application state, use localStorage:

```javascript
// Before OAuth
const appState = { view: 'dashboard', filters: { status: 'active' } };
localStorage.setItem('oauth-return-state', JSON.stringify(appState));
window.location.href = '/oauth/github/login?redirect=/app';

// After OAuth - in your SPA initialization
const state = JSON.parse(localStorage.getItem('oauth-return-state') || '{}');
if (state.view) {
	restoreAppState(state);
	localStorage.removeItem('oauth-return-state');
}
```

### Complete Redirect Configuration Example

```yaml
'@harperfast/oauth':
  package: '@harperfast/oauth'
  redirectUri: ${OAUTH_REDIRECT_URI} # OAuth callback: https://app.example.com/oauth/callback
  postLoginRedirect: ${OAUTH_POST_LOGIN_REDIRECT} # After login: /dashboard
  debug: false
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

**Environment variables:**

```bash
# OAuth provider callback (must match OAuth app settings)
OAUTH_REDIRECT_URI=https://app.example.com/oauth/callback

# Where to send users after successful login
OAUTH_POST_LOGIN_REDIRECT=/app#home

# Provider credentials
OAUTH_GITHUB_CLIENT_ID=your_github_client_id
OAUTH_GITHUB_CLIENT_SECRET=your_github_client_secret
```

**OAuth Flow:**

1. User clicks "Login with GitHub"
2. User redirected to GitHub for authentication
3. GitHub redirects back to `https://app.example.com/oauth/github/callback`
4. Plugin processes OAuth callback
5. User redirected to `/app#home` (or `redirect` query param if provided)

## Lifecycle Hooks

Lifecycle hooks are **not configured in config.yaml**. Instead, they must be registered programmatically in your application code.

See the [Lifecycle Hooks documentation](./lifecycle-hooks.md) for complete details.

**Quick example:**

```javascript
// resources.js
import { registerHooks } from '@harperfast/oauth';
import { hooks } from './src/lib/oauthHooks.js';

registerHooks(hooks);
```

For complete hook implementation patterns, see [Lifecycle Hooks](./lifecycle-hooks.md).

## Account-Adoption Gate

When an OAuth login resolves a username that matches an existing `hdb_user` account, the plugin applies a trust gate before allowing the session to inherit that account's roles. This prevents an attacker from choosing a provider username that collides with a privileged Harper account.

Most deployments are already on the trusted path and need no change: Google or GitHub keyed on the account's **verified email** satisfies the gate, and any login resolved by an `onLogin` hook is authoritative and bypasses it. The gate only changes behavior for logins that would have adopted an account from an **unverified or non-email** claim (an unsigned userinfo `email`, or a reassignable handle/username such as GitHub `login`); those are now denied unless the escape hatch below is enabled.

### Trust model

Email provenance is **always assigned by the plugin**, never read from adapter or remote data. Any `_emailProvenance` value a custom `getUserInfo` adapter or UserInfo endpoint returns is stripped before the gate runs; only the plugin's own determination counts.

There are exactly **two** trusted email sources. A login may adopt an existing account only when **all** conditions for one of these sources are satisfied:

**Source 1 — JWKS-signed OIDC id token (`signed-oidc`)**:

- The email is a claim in a JWKS-signature-verified id token.
- The token's `iss` was validated against the provider's **expected issuer** (`config.issuer`). Providers without a known issuer — Azure `/common` (multi-tenant) and issuer-less generic providers — are not trusted for adoption.
- `email_verified === true` for the **standard `email` claim**. Providers that use a custom `emailClaim` cannot earn adoption trust because `email_verified` only attests the standard claim.
- The verified email equals the resolved username (`usernameClaim === 'email'`).

**Source 2 — GitHub authenticated email fetch (`github-authenticated`)**:

- `config.provider` is `'github'` (defense-in-depth: a non-GitHub provider cannot claim this trust level).
- A call to GitHub's `/user/emails` API actually succeeded and returned the verified flag.
- `email_verified === true` for the fetched email (a `verified: false` record does not qualify).
- The verified email equals the resolved username.

Any other source (unsigned token, plain UserInfo, failed GitHub fetch, custom `emailClaim`, non-GitHub provider) yields provenance `unauthenticated` → adoption denied.

When an `onLogin` hook supplies the identity (`hookData.user`), the gate is skipped entirely — the hook is authoritative.

**`fetchEmail` and OIDC providers without email in the id token** — when `fetchEmail: true` is configured and the id token lacks an `email` claim, the plugin fetches the email from the UserInfo endpoint so the login can resolve a username. The email is populated but the provenance is `unauthenticated` (it is not a signed claim), so adoption of an existing account is still denied. The login proceeds as a roleless session carrying a quarantine principal (see below).

**Unverified sessions for new accounts** — when the login claim is not trusted and no existing account is found, the session identity is set to an unpredictable, non-resolvable **quarantine principal** of the form `unverified:<email>#<random>` rather than the raw claim. Because the random suffix cannot be guessed, no `hdb_user` can be created to match it, so a later-provisioned privileged account of the claim's name can never be adopted by a replayed unverified login. `oauthUser` (including any app-level role claim) is preserved for the application's own authorization. The `/user` endpoint for such sessions reports the IdP-derived identity with a `null` role — never leaking the opaque principal. See [Quarantine principal](#quarantine-principal) and [Pre-emption](#known-limitations) below.

**Denied by default:**

| Scenario                                                            | Reason                                               |
| ------------------------------------------------------------------- | ---------------------------------------------------- |
| GitHub `login` claim → existing account                             | `login` ≠ email; username and email differ           |
| Okta `preferred_username` ≠ email → existing account                | username claim differs from email                    |
| `email_verified` absent or false                                    | Provider has not attested the email                  |
| Custom `emailClaim` (non-`email` claim used as identity)            | `email_verified` does not attest the custom claim    |
| Unsigned / unverified id token                                      | Signature not verified                               |
| JWKS-signed token from issuer-less provider (Azure /common, etc.)   | Issuer cannot be validated; nOAuth class attack      |
| Azure id token without `email_verified`                             | No verified-email attestation available              |
| Plain UserInfo response (no id token)                               | No authenticated binding to the identity             |
| GitHub `/user/emails` fetch failed or returned non-OK               | Email not confirmed by an authenticated call         |
| GitHub `/user/emails` returned `verified: false`                    | Email not verified by GitHub                         |
| Non-GitHub provider with custom `getUserInfo` adapter               | `github-authenticated` requires `provider=github`    |
| Custom adapter returning `_emailProvenance: 'github-authenticated'` | Provenance is plugin-assigned; adapter value ignored |
| `fetchEmail: true` resolved email from UserInfo (no signed token)   | Email is present but provenance is unauthenticated   |

**Allowed:**

| Scenario                                                       | Reason                                                      |
| -------------------------------------------------------------- | ----------------------------------------------------------- |
| Google (JWKS-signed token, `email_verified=true`)              | `signed-oidc`: issuer validated, email verified             |
| Auth0 (JWKS-signed token, `email_verified=true`)               | `signed-oidc`: issuer derived from domain                   |
| Okta (JWKS-signed token, `preferred_username` equals email)    | `signed-oidc`: issuer derived from domain                   |
| Azure single-tenant (JWKS-signed, `email_verified=true`)       | `signed-oidc`: issuer derived from tenant ID                |
| GitHub (`provider=github`) with verified email, username=email | `github-authenticated`: successful `/user/emails`, verified |
| `onLogin` hook returns `{ user }`                              | Hook path, gate skipped                                     |

### Escape hatch: `allowUnverifiedClaimInheritance`

If you have an operational need to allow adoption without the full trust chain (e.g., a legacy deployment migrating to verified claims), you can enable the escape hatch:

```yaml
'@harperfast/oauth':
  allowUnverifiedClaimInheritance: true # or ${MY_ENV_VAR} for env-controlled rollout
```

This setting accepts `${ENV_VAR}` expansion, so you can enable it via environment variable for a controlled rollout:

```bash
export OAUTH_ALLOW_UNVERIFIED=true  # disable once migration is complete
```

```yaml
'@harperfast/oauth':
  allowUnverifiedClaimInheritance: ${OAUTH_ALLOW_UNVERIFIED}
```

When enabled, the plugin logs a warning on every login that uses the escape hatch. **Disable this setting as soon as operationally practical** — it restores the pre-gate behavior where an unverified claim can adopt any existing account.

Default: `false` (off). Junk values, unresolved `${VAR}` placeholders (environment variable not set), and anything that is not `true` or `false` are treated as `false`.

### Quarantine principal

For a roleless login with no matching account and an untrusted claim, the plugin sets the session identity to a **quarantine principal** of the form `unverified:<claim>#<random>`. The random suffix makes the value unpredictable, so it can never be created as an `hdb_user` and can never resolve to a role. Unlike a fixed reserved prefix, it requires no naming convention and no fail-closed collision check — its security comes from unpredictability, not from a reserved namespace. The claim is embedded before the `#` purely for log readability and is never parsed back out.

### Pre-existing sessions (upgrade note)

Harper sessions do not expire by default. A session established **before this release** still holds a raw claim as its identity, which Harper resolves by name against `hdb_user` — and the login-time gate governs only _new_ logins, so it cannot retract an already-persisted session. Every OAuth login from this release forward records a provenance stamp (`authTrust`) on the session; a session whose `oauth` metadata carries no stamp is a **legacy** (pre-gate) session.

This release does **not** yet neutralize legacy sessions automatically. On the operations-API path in particular, the session cookie is resolved to an `hdb_user` role in Harper's core — on a listener this plugin's request middleware never wraps — so a legacy session there cannot be retracted from within the plugin at request time; retracting it requires rewriting the stored session rows, which is deferred to a follow-up.

**What operators should do on upgrade:** the gate protects new logins only — it does not retract sessions created before the upgrade. Typical Google/GitHub verified-email setups have nothing to retract. Any deployment that _could_ have accepted an unverified or non-email claim (intentionally or not) should revoke pre-2.6 OAuth sessions fleet-wide by clearing `system.hdb_session` — an administrator action. A user re-login is **not** sufficient: it only replaces that user's own session cookie and leaves any other (e.g. attacker-held) session active. Sessions created after the upgrade carry a provenance stamp and are governed by the gate.

Automatic neutralization of pre-existing sessions (a durable, fail-closed mechanism that also covers the operations-API path) is tracked as a fast-follow.

### Known limitations

- **Pre-emption (closed)**: An untrusted login with no matching account persists a non-resolvable quarantine principal, not the raw claim, so a later-provisioned privileged account of the claim's name can never be adopted by that session — there is no window to exploit. A subsequent trusted login (with a verified claim) establishes a new session with the real identity.
- **Naive passthrough hook**: An `onLogin` hook that returns `{ user: oauthUser.username }` bypasses the gate for that deployment — the hook is authoritative by design. Hooks must not blindly echo the OAuth username; they should validate before returning a `user`.
- **Void-provisioning hook**: A hook that creates the account but returns void (no `{ user }`) is gated on that same login. Provisioning hooks should return `{ user }` so the gate treats them as authoritative.

## Debug Mode

When `debug: true` is enabled, additional endpoints are available:

- `GET /oauth/` - List all configured providers
- `GET /oauth/test` - Interactive test page
- `GET /oauth/{provider}/user` - Current user info and token status
- `GET /oauth/{provider}/refresh` - Trigger token refresh

### Security: IP-Based Access Control

**By default, debug endpoints are only accessible from localhost** (`127.0.0.1` and `::1`). This prevents unauthorized access to sensitive debugging information.

To allow access from other IPs, set the `DEBUG_ALLOWED_IPS` environment variable:

```bash
# Allow single IP
DEBUG_ALLOWED_IPS=192.168.1.100

# Allow multiple IPs (comma-separated)
DEBUG_ALLOWED_IPS=192.168.1.100,192.168.1.101,10.0.0.50

# Allow IP range using prefix matching (e.g., all 10.0.0.x)
DEBUG_ALLOWED_IPS=10.0.0.

# Deny all access (empty string)
DEBUG_ALLOWED_IPS=
```

**Access denial response:**

```json
{
	"error": "Access forbidden",
	"message": "Debug endpoints are only accessible from allowed IPs.",
	"hint": "Set DEBUG_ALLOWED_IPS environment variable to allow access from your IP. Defaults to localhost only (127.0.0.1,::1)."
}
```

**Security best practices:**

- Keep debug mode disabled in production
- Use IP allowlist when debug mode must be enabled remotely
- Monitor access logs for unauthorized attempts
- Regular endpoints (`/login`, `/callback`, `/logout`) are not affected by IP restrictions

**Warning:** Never enable debug mode in production environments without strict IP controls.

## Complete Example

```yaml
'@harperfast/oauth':
  package: '@harperfast/oauth'
  debug: false
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
      scope: 'user:email'
    google:
      clientId: ${OAUTH_GOOGLE_CLIENT_ID}
      clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
    azure:
      clientId: ${OAUTH_AZURE_CLIENT_ID}
      clientSecret: ${OAUTH_AZURE_CLIENT_SECRET}
      tenantId: ${OAUTH_AZURE_TENANT_ID}
    auth0:
      domain: ${OAUTH_AUTH0_DOMAIN}
      clientId: ${OAUTH_AUTH0_CLIENT_ID}
      clientSecret: ${OAUTH_AUTH0_CLIENT_SECRET}
```

## Next Steps

- [Set up OAuth providers](./providers.md)
- [Implement lifecycle hooks](./lifecycle-hooks.md)
- [API reference](./api-reference.md)
