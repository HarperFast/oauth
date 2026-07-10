# MCP OAuth

> **Status: experimental, opt-in.** Enable with `mcp.enabled: true`. The surface
> described here is stable, but the feature is gated behind the flag and the
> wire format may still change in a minor release. See [issue #86](https://github.com/HarperFast/oauth/issues/86).

The plugin can act as an OAuth 2.1 **authorization server** for [Model Context
Protocol](https://modelcontextprotocol.io) clients (Claude Desktop, Cursor,
`mcp-remote`, the MCP Inspector). It lets those clients authenticate against the
same upstream providers you already configure for human login, then mints
audience-bound JWT access tokens your MCP routes can verify with a single wrapper.

It implements the [MCP authorization specification (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
and the OAuth RFCs it builds on:

| RFC                                                   | Role here                                                      |
| ----------------------------------------------------- | -------------------------------------------------------------- |
| [6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 authorization-code grant                             |
| [6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer token usage (`Authorization: Bearer`)                   |
| [7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration (`/register`)                      |
| [7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE (`S256`, required — `plain` is rejected)                  |
| [8252](https://datatracker.ietf.org/doc/html/rfc8252) | OAuth for native apps (loopback redirect URIs)                 |
| [8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata (`/.well-known/...`)             |
| [8707](https://datatracker.ietf.org/doc/html/rfc8707) | Resource Indicators (the `resource` parameter, `aud` binding)  |
| [9728](https://datatracker.ietf.org/doc/html/rfc9728) | Protected Resource Metadata (the `WWW-Authenticate` challenge) |

---

## Quickstart

Two pieces: turn on the authorization server in `config.yaml`, and guard your MCP
route handler with `withMCPAuth`.

**1. Enable the authorization server** (`config.yaml`):

```yaml
'@harperfast/oauth':
  package: '@harperfast/oauth'
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
  mcp:
    enabled: true
    issuer: https://my-app.example.com # required; pin to your public origin
```

**2. Guard your MCP handler** (`resources.ts`):

```typescript
import { server } from 'harper';
import { withMCPAuth } from '@harperfast/oauth';

// Your MCP endpoint. request.mcp is guaranteed present here — the guard rejects
// missing/invalid tokens before your handler runs, so no optional-chaining needed.
function mcpHandler(request) {
	const { sub, client_id, scope } = request.mcp; // verified token claims
	// Harper HTTP listeners return { status, body, headers? }; MCP messages are
	// JSON-RPC 2.0, so serialize the JSON-RPC response as the body.
	return { status: 200, body: JSON.stringify({ jsonrpc: '2.0', result: { hello: sub } }) };
}

// Register on a urlPath subroute so Harper's core auth never sees the request.
server.http(withMCPAuth(mcpHandler), { urlPath: '/mcp' });
```

That's it. An MCP client pointed at `https://my-app.example.com/mcp` now
discovers the authorization server, registers itself, walks the user through your
GitHub login, and presents a bearer token on every subsequent call — which
`withMCPAuth` verifies before `mcpHandler` runs.

> **Why `urlPath`, not the default route?** Harper's core auth is a default-group
> middleware that consumes `Authorization: Bearer` and rejects any token that
> isn't a Harper _operation_ token — answering with `WWW-Authenticate: Basic`,
> not the `Bearer` challenge MCP clients need. Registering on a `urlPath`
> subroute gives the route its own dispatch chain that core auth never runs on.
> See [The `withMCPAuth` wrapper](#the-withmcpauth-wrapper) for the default-group
> fallback.

---

## The flow

```
 MCP Client                  Harper (OAuth plugin)              Upstream IdP
     │                                │                          (GitHub/…)
     │  1. GET /mcp  (no token)       │                              │
     │ ─────────────────────────────▶│                              │
     │  401 + WWW-Authenticate:       │                              │
     │     Bearer resource_metadata   │                              │
     │ ◀─────────────────────────────│                              │
     │                                │                              │
     │  2. GET /.well-known/oauth-protected-resource   (RFC 9728)    │
     │ ─────────────────────────────▶│                              │
     │  3. GET /.well-known/oauth-authorization-server (RFC 8414)    │
     │ ─────────────────────────────▶│                              │
     │                                │                              │
     │  4. POST /oauth/mcp/register   (RFC 7591 DCR)                 │
     │ ─────────────────────────────▶│   → client_id                │
     │                                │                              │
     │  5. GET /oauth/mcp/authorize?code_challenge=…&resource=…      │
     │ ─────────────────────────────▶│  302 to upstream login       │
     │                                │ ────────────────────────────▶
     │                  (user authenticates with the upstream IdP)   │
     │                                │ ◀────────────────────────────
     │  302 back to client redirect_uri?code=…                       │
     │ ◀─────────────────────────────│                              │
     │                                │                              │
     │  6. POST /oauth/mcp/token  (code + code_verifier)             │
     │ ─────────────────────────────▶│  → access_token (RS256 JWT)  │
     │                                │     + refresh_token          │
     │                                │                              │
     │  7. GET /mcp  Authorization: Bearer <access_token>            │
     │ ─────────────────────────────▶│  withMCPAuth verifies → 200  │
     │ ◀─────────────────────────────│                              │
```

1. **Challenge.** A request to your guarded MCP route with no (or an invalid)
   token gets `401` with `WWW-Authenticate: Bearer resource_metadata="<url>"`,
   pointing at the Protected Resource Metadata document (RFC 9728).
2. **Protected Resource Metadata.** The client fetches it to learn which
   authorization server to use.
3. **Authorization Server Metadata.** The client fetches the AS metadata (RFC 8414) to learn the `authorize`, `token`, `register`, and `jwks_uri` endpoints
   and the supported methods.
4. **Dynamic Client Registration.** The client registers itself (RFC 7591) and
   receives a `client_id`. Registrations persist, so a cached `client_id`
   survives Harper restarts.
5. **Authorization.** The client opens `/oauth/mcp/authorize` with a PKCE
   challenge and the `resource` it wants a token for. The plugin redirects the
   user to the upstream IdP; on return it mints a single-use authorization code
   and redirects back to the client's `redirect_uri`.
6. **Token exchange.** The client posts the code plus its PKCE `code_verifier` to
   `/oauth/mcp/token` and receives an RS256-signed access token (and a refresh
   token) bound to the `resource` as its `aud`.
7. **Authenticated requests.** The client calls your MCP route with
   `Authorization: Bearer <access_token>`. `withMCPAuth` verifies the signature,
   audience, and issuer, attaches the claims as `request.mcp`, and runs your
   handler.

No upstream IdP token is ever embedded in the issued JWT — the access token is
minted and signed by this plugin.

---

## Endpoints

All endpoints are served only when `mcp.enabled: true` (otherwise `404`, or the
discovery handlers fall through).

### Discovery (`/.well-known/*`)

| Path                                          | Spec     | Returns                                                                              |
| --------------------------------------------- | -------- | ------------------------------------------------------------------------------------ |
| `GET /.well-known/oauth-protected-resource`   | RFC 9728 | `resource`, `authorization_servers`, `bearer_methods_supported`                      |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | `issuer`, the endpoint URLs, and supported response/grant/PKCE/auth methods          |
| `GET /.well-known/jwks.json`                  | —        | The RS256 public keys for verifying issued tokens (empty until the first token mint) |

All three send `Access-Control-Allow-Origin: *` so browser-based clients and
discovery tools can fetch them cross-origin. When `mcp.resource` carries a path
(e.g. `https://host/mcp`), the Protected Resource Metadata document is **also**
served at the RFC 9728 path-appended location `/.well-known/oauth-protected-resource/mcp`
(the well-known segment sits between the origin and the resource path), which is the
form the `WWW-Authenticate` challenge advertises.

### Authorization server

| Endpoint               | Method | Notes                                                                                                                                     |
| ---------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `/oauth/mcp/register`  | POST   | RFC 7591 Dynamic Client Registration. Open by default; gate with `initialAccessToken`. Returns `201`.                                     |
| `/oauth/mcp/authorize` | GET    | OAuth 2.1 + PKCE. Requires `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `resource`. |
| `/oauth/mcp/token`     | POST   | Grants: `authorization_code`, `refresh_token`. Returns the token pair with `Cache-Control: no-store`.                                     |

> `mcp` is a reserved provider name — the plugin refuses to start if you configure
> a provider called `mcp`, because it would collide with `/oauth/mcp/*`.

### Issued access tokens

RS256 JWT, signed with key id `rs256-default`, carrying:

| Claim       | Value                                                                 |
| ----------- | --------------------------------------------------------------------- |
| `iss`       | `mcp.issuer`                                                          |
| `sub`       | The Harper user the token was issued to (from your `onLogin` mapping) |
| `aud`       | `mcp.resource` (RFC 8707 audience binding)                            |
| `client_id` | The DCR-issued client identifier                                      |
| `scope`     | Space-separated scope string (omitted when empty)                     |
| `iat`/`exp` | Issued-at / expiry (`exp` = `iat` + `accessTokenTtl`, default 1 hour) |
| `jti`       | Unique token id (used in audit events; safe to log)                   |

Refresh tokens rotate on use: presenting an already-used token from a family
revokes the whole family (replay defense). Refresh families live for
`refreshTokenTtl` (default 30 days).

---

## The `withMCPAuth` wrapper

`withMCPAuth(handler, options?)` wraps an MCP route handler so every request must
present a valid access token minted by this plugin before the handler runs. It is
the bearer-token counterpart to `withOAuthValidation` (which guards
cookie/session routes).

On any failure it **fails closed** with the spec 401:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://my-app.example.com/.well-known/oauth-protected-resource/mcp"
Content-Type: application/json

{"error":"invalid_token","error_description":"<reason>"}
```

When a valid token is presented, the wrapper attaches the verified claims and
calls your handler:

```typescript
request.mcp = { sub, client_id, aud, scope };
```

Tokens are read from the `Authorization: Bearer` header only (RFC 6750 §2.1) —
query-string and body tokens are ignored.

### Registration

**Primary — `urlPath` subroute (recommended):**

```typescript
server.http(withMCPAuth(mcpHandler), { urlPath: '/mcp' });
```

Harper dispatches a `urlPath` subroute on its own chain and returns, so the
default chain — where core auth lives — never runs for `/mcp`. The bearer
challenge can't be clobbered. This is the same isolation `/.well-known/*` uses.
No `path` option and no ordering hint are needed.

**Fallback — default group, ahead of core auth:**

```typescript
server.http(withMCPAuth(mcpHandler, { path: '/mcp' }), { before: 'authentication' });
```

When the route shares the default chain with auth (no `urlPath`), pass `path` so
the wrapper guards only that path and calls `next()` for everything else, and
register with `{ before: 'authentication' }` so it runs ahead of core auth. In
this mode the wrapped handler **must terminate the request** (not call `next`),
or core auth runs afterward and re-rejects the token. This mirrors Harper's own
`server/static.ts`.

### Options

| Option        | Type                                   | Default                    | Purpose                                                                                                                                       |
| ------------- | -------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`        | `string`                               | (unset)                    | Set only for the default-group fallback — the path this guard owns; requests outside it fall through to `next()`.                             |
| `onAuthError` | `(request, reason: string) => any`     | (unset)                    | Custom denial handler. **Any falsy return falls back to the default 401** — a no-return handler can't accidentally turn a denial into a pass. |
| `getConfig`   | `() => MCPConfig \| undefined`         | live plugin config         | MCP config source, read per request. Override for tests.                                                                                      |
| `logger`      | `Logger`                               | plugin logger              | Logger for verification failures. Override for tests.                                                                                         |
| `keyStore`    | `{ getAllPublicKeys(): Promise<...> }` | the plugin's `MCPKeyStore` | Signing-key source. Override for tests.                                                                                                       |

A request whose path exceeds 2048 characters is rejected before any token work
(DoS guard). If MCP is disabled, no token is presented, or no signing keys exist
yet, the wrapper denies — it never serves a guarded route in an unconfigured state.

### Using `withMCPAuth` from a different component than the plugin

By default `withMCPAuth` reads the live MCP config from the plugin via
`OAuthResource.mcpConfig`. That works when the component that **declares**
`@harperfast/oauth` is the same one that exposes the MCP route. If your MCP tools
live in a **separate** component (it imports `withMCPAuth` as a function but
doesn't declare the plugin in its own `config.yaml`), that consumer resolves its
**own** `node_modules` copy of the package, where `OAuthResource.mcpConfig` is a
module-local static that is never populated — so it reads as `undefined` and the
guard fails closed.

In that setup, **inject `getConfig`** so the wrapper sees the config:

```typescript
server.http(
	withMCPAuth(mcpHandler, {
		// Pin issuer/resource to the values the plugin component issues tokens with,
		// so the iss/aud checks match the minted tokens.
		getConfig: () => ({
			enabled: true,
			issuer: 'https://my-app.example.com',
			resource: 'https://my-app.example.com/mcp',
		}),
	}),
	{ urlPath: '/mcp' }
);
```

Signing keys need no extra wiring: the default `MCPKeyStore` reads
`databases.oauth.harper_oauth_mcp_keys`, which is cluster-global, so the consumer
verifies against the same JWKS the plugin component mints with. Importing
`withMCPAuth` as a function does **not** spin up a second plugin instance.

---

## The `onMCPTokenIssued` hook

Register `onMCPTokenIssued` to react in your own application each time an access
or refresh token is minted. It is the MCP-client analog of [`onLogin`](./lifecycle-hooks.md#onlogin):
where `onLogin` lets you provision a user on human sign-in, this lets you record
and respond to an MCP client gaining access. Typical uses:

- **Associate the client with a user** — link the `client_id` to `sub` in your
  own data model so you know which MCP clients are acting for which users.
- **Monitoring and security** — track active clients, or alert when a new or
  unexpected `client_id` obtains a token.
- **Rate-limiting / quota** — count issuance per `client_id`.

(The built-in [audit log](#audit-events) already records that a token was issued —
reach for this hook when you need to act on it, not just log it.)

```typescript
import { registerHooks } from '@harperfast/oauth';

registerHooks({
	onMCPTokenIssued: async (event, request) => {
		// event = { type: 'access' | 'refresh', client_id, sub, aud, scope?, jti }
		// Record which MCP client is acting for which user. `tables` is a Harper
		// global (no import needed); `McpClient` here is an example app-owned table —
		// the plugin doesn't provide it, so define your own.
		await tables.McpClient.put({ id: event.client_id, user: event.sub, lastSeen: Date.now() });
	},
});
```

It fires **after** the token is durably issued and runs **detached** — it is not
awaited, so it never delays or blocks the token response (a slow hook can't add
latency to issuance). It is fire-and-forget: a throwing hook is caught and logged,
never surfaced. Because it isn't awaited, its side effects may complete after the
client already has the token — don't rely on it finishing before the response.

> **Security:** `event` is sanitized — it carries only the `jti` (a token
> identifier, safe to log), never the access/refresh token strings. The `request`
> is **not** sanitized: on the refresh path its body carries the `refresh_token`
> the client presented. Do not log `request` wholesale.

See [Lifecycle Hooks](./lifecycle-hooks.md) for `registerHooks` and the other hooks.

---

## Audit events

Token lifecycle events are written to Harper's structured log (`hdb.log`) at
`info`, each line prefixed `MCP audit:` with a JSON payload:

```
MCP audit: {"event":"oauth.mcp.token.issued","client_id":"…","sub":"…","aud":"https://my-app.example.com/mcp","scope":"…","jti":"…","timestamp":"2026-06-29T17:00:00.000Z"}
```

| `event`                     | When                                                  |
| --------------------------- | ----------------------------------------------------- |
| `oauth.mcp.token.issued`    | An access token was minted (authorization-code grant) |
| `oauth.mcp.token.refreshed` | A token pair was rotated (refresh-token grant)        |
| `oauth.mcp.token.rejected`  | A bearer token was rejected by `withMCPAuth`          |

Payloads carry only the `jti` — never `access_token`, `refresh_token`, or
`client_secret`. Filter your log aggregator on the `MCP audit:` prefix or the
`event` value. Dynamic Client Registration attempts are logged separately by the
`/register` handler.

---

## Production deployment

A checklist before you expose MCP OAuth publicly:

- [ ] **HTTPS.** Serve everything over TLS. OAuth bearer tokens are only as safe
      as the transport.
- [ ] **Pin `mcp.issuer`** to your public origin (e.g. `https://my-app.example.com`).
      It is required when `mcp.enabled` — the plugin refuses to start without it —
      because otherwise `iss` (and `aud`, which derives from it) would float with
      the client-controlled `Host` header, an audience-confusion risk. Pinning
      `resource` alone is not enough; `iss` still floats.
- [ ] **Gate Dynamic Client Registration.** `/register` is open by default per
      RFC 7591. Set `mcp.dynamicClientRegistration.initialAccessToken` to require
      a bearer token, or accept open registration deliberately.
- [ ] **Restrict redirect URI hosts** with
      `mcp.dynamicClientRegistration.allowedRedirectUriHosts`. Loopback is always
      allowed for native clients (RFC 8252).
- [ ] **Review cluster signing-key strategy.** The plugin publishes _all_ persisted
      signing keys in the JWKS, so a token signed by any node's key is always
      verifiable — the clustered first-boot race is no longer a hard blocker.
      Two strategies: - _Recommended for production_: set `mcp.signingKeyPem` to the **same** PEM
      on every node. One canonical key, no race, no rotation. - _Without a pinned key_: each node generates its own key on first mint, and
      all of them are published in the JWKS. Tokens verify across nodes once
      replication converges (within seconds). Enable `mcp.keyRotationInterval` to
      roll keys automatically (see below).
- [ ] **Resolve to exactly one provider.** v1 requires a single eligible upstream
      provider. If you configure more than one globally, set `mcp.providers` to the
      one that should serve the MCP flow, or `/oauth/mcp/authorize` returns
      `server_error`.

See [Configuration → MCP OAuth](./configuration.md#mcp-oauth) for the full option
table.

---

## Troubleshooting

**Client can't discover the server / "could not find authorization server".**
Confirm `mcp.enabled: true` and that `GET /.well-known/oauth-protected-resource`
and `GET /.well-known/oauth-authorization-server` return `200`. If your `resource`
has a path, the client may be looking at the path-appended PRM location — both are
served.

**Client gets `WWW-Authenticate: Basic` instead of `Bearer`.** Core Harper auth
ran ahead of `withMCPAuth`. Register the guarded route on a `urlPath` subroute, or
use the default-group fallback with `{ before: 'authentication' }`. See
[Registration](#registration).

**Token verification fails right after enabling MCP.** `GET /.well-known/jwks.json`
returns an empty key set until the first token is minted — the signing key is
created lazily. Complete one authorization flow and the key (and JWKS entry)
appear. In a cluster, an empty JWKS after traffic usually means no token has been minted
yet (the key is generated lazily). A mismatched JWKS (token signed by a key not
in the set) can happen in the brief window before replication converges; it
resolves automatically once the key table replicates.

**`/oauth/mcp/authorize` returns `server_error`.** More than one upstream provider
resolved as eligible. Set `mcp.providers` to exactly one.

**`/oauth/mcp/authorize` returns `invalid_request` for `code_challenge_method`.**
Only `S256` is accepted — OAuth 2.1 forbids `plain`.

**Registration returns `401`.** `mcp.dynamicClientRegistration.initialAccessToken`
is set and the client didn't present a matching `Authorization: Bearer <token>`.

**Reading the audit trail.** Grep `hdb.log` for `MCP audit:` (see
[Audit events](#audit-events)).

---

## Migrating from a hand-rolled MCP authorization server

If your app already implements MCP OAuth by hand, swap your pieces for the
plugin's:

| You had                                                                   | Replace with                                                         |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Custom `/.well-known/*`, `/register`, `/authorize`, `/token`, JWKS routes | `mcp.enabled: true` — the plugin serves all of them                  |
| Your own bearer-token verification middleware                             | `withMCPAuth(handler)` on the MCP route                              |
| Side effects on token mint (client tracking, monitoring, audit)           | The `onMCPTokenIssued` hook + the built-in `MCP audit:` log events   |
| A hand-managed signing key                                                | `mcp.signingKeyPem` (or let the plugin generate one for single-node) |

Point your MCP clients at the same route; they rediscover the endpoints via the
`WWW-Authenticate` challenge and re-register.

---

## Signing-key rotation

By default, the plugin generates one RS256 keypair per node on first mint and
keeps it indefinitely. The JWKS endpoint publishes **all** persisted keys, so
tokens signed by any node's key are always verifiable — the cluster first-boot
race is resolved without any manual coordination.

To roll signing keys automatically, set `mcp.keyRotationInterval` (seconds):

```yaml
mcp:
  enabled: true
  issuer: https://my-app.example.com
  keyRotationInterval: 86400 # rotate once a day
  accessTokenTtl: 3600
```

When the newest key's age exceeds `keyRotationInterval`, a new UUID-kid keypair
is generated at the next token mint. The old key **remains in the JWKS** until
every token it signed can no longer be valid (`2 × accessTokenTtl` after the
newer key's creation time), then it is garbage-collected. During that overlap
window, both old and new tokens verify correctly.

**Pin vs rotation — mutually exclusive.** `mcp.signingKeyPem` and
`mcp.keyRotationInterval` conflict: the pin prevents rotation (a pinned key is
identical everywhere; rotating it would invalidate that identity). If both are
set, a warning is logged at startup and rotation is silently skipped. Pick one:

| Goal                                             | Config                    |
| ------------------------------------------------ | ------------------------- |
| Fixed key, identical everywhere (zero race risk) | `mcp.signingKeyPem`       |
| Automatic rotation, lazy JWKS GC                 | `mcp.keyRotationInterval` |
| No rotation, no pin (single node or low-traffic) | neither                   |

---

## Client ID Metadata Documents (CIMD)

The MCP authorization spec allows a client to identify itself with an HTTPS URL
instead of an opaque string. When the AS receives such a `client_id`, it fetches
the URL as a JSON metadata document, validates the fields, and uses those values
in place of a registered (DCR) client.

CIMD is **enabled by default** when `mcp.enabled: true`. No configuration is needed
for the basic case — any well-formed HTTPS client_id with a non-root path triggers
automatic resolution.

### How it works

1. The MCP client sends `client_id=https://app.example.com/client.json` to
   `/oauth/mcp/authorize`.
2. The AS verifies the URL shape (HTTPS, non-root path, no dot path segments, no
   IP literal host), then does a DNS pre-flight check — **all** resolved addresses
   must be globally routable, checked against the full IANA special-purpose
   registries. IPv4 rejects `0/8`, `10/8`, `100.64/10` (CGNAT), `127/8`,
   `169.254/16`, `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.88.99/24`,
   `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`+, and the
   AS112/AMT blocks; IPv6 allows only global unicast (`2000::/3`), with v4-mapped
   and 6to4/ISATAP transition forms classified by their embedded IPv4 and the
   in-`2000::/3` special-use prefixes (Teredo, ORCHID, documentation) also
   rejected. This blocks SSRF to internal services. All DNS-gate rejections return
   one generic `invalid_client` message so callers cannot probe the server's
   internal DNS view. Concurrent resolutions are globally bounded (getaddrinfo
   runs on an uncancellable thread pool) and deduped per client_id.
3. The AS fetches the URL (5 s deadline covering DNS, connect, and the full body;
   64 KB cap; no redirects; only `200 OK` accepted) over a **connection pinned to
   the address the gate validated** — the socket connects to that exact IP while
   the hostname is used for TLS SNI and certificate verification, so DNS rebinding
   between the gate and the connection cannot re-target the fetch. It then
   validates the document: `client_id` must match the URL, `client_name` and
   `redirect_uris` are required, grant types and auth methods must match supported
   values.
4. Instead of immediately redirecting to the upstream IdP, the AS shows the user an
   **interstitial confirmation page** that displays the `client_id` host (the
   authoritative CIMD identity), the `client_name`, and the redirect URI hostname
   (with a loopback warning when applicable). This satisfies the MCP spec
   requirement to clearly display who the user is authorizing. The page is served
   with `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`,
   and `Cache-Control: no-store`, and it sets a per-flow `__Host-` consent cookie
   that binds the rest of the flow to this browser.
5. The user submits the form, which POSTs a one-time confirm token to
   `/oauth/mcp/confirm`. The AS verifies and consumes the token, checks that the
   consent cookie matches the hash bound into the token, then performs the
   upstream redirect exactly as it would for a DCR client. The same cookie is
   re-checked when the upstream IdP redirects back, **before** the upstream code
   is exchanged or any authorization code is issued.
6. Successfully resolved documents are **cached per process** (LRU-bounded to
   1 000 entries) with a TTL derived from `Cache-Control: max-age` (clamped to
   [60 s, 86 400 s]; default 3 600 s; `no-store`/`no-cache` floor at 60 s as
   deliberate DoS protection). Failures are never cached (the CIMD draft forbids
   caching error responses and invalid documents). Cached records are revalidated
   against the live `allowedRedirectUriHosts` policy on every hit, so tightening
   that setting takes effect immediately.

### Security properties

- SSRF: DNS pre-flight checks all A/AAAA records against the IANA special-purpose
  registries; IP-literal hosts in the URL are rejected before DNS. The fetch is
  **pinned** to the validated address (custom `lookup`), so DNS rebinding between
  the gate and the connection cannot re-target the socket — the hostname is still
  used for TLS SNI and certificate verification. Concurrent DNS resolutions are
  globally bounded so a flood of blackholed-DNS client_ids can't exhaust the
  thread pool.
- XSS: `client_name` and all other client-supplied strings are HTML-escaped before
  rendering in the interstitial page. Clients are attacker-controlled; treat every
  field as untrusted. `client_uri` is labelled as unverified — only the `client_id`
  host is an authenticated identity.
- Token binding: the confirm token embeds the full set of authorize parameters
  (redirect_uri, code_challenge, resource, scope). Swapping params between the
  interstitial and the confirm POST is not possible — the token is single-use and
  binds all values at mint time.
- Browser binding: consent is bound to the approving browser via a per-flow
  `__Host-`-prefixed, Secure, HttpOnly, SameSite=Lax nonce cookie whose SHA-256
  hash travels inside the server-side state. The `__Host-` prefix means a sibling
  origin (e.g. `evil.example.com` against `auth.example.com`) cannot plant a
  parent-domain cookie to forge the binding — plain `SameSite=Lax` does not stop
  that, since sibling subdomains are same-site. Both `/oauth/mcp/confirm` and the
  upstream OAuth callback require the cookie to match — the callback checks it
  **before** exchanging the upstream code or running the `onLogin` hook, so a
  mismatched (self-approved) flow triggers no side effects. A malicious client
  therefore cannot approve the interstitial itself and hand the victim a
  ready-made upstream login URL. Cookies must be enabled in the user's browser for
  CIMD authorization. Because the consent cookie is `__Host-`/`Secure`, CIMD
  interactive authorization requires the AS to be served over **HTTPS** — on a
  plain-HTTP origin the browser silently drops the cookie and `/oauth/mcp/confirm`
  always rejects. Most browsers carve out `http://localhost` as trustworthy for
  development, but behavior varies; use TLS for anything beyond local testing.
- Token purpose: confirm tokens are rejected if presented as upstream OAuth
  callback `state` (and vice versa) — each token is only accepted by the
  endpoint it was minted for.
- Config safety: `mcp.enabled`, `clientIdMetadataDocuments.enabled`, and
  `allowedHosts` are normalized at load — an env-expanded `"false"` disables the
  feature (not left truthy), and `allowedHosts` is coerced to an array of exact,
  lowercased hostnames (never substring-matched).

### Configuration

```yaml
mcp:
  enabled: true
  issuer: https://my-app.example.com
  clientIdMetadataDocuments:
    enabled: true # default; set false to disable CIMD entirely
    allowedHosts: # optional allowlist; omit to allow any public host
      - mcp-client.example.com
      - tools.partner.com
    fetchTimeoutMs: 5000 # default 5 000 ms
    maxDocumentBytes: 65536 # default 64 KB
```

When `allowedHosts` is configured, any CIMD `client_id` whose host is not in the
list is treated as an unknown client (`invalid_client`) without revealing whether
the host would otherwise be valid — the list is not disclosed to the client.
Entries are matched exactly (case-insensitive) against the URL host; a single
hostname string is accepted and normalized to a one-element list. Omitting
`allowedHosts` (or an empty list) allows any globally-routable host — the SSRF
gate still applies.

> **v1 limitation:** only `token_endpoint_auth_method: none` (public clients) is
> supported for CIMD clients. `private_key_jwt` authentication will be activated
> by issue [#159](https://github.com/HarperFast/oauth/issues/159). Other auth
> methods are rejected with `invalid_client`.

### Stored/DCR clients are unchanged

CIMD resolution only applies to URL-shaped client IDs. Any `client_id` that does
not parse as an HTTPS URL with a non-root path goes directly to the DCR store as
before. CIMD clients and DCR clients can coexist; existing DCR registrations are
not affected.

---

## Not yet supported (v1.1+)

These are **not** available and no config or code sample here implies them:

- Per-tool / fine-grained scopes (the `scope` claim is passed through, not enforced per tool)
- Transitive revocation (revoking the upstream IdP session does not invalidate already-issued MCP tokens)
- Signing algorithms other than RS256
- A native, composed MCP server (this plugin is the authorization server, not the MCP transport)
