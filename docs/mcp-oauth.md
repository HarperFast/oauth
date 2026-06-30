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
import { withMCPAuth } from '@harperfast/oauth';

// Your MCP endpoint. request.mcp is populated only after a valid bearer token.
function mcpHandler(request, next) {
	const { sub, client_id, scope } = request.mcp; // verified token claims
	return { jsonrpc: '2.0', result: { hello: sub } };
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
served at the RFC 9728 path-appended location `/mcp/.well-known/oauth-protected-resource`,
which is the form the `WWW-Authenticate` challenge advertises.

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
WWW-Authenticate: Bearer resource_metadata="https://my-app.example.com/mcp/.well-known/oauth-protected-resource"
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
		// Record which MCP client is acting for which user.
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
- [ ] **Set `mcp.signingKeyPem` in clusters.** The signing key is a single row at
      a fixed key id. Without a configured PEM, two nodes can each generate a
      different key on first mint and sign tokens the published JWKS doesn't list
      until replication converges. Provide the **same** PEM on every node.
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
appear. In a cluster, an empty or mismatched JWKS after traffic usually means
`mcp.signingKeyPem` isn't pinned (see [Production deployment](#production-deployment)).

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

## Not yet supported (v1.1+)

These are **not** available and no config or code sample here implies them:

- Per-tool / fine-grained scopes (the `scope` claim is passed through, not enforced per tool)
- Transitive revocation (revoking the upstream IdP session does not invalidate already-issued MCP tokens)
- Signing algorithms other than RS256, and multi-key JWKS / key rotation
- A native, composed MCP server (this plugin is the authorization server, not the MCP transport)
