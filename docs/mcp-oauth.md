# MCP OAuth

> **Status: experimental, opt-in.** Enable with `mcp.enabled: true`. The surface
> described here is stable, but the feature is gated behind the flag and the
> wire format may still change in a minor release. See [issue #86](https://github.com/HarperFast/oauth/issues/86).

The plugin can act as an OAuth 2.1 **authorization server** for [Model Context
Protocol](https://modelcontextprotocol.io) clients (Claude Desktop, Cursor,
`mcp-remote`, the MCP Inspector). It lets those clients authenticate against the
same upstream providers you already configure for human login, then mints
audience-bound JWT access tokens your MCP routes can verify with a single wrapper.

It implements the [MCP authorization specification (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
and the OAuth RFCs it builds on:

| RFC                                                   | Role here                                                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| [6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 authorization-code grant                                                                |
| [6750](https://datatracker.ietf.org/doc/html/rfc6750) | Bearer token usage (`Authorization: Bearer`)                                                      |
| [7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration (`/register`) — **deprecated** in 2026-07-28 (compat path; see below) |
| [7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE (`S256`, required — `plain` is rejected)                                                     |
| [8252](https://datatracker.ietf.org/doc/html/rfc8252) | OAuth for native apps (loopback redirect URIs)                                                    |
| [8414](https://datatracker.ietf.org/doc/html/rfc8414) | Authorization Server Metadata (`/.well-known/...`)                                                |
| [8707](https://datatracker.ietf.org/doc/html/rfc8707) | Resource Indicators (the `resource` parameter, `aud` binding)                                     |
| [9207](https://datatracker.ietf.org/doc/html/rfc9207) | Issuer identification (`iss` on authorization responses)                                          |
| [9728](https://datatracker.ietf.org/doc/html/rfc9728) | Protected Resource Metadata (the `WWW-Authenticate` challenge)                                    |

> **Client registration in 2026-07-28.** The spec makes [Client ID Metadata
> Documents](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#client-id-metadata-documents)
> (CIMD) the primary registration mechanism (a **SHOULD**) and [**deprecates**
> Dynamic Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration#dynamic-client-registration)
> (now a **MAY**, "retained for backwards compatibility") under a 12-month
> window. The plugin already matches this posture: **CIMD is default-on** and
> DCR (`/register`) is opt-in — see [Client ID Metadata Documents](#client-id-metadata-documents-cimd)
> below. Discovery (RFC 9728 Protected Resource Metadata) is a **MUST** in
> 2026-07-28 and is served unconditionally when `mcp.enabled`.

For a requirement-by-requirement map of what's implemented and the test that
asserts each one, see [MCP OAuth conformance](./mcp-oauth-conformance.md).

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
     │  1. MCP request (no token)     │                              │
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
     │  4. Obtain client_id (CIMD URL, or DCR /register)             │
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
     │ ─────────────────────────────▶│  → access_token (signed JWT) │
     │                                │     + refresh_token          │
     │                                │                              │
     │  7. MCP request + Authorization: Bearer <access_token>        │
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
4. **Client registration.** In 2026-07-28 the primary path is a **Client ID
   Metadata Document** (CIMD): the client uses an HTTPS URL as its `client_id`,
   which the AS resolves at authorize time — there is no registration call.
   Dynamic Client Registration (RFC 7591, `POST /oauth/mcp/register`) is the
   deprecated backwards-compat path — off by default, opt-in. Either way the
   client ends up with a `client_id`; DCR registrations persist so a cached
   `client_id` survives Harper restarts. See [CIMD](#client-id-metadata-documents-cimd).
5. **Authorization.** The client opens `/oauth/mcp/authorize` with a PKCE
   challenge and the `resource` it wants a token for. The plugin redirects the
   user to the upstream IdP; on return it mints a single-use authorization code
   and redirects back to the client's `redirect_uri`.
6. **Token exchange.** The client posts the code plus its PKCE `code_verifier` to
   `/oauth/mcp/token` and receives a signed access token (RS256 or ES256, per `mcp.signingAlgorithm`)
   and a refresh token, bound to the `resource` as its `aud`.
7. **Authenticated requests.** The client calls your MCP route with
   `Authorization: Bearer <access_token>`. `withMCPAuth` verifies the signature,
   audience, and issuer, attaches the claims as `request.mcp`, and runs your
   handler.

No upstream IdP token is ever embedded in the issued JWT — the access token is
minted and signed by this plugin.

> **Transport note.** The diagram shows the guarded MCP request abstractly.
> 2026-07-28 Streamable HTTP is POST-based — the earlier `GET /mcp` endpoint was
> replaced ([SEP-2575](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575)),
> and POSTs carry `Mcp-Method`/`Mcp-Name` headers. `withMCPAuth` is
> **method-agnostic**: it guards on the `Authorization: Bearer` token regardless
> of HTTP method, so the transport change needs no change here.

---

## Endpoints

All endpoints are served only when `mcp.enabled: true` (otherwise `404`, or the
discovery handlers fall through).

### Discovery (`/.well-known/*`)

| Path                                          | Spec     | Returns                                                                                                               |
| --------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------- |
| `GET /.well-known/oauth-protected-resource`   | RFC 9728 | `resource`, `authorization_servers`, `bearer_methods_supported`                                                       |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | `issuer`, the endpoint URLs, and supported response/grant/PKCE/auth methods                                           |
| `GET /.well-known/jwks.json`                  | —        | The signing public keys (RSA and/or EC, per-key `alg`) for verifying issued tokens (empty until the first token mint) |

All three send `Access-Control-Allow-Origin: *` so browser-based clients and
discovery tools can fetch them cross-origin. When `mcp.resource` carries a path
(e.g. `https://host/mcp`), the Protected Resource Metadata document is **also**
served at the RFC 9728 path-appended location `/.well-known/oauth-protected-resource/mcp`
(the well-known segment sits between the origin and the resource path), which is the
form the `WWW-Authenticate` challenge advertises.

### Authorization server

| Endpoint               | Method | Notes                                                                                                                                                                                                                                   |
| ---------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/oauth/mcp/register`  | POST   | RFC 7591 Dynamic Client Registration — **deprecated in 2026-07-28** (compat path; CIMD is primary). Exists only when `mcp.dynamicClientRegistration` is configured (absent block ⇒ 404); gate with `initialAccessToken`. Returns `201`. |
| `/oauth/mcp/authorize` | GET    | OAuth 2.1 + PKCE. Requires `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `resource`.                                                                                               |
| `/oauth/mcp/token`     | POST   | Grants: `authorization_code`, `refresh_token`, and (opt-in) `client_credentials`. Returns the token pair with `Cache-Control: no-store`.                                                                                                |

> `mcp` is a reserved provider name — the plugin refuses to start if you configure
> a provider called `mcp`, because it would collide with `/oauth/mcp/*`.

### Issued access tokens

A signed JWT — RS256 by default, ES256 when configured (`mcp.signingAlgorithm`).
The `kid` header identifies the signing key; resolve it against the published
JWKS rather than assuming a fixed key id. Claims:

| Claim       | Value                                                                                                                                                                                                                                                                                                                     |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iss`       | `mcp.issuer`                                                                                                                                                                                                                                                                                                              |
| `sub`       | The Harper user the token was issued to (from your `onLogin` mapping). For a login whose claim is not from an authenticated source and matches no existing account, this is the non-resolvable quarantine principal `unverified:<claim>#<random>` — see [Account-Adoption Gate](./configuration.md#account-adoption-gate) |
| `aud`       | `mcp.resource` (RFC 8707 audience binding)                                                                                                                                                                                                                                                                                |
| `client_id` | The DCR-issued client identifier                                                                                                                                                                                                                                                                                          |
| `scope`     | Space-separated scope string (omitted when empty)                                                                                                                                                                                                                                                                         |
| `iat`/`exp` | Issued-at / expiry (`exp` = `iat` + `accessTokenTtl`, default 1 hour)                                                                                                                                                                                                                                                     |
| `jti`       | Unique token id (used in audit events; safe to log)                                                                                                                                                                                                                                                                       |

Refresh tokens rotate on use: a superseded (already-used) refresh token is
refused with `invalid_grant` and revokes the whole family (replay defense). If
the revocation write fails, the token is still refused with `invalid_grant` and
nothing is issued. The response does not claim the revocation; the token
endpoint's handler logs one fixed line naming the failure, without the error
text or the token, and claims no revocation; the refresh-family store's own
write-error log still carries the underlying error. The family stays live until
a later presentation retires or revokes it, or it expires. Refresh families
live for `refreshTokenTtl` (default 30 days).

Refresh families minted by this version carry a provenance marker in the
family id itself; a family from before that (or replicated from an older
node) is rejected with `invalid_grant` and retired the first time it is
presented for refresh, so the client re-authorizes into a fresh, provenanced
family. If the retirement write fails, the request is still rejected with
`invalid_grant`, the failure is logged, and the family stays live until a later
presentation retires or revokes it, or it expires.
This is a lazy, per-family check on the existing refresh path — no
startup sweep. Because the marker lives in the id and rotation reuses the id,
mixed-version rollouts are safe: an old worker or node rotating a family
minted by this version leaves its provenance untouched.

Real cost when upgrading: every MCP client holding a refresh token minted
before this version re-authorizes once, at its next refresh. After a
rollback, only families minted while rolled back re-authorize once after
re-upgrading. Nothing else to run — no manual step, no data migration.

By default any client whose registered `grant_types` include `refresh_token`
receives a refresh token on the code exchange. The AS metadata advertises
`offline_access` in `scopes_supported` (SEP-2207), so clients that want refresh
tokens may request that scope explicitly; setting
`mcp.refreshTokenRequiresOfflineAccess: true` makes that opt-in mandatory —
refresh tokens are then withheld unless the granted scope carries
`offline_access`. The PRM document never lists `offline_access` (refresh tokens
are not a resource requirement).

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

| `event`                     | When                                                                  |
| --------------------------- | --------------------------------------------------------------------- |
| `oauth.mcp.token.issued`    | An access token was minted (authorization-code grant)                 |
| `oauth.mcp.token.refreshed` | A token pair was rotated (refresh-token grant)                        |
| `oauth.mcp.token.rejected`  | A bearer token was rejected by `withMCPAuth`                          |
| `oauth.mcp.token.retired`   | A pre-provenance refresh family was retired instead of rotated (#229) |

Payloads never carry `access_token`, `refresh_token`, or `client_secret`; a
minted token's payload carries only its `jti`, and a `retired` payload (no
token is minted on that path) carries `family_id` instead. Filter your log
aggregator on the `MCP audit:` prefix or the `event` value. Dynamic Client
Registration attempts are logged separately by the `/register` handler.

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
- [ ] **Gate Dynamic Client Registration (if you enable it).** DCR is disabled
      until a `mcp.dynamicClientRegistration` block is present (#182) — the
      endpoint 404s and metadata omits `registration_endpoint`. When you do
      enable it, set `mcp.dynamicClientRegistration.initialAccessToken` to
      require a bearer token, or accept open registration deliberately (a
      once-per-process warning is logged when DCR runs ungated). CIMD-based
      client identity needs no DCR at all.
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

By default, the plugin generates one keypair per node (RS256 by default; `mcp.signingAlgorithm: ES256` for EC P-256) on first mint and
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
   `redirect_uris` are required, grant types must include `authorization_code`,
   and the declared token-endpoint authentication is parsed (see
   [Token endpoint authentication for CIMD clients](#token-endpoint-authentication-for-cimd-clients)).
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

### Token endpoint authentication for CIMD clients

The client presents a method; the server permits exactly one method per client
and rejects any other presentation.

**Which method is permitted.** For an interactive CIMD client, the server takes
the intersection of:

- the methods the document declares: `token_endpoint_auth_methods_supported`
  when present, else `token_endpoint_auth_method`, else `none`;
- the methods this server advertises in `token_endpoint_auth_methods_supported`;
- the methods usable for this client: `none`, and `private_key_jwt` subject to
  the client's keys.
  Selection checks the inline key set or the `jwks_uri` location policy and any signing-algorithm pin. For `jwks_uri`, the fetched keys are validated during token exchange.

The document's singular `token_endpoint_auth_method` wins if it is in the
intersection; otherwise the sole member; otherwise `private_key_jwt` if it is a
member. An empty intersection refuses the client (`unauthorized_client` at
`/authorize`, `invalid_client` at `/token`). A client that prefers
`private_key_jwt`, which this server advertises, but whose keys are unusable is
refused rather than resolved to `none`.

**What is advertised.** `private_key_jwt` appears in the metadata exactly when
a verification path for it is enabled:

- the headless path, `mcp.clientCredentials.enabled`, accepts `EdDSA`;
- the interactive CIMD path accepts `RS256`, `ES256` and `EdDSA`. It is active
  whenever CIMD resolution is on and `private_key_jwt` is advertised: by
  `mcp.clientIdMetadataDocuments.privateKeyJwt.enabled`, or by the headless
  grant, whose advertisement steers interactive clients too.

`token_endpoint_auth_signing_alg_values_supported` is the union of what the
enabled paths accept: `RS256`, `ES256`, `EdDSA` whenever the interactive path is
active, and `EdDSA` alone only if CIMD resolution is off.

**Recorded ChatGPT behaviour.** In one session recorded against a test
authorization server that advertised both `none` and `private_key_jwt`, ChatGPT
authenticated its code exchange and four refreshes with `private_key_jwt`:
`RS256` with a 2048-bit key from its same-origin `jwks_uri`, header `typ` `JWT`,
a 60-second lifetime, and the token endpoint URL as the single `aud`. In a
second session, offered only `none`, it used `none`. This server's issuer-only
audience policy refuses those assertions unless the audience exception below
lists ChatGPT's client ID and has not expired. The recording was not made against this plugin; it
covers one session per case, shows no key rotation, and does not show whether
each refresh presented the refresh token returned by the previous one.

| Configuration                                                              | `private_key_jwt` advertised | `token_endpoint_auth_signing_alg_values_supported` | ChatGPT is permitted | ChatGPT's recorded request shape                                  |
| -------------------------------------------------------------------------- | ---------------------------- | -------------------------------------------------- | -------------------- | ----------------------------------------------------------------- |
| CIMD on, `privateKeyJwt.enabled` absent or `false`, headless off (default) | no                           | omitted                                            | `none`               | the `none` form is accepted                                       |
| CIMD on, `privateKeyJwt.enabled: true`                                     | yes                          | `RS256`, `ES256`, `EdDSA`                          | `private_key_jwt`    | refused (`invalid_client`) unless an unexpired exception lists it |
| CIMD on, headless on, `privateKeyJwt.enabled` any value                    | yes                          | `RS256`, `ES256`, `EdDSA`                          | `private_key_jwt`    | refused (`invalid_client`) unless an unexpired exception lists it |
| CIMD off, headless off, `privateKeyJwt.enabled` absent or `false`          | no                           | omitted                                            | not resolved         | —                                                                 |
| CIMD off with headless on, or with `privateKeyJwt.enabled: true`           | startup error                | —                                                  | —                    | —                                                                 |

Enabling or disabling Dynamic Client Registration does not change these arrays:
stored clients keep authenticating with their registered secrets, so the secret
methods stay listed. The audience exception changes neither the metadata nor the
method a client is permitted.

**Document rules.** The document is rejected with `invalid_client` when:

- `token_endpoint_auth_method` is present but not a string;
- `token_endpoint_auth_methods_supported` is not an array of strings, or omits
  the singular value;
- it declares `client_secret_basic`, `client_secret_post` or `client_secret_jwt`;
- it has both `jwks` and `jwks_uri`, or inline keys with private or symmetric
  key material;
- `jwks_uri` or `token_endpoint_auth_signing_alg` is present but not a string.

Unusable keys (no public signature key, a `jwks_uri` outside the location
policy, or a `token_endpoint_auth_signing_alg` other than `RS256`, `ES256` or
`EdDSA`) make `private_key_jwt` unusable for that client.

**Keys.** From inline `jwks` or from `jwks_uri`, never both.

- `jwks_uri` must be https, without userinfo, fragment or IP-literal host, and on
  the client ID's exact origin. `privateKeyJwt.jwksUriAllowedOrigins` admits
  other exact origins. The policy is re-checked on every use.
- It is fetched like the document: all resolved addresses validated, connection
  pinned, no redirects, `fetchTimeoutMs` and `maxDocumentBytes` limits.
  The response media type, excluding parameters, must be exactly `application/json` or `application/jwk-set+json`.
- Only key material of public signature keys is cached: RSA (2048 to 8192 bits),
  EC P-256 and Ed25519. The cache is per client and URL.
  The lifetime follows `Cache-Control`: `no-store` and `no-cache` give none; an explicit `max-age` is capped at 3600 seconds; an absent caching directive gives 300 seconds.
  An explicit `max-age` counts from the response's HTTP current age (RFC 9111 §4.2.3: from `Age`, and from the response time against `Date`).
  Whatever the directives, a fetched key set is kept at least 60 seconds and used only to verify assertions, so a response's caching directives cannot make every request fetch.
  `Age` must be a single delta-seconds value and `Date` an HTTP-date (RFC 9110 §5.6.7); otherwise each is ignored. `max-age` and the current age are compared exactly.
- Concurrent misses share one fetch; in-flight fetches are capped at 8 per
  worker; attempts are limited to 10 per minute per client and URL.
  An unknown `kid` can trigger a refetch only after the previous unknown-`kid` attempt’s one-minute interval, including when that attempt failed.
  An unknown `kid` seen while a refetch is in flight waits for that refetch.

**Assertion checks** (`private_key_jwt` on `authorization_code` and
`refresh_token`):

- `alg` is `RS256`, `ES256` or `EdDSA`, narrowed to the document's
  `token_endpoint_auth_signing_alg` when present. The key's type, and its JWK
  `alg` when present, must match. `use` must be `sig` when present.
- `typ` may be absent, or may be `JWT` or `client-authentication+jwt`, compared case-insensitively with an optional `application/` prefix.
  `crit`, `jku`, `jwk`, `x5u` and `x5c` headers are rejected.
- `iss` and `sub` equal the client ID. `aud` is the issuer, as a string or a
  one-element array.
- `exp` and `iat` are required, with a lifetime of at most 300 seconds and 5
  seconds of clock skew. `nbf` is honoured.
- `jti` is required.
  A `jti` is accepted at most once per node, including when presented concurrently.
  - Replay records: Expires at the later of assertion `exp` and insertion time, plus 60 seconds.

**Audience exception (opt-in, expiring).** `privateKeyJwt.tokenEndpointAudience`
also accepts the exact advertised token endpoint URL as the sole `aud`:

- only for the listed CIMD client IDs, matched exactly against the fetched and
  validated client ID;
- only while `expiresAt` is in the future, checked on every request;
- only when the keys come from that client ID's own origin;
- only on `authorization_code` and `refresh_token`, never for headless or
  stored clients.

The accepted audience form (`issuer` or `token_endpoint`) is logged; the
assertion never is. This departs from RFC 7523bis §4, which forbids the token
endpoint as an audience.

```yaml
mcp:
  clientIdMetadataDocuments:
    privateKeyJwt:
      enabled: false # default; advertise private_key_jwt for interactive clients
      jwksUriAllowedOrigins: # optional; exact https origins besides the client ID's own
        - https://keys.example.com
      tokenEndpointAudience: # optional, off unless set; requires an expiry
        clientIds:
          - https://chatgpt.com/oauth/client.json
        expiresAt: '2027-01-31T00:00:00Z'
```

`privateKeyJwt.enabled` requires CIMD resolution and an `https:` issuer (loopback
`http:` is allowed for development).

#### ChatGPT on a server with headless agents

Enabling `mcp.clientCredentials` advertises `private_key_jwt` and activates the
interactive verifier, so ChatGPT, which prefers `private_key_jwt`, must present a
verified assertion on every code exchange and refresh once its host is admitted. Setting
`privateKeyJwt.enabled: false` does not change that, and ChatGPT's recorded
assertions use the token endpoint as `aud`, which the issuer-only policy
refuses. To keep ChatGPT working on such a server, before the cutover:

1. Configure the exact-ID exception with an expiry you choose, as a date-time
   with an explicit timezone:

   ```yaml
   mcp:
     clientIdMetadataDocuments:
       privateKeyJwt:
         tokenEndpointAudience:
           clientIds:
             - https://chatgpt.com/oauth/client.json
           expiresAt: '${CHATGPT_AUDIENCE_EXCEPTION_EXPIRES_AT}' # for example 2027-01-31T00:00:00Z
   ```

   An unset variable leaves the placeholder unparseable, and startup fails.

2. Add `chatgpt.com` to `clientIdMetadataDocuments.allowedHosts`, which headless
   agents require, and to `dynamicClientRegistration.allowedRedirectUriHosts` if
   that is set, keeping the existing entries.
3. Reauthorize ChatGPT links whose grants are bound to `none`; the exception
   cannot change a grant's binding.

Once `expiresAt` passes, ChatGPT's token-endpoint-audience assertions are
refused (`invalid_client`) until the exception is renewed.

### Presented client authentication at the token endpoint

These rules apply to every client on `authorization_code` and `refresh_token`:

- `client_assertion` and `client_assertion_type` together present
  `private_key_jwt`. A `Basic` header with a non-empty secret presents
  `client_secret_basic`, and a body `client_secret` presents
  `client_secret_post`. Nothing, or an empty-secret `Basic` header carrying only
  the `client_id`, presents `none`.
- These are rejected with `invalid_request` (400) before any client lookup: a
  parameter repeated in a form body, a `client_id` or credential parameter that
  is empty or not a single string, half an assertion pair, and more than one
  mechanism (a `Basic` header with a secret alongside a body `client_secret`, or
  an assertion alongside a secret or any `Basic` header).
- These are rejected with `invalid_client` (401) before any client lookup: an
  unknown `client_assertion_type`, malformed `Basic` credentials, and an
  assertion longer than 8192 characters.
- A `401` answering a request that carried an `Authorization: Basic` header
  includes `WWW-Authenticate: Basic`.
- A presentation that differs from the permitted method is `invalid_client`. A
  client permitted `none` that sends assertion parameters is rejected rather
  than having them ignored.
- With an assertion, `client_id` may be omitted; the client is identified by the
  assertion's `sub` and verified in full.
- A storage failure while reading the client, the authorization code or the
  refresh family returns `server_error` (500); a record that does not exist
  returns `invalid_client` or `invalid_grant`.

### Grant binding

The permitted method is captured at `/authorize`, carried through the flow
state into the authorization code, and copied into the refresh family. The
exchange and every refresh must use exactly that method; the check runs before
the code is consumed or the family rotated.
A request that authenticates under current policy but conflicts with a bound code or family returns `invalid_grant`; a currently unpermitted presentation returns `invalid_client` before grant lookup.
The client then reauthorizes. A later document or configuration change therefore
never weakens a live grant.

Migration and rollback:

- A flow state or authorization code created before this version has no
  binding: the callback or the exchange rejects it, and the client restarts
  authorization.
- New refresh families have `p2-` ids and carry the binding. A `p2-` family
  without it (for example, rewritten by an older node) is rejected.
- `p1-` families from earlier versions are bound to the method used then:
  `none` for CIMD clients, the registered method for stored clients. A CIMD link
  that must now use `private_key_jwt` reauthorizes.
- Drain older nodes before issuing bound grants, and never route bound grants to
  them: 2.7.x retires `p2-` families (fail closed), but versions before 2.7 do
  not check them.
- This version binds every new authorization code and refresh family, whether or
  not `private_key_jwt` is advertised, so the drain applies before it serves any
  grant. Versions before
  this one neither write nor read a code's binding, so they do not check it when
  redeeming a code, and a family rotated by a version before 2.7 loses its
  binding, after which this version refuses it.

**Refresh bursts.** In the recorded session ChatGPT refreshed four times within
6.6 seconds of the code exchange, each time with a new assertion. A grant bound
to `private_key_jwt` needs a new assertion on every refresh, and every refresh
must present the refresh token returned by the previous one; there is no minimum
interval between refreshes and no grace period for a superseded token. The same
assertion presented again is `invalid_client` and rotates nothing; a superseded
refresh token is `invalid_grant` and revokes the family, and if the revocation
cannot be written it is still `invalid_grant`, without claiming the revocation,
with nothing issued and the family left live until a later presentation retires
or revokes it, or it expires.

**Concurrency.** The replay record is an atomic counter: of concurrent
presentations of one assertion, at most one is accepted on a node, and possibly
none. Across nodes, each node can accept one presentation within the
replication delay. Concurrent refreshes of one token are not serialized: depending on timing, more
than one can rotate it, after which only the last-written token works and
presenting any other revokes the family; or the later requests see a superseded
token and revoke the family at once, and the client reauthorizes. A rotation
writes only the token hash, so it does not undo a revocation committed by a
concurrent request. A revocation whose write fails still answers
`invalid_grant`, without claiming the revocation, and leaves the family live.

### Stored/DCR registration and method selection remain; the stricter token-request parser and grant binding also apply to stored clients.

CIMD resolution only applies to URL-shaped client IDs. Any `client_id` that does
not parse as an HTTPS URL with a non-root path goes directly to the DCR store as
before. CIMD clients and DCR clients can coexist; existing DCR registrations are
not affected.

## Headless agents (client_credentials)

Autonomous agents — no browser, no human at request time — authenticate **as
themselves** with the RFC 7523 `client_credentials` grant (`private_key_jwt`,
EdDSA/Ed25519). The grant is **explicit opt-in** and gated on a pinned CIMD
allowlist:

```yaml
mcp:
  enabled: true
  issuer: https://as.example.com
  clientIdMetadataDocuments:
    allowedHosts:
      - agents.example.com # REQUIRED for client_credentials — startup error without it
  clientCredentials:
    enabled: true
    accessTokenTtl: 300 # default; agents re-mint on 401
    rateLimit: 30 # default; issuance requests/min per client_id, false disables
```

Agents don't register. Each agent's `client_id` is an HTTPS URL to a CIMD
document carrying its public Ed25519 key set:

```json
{
	"client_id": "https://agents.example.com/fleet/agent-1.json",
	"client_name": "Fleet Agent 1",
	"grant_types": ["client_credentials"],
	"token_endpoint_auth_method": "private_key_jwt",
	"jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "agent-key-1" }] }
}
```

Document rules (all rejections are `invalid_client`):

- `grant_types` must be exactly `["client_credentials"]` — no mixing with
  redirect-based grants or `refresh_token`.
- `token_endpoint_auth_method` must be `private_key_jwt`.
- `jwks` is required inline: 1–8 **public** OKP/Ed25519 keys. Any key carrying
  private material (`d`) rejects the whole document. `jwks_uri` is rejected —
  the document itself is the hosted-key story, and a second SSRF-fetch surface
  isn't worth an indirection.
- `redirect_uris` / `response_types` must be **absent**. This deviates from the
  CIMD draft's required-fields list deliberately: RFC 7591 §2 requires
  `redirect_uris` only for redirect-based grant types, and a
  `client_credentials`-only client has no redirect surface by construction.
  (The MCP [OAuth Client Credentials extension](https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials)
  doesn't profile the document shape; if it later does, revisit.)
- The document's host must be in `clientIdMetadataDocuments.allowedHosts`. The
  grant refuses to start without a non-empty allowlist (startup error) and
  refuses credentials documents at resolution without it — hosting a reachable
  document must never suffice to mint tokens.

The token request (RFC 7523 §2.2 client authentication):

```
POST /oauth/mcp/token
grant_type=client_credentials
client_id=https://agents.example.com/fleet/agent-1.json
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<EdDSA-signed JWT>
resource=https://app.example.com/mcp   (optional; must exactly match when present)
```

Assertion requirements: `alg: EdDSA`; `iss` = `sub` = the `client_id`; `aud` =
the issuer, or the token endpoint URL exactly unless
`mcp.clientCredentials.acceptTokenEndpointAudience` is `false` (move signers to
the issuer, which RFC 7523bis requires); `typ` absent, `JWT` or
`client-authentication+jwt`; no `jku`, `jwk`, `x5u` or `x5c` header; `exp`
within 60 s of now; `jti` required, recorded in the shared
`mcp_assertion_jtis` table.
A `jti` is accepted at most once per node, including when presented concurrently.
A `Basic` header or `client_secret` alongside the assertion is rejected — proof
of key possession is the only accepted authentication for this grant.

> **Replay-guard bound:** each presentation atomically adds 1 to the replay
> record's `uses`, and only the presentation that reads back 1 is accepted, so
> single use holds per node under concurrency. Across nodes, each node can
> accept one presentation within the replication delay. The residual is
> deliberately narrow: assertions live ≤ 60 s, the grant requires
> an `https:` issuer, and capturing a live assertion in transit therefore
> implies a vantage point (TLS interception, host access) from which the
> minted bearer token itself is equally exposed.

The issued token is the same signed Bearer JWT as the interactive flow, with two
differences: **`sub` is the client identity** (`sub` = `client_id`, RFC 9068
§2.2 — there is no end user in this grant) and **no refresh token is ever
issued** — the default TTL is 5 minutes and agents simply re-mint on 401.
`onMCPTokenIssued` fires with `type: 'client_credentials'`. The token's scope
is the document-declared `scope`; a `scope` parameter on the token request is
not honored (a client can never escalate past its registered scope, and
RFC 6749 §3.3 downscoping-on-request is future work).

Issuance is **rate-limited per `client_id`** (`mcp.clientCredentials.rateLimit`,
default 30 requests/min, `false` disables): over-limit requests receive `429`
with `error: "slow_down"` and a `Retry-After` header (seconds until a retry can
succeed). The limit is debited **after** the client assertion is verified, so it
counts only authenticated issuance — a caller cannot drain a real agent's quota
by replaying the agent's public `client_id` URL with a bogus assertion (those
fail verification with `401` and never touch the bucket). Pre-auth work is
bounded separately: CIMD metadata fetches are limited at a fixed 10 attempts/min
per `client_id` URL (cache hits don't consume, so only failing documents
repeat), and resolution/DNS concurrency is capped globally.
Both limits are per-node token buckets (a replicated counter would be a
hot-write anti-pattern; the assertion replay guard and ≤60s window bound
cross-node abuse). The bucket state is per worker thread: if the plugin runs
across N HTTP worker threads on a node, the effective ceiling is N × the
configured limit per `client_id` (as with the CIMD fetch cache and concurrency
caps, which are likewise per-thread). This is intentional for a defense-in-depth
control — treat the configured value as a per-thread floor, not a hard node-wide
cap.

Key rotation / revocation semantics: the fleet rotates a key by updating the
agent's metadata document. The change takes effect within the CIMD cache TTL
(up to 24 h, typically 1 h — bound it with `Cache-Control: max-age` on the
document), further bounded by the ≤60 s assertion window and the short access
token TTL. Removing the document (or the host from `allowedHosts`) revokes the
agent on the same schedule; a dropped allowlist takes effect immediately, even
for cached documents.

---

## Not yet supported (v1.1+)

These are **not** available and no config or code sample here implies them:

- Per-tool / fine-grained scopes (the `scope` claim is passed through, not enforced per tool)
- The 2026-07-28 **step-up authorization flow** (SEP-2350): a `403 insufficient_scope`
  with a `scope` hint in `WWW-Authenticate`, and the `scope` challenge parameter on
  the initial 401. `withMCPAuth` denies with `invalid_token`, not `insufficient_scope`;
  per-operation scope challenges are v1.1 forward-work (tracked in [#156](https://github.com/HarperFast/oauth/issues/156)).
- Transitive revocation (revoking the upstream IdP session does not invalidate already-issued MCP tokens)
- Signing algorithms other than RS256 and ES256 (e.g. EdDSA)
- A native, composed MCP server (this plugin is the authorization server, not the MCP transport)
