# AGENTS.md

Guidance for an AI agent working in this repository: OAuth 2.0 plugin for Harper (GitHub, Google, Azure, Auth0, Okta, custom providers), plus an MCP authorization server. Automatic token refresh, session management, lifecycle hooks, CSRF protection, multi-tenant SSO.

## Commands

```bash
npm install             # Install dependencies
npm run build           # Compile TypeScript (tolerates TS errors via `tsc || true` — build passing ≠ types sound)
npm run dev             # tsc --watch
npm test                # Build, then run Node.js tests (mocks the `harper` module — see Gotchas)
bun test                # Run Bun tests (requires Bun; separate mock via `.bun/preload.js`)
npm run test:coverage   # Node 22+ coverage run
npm run install:fixtures && npm run test:integration   # Integration tests: real Harper child process per fixture (packs+installs the plugin; a `file:` symlink is rejected by Harper's VM sandbox)
npm run lint            # ESLint only — does not type-check; no separate typecheck script
npm run format:check    # Prettier check
```

## Architecture

1. **Plugin entry** (`src/index.ts`) — `handleApplication()`; HTTP middleware for auto token refresh; watches `scope.options` for live config reload
2. **OAuth resource** (`src/lib/resource.ts`) — REST endpoints, Resource API v2 (`static loadAsInstance = false`)
3. **Session validator** (`src/lib/sessionValidator.ts`) — refreshes tokens on every request, at 80% of token lifetime
4. **Hook system** (`src/lib/hookManager.ts`) — `onLogin`, `onLogout`, `onTokenRefresh`, `onMCPTokenIssued`
5. **Provider registry** (`src/lib/config.ts`) — builds and validates provider config; presets in `src/lib/providers/`
6. **Multi-tenant SSO** (`src/lib/multiTenantResource.ts`, `src/lib/tenantManager.ts`) — per-tenant provider resolution

`request.session` is `user` (Harper username), `oauthUser` (OAuth profile), `oauth` (token metadata for refresh — `providerConfigId`, `accessToken`, `refreshToken`, `expiresAt`, `authTrust`, …), plus any custom fields an `onLogin` hook adds. See `Session`/`OAuthSessionMetadata` in `src/types.ts` for the current full shape rather than duplicating it here — it grows fields (`authTrust`, `lastValidated` are recent additions).

### MCP authorization server (`src/lib/mcp/`)

A separate OAuth 2.1 AS surface for MCP clients (Claude Desktop, ChatGPT, headless agents), gated behind `mcp.enabled`. Start from `docs/mcp-oauth.md` and `docs/mcp-oauth-conformance.md`; in code:

- `cimd.ts` — Client ID Metadata Document resolution (SSRF-guarded fetch); `dcr.ts` — RFC 7591 Dynamic Client Registration
- `clientAuthMethod.ts` / `clientAssertion.ts` — one permitted client-auth method per client; verifies `private_key_jwt` assertions (RFC 7523)
- `token.ts` / `tokenIssuer.ts` — grant handling and access-token minting; client-auth method is bound to the grant at authorize, exchange, and every refresh
- `refreshTokenStore.ts` — refresh-token families; `p1-` = legacy (pre client-auth binding), `p2-` = bound; a mixed-version rollout retires the wrong generation on either side, by design
- `assertionJtiStore.ts` — RFC 7523 §3 replay guard on client-assertion `jti`
- `jwksFetcher.ts` / `keyStore.ts` / `clientKeySet.ts` — pinned, bounded `jwks_uri` fetching and key caching
- `withMCPAuth.ts` — bearer-token guard for app routes; register it, or core auth consumes the token first

## Non-obvious Harper gotchas

- **A table read/write with no explicit context joins the ambient transaction.** Inside a REST request, `table.get(id)` / `table.patch(...)` default to the request's own transaction and snapshot. A read meant to observe a write that _just committed_ (e.g. confirming a replay guard's counter) needs a fresh context — pass `{}` to open a new transaction. See `assertionJtiStore.ts`'s module comment and `checkAndRecord()` for the canonical example.
- **`{ ...obj }` copies nothing on a Harper tracked object** (e.g. `request.session`, `request.session.oauth`). Use explicit property access to build a plain object from one.
- **`table.patch(id, { field: { __op__: 'add', value: 1 } }, opts)` composes at commit**, not at call time — Harper applies the delta on top of whatever the row holds when the patch lands, retrying on a conflicting write. This is how `assertionJtiStore` does an atomic counter without a read-modify-write race.
- **`lock()` is not usable** under this plugin's `harper: ">=5.0.0"` peer range — it throws `Not yet implemented` at v5.0.0. Don't reach for it; see #212's rejected alternatives for why a cross-node primitive is needed instead.
- **Harper's form-urlencoded body deserializer only gained correct repeated-field arrays in `HarperFast/harper#2953`.** Before that, a repeated key keeps only its first value under `body.key` — later values aren't visible there at all. Code that must refuse (not silently drop) a repeated single-valued parameter checks `Array.isArray(body[name])`, which only works against the fixed deserializer; see `repeatedParameter()` in `src/lib/mcp/token.ts` and the note in `docs/mcp-oauth.md`.
- **Config reloads arrive as per-key `change` events**, fired synchronously by `OptionsWatcher`'s merge before a multi-key edit finishes landing. `runUpdate()` in `src/index.ts` yields one macrotask (`setImmediate`) before reading `getAll()`, so a multi-key reload is read as one settled snapshot rather than mid-application; it also loops while a new update arrived during the previous one, so the last snapshot always wins.

## Config conventions

- `isUnresolvedEnvPlaceholder()` and the security-setting fail-closed rule (`src/lib/config.ts`): an unresolved `${VAR}`, an empty value, or (for list/mapping fields) a non-mapping block on a security-relevant setting throws at startup naming the key, instead of silently changing a gate.
- `normalizeBooleanField(obj, key, path, logger, failOnPlaceholder, requireBoolean)` coerces a declared boolean field. An unresolved placeholder or empty string **throws** when `failOnPlaceholder` is true, or warns and deletes the field (falling back to its own documented default) when false. The four MCP sub-feature booleans pass `mcpConfig.enabled === true` as `failOnPlaceholder` — inert while MCP is off, fail-closed once it's on; `mcp.enabled` itself always passes `false` (kept on the pre-#207 warn-and-drop path).
- An unconfigured or half-configured provider is detected (and skipped) **before** `buildProviderConfig()` runs — that function throws on a missing `redirectUri`, so checking configured-ness first keeps one unset provider from blocking every other provider's config from building (#259).

## Testing

Unit tests (`test/`) import from compiled `dist/`, not `src/` — run `npm run build` first (or let `npm test` do it). Both Node and Bun runners mock the `harper` module (`test/helpers/harper-mock.mjs`, `.bun/preload.js`): importing the real module opens the system RocksDB at load time, and RocksDB doesn't allow multi-process read-write access, so `node --test`'s per-file subprocesses would otherwise contend for the same lock. Integration tests (`integrationTests/`) skip the mock and boot a real Harper child process per fixture instead.

## Error handling

No central `errors.ts` — error classes are defined locally near where they're thrown (e.g. `CimdClientError` in `cimd.ts`) with a `statusCode` field callers map to an HTTP/OAuth error response. Never log tokens or expose them in responses.

## Code conventions

- TypeScript strict mode, ES modules (`.ts` extensions in relative imports), named exports only
- `logger?.info?.()` pattern — the logger is optional everywhere
- CSRF: all flows use state tokens, 10-minute expiry (`CSRFTokenManager`)
- Security invariants for any new endpoint: context validation in `get()`/`post()`, path length ≤ 2048 chars, cross-provider CSRF redirects with an error (never a bare 403), debug-only routes gated by IP (`isDebugOnlyRoute` in `src/lib/resource.ts`; `DEBUG_ALLOWED_IPS`, default `127.0.0.1,::1`)

## Where design decisions live

Non-trivial issues carry their design and status in the issue body itself, kept current as work lands — read the issue before re-deciding something it already settled (current examples: #231, #244, #212, #213, #264). `docs/mcp-oauth-conformance.md` maps every MCP requirement to its implementing code and test and must be updated in the same PR as any behavior change. See **[docs/maintaining.md](docs/maintaining.md)** for the release process, CI/review automation, and the Harper peer-dependency relationship.

## Dependencies

- **Runtime:** `jsonwebtoken`, `jwks-rsa`
- **Peer:** `harper` (`>=5.0.0`)
- **Dev:** `typescript`, `eslint`, `prettier`, `@types/node`, `@types/jsonwebtoken`, `@harperdb/code-guidelines`, `@harperfast/integration-testing`, `harper` (types + test)
- Justify any new runtime dependency in the PR; prefer built-ins (`fetch`, `crypto`)
