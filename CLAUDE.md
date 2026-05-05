# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

OAuth 2.0 plugin for Harper. Authentication with any OAuth provider (GitHub, Google, Azure, Auth0, Okta, custom). Automatic token refresh, session management, lifecycle hooks for user provisioning, CSRF protection. Supports multi-tenant SSO with dynamic per-tenant provider resolution.

## Development Commands

```bash
npm install             # Install dependencies
npm run build           # Compile TypeScript (tolerates TS errors via `tsc || true`)
npm run dev             # tsc --watch
npm test                # Build, then run Node.js tests
bun test                # Run Bun tests (requires Bun)
npm run test:coverage   # Node 22+ coverage run
npm run lint            # ESLint (not a type check — see Gotchas)
npm run format:check    # Prettier check
npm run format:write    # Prettier fix
```

## Architecture

1. **Plugin entry** (`src/index.ts`) — `handleApplication()` with HTTP middleware for auto token refresh
2. **OAuth resource** (`src/lib/resource.ts`) — REST endpoints using Resource API v2
3. **Session validator** (`src/lib/sessionValidator.ts`) — token refresh on every request
4. **Hook system** (`src/lib/hookManager.ts`) — lifecycle hooks (`onLogin`, `onLogout`, `onTokenRefresh`)
5. **Provider registry** (`src/lib/config.ts`) — initializes and manages OAuth providers
6. **Multi-tenant SSO** (`src/lib/multiTenantResource.ts`, `src/lib/tenantManager.ts`) — dynamic per-tenant provider resolution

### Token refresh

Middleware runs on every HTTP request. Refreshes at 80% of token lifetime. Transparent to application code.

### Providers

Base class in `src/lib/providers/base.ts`. Built-in: GitHub, Google, Azure, Auth0, Okta. Custom providers implement `authorize()` and `getUserInfo()`.

### Errors

Custom classes in `src/errors.ts` (`ConfigurationError`, `OAuthProviderError`, `TokenExchangeError`, ...). All include `statusCode`. Provider-specific errors include `provider`.

## Session Structure

```typescript
request.session = {
  user: 'username',             // Harper username
  oauthUser: {                  // OAuth profile
    username, email, name, role,
  },
  oauth: {                      // Token metadata
    provider: string,           // Config key — backwards-compatible name
    providerConfigId: string,   // Config key — clearer naming, same value as provider
    providerType: string,       // e.g., 'github', 'okta'
    accessToken: string,
    refreshToken?: string,
    expiresAt: number,
    refreshThreshold: number,
    scope: string,
    tokenType: string,
    lastRefreshed: number,
  },
  // Additional custom data from onLogin hook
  [key: string]: any,
}
```

## Code Conventions

- TypeScript strict mode
- ES modules — `.js` extensions in imports
- Named exports, no default exports
- Custom error classes from `src/errors.ts`
- Logging: `logger?.info?.()` pattern (optional logger)
- **Never log tokens; never expose tokens in responses**
- CSRF protection: all flows use state tokens (10-minute expiry)
- Harper types: `import type { Scope, User, RequestTarget } from 'harper'`

## Non-Obvious Gotchas

**Resource API v2:**

- Classes declare `static loadAsInstance = false`
- Methods are instance methods; Harper instantiates the class
- Test mocks must instantiate accordingly

**`GenericTrackedObject` + spread:**

- `{ ...obj }` does NOT work on Harper tracked objects — copies nothing
- Use explicit property access: `{ provider: oauth.provider, ... }`
- Affects `request.session.oauth` and any session fields

**Build tolerates TS errors:**

- `npm run build` runs `tsc || true` — passes even with type errors
- "Build passes" ≠ "types are sound"; rely on editor diagnostics and CI separately

**Lint is ESLint only:**

- `npm run lint` runs ESLint against source. It does NOT type-check.
- No explicit `typecheck` script exists; `npm run build` is the closest proxy but suppresses errors (see above)

**Security invariants (enforce in any new endpoint):**

- Context validation in `get()` / `post()` methods
- Path length ≤ 2048 chars
- Debug endpoints: IP-based access control (localhost by default; `DEBUG_ALLOWED_IPS` env var to allow others)
- Cross-provider CSRF: redirect with error, not 403 page

## Testing

**Unit tests** (`test/`): Node.js built-in test runner (`node:test`) and Bun. Tests import from compiled `dist/`. Use `node:assert/strict`. Both runners mock the `harper` module to keep unit tests off the real RocksDB:

- Bun: `.bun/preload.js` (`mock.module`).
- Node: `test/helpers/harper-mock.mjs` registered via `--import` in the npm test scripts. Importing real `harper` opens the system RocksDB at module-load time, and RocksDB doesn't allow multi-process read-write access — so `node --test`'s per-file subprocesses contend for the LOCK and surface flaky errors. Drop this mock once harper exposes a read-only RocksDB mode (in flight); RocksDB does support multi-process read-only access.

**Integration tests** (`integrationTests/`): Boot a real Harper child process with the plugin installed, via `@harperfast/integration-testing` (`harper-integration-test-run`). Tests are `.test.ts` (Node 22+ type stripping). Run order:

```bash
npm run install:fixtures   # npm pack + install the plugin into each fixture
npm run test:integration
```

The fixture install uses `npm pack` (not a `file:` symlink) because Harper's default VM sandbox rejects symlinked plugins with "Can not load module outside of allowed path". Adding a new fixture: drop a directory under `integrationTests/fixtures/` with a `config.yaml` and a `package.json` (no deps — install-fixtures injects the OAuth tarball).

## Dependencies

- **Runtime:** `jsonwebtoken`, `jwks-rsa` (required by Okta / JWT-based providers)
- **Peer:** `harper` (`>=5.0.0`)
- **Dev:** `typescript`, `eslint`, `prettier`, `@types/node`, `@types/jsonwebtoken`, `@harperdb/code-guidelines`, `harper` (for types + test)
- **Invariant:** justify any new runtime dependency in the PR; prefer built-ins (`fetch`, `crypto`)
