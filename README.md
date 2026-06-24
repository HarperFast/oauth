# Harper OAuth Plugin

OAuth 2.0 and OpenID Connect authentication for Harper applications. Supports GitHub, Google, Azure AD, Auth0, and custom OIDC providers with automatic token refresh and lifecycle hooks for user provisioning.

## Features

- **Multi-provider support** - GitHub, Google, Azure AD, Auth0, and custom OIDC providers
- **Automatic token refresh** - Proactive token renewal on every request
- **Lifecycle hooks** - Extensible hooks for user provisioning and custom logic
- **CSRF protection** - Distributed token storage for cluster support
- **ID token verification** - Full OIDC support with signature validation
- **Zero configuration** - Works with Harper's session system automatically

## Installation

**Requires Harper v5** (`harper >=5.0.0`). For Harper v4 (the legacy `harperdb` package), use the [`1.x`](https://github.com/HarperFast/oauth/tree/v1.x) line.

```bash
npm install @harperfast/oauth
```

## Quick Start

### 1. Configure OAuth Plugin

Add to your `config.yaml`:

```yaml
'@harperfast/oauth':
  package: '@harperfast/oauth'
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

### 2. Set Environment Variables

```bash
export OAUTH_GITHUB_CLIENT_ID="your-client-id"
export OAUTH_GITHUB_CLIENT_SECRET="your-client-secret"
```

> **Note:** The `export` commands above are for local development and quick testing only. You can also use a `.env` file with `dotenv-cli` for local dev — just don't commit it. For **Harper Fabric** deployments, see the [Harper Fabric documentation](https://docs.harperdb.io/docs/fabric/managing-applications) for managing runtime environment variables.

### 3. Configure OAuth Callback

Set your OAuth callback URL in your provider settings:

```
https://your-domain/oauth/github/callback
```

### 4. (Optional) Register Lifecycle Hooks

Create or update users when they log in:

```typescript
// resources.ts
import { registerHooks } from '@harperfast/oauth';

registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		const { User } = tables;

		// Find or create user
		let user;
		for await (const existing of User.search({ email: oauthUser.email })) {
			user = existing;
			break;
		}

		if (!user) {
			user = await User.create({
				email: oauthUser.email,
				name: oauthUser.name,
				provider: provider,
			});
		}

		return { user: String(user.id) };
	},
});

// Export your resources...
```

### 5. Test Authentication

Navigate to:

```
http://localhost:9926/oauth/github/login
```

## Usage

Access authenticated user in your resources:

```typescript
export class MyResource extends tables.Resource {
	async get(target, request) {
		if (!request.session?.user) {
			throw new ClientError('Not authenticated', 401);
		}

		return {
			userId: request.session.user,
			email: request.session.oauthUser.email,
		};
	}
}
```

## Supported Providers

Built-in provider templates (not active until configured):

- **GitHub** - OAuth 2.0
- **Google** - OpenID Connect
- **Azure AD** - OpenID Connect
- **Auth0** - OpenID Connect
- **Okta** - OpenID Connect (with multi-tenant support)
- **Custom OIDC** - Any compliant provider

> **Note:** Built-in providers are templates that require configuration. None are active until you provide OAuth credentials (`clientId`, `clientSecret`, etc.). Having provider code in the plugin does not enable authentication or create security exposure.

## How It Works

The plugin automatically handles:

1. **OAuth Flow** - Redirects to provider, handles callback, exchanges code for tokens
2. **Token Management** - Validates and refreshes tokens on every HTTP request
3. **Session Integration** - Stores OAuth data in Harper sessions
4. **CSRF Protection** - Validates state parameter using distributed token storage
5. **Auto-logout** - Clears session when tokens expire and can't be refreshed

## Documentation

Complete documentation is available in the [docs](./docs) directory:

- **[Getting Started](./docs/getting-started.md)** - Installation and quick start guide
- **[Configuration](./docs/configuration.md)** - Complete configuration reference
- **[OAuth Providers](./docs/providers.md)** - Provider setup guides
- **[Lifecycle Hooks](./docs/lifecycle-hooks.md)** - User provisioning and custom logic
- **[Multi-Tenant SSO](./docs/multi-tenant-sso.md)** - Per-organization OAuth providers for B2B SaaS
- **[Token Refresh and Sessions](./docs/token-refresh-and-sessions.md)** - How OAuth tokens and Harper sessions interact
- **[API Reference](./docs/api-reference.md)** - Endpoints and programmatic API

## Development

### Build

```bash
npm install
npm run build
```

### Test

```bash
npm test
npm run test:coverage
```

### Lint & Format

```bash
npm run lint
npm run format:check
npm run format:write
```

## Database Schema

The plugin creates a `csrf_tokens` table for CSRF protection:

```graphql
type CSRFToken @table {
	token: string @key
	sessionId: string
	provider: string
	originalUrl: string
	createdAt: number
	expiresAt: number @index
}
```

Tokens automatically expire after 10 minutes.

When MCP OAuth is enabled (see [issue #86](https://github.com/HarperFast/oauth/issues/86)), the plugin also creates a `harper_oauth_mcp_clients` table for RFC 7591 Dynamic Client Registration. Registrations persist indefinitely so `client_id`s cached by MCP clients (Claude Desktop, Cursor, `mcp-remote`) survive Harper restarts.

## MCP OAuth (experimental)

The plugin can also act as an OAuth authorization server for **Model Context Protocol** clients (Claude Desktop, Cursor, `mcp-remote`), letting them authenticate against the same upstream providers. Enable it with `mcp.enabled: true` (see [`docs/configuration.md`](./docs/configuration.md)).

**Status: experimental, opt-in.** Available now: RFC 7591 Dynamic Client Registration, discovery metadata (`/.well-known/*`), the authorization endpoint, audience-bound JWT token issuance, and token _verification_ for app-owned MCP routes (`withMCPAuth`, below). The remaining pieces land in 2.0.x — see [issue #86](https://github.com/HarperFast/oauth/issues/86).

### Protecting an MCP route — `withMCPAuth`

The plugin doesn't own the MCP endpoint — your app does. `withMCPAuth` wraps your handler so it enforces the spec contract once, centrally: it validates the `Authorization: Bearer` access token (signature against the published JWKS, `exp`/`nbf`, and audience binding to `mcp.resource` per RFC 8707), and on any failure returns `401` with `WWW-Authenticate: Bearer resource_metadata="…"` (RFC 9728) pointing MCP clients at discovery. On success it attaches the verified claims as `request.mcp = { sub, client_id, aud, scope }` and invokes your handler unchanged.

```ts
import { server } from 'harper';
import { withMCPAuth } from '@harperfast/oauth';

const mcpHandler = (request) => {
	// request.mcp is guaranteed present here: { sub, client_id, aud, scope }
	return { status: 200, body: JSON.stringify({ user: request.mcp.sub }) };
};

// Recommended: register on a urlPath subroute.
server.http(withMCPAuth(mcpHandler), { urlPath: '/mcp' });
```

**Registration matters — Harper's core auth will otherwise reject the token.** Core auth consumes `Authorization: Bearer` and rejects any non-Harper token with `WWW-Authenticate: Basic`, which breaks the MCP discovery loop. Register `withMCPAuth` so it owns the response for its route:

- **urlPath subroute (recommended):** `server.http(withMCPAuth(handler), { urlPath: '/mcp' })`. Harper routes the request to this chain alone, so core auth never runs for it — the same isolation the `/.well-known/*` endpoints use. No extra options needed.
- **Default-group fallback:** `server.http(withMCPAuth(handler, { path: '/mcp' }), { before: 'authentication' })`. When the route shares the default middleware chain with auth, pass `path` (so the guard scopes to your route and lets other paths fall through) and register `before: 'authentication'` so it runs ahead of core auth.

`withMCPAuth(handler, options?)` options: `path` (default-group scoping, above), `onAuthError(request, reason)` (custom denial response — a falsy return still fails closed to the default `401`), plus `getConfig` / `logger` / `keyStore` overrides (default to the plugin's live MCP config, logger, and key store). The guard fails closed: while MCP is disabled or no signing key has been published, every request is rejected. Query-string tokens are ignored (header-only, RFC 6750). See [`docs/configuration.md`](./docs/configuration.md).

## Security Considerations

- **HTTPS required** - OAuth requires HTTPS in production
- **CSRF protection** - Automatic via state parameter validation
- **ID token verification** - OIDC providers verify token signatures
- **Secure sessions** - Use Harper's secure session configuration
- **Token storage** - Tokens stored in session (configure secure cookies)
- **MCP client registration (when `mcp.enabled` is true)** - The `/oauth/mcp/register` endpoint defaults to **open registration** per RFC 7591. Set `mcp.dynamicClientRegistration.initialAccessToken` to require a bearer token on registration, or `mcp.dynamicClientRegistration.allowedRedirectUriHosts` to restrict which hosts may register `redirect_uri`s. See [`docs/configuration.md`](./docs/configuration.md).

## Debug Mode

Enable debug endpoints for testing:

```yaml
'@harperfast/oauth':
  debug: true
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

Debug endpoints:

- `GET /oauth/` - List configured providers
- `GET /oauth/test` - Interactive test page
- `GET /oauth/{provider}/user` - View current session
- `GET /oauth/{provider}/refresh` - Trigger token refresh

**Warning:** Never enable debug mode in production.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright 2025 HarperDB, Inc.
