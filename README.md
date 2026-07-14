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

The hook can also gate the login: return `{ status: 'denied' }` or `{ status: 'needs_confirmation', redirect }` and no session is created — see [Lifecycle Hooks](docs/lifecycle-hooks.md#onlogin).

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
- **[MCP OAuth](./docs/mcp-oauth.md)** - Authorization server for Model Context Protocol clients (experimental)
- **[API Reference](./docs/api-reference.md)** - Endpoints and programmatic API
- **[Changelog](./CHANGELOG.md)** - Release history

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

The plugin manages its own tables in the `oauth` database — see [`schema/oauth.graphql`](./schema/oauth.graphql) for the definitions:

- `csrf_tokens` — CSRF protection for the human OAuth flow (10-minute expiration)
- `harper_oauth_mcp_clients` — RFC 7591 Dynamic Client Registration; no expiration, so `client_id`s cached by MCP clients (Claude Desktop, Cursor, `mcp-remote`) survive Harper restarts
- `harper_oauth_mcp_keys` — MCP JWT signing keys, stored in the database so replicated nodes share one rotation-aware key set
- `mcp_auth_codes` — single-use PKCE authorization codes (5-minute expiration)
- `mcp_refresh_families` — OAuth 2.1 single-use refresh-token rotation state
- `mcp_assertion_jtis` — RFC 7523 client-assertion replay guard (120-second expiration)

## MCP OAuth (experimental)

The plugin can also act as an OAuth 2.1 authorization server for **Model Context Protocol** clients (Claude Desktop, Cursor, `mcp-remote`), letting them authenticate against the same upstream providers. Two steps: enable it in config, and guard your MCP route with `withMCPAuth`.

```yaml
# config.yaml
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

```typescript
// resources.ts
import { server } from 'harper';
import { withMCPAuth } from '@harperfast/oauth';

// request.mcp (verified { sub, client_id, aud, scope }) is guaranteed present inside the guarded handler.
server.http(
	withMCPAuth((request) => ({ status: 200, body: JSON.stringify({ user: request.mcp.sub }) })),
	{
		urlPath: '/mcp',
	}
);
```

The plugin serves discovery (`/.well-known/*`), Dynamic Client Registration, the authorize/token endpoints, and JWKS; `withMCPAuth` verifies the audience-bound JWT on every call and fails closed. There's an [`onMCPTokenIssued`](./docs/lifecycle-hooks.md#onmcptokenissued) hook to react when a client gains access (client→user mapping, monitoring, rate-limiting) and a built-in audit log.

**Headless agents (machine-to-machine).** An agent with no browser and no human authenticates as itself: `grant_type=client_credentials` with an RFC 7523 `private_key_jwt` client assertion (EdDSA), rate-limited per verified client. Client identity resolves CIMD-first — a URL-shaped `client_id` is fetched as a [Client ID Metadata Document](./docs/mcp-oauth.md#client-id-metadata-documents-cimd) through an SSRF-guarded, rate-limited fetch. See [Headless agents](./docs/mcp-oauth.md#headless-agents-client_credentials).

**Status: experimental, opt-in.** See **[MCP OAuth](./docs/mcp-oauth.md)** for the full flow, the `withMCPAuth` registration models and options, the hook, configuration, the production checklist, and troubleshooting — and [what's not yet supported](./docs/mcp-oauth.md#not-yet-supported-v11) ([#156](https://github.com/HarperFast/oauth/issues/156)) for v1.1 forward-work.

## Security Considerations

- **HTTPS required** - OAuth requires HTTPS in production
- **CSRF protection** - Automatic via state parameter validation
- **ID token verification** - OIDC providers verify token signatures
- **Secure sessions** - Use Harper's secure session configuration
- **Token storage** - Tokens stored in session (configure secure cookies)
- **MCP client registration (when `mcp.enabled` is true)** - The `/oauth/mcp/register` endpoint defaults to **open registration** per RFC 7591. Set `mcp.dynamicClientRegistration.initialAccessToken` to require a bearer token on registration, or `mcp.dynamicClientRegistration.allowedRedirectUriHosts` to restrict which hosts may register `redirect_uri`s. See [`docs/configuration.md`](./docs/configuration.md).
- **CIMD resolution (when `mcp.enabled` is true)** - URL-shaped `client_id`s are resolved as Client ID Metadata Documents **by default**. Disable with `mcp.clientIdMetadataDocuments.enabled: false`, or restrict which hosts are fetched with `mcp.clientIdMetadataDocuments.allowedHosts`.

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
