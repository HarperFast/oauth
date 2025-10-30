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

```bash
npm install @harperdb/oauth
```

## Quick Start

### 1. Configure OAuth Plugin

Add to your `config.yaml`:

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
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

### 3. Configure OAuth Callback

Set your OAuth callback URL in your provider settings:

```
https://your-domain/oauth/github/callback
```

### 4. (Optional) Register Lifecycle Hooks

Create or update users when they log in:

```typescript
// resources.ts
import { registerHooks } from '@harperdb/oauth';

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

- **GitHub** - OAuth 2.0
- **Google** - OpenID Connect
- **Azure AD** - OpenID Connect
- **Auth0** - OpenID Connect
- **Custom** - Generic OIDC provider

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

## Security Considerations

- **HTTPS required** - OAuth requires HTTPS in production
- **CSRF protection** - Automatic via state parameter validation
- **ID token verification** - OIDC providers verify token signatures
- **Secure sessions** - Use Harper's secure session configuration
- **Token storage** - Tokens stored in session (configure secure cookies)

## Debug Mode

Enable debug endpoints for testing:

```yaml
'@harperdb/oauth':
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
