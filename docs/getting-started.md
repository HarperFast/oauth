# Getting Started with @harperdb/oauth

The `@harperdb/oauth` plugin provides OAuth 2.0 and OpenID Connect (OIDC) authentication for Harper applications.

## Installation

```bash
npm install @harperdb/oauth
```

## Quick Start

### 1. Configure the Plugin

Add the plugin to your Harper application's `config.yaml`:

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
export OAUTH_GITHUB_CLIENT_ID="your_github_client_id"
export OAUTH_GITHUB_CLIENT_SECRET="your_github_client_secret"
```

### 3. (Optional) Register Lifecycle Hooks

If you need to provision users or customize the authentication flow, register hooks in your `resources.js`:

```javascript
import { registerHooks } from '@harperdb/oauth';

registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		// Create user in your database
		const user = await tables.User.put({
			email: oauthUser.email,
			name: oauthUser.name,
		});
		return { user: String(user.id) };
	},
});
```

See [Lifecycle Hooks](./lifecycle-hooks.md) for complete details.

### 4. Start Your Application

```bash
npm start
```

### 5. Test Authentication

Navigate to:

```
http://localhost:9926/oauth/github/login
```

## Supported Providers

- **GitHub** - OAuth 2.0
- **Google** - OIDC
- **Azure AD** - OIDC
- **Auth0** - OIDC
- **Custom** - Generic OIDC provider

## Next Steps

- [Configure additional providers](./configuration.md)
- [Set up provider applications](./providers.md)
- [Add lifecycle hooks](./lifecycle-hooks.md)
- [Review API reference](./api-reference.md)
