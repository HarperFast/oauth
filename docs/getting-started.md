# Getting Started with @harperfast/oauth

The `@harperfast/oauth` plugin provides OAuth 2.0 and OpenID Connect (OIDC) authentication for Harper applications.

## Installation

```bash
npm install @harperfast/oauth
```

## Quick Start

### 1. Configure the Plugin

Add the plugin to your Harper application's `config.yaml`:

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
export OAUTH_GITHUB_CLIENT_ID="your_github_client_id"
export OAUTH_GITHUB_CLIENT_SECRET="your_github_client_secret"
```

### 3. (Optional) Register Lifecycle Hooks

If you need to provision users or customize the authentication flow, register hooks in your `resources.js`:

```javascript
import { registerHooks } from '@harperfast/oauth';

registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		// Find or create user
		let user;
		for await (const u of tables.User.search([{ attribute: 'email', value: oauthUser.email }])) {
			user = u;
			break;
		}
		if (!user) {
			user = await tables.User.create({ email: oauthUser.email, name: oauthUser.name });
		}
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

The OAuth plugin includes built-in templates for:

- **GitHub** - OAuth 2.0
- **Google** - OIDC
- **Azure AD** - OIDC
- **Auth0** - OIDC
- **Okta** - OIDC
- **Custom** - Generic OIDC provider

> **Important:** Built-in providers are templates only. **None are active** until you configure them with `clientId`, `clientSecret`, and other required settings. The presence of provider code does not enable authentication or create security exposure.

## Next Steps

- [Configure additional providers](./configuration.md)
- [Set up provider applications](./providers.md)
- [Add lifecycle hooks](./lifecycle-hooks.md)
- [Review API reference](./api-reference.md)
