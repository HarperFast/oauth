# Configuration Reference

Complete configuration options for the `@harperdb/oauth` plugin.

## Basic Configuration

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
    google:
      clientId: ${OAUTH_GOOGLE_CLIENT_ID}
      clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
```

## Configuration Options

### Global Options

| Option  | Type    | Default | Description                        |
| ------- | ------- | ------- | ---------------------------------- |
| `debug` | boolean | `false` | Enable debug endpoints and logging |

### Provider Configuration

Each provider requires:

| Option         | Type   | Required | Description                               |
| -------------- | ------ | -------- | ----------------------------------------- |
| `clientId`     | string | Yes      | OAuth client ID from provider             |
| `clientSecret` | string | Yes      | OAuth client secret from provider         |
| `scope`        | string | No       | OAuth scopes (provider-specific defaults) |

### Provider-Specific Options

#### Azure AD

- `tenantId` - Azure AD tenant ID (required)

#### Auth0

- `domain` - Auth0 domain, e.g., `yourapp.auth0.com` (required)

#### Custom OIDC Provider

- `authorizationUrl` - Authorization endpoint URL (required)
- `tokenUrl` - Token endpoint URL (required)
- `userInfoUrl` - User info endpoint URL (required)
- `jwksUrl` - JWKS endpoint URL (required for ID token verification)

## Environment Variables

All configuration options can be set via environment variables:

### Provider Credentials

**GitHub:**

```bash
OAUTH_GITHUB_CLIENT_ID=your_client_id
OAUTH_GITHUB_CLIENT_SECRET=your_client_secret
OAUTH_GITHUB_SCOPE="user:email"  # Optional
```

**Google:**

```bash
OAUTH_GOOGLE_CLIENT_ID=your_client_id
OAUTH_GOOGLE_CLIENT_SECRET=your_client_secret
OAUTH_GOOGLE_SCOPE="openid profile email"  # Optional
```

**Azure:**

```bash
OAUTH_AZURE_CLIENT_ID=your_client_id
OAUTH_AZURE_CLIENT_SECRET=your_client_secret
OAUTH_AZURE_TENANT_ID=your_tenant_id
OAUTH_AZURE_SCOPE="openid profile email"  # Optional
```

**Auth0:**

```bash
OAUTH_AUTH0_DOMAIN=yourapp.auth0.com
OAUTH_AUTH0_CLIENT_ID=your_client_id
OAUTH_AUTH0_CLIENT_SECRET=your_client_secret
OAUTH_AUTH0_SCOPE="openid profile email"  # Optional
```

### Global Options

```bash
OAUTH_DEBUG=true  # Enable debug mode
```

## Lifecycle Hooks

Lifecycle hooks are **not configured in config.yaml**. Instead, they must be registered programmatically in your application code.

See the [Lifecycle Hooks documentation](./lifecycle-hooks.md) for complete details.

**Quick example:**

```javascript
// resources.js
import { registerHooks } from '@harperdb/oauth';
import { hooks } from './src/lib/oauthHooks.js';

registerHooks(hooks);
```

For complete hook implementation patterns, see [Lifecycle Hooks](./lifecycle-hooks.md).

## Debug Mode

When `debug: true` is enabled, additional endpoints are available:

- `GET /oauth/` - List all configured providers
- `GET /oauth/test` - Interactive test page
- `GET /oauth/{provider}/user` - Current user info and token status
- `GET /oauth/{provider}/refresh` - Trigger token refresh

**Warning:** Never enable debug mode in production environments.

## Complete Example

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  debug: false
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
      scope: 'user:email'
    google:
      clientId: ${OAUTH_GOOGLE_CLIENT_ID}
      clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
    azure:
      clientId: ${OAUTH_AZURE_CLIENT_ID}
      clientSecret: ${OAUTH_AZURE_CLIENT_SECRET}
      tenantId: ${OAUTH_AZURE_TENANT_ID}
    auth0:
      domain: ${OAUTH_AUTH0_DOMAIN}
      clientId: ${OAUTH_AUTH0_CLIENT_ID}
      clientSecret: ${OAUTH_AUTH0_CLIENT_SECRET}
```

## Next Steps

- [Set up OAuth providers](./providers.md)
- [Implement lifecycle hooks](./lifecycle-hooks.md)
- [API reference](./api-reference.md)
