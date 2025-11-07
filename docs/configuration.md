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

| Option              | Type    | Default    | Description                                                |
| ------------------- | ------- | ---------- | ---------------------------------------------------------- |
| `debug`             | boolean | `false`    | Enable debug endpoints and logging                         |
| `redirectUri`       | string  | (auto-gen) | OAuth callback URL where providers redirect back to        |
| `postLoginRedirect` | string  | `/`        | Default URL to redirect users after successful OAuth login |

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
OAUTH_REDIRECT_URI=https://yourdomain.com/oauth/callback  # OAuth callback URL
OAUTH_POST_LOGIN_REDIRECT=/dashboard  # Where to send users after login
```

## Understanding Redirects

The OAuth plugin uses two different redirect configurations that serve distinct purposes. Understanding the difference is critical for proper OAuth integration.

### 1. OAuth Callback URL (`redirectUri`)

**Purpose:** Tells OAuth providers (GitHub, Google, etc.) where to send users after they authenticate with the provider.

**Configuration:**

```yaml
'@harperdb/oauth':
  redirectUri: ${OAUTH_REDIRECT_URI}
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

**Example:** `https://yourdomain.com/oauth/callback`

**How it works:**

- The plugin automatically appends the provider name to create the full callback path
- `redirectUri: https://yourdomain.com/oauth/callback` becomes:
  - `https://yourdomain.com/oauth/github/callback` (for GitHub)
  - `https://yourdomain.com/oauth/google/callback` (for Google)
- This URL **must be registered** in your OAuth provider's application settings

**Important:**

- Must be a fully-qualified URL (protocol + domain + path)
- Must match exactly what's registered with the OAuth provider
- Used only during the OAuth handshake - users briefly visit this URL but don't stay there

### 2. Post-Login Redirect (`postLoginRedirect`)

**Purpose:** Where to redirect users **in your application** after successful OAuth login.

**Configuration:**

```yaml
'@harperdb/oauth':
  postLoginRedirect: ${OAUTH_POST_LOGIN_REDIRECT} # Default: '/'
```

**Examples:**

- `/dashboard` - Simple path
- `/app?view=settings` - With query parameters
- `/app#welcome` - With URL fragment for SPAs

**How it works:**

- After OAuth completes successfully, users are redirected to this path
- Supports relative paths, query parameters, and URL fragments
- For SPAs, you can include the hash/fragment: `/app#dashboard`

**Default:** `/` (application root)

### Dynamic Redirect per Login Request

Override `postLoginRedirect` on a per-request basis using the `redirect` query parameter:

```javascript
// Redirect to specific page after login
window.location.href = '/oauth/github/login?redirect=/dashboard';

// Redirect with query parameters
window.location.href = '/oauth/github/login?redirect=/app?view=settings';

// Redirect with URL fragment (for SPAs)
window.location.href = '/oauth/github/login?redirect=' + encodeURIComponent('/app#welcome');
```

**Redirect Priority (highest to lowest):**

1. `redirect` query parameter
2. `Referer` header (where the user came from)
3. `postLoginRedirect` config setting
4. `/` (fallback)

**Security:** The `redirect` parameter is automatically sanitized to prevent open redirect attacks. Only the path portion (pathname + search + hash) is preserved - any protocol, host, or port is stripped.

```javascript
// Safe - these all work as expected
'/dashboard'                    → '/dashboard'
'/app?view=settings'            → '/app?view=settings'
'/app#section'                  → '/app#section'

// Sanitized - protocol and host stripped for security
'https://evil.com/phishing'     → '/phishing'
'http://attacker.com/steal'     → '/steal'
'//evil.com/bad'                → '/bad'
```

### Single-Page Application (SPA) Integration

**Recommended:** Configure `postLoginRedirect` with your SPA route including the fragment:

```yaml
'@harperdb/oauth':
  postLoginRedirect: '/app#home' # Always land on SPA home view
```

Or use environment variables for flexibility:

```bash
OAUTH_POST_LOGIN_REDIRECT=/app#dashboard
```

**Dynamic routing:** For user-specific or context-aware redirects, use the redirect parameter:

```javascript
// Direct user to their specific page
const userId = getCurrentUserId();
const destination = `/app#profile/${userId}`;
window.location.href = `/oauth/github/login?redirect=${encodeURIComponent(destination)}`;
```

**State management:** For complex application state, use localStorage:

```javascript
// Before OAuth
const appState = { view: 'dashboard', filters: { status: 'active' } };
localStorage.setItem('oauth-return-state', JSON.stringify(appState));
window.location.href = '/oauth/github/login?redirect=/app';

// After OAuth - in your SPA initialization
const state = JSON.parse(localStorage.getItem('oauth-return-state') || '{}');
if (state.view) {
	restoreAppState(state);
	localStorage.removeItem('oauth-return-state');
}
```

### Complete Redirect Configuration Example

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  redirectUri: ${OAUTH_REDIRECT_URI} # OAuth callback: https://app.example.com/oauth/callback
  postLoginRedirect: ${OAUTH_POST_LOGIN_REDIRECT} # After login: /dashboard
  debug: false
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

**Environment variables:**

```bash
# OAuth provider callback (must match OAuth app settings)
OAUTH_REDIRECT_URI=https://app.example.com/oauth/callback

# Where to send users after successful login
OAUTH_POST_LOGIN_REDIRECT=/app#home

# Provider credentials
OAUTH_GITHUB_CLIENT_ID=your_github_client_id
OAUTH_GITHUB_CLIENT_SECRET=your_github_client_secret
```

**OAuth Flow:**

1. User clicks "Login with GitHub"
2. User redirected to GitHub for authentication
3. GitHub redirects back to `https://app.example.com/oauth/github/callback`
4. Plugin processes OAuth callback
5. User redirected to `/app#home` (or `redirect` query param if provided)

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
