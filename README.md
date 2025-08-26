# Harper OAuth Plugin

OAuth 2.0 authentication plugin for Harper applications with support for multiple providers.

## Features

- 🔐 **Multi-provider support**: GitHub, Google, Azure AD, Auth0, and custom providers
- 🔄 **Seamless integration**: Works with Harper's session management system
- 🛡️ **CSRF protection**: Distributed token storage for cluster support
- 🎯 **ID token verification**: Full OIDC support for compatible providers
- 🔧 **Environment variables**: Secure configuration via `${ENV_VAR}` syntax
- 📊 **Self-contained**: Includes its own database schema

## Installation

```bash
npm install @harperdb/oauth
```

## Quick Start

### 1. Configure the Plugin

Add the OAuth plugin to your application's `config.yaml`:

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

### 2. Set Environment Variables

```bash
# GitHub
export OAUTH_GITHUB_CLIENT_ID="your-github-client-id"
export OAUTH_GITHUB_CLIENT_SECRET="your-github-client-secret"

# Google
export OAUTH_GOOGLE_CLIENT_ID="your-google-client-id"
export OAUTH_GOOGLE_CLIENT_SECRET="your-google-client-secret"
```

### 3. Configure OAuth Apps

Set your OAuth callback URL to:

```text
https://your-domain/oauth/{provider}/callback
```

For local development with non-standard ports:

```text
https://localhost:9953/oauth/{provider}/callback
```

## Endpoints

Each configured provider gets its own set of endpoints:

| Endpoint                     | Description                            |
| ---------------------------- | -------------------------------------- |
| `/oauth/{provider}/login`    | Initiates OAuth flow                   |
| `/oauth/{provider}/callback` | OAuth callback (configure in provider) |
| `/oauth/{provider}/logout`   | Logs out the user                      |
| `/oauth/{provider}/user`     | Returns current user info (debug mode) |
| `/oauth/{provider}/test`     | Test page for OAuth flow (debug mode)  |

## Provider Configuration

### GitHub

```yaml
github:
  clientId: ${OAUTH_GITHUB_CLIENT_ID}
  clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
  # Optional overrides
  scope: 'user:email read:org'
```

**Setup:**

1. Go to [GitHub Settings > Developer settings > OAuth Apps](https://github.com/settings/applications/new)
2. Set Authorization callback URL (e.g., `https://localhost:9953/oauth/github/callback` for local development)
3. Copy the Client ID and Client Secret

### Google

```yaml
google:
  clientId: ${OAUTH_GOOGLE_CLIENT_ID}
  clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
  # Optional overrides
  scope: 'openid profile email'
```

**Setup:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID
3. Add authorized redirect URI (e.g., `https://localhost:9953/oauth/google/callback` for local development)
4. Copy the Client ID and Client Secret

### Azure AD

```yaml
azure:
  clientId: ${OAUTH_AZURE_CLIENT_ID}
  clientSecret: ${OAUTH_AZURE_CLIENT_SECRET}
  tenantId: ${OAUTH_AZURE_TENANT_ID}
  # Optional: specify tenant (defaults to 'common')
  # tenantId: 'your-tenant-id'
```

**Setup:**

1. Go to [Azure Portal > App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Create new registration
3. Add redirect URI (e.g., `https://localhost:9953/oauth/azure/callback` for local development)
4. Copy Application ID (Client ID) and create a client secret
5. Note your Tenant ID

### Auth0

```yaml
auth0:
  domain: ${OAUTH_AUTH0_DOMAIN} # e.g. 'myapp.auth0.com'
  clientId: ${OAUTH_AUTH0_CLIENT_ID}
  clientSecret: ${OAUTH_AUTH0_CLIENT_SECRET}
```

**Setup:**

1. Go to your Auth0 Dashboard > Applications
2. Create a new Regular Web Application
3. Add callback URL (e.g., `https://localhost:9953/oauth/auth0/callback` for local development)
4. Copy Domain, Client ID, and Client Secret

### Custom Provider

For any OAuth 2.0 compatible provider, you can configure a custom provider with any name:

```yaml
mycompany: # Your chosen provider name
  authorizationUrl: 'https://provider.com/oauth/authorize'
  tokenUrl: 'https://provider.com/oauth/token'
  userInfoUrl: 'https://provider.com/userinfo'
  clientId: ${OAUTH_CUSTOM_CLIENT_ID}
  clientSecret: ${OAUTH_CUSTOM_CLIENT_SECRET}
  scope: 'openid profile email'
  usernameClaim: 'email' # Field to use as username
  defaultRole: 'user' # Default Harper role
```

This creates endpoints at `/oauth/mycompany/login`, `/oauth/mycompany/callback`, etc.

## Configuration Options

### Global Options

Set default values for all providers in your `config.yaml`:

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  # Global defaults
  scope: 'openid profile email'
  usernameClaim: 'email'
  defaultRole: 'user'
  postLoginRedirect: '/dashboard'
  debug: true # Enable debug endpoints
  providers:
    # ... provider configs
```

### Provider Options

Each provider can override global defaults:

| Option              | Description                 | Default           |
| ------------------- | --------------------------- | ----------------- |
| `scope`             | OAuth scopes to request     | Provider-specific |
| `usernameClaim`     | Field to use as username    | `'email'`         |
| `defaultRole`       | Harper role to assign       | `'user'`          |
| `postLoginRedirect` | URL to redirect after login | `'/'`             |
| `redirectUri`       | Custom callback URL         | Auto-generated    |

## How It Works

The OAuth plugin provides authentication without requiring you to manage Harper users manually. When a user authenticates via OAuth:

1. **Automatic Session Creation**: The plugin creates a Harper session with the OAuth user's information
2. **No User Management Required**: Users don't need to be pre-created in Harper's user system
3. **Session-Based Access**: Once authenticated, users can access your Harper application through standard session cookies
4. **Role Assignment**: Users are automatically assigned a default role (configurable per provider)

### Technical Flow

1. **Login Initiation** (`/oauth/{provider}/login`)
   - Generates a CSRF token with metadata (original URL, session ID)
   - Redirects user to OAuth provider's authorization endpoint with state parameter

2. **OAuth Callback** (`/oauth/{provider}/callback`)
   - Provider redirects back with authorization code and state parameter
   - Plugin verifies the state parameter (CSRF protection)
   - Exchanges authorization code for access token (server-to-server request)
   - For OIDC providers: Verifies ID token signature and claims
   - Fetches user information from provider's userinfo endpoint
   - Maps provider user data to Harper user object

3. **Session Creation**
   - Updates Harper session with user information: `request.session.update({ user })`
   - Stores OAuth tokens in session for potential API calls
   - Session is tracked via secure HTTP-only cookie
   - Redirects user back to original application URL

### Customization Points

While the plugin handles the OAuth flow automatically, applications can customize:

- **User Mapping**: Configure which OAuth claim becomes the Harper username via `usernameClaim`
- **Role Assignment**: Set default role via `defaultRole` configuration
- **Post-Login Redirect**: Configure where users go after authentication

**Note**: Currently, the plugin creates session-only users. Future versions will support:

- Custom user creation handlers for persisting users to database
- Application-specific logic for user provisioning
- Role mapping based on OAuth provider groups/claims

## Session Integration

The plugin integrates seamlessly with Harper's session management:

```javascript
// After successful OAuth login:
request.session.user; // Harper username (from OAuth provider)
request.session.oauthUser; // Full OAuth user details
request.session.oauthToken; // OAuth access token
request.session.oauthRefreshToken; // OAuth refresh token (if provided)
```

## Current Limitations & Future Plans

### Current Limitations

- **No Harper User Creation**: OAuth users are session-only and not persisted as Harper database users
- **No Role Mapping**: All users get the same default role - no mapping from OAuth provider roles/groups
- **Session-Only**: Authentication is lost when the session expires (no persistent user records)
- **No Authorization Rules**: Cannot define Harper-specific permissions based on OAuth attributes

### Possible Future Enhancements

- **User Persistence**: Option to automatically create/update Harper users from OAuth profiles
- **Role Mapping**: Map OAuth provider groups/roles to Harper roles
- **Custom Claims Processing**: Transform OAuth claims into Harper user attributes
- **Multi-Factor Authentication**: Additional security layers after OAuth
- **Account Linking**: Link OAuth identities to existing Harper users

## Debug Mode

Enable debug mode to access additional endpoints:

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  debug: true
  providers:
    github:
      provider: github
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

Debug endpoints:

- `/oauth/` - List all configured providers
- `/oauth/test` - Interactive test page
- `/oauth/{provider}/user` - Get current user info
- `/oauth/{provider}/refresh` - Refresh access token

## Database Schema

The plugin automatically creates its required database tables via GraphQL schema:

- **Database**: `oauth`
- **Table**: `csrf_tokens` (10-minute expiration for CSRF protection)

No manual database setup required - the plugin handles this automatically.

## Security Considerations

1. **HTTPS Required**: Always use HTTPS in production
2. **Environment Variables**: Never commit secrets to version control
3. **CSRF Protection**: Automatic via state parameter
4. **Token Storage**: Distributed storage supports clustered deployments
5. **ID Token Verification**: Automatic for OIDC providers

## Development

### Setup

For local development, it's recommended to use HTTPS for OAuth callback URLs. Set the `securePort` in your `harperdb-config.yaml`:

```yaml
http:
  securePort: 9953 # HTTPS port
  port: 9926 # HTTP port
```

### Building

```bash
npm run build  # Compile TypeScript
npm run dev    # Watch mode for development
```

### Testing

```bash
npm test        # Run all tests
npm run lint    # ESLint
npm run format  # Prettier
```

### Project Structure

```text
oauth/
├── src/
│   ├── lib/
│   │   ├── providers/  # Provider configurations
│   │   ├── CSRFTokenManager.ts
│   │   ├── OAuthProvider.ts
│   │   └── resource.ts
│   ├── schema/         # GraphQL schemas
│   │   └── oauth.graphql
│   └── index.ts
├── dist/               # Compiled output
├── test/               # Tests
└── config.yaml         # Plugin config
```

## Error Handling

The plugin uses URL-based error reporting for production environments. When errors occur during OAuth flows, users are redirected with error parameters:

| Error Type           | Redirect URL                                                 | Description                                      |
| -------------------- | ------------------------------------------------------------ | ------------------------------------------------ |
| OAuth Provider Error | `{postLoginRedirect}?error=oauth_failed&reason={error_code}` | Provider returned an error (e.g., access_denied) |
| Invalid Request      | `{postLoginRedirect}?error=invalid_request`                  | Missing required OAuth parameters                |
| Session Expired      | `/oauth/{provider}/login?error=session_expired`              | CSRF token expired or invalid                    |

Applications can check for these error parameters and display appropriate messages to users.

## Troubleshooting

### "OAuth CSRF tokens table not found"

The plugin requires its GraphQL schema to be loaded. Ensure:

1. The plugin is properly configured in your application's `config.yaml`
2. Harper has loaded the plugin's schema files

### "Missing required OAuth configuration"

Ensure all required fields are provided:

- `clientId` and `clientSecret` for all providers
- `tenantId` for Azure (if not using 'common')
- `domain` for Auth0

### Session Expired Errors

CSRF tokens expire after 10 minutes for security. If users encounter an expired session, they'll be redirected back to the login page with `?error=session_expired` to retry the authentication flow.

## License

TBD
