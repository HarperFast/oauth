# Harper OAuth Plugin

OAuth 2.0 authentication plugin for Harper applications with support for multiple providers.

## Features

- 🔐 **Multi-provider support**: GitHub, Google, Azure AD, Auth0, and custom providers
- 🔄 **Automatic token refresh**: Proactive token renewal on every request (80% lifetime threshold)
- 🪝 **Lifecycle hooks**: Extensible hooks for user provisioning, logout, and token refresh events
- 🔄 **Seamless integration**: Works with Harper's session management system via HTTP middleware
- 🛡️ **CSRF protection**: Distributed token storage for cluster support
- 🎯 **ID token verification**: Full OIDC support for compatible providers
- 🔧 **Environment variables**: Secure configuration via `${ENV_VAR}` syntax
- 🔥 **Hot-reloading**: Config changes applied automatically without restart
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

## Automatic Token Management

The plugin automatically manages OAuth token lifecycle on **every HTTP request**:

- ✅ **Validates sessions** - Checks OAuth session data on each request
- ✅ **Proactive refresh** - Refreshes tokens at 80% of their lifetime
- ✅ **On-demand refresh** - Refreshes expired tokens immediately (if refresh token available)
- ✅ **Auto-logout** - Logs out users when tokens expire and can't be refreshed
- ✅ **Zero configuration** - No code changes needed in your application

**Token Expiration Behavior**: If an OAuth token expires and cannot be refreshed (no refresh token or refresh fails), the user is automatically logged out (entire session cleared). This ensures session state remains consistent.

Simply configure the OAuth plugin and it handles everything automatically. Your application code can access the OAuth user via:

```typescript
export function handleApplication(scope) {
	const myResource = {
		async get(target, request) {
			// OAuth tokens are automatically validated and refreshed
			if (request.session?.oauthUser) {
				return {
					message: 'Authenticated user',
					user: request.session.oauthUser.username,
					email: request.session.oauthUser.email,
				};
			}
			return { message: 'Not authenticated' };
		},
	};

	scope.resources.set('api', myResource);
}
```

**Note**: The plugin doesn't enforce authentication - it only validates and refreshes tokens for sessions that have OAuth data. To require authentication, check for `request.session?.oauthUser` in your application code and return 401 if not present.

## Endpoints

### Authentication Endpoints

| Endpoint                     | Method | Description                            |
| ---------------------------- | ------ | -------------------------------------- |
| `/oauth/{provider}/login`    | GET    | Initiates OAuth flow                   |
| `/oauth/{provider}/callback` | GET    | OAuth callback (configure in provider) |
| `/oauth/logout`              | POST   | Logs out the user (any provider)       |

### Debug Endpoints (when `debug: true`)

| Endpoint                    | Method | Description                   |
| --------------------------- | ------ | ----------------------------- |
| `/oauth/`                   | GET    | List all configured providers |
| `/oauth/test`               | GET    | Interactive test page         |
| `/oauth/{provider}/user`    | GET    | Current user info and tokens  |
| `/oauth/{provider}/refresh` | GET    | Check/trigger token refresh   |

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

### Configuration Hot-Reloading

The plugin supports hot-reloading of configuration changes:

- **Automatic Detection**: Config file changes are detected and applied automatically
- **Concurrency Protection**: Only one config update runs at a time to prevent race conditions
- **Queued Updates**: Rapid config changes are queued and processed sequentially
- **Error Handling**: Config errors are logged but don't crash the plugin
- **Active Sessions**: Existing OAuth sessions continue to work during reload

You can safely edit `config.yaml` while the application is running, and changes will be applied without requiring a restart.

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
request.session.oauth; // OAuth metadata including tokens and expiration
```

### Automatic Token Refresh

The plugin automatically manages OAuth token lifecycle:

- **Proactive Refresh**: Tokens are automatically refreshed when they reach 80% of their lifetime
- **On-Demand Refresh**: Expired tokens are refreshed on the next request (if refresh token available)
- **Graceful Degradation**: If a token cannot be refreshed, the OAuth session data is cleared
- **Transparent**: Applications don't need to handle token refresh logic

Token metadata stored in session:

```javascript
request.session.oauth = {
	provider: 'github', // OAuth provider name
	accessToken: '...', // Current access token
	refreshToken: '...', // Refresh token for renewals
	expiresAt: 1234567890000, // Token expiration timestamp (ms)
	refreshThreshold: 1234567800, // When to proactively refresh (80% of lifetime)
	scope: 'openid profile email', // Granted scopes
	tokenType: 'Bearer', // Token type
	lastRefreshed: 1234567000000, // Last successful refresh
};
```

## Lifecycle Hooks

The OAuth plugin provides lifecycle hooks that allow you to customize behavior at key authentication events. This is useful for user provisioning, analytics, access control, and integrating with other systems.

### Available Hooks

| Hook             | When Called                   | Use Cases                                        |
| ---------------- | ----------------------------- | ------------------------------------------------ |
| `onLogin`        | After successful OAuth login  | User provisioning, role mapping, logging         |
| `onLogout`       | When user logs out            | Cleanup, audit logging, revoke external sessions |
| `onTokenRefresh` | After automatic token refresh | Update cached data, log token refreshes          |

### Registering Hooks

Register hooks programmatically using the `registerHooks()` function. This can be called at module load time (before the plugin initializes) or after the plugin has loaded:

```typescript
import { registerHooks } from '@harperdb/oauth';

// Register hooks - can be called at module load time
registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		console.log(`User ${oauthUser.username} logged in via ${provider}`);
		// Add your custom logic here
	},

	onLogout: async (session, request) => {
		console.log('User logged out');
		// Cleanup logic here
	},

	onTokenRefresh: async (session, refreshed, request) => {
		if (refreshed) {
			console.log('Token refreshed successfully');
		}
	},
});
```

**Timing Note**: The `registerHooks()` function can be called before or after the plugin initializes:

- **Before initialization** - Hooks are queued and applied when the plugin loads
- **After initialization** - Hooks are applied immediately

This is a module-level singleton, shared across all OAuth plugin instances. For most applications with a single OAuth instance, this is the recommended approach.

### Hook Signatures

#### onLogin Hook

Called after successful OAuth authentication, before the session is stored. Can return data to be merged into the session.

```typescript
async function onLogin(
	oauthUser: OAuthUser, // Mapped OAuth user data
	tokenResponse: TokenResponse, // Raw OAuth token response
	session: any, // Current Harper session
	request: any, // Harper request object
	provider: string // Provider name (e.g., 'github')
): Promise<Record<string, any> | void> {
	// Example: Create/update user in database
	const user = await tables.User.upsert({
		email: oauthUser.email,
		name: oauthUser.name,
		oauthProvider: provider,
		lastLogin: new Date().toISOString(),
	});

	// Return data to merge into session
	return {
		userId: user.id,
		roles: user.roles,
	};
}
```

**Available Data:**

- `oauthUser.username` - Username from OAuth provider
- `oauthUser.email` - Email address
- `oauthUser.name` - Full name
- `oauthUser.role` - Assigned Harper role
- `tokenResponse.access_token` - OAuth access token
- `tokenResponse.id_token` - OIDC ID token (if available)

#### onLogout Hook

Called before the user's session is cleared. Use this for cleanup operations.

```typescript
async function onLogout(
	session: any, // Session being cleared
	request: any // Harper request object
): Promise<void> {
	// Example: Audit log
	logger.info('User logged out', {
		username: session.oauthUser?.username,
		timestamp: new Date().toISOString(),
	});

	// Example: Revoke external tokens
	if (session.oauth?.accessToken) {
		await externalService.revokeToken(session.oauth.accessToken);
	}
}
```

#### onTokenRefresh Hook

Called after the OAuth access token is automatically refreshed.

```typescript
async function onTokenRefresh(
	session: any, // Updated session with new tokens
	refreshed: boolean, // Whether tokens were actually refreshed
	request?: any // Harper request object (if available)
): Promise<void> {
	if (refreshed) {
		logger.debug('Token refreshed', {
			provider: session.oauth?.provider,
			expiresAt: session.oauth?.expiresAt,
		});

		// Example: Update cached external data
		await updateUserCache(session.oauthUser.username);
	}
}
```

### Example: User Provisioning Plugin

Here's a complete example of a user provisioning plugin that uses OAuth hooks:

```typescript
// user-provisioning/src/index.ts
export async function handleApplication(scope) {
	const logger = scope.logger;
	const { User } = scope.tables;

	// Export hooks for OAuth plugin
	scope.exports = {
		// Called after successful OAuth login
		async onLogin(oauthUser, tokenResponse, session, request, provider) {
			logger.info('User logging in', { email: oauthUser.email, provider });

			// Create or update user in database
			const user = await User.upsert({
				email: oauthUser.email,
				name: oauthUser.name,
				oauthProvider: provider,
				lastLoginDate: new Date().toISOString(),
				isVerified: true, // OAuth email is verified
			});

			// Map user to organization based on email domain
			const domain = oauthUser.email.split('@')[1];
			const org = await scope.tables.Organization.search({
				conditions: [{ attribute: 'emailDomain', value: domain }],
			}).next();

			// Assign roles
			const roles = org ? await assignOrgRoles(user.id, org.id) : [];

			// Return data to merge into session
			return {
				userId: user.id,
				organizationId: org?.id,
				roles: roles.map((r) => r.name),
			};
		},

		// Called when user logs out
		async onLogout(session, request) {
			logger.info('User logging out', {
				username: session.oauthUser?.username,
				userId: session.userId,
			});

			// Record logout time
			if (session.userId) {
				await User.patch({
					id: session.userId,
					lastLogoutDate: new Date().toISOString(),
				});
			}
		},

		// Called after token refresh
		async onTokenRefresh(session, refreshed, request) {
			if (refreshed) {
				logger.debug('Token refreshed for user', {
					username: session.oauthUser?.username,
				});
			}
		},
	};
}

async function assignOrgRoles(userId, orgId) {
	// Custom logic to assign roles based on organization
	const defaultRole = await scope.tables.Role.search({
		conditions: [
			{ attribute: 'organizationId', value: orgId },
			{ attribute: 'isDefault', value: true },
		],
	}).next();

	return defaultRole ? [defaultRole] : [];
}
```

**Configuration:**

```yaml
# config.yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  hooks: '@company/user-provisioning'
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}

'@company/user-provisioning':
  package: '@company/user-provisioning'
```

### Hook Best Practices

1. **Keep hooks lightweight**: Hooks run on every login/logout/refresh - avoid expensive operations
2. **Handle errors gracefully**: Hook errors are logged but don't block the OAuth flow
3. **Don't modify session directly**: Return data from onLogin to merge into session
4. **Use onTokenRefresh sparingly**: This hook runs frequently (every token refresh)
5. **Log appropriately**: Use logger for debugging but avoid sensitive data

## Current Limitations & Future Plans

### Current Limitations

- **No Built-in User Creation**: OAuth users are session-only by default (use hooks for persistence)
- **No Role Mapping**: All users get the same default role (use onLogin hook for custom logic)
- **Session-Based**: Authentication persists only while session is active
- **No Authorization Rules**: Cannot define Harper-specific permissions based on OAuth attributes (use hooks)

### Possible Future Enhancements

- **Built-in User Persistence**: Optional automatic creation/update of Harper users from OAuth profiles
- **Built-in Role Mapping**: Map OAuth provider groups/roles to Harper roles
- **Custom Claims Processing**: Transform OAuth claims into Harper user attributes
- **Multi-Factor Authentication**: Additional security layers after OAuth
- **Account Linking**: Link OAuth identities to existing Harper users

## Debug Mode

Enable debug mode to access additional endpoints:

```yaml
'@harperdb/oauth':
  package: '@harperdb/oauth'
  debug: true # or use ${OAUTH_DEBUG} for environment variable
  providers:
    github:
      provider: github
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

**Note**: Debug mode can be controlled via environment variable:

```bash
export OAUTH_DEBUG=true  # Enable debug endpoints
```

Debug endpoints:

- `/oauth/` - List all configured providers
- `/oauth/test` - Interactive test page
- `/oauth/{provider}/user` - Get current user info and token status
- `/oauth/{provider}/refresh` - Check token status and trigger refresh if needed

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
