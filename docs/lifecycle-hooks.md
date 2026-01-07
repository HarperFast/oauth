# Lifecycle Hooks

Lifecycle hooks allow you to customize the OAuth authentication flow by executing custom logic at key events.

## Available Hooks

### onResolveProvider

Called when a provider is not found in the static registry. Allows applications to implement multi-tenant OAuth by dynamically resolving provider configurations based on naming conventions.

**Purpose:** Multi-tenant SSO, organization-specific OAuth providers, database-backed provider configuration

**Signature:**

```typescript
async function onResolveProvider(providerName: string, logger?: Logger): Promise<OAuthProviderConfig | null>;
```

**Parameters:**

- `providerName` - Provider name from URL path (e.g., `"okta-org_abc123"`)
- `logger` - Optional logger instance

**Returns:** Provider configuration object or null if provider not found

**Example:**

```javascript
import {
	getProvider,
	validateTenantId,
	validateDomainSafety,
	validateDomainAllowlist,
	validateAzureTenantId,
} from '@harperdb/oauth';

const { Organization } = tables;

async function resolveOAuthProvider(providerName, logger) {
	// Parse provider name format: "{provider}-{tenantId}"
	const match = providerName.match(/^(okta|azure|auth0)-(.+)$/);
	if (!match) {
		// Not a multi-tenant provider name
		return null;
	}

	const [, provider, tenantId] = match;

	// Validate tenant ID format BEFORE database lookup
	try {
		validateTenantId(tenantId);
	} catch (error) {
		logger?.warn?.(`Invalid tenant ID in provider name: ${providerName}`);
		return null; // Return 404, not 500
	}

	// Query Organization table for OAuth config
	const org = await Organization.get(tenantId);

	// Check if OAuth is enabled for this organization
	if (!org?.oauthConfig?.enabled || org.oauthConfig.status !== 'active') {
		logger?.debug?.(`OAuth not enabled for tenant: ${tenantId}`);
		return null;
	}

	const config = org.oauthConfig;

	// Verify provider type matches
	if (config.provider !== provider) {
		logger?.warn?.(`Provider mismatch: URL has ${provider}, config has ${config.provider}`);
		return null;
	}

	// Get base provider configuration from OAuth plugin
	const baseProvider = getProvider(provider);
	if (!baseProvider) {
		logger?.error?.(`Unknown provider type: ${provider}`);
		return null;
	}

	// Apply provider-specific configuration with validation
	let providerSpecificConfig = {};

	try {
		if (baseProvider.configure) {
			switch (provider) {
				case 'okta':
				case 'auth0':
					if (!config.domain) {
						throw new Error(`${provider} requires domain configuration`);
					}
					// Validate domain safety (SSRF protection)
					const hostname = validateDomainSafety(config.domain, provider);
					const allowedDomains = {
						okta: ['.okta.com', '.okta-emea.com', '.oktapreview.com'],
						auth0: ['.auth0.com', '.eu.auth0.com', '.au.auth0.com'],
					};
					validateDomainAllowlist(hostname, allowedDomains[provider], provider);
					providerSpecificConfig = baseProvider.configure(config.domain);
					break;

				case 'azure':
					if (!config.azureTenantId) {
						throw new Error('Azure requires tenantId configuration');
					}
					// Validate Azure tenant ID format
					validateAzureTenantId(config.azureTenantId);
					providerSpecificConfig = baseProvider.configure(config.azureTenantId);
					break;
			}
		}
	} catch (error) {
		logger?.error?.(`Invalid OAuth config for organization ${org.name}:`, error);
		return null;
	}

	// Build complete provider configuration
	const providerConfig = {
		// Base provider properties
		provider: config.provider,
		scope: config.scope || baseProvider.scope,
		usernameClaim: baseProvider.usernameClaim,
		emailClaim: baseProvider.emailClaim,
		nameClaim: baseProvider.nameClaim,
		roleClaim: baseProvider.roleClaim,
		defaultRole: baseProvider.defaultRole,
		preferIdToken: baseProvider.preferIdToken,
		// Provider-specific URLs from configure()
		authorizationUrl: providerSpecificConfig.authorizationUrl,
		tokenUrl: providerSpecificConfig.tokenUrl,
		userInfoUrl: providerSpecificConfig.userInfoUrl,
		jwksUri: providerSpecificConfig.jwksUri,
		issuer: providerSpecificConfig.issuer,
		// Tenant-specific credentials from database
		clientId: config.clientId,
		clientSecret: config.clientSecret,
	};

	return providerConfig;
}
```

**Security Requirements:**

- **MUST** validate tenant ID format before database lookup
- **MUST** validate domain safety (SSRF protection)
- **MUST** validate provider-specific configuration
- **MUST NOT** return configurations for disabled/inactive tenants
- **SHOULD** log all resolution attempts for audit trail

**URL Structure:**

When using `onResolveProvider`, users access tenant-specific login URLs:

```bash
/oauth/okta-org_abc123/login    ← Acme Corp's Okta
/oauth/azure-org_xyz789/login   ← Globex's Azure AD
```

The provider name (`okta-org_abc123`) is parsed by your hook to extract the provider type and tenant ID, then dynamically resolves the configuration from your database.

---

### onLogin

Called after successful OAuth authentication, before the session is created.

**Purpose:** User provisioning, role mapping, custom session data, analytics

**Signature:**

```typescript
async function onLogin(
	oauthUser: OAuthUserInfo,
	tokenResponse: TokenResponse,
	session: Session,
	request: Request,
	provider: string
): Promise<object | void>;
```

**Parameters:**

- `oauthUser` - OAuth user profile (username, email, name, role)
- `tokenResponse` - Complete OAuth token response from provider
- `session` - Current session object
- `request` - HTTP request object
- `provider` - Provider name (e.g., 'github', 'google')

**Returns:** Object to merge into session. **Important:** Return `{ user: userId }` to set the Harper system username for authentication.

**Example:**

```javascript
async function handleLogin(oauthUser, tokenResponse, session, request, provider) {
	const { User } = tables;
	const context = request.context || {};

	// Validate email
	if (!oauthUser?.email) {
		throw new Error('OAuth provider did not provide email');
	}

	// Find existing user by email
	let user;
	for await (const record of User.search([{ attribute: 'email', value: oauthUser.email }], context)) {
		user = record;
		break; // Take first match
	}

	if (!user) {
		// New user - create database record
		user = await User.create(
			{
				email: oauthUser.email,
				name: oauthUser.name,
				provider: provider,
				createdAt: new Date().toISOString(),
			},
			context
		);
	} else {
		// Update last login
		await User.patch(
			user.id,
			{
				lastLoginDate: new Date().toISOString(),
				provider: provider,
			},
			context
		);
	}

	// Return Harper system username for authentication
	return {
		user: String(user.id),
	};
}
```

---

### onLogout

Called before the session is cleared during logout.

**Purpose:** Cleanup, audit logging, revoke external tokens

**Signature:**

```typescript
async function onLogout(session: Session, request: Request): Promise<void>;
```

**Parameters:**

- `session` - Current session object with user and OAuth data
- `request` - HTTP request object

**Returns:** void

**Example:**

```javascript
async function handleLogout(session, request) {
	// Log the logout event
	logger.info('User logged out', {
		userId: session.user,
		email: session.oauthUser?.email,
	});

	// Optional: Create audit log
	if (session.user) {
		await tables.AuditLog.create({
			userId: session.user,
			action: 'logout',
			timestamp: new Date().toISOString(),
		});
	}
}
```

---

### onTokenRefresh

Called after an automatic token refresh (on every HTTP request).

**Purpose:** Update caches, log refresh events, sync external systems

**Signature:**

```typescript
async function onTokenRefresh(session: Session, refreshed: boolean, request: Request): Promise<void>;
```

**Parameters:**

- `session` - Current session object with updated token
- `refreshed` - Whether token was actually refreshed (true) or still valid (false)
- `request` - HTTP request object

**Returns:** void

**Example:**

```javascript
async function handleTokenRefresh(session, refreshed, request) {
	if (refreshed) {
		logger.debug('OAuth token refreshed', {
			userId: session.user,
			provider: session.oauth?.provider,
			expiresAt: new Date(session.oauth?.expiresAt).toISOString(),
		});
	}
}
```

## Hook Registration

Hooks are **lazy-referenced** - they are looked up when OAuth events occur (login, logout, token refresh), not when registered. This means you can call `registerHooks()` at any time, and there's no specific initialization window. The hooks are simply stored and referenced later when needed.

The typical pattern is to register hooks in your application's main entry point (e.g., `resources.js`), but the timing is flexible.

### Recommended Pattern (Separate File)

**resources.js (application entry point):**

```javascript
import { registerHooks } from '@harperdb/oauth';
import { hooks } from './src/lib/oauthHooks.js';

// Register hooks at module load time
registerHooks(hooks);

// Export your resources...
export { User } from './src/resources/User.js';
export { Organization } from './src/resources/Organization.js';
// ...
```

**src/lib/oauthHooks.js:**

```javascript
const { User } = tables;

async function handleLogin(oauthUser, tokenResponse, session, request, provider) {
	const context = request.context || {};

	if (!oauthUser?.email) {
		throw new Error('OAuth provider did not provide email');
	}

	// Find existing user by email
	let user;
	for await (const record of User.search([{ attribute: 'email', value: oauthUser.email }], context)) {
		user = record;
		break; // Take first match
	}

	if (!user) {
		// Create new user - ID will be auto-generated
		user = await User.create(
			{
				email: oauthUser.email,
				name: oauthUser.name,
				provider: provider,
				createdAt: new Date().toISOString(),
			},
			context
		);
	} else {
		// Update existing user
		await User.patch(
			user.id,
			{
				lastLoginDate: new Date().toISOString(),
				provider: provider,
			},
			context
		);
	}

	// Return Harper system username for authentication
	return { user: String(user.id) };
}

async function handleLogout(session, request) {
	logger.info('User logged out', { userId: session.user });
}

async function handleTokenRefresh(session, refreshed, request) {
	if (refreshed) {
		logger.debug('Token refreshed', { userId: session.user });
	}
}

// Export hooks object
export const hooks = {
	onLogin: handleLogin,
	onLogout: handleLogout,
	onTokenRefresh: handleTokenRefresh,
};
```

---

### Inline Pattern

You can also register hooks inline:

**resources.js:**

```javascript
import { registerHooks } from '@harperdb/oauth';

registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		const user = await tables.User.patch({
			email: oauthUser.email,
			name: oauthUser.name,
			provider: provider,
		});
		return { user: String(user.id) };
	},
	onLogout: async (session, request) => {
		logger.info('User logged out', { userId: session.user });
	},
	onTokenRefresh: async (session, refreshed, request) => {
		if (refreshed) logger.debug('Token refreshed', { userId: session.user });
	},
});

// Export your resources...
```

## Session Data Structure

After `onLogin` completes, the session contains:

```javascript
{
  user: 'guid-1234',             // Harper system username (from onLogin hook)
  oauthUser: {                   // OAuth user profile
    username: 'oauth_username',
    email: 'user@example.com',
    name: 'User Name',
    role: 'user'
  },
  oauth: {                       // Token metadata
    provider: 'github',
    accessToken: 'token_value',
    refreshToken: 'refresh_value',
    expiresAt: 1234567890,
    refreshThreshold: 1234567800,
    scope: 'user:email',
    tokenType: 'Bearer',
    lastRefreshed: 1234567890
  },
  // Additional custom data from onLogin hook return value
  organizationId: 'org_456',
  roles: ['admin']
}
```

**Accessing session in your code:**

```javascript
export class MyResource extends tables.Resource {
	async get(target, request) {
		// Check authentication
		if (!request.session?.user) {
			throw new ClientError('Not authenticated', 401);
		}

		// Access user data
		const userId = request.session.user; // Harper system username
		const email = request.session.oauthUser.email;

		return { userId, email };
	}
}
```

## Best Practices

### Error Handling

- **onLogin:** Throw errors to prevent login (e.g., suspended accounts)
- **onLogout/onTokenRefresh:** Catch and log errors, don't throw (non-critical)

```javascript
async function handleLogout(session, request) {
	try {
		await cleanupUserData(session.user);
	} catch (error) {
		logger.error('Logout cleanup failed', error);
		// Don't throw - allow logout to proceed
	}
}
```

### Performance

- Keep hooks fast - token refresh runs on every request
- Use background jobs for heavy operations
- Cache frequently accessed data

```javascript
async function handleLogin(oauthUser, tokenResponse, session, request, provider) {
	// Quick operation - runs inline
	const user = await quickUserLookup(oauthUser.email);

	// Heavy operation - queue for background processing
	await queue.add('user-provisioning', {
		userId: user.id,
		oauthData: tokenResponse,
	});

	return { user: user.id };
}
```

### Security

- Validate all input data
- Don't expose sensitive OAuth tokens
- Log authentication events for audit

```javascript
async function handleLogin(oauthUser, tokenResponse, session, request, provider) {
	// Validate email format
	if (!isValidEmail(oauthUser.email)) {
		throw new Error('Invalid email address');
	}

	// Don't store raw OAuth tokens in logs
	logger.info('Login successful', {
		email: oauthUser.email,
		provider: provider,
		// Don't log: tokenResponse.access_token
	});

	return await provisionUser(oauthUser);
}
```

## Testing Hooks

Use debug mode to test hooks during development:

```yaml
'@harperdb/oauth':
  debug: true
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
```

Then monitor logs and test with debug endpoints:

- `GET /oauth/{provider}/user` - View current session
- `GET /oauth/{provider}/refresh` - Trigger token refresh

## Next Steps

- [Configuration Reference](./configuration.md)
- [OAuth Provider Setup](./providers.md)
- [API Reference](./api-reference.md)
