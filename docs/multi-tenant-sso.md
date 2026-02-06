# Multi-Tenant SSO

Enable multiple enterprises to use their own OAuth providers (Okta, Azure AD, Auth0, etc.) in your B2B SaaS application. Each organization gets a unique SSO login URL.

## Overview

**What you get:**

- Each customer uses their own identity provider
- Zero-config tenant registration via hooks
- Automatic provider resolution from your database
- Works with Okta, Azure AD, Auth0, Google, and any OAuth 2.0 provider

**How it works:**

```
Organization has URL → /oauth/acme-corp/login → Plugin calls your hook → Hook returns OAuth config → User authenticates
```

## Quick Start

### 1. Store Tenant Configurations

Store OAuth configs in your database (structure is up to you):

```typescript
// Example: tenants table
{
  id: 'acme-corp',
  name: 'Acme Corporation',
  provider: 'okta',
  domain: 'acme-corp.okta.com',  // For Okta/Auth0
  client_id: '...',
  client_secret: '...',  // Encrypt in production!
}
```

### 2. Register Hook to Resolve Providers

The OAuth plugin calls your `onResolveProvider` hook when a user visits `/oauth/{tenantId}/login`:

```typescript
import { registerHooks } from '@harperfast/oauth';

export async function handleApplication(scope) {
	const { tables, logger } = scope;

	// Register hook to dynamically load tenant OAuth configs
	registerHooks({
		async onResolveProvider(tenantId, logger) {
			// Look up tenant in your database (structure is up to you)
			const tenant = await tables.tenants.get(tenantId);

			if (!tenant) {
				return null; // 404 - tenant not found
			}

			// Return OAuth config for this tenant
			return {
				provider: tenant.provider, // 'okta' | 'azure' | 'auth0' | 'google' | 'github'
				domain: tenant.domain, // For Okta/Auth0
				azureTenantId: tenant.azure_tenant_id, // For Azure
				clientId: tenant.client_id,
				clientSecret: tenant.client_secret,
				scope: tenant.scope || 'openid profile email',
			};
		},
	});
}
```

### 3. Distribute SSO Links

Each organization gets a unique login URL to distribute to their employees:

```
https://yourapp.com/oauth/acme-corp/login
https://yourapp.com/oauth/globex/login
https://yourapp.com/oauth/initech/login
```

**How organizations use these links:**

- Add to SSO portal (Okta, Azure)
- Bookmark for employees
- Include in onboarding emails
- Display on login page

## Frontend Integration

### Option 1: Direct SSO Links (Recommended)

Each organization gets a unique login URL:

```
https://yourapp.com/oauth/acme-corp/login
https://yourapp.com/oauth/globex/login
```

Users access their organization's specific URL (typically bookmarked or linked from their SSO portal).

**Benefits:**

- No email domain issues (contractors, shared domains)
- Users can belong to multiple organizations
- No security enumeration risks
- Simple implementation

### Option 2: Organization Picker

If you need a login page that lists organizations, fetch tenants from your database and display them. Important: Always sanitize tenant names with `sanitizeTenantName()` before displaying in HTML to prevent XSS.

**Note on Email-Based Discovery:** While you could implement email domain lookup (e.g., `user@acme.com` → redirect to `acme-corp` tenant), this pattern has challenges:

- Contractors with vendor emails can't be reliably mapped
- Users in multiple organizations create ambiguity
- Requires storing and maintaining email domain mappings
- Adds complexity without significant UX benefit over direct links

For most applications, Direct SSO Links (Option 1) provide a simpler, more reliable user experience.

## OAuth Endpoints

Each tenant automatically gets these endpoints:

| Endpoint                     | Method | Description            |
| ---------------------------- | ------ | ---------------------- |
| `/oauth/{tenantId}/login`    | GET    | Initiates OAuth flow   |
| `/oauth/{tenantId}/callback` | GET    | OAuth callback handler |
| `/oauth/logout`              | POST   | Clears session         |

## Adding New Tenants

### Static Configuration

Define tenants in your application code:

```typescript
export async function handleApplication(scope) {
	registerHooks({
		async onResolveProvider(tenantId) {
			const staticTenants = {
				'acme-corp': {
					provider: 'okta',
					domain: 'acme-corp.okta.com',
					clientId: process.env.ACME_CLIENT_ID,
					clientSecret: process.env.ACME_CLIENT_SECRET,
				},
				'globex': {
					provider: 'azure',
					azureTenantId: process.env.GLOBEX_TENANT_ID,
					clientId: process.env.GLOBEX_CLIENT_ID,
					clientSecret: process.env.GLOBEX_CLIENT_SECRET,
				},
			};

			return staticTenants[tenantId] || null;
		},
	});
}
```

**Best for:** Small number of enterprise customers.

### Database-Driven (Dynamic)

Load from database at runtime (shown in Quick Start above).

**Best for:** Moderate to large number of customers.

### Admin API

Create an admin endpoint to add tenants without redeployment. The endpoint should:

- Verify admin access
- Validate tenant data (use `validateTenantId()` and `validateDomainSafety()` from '@harperfast/oauth')
- Store tenant config in your database
- Encrypt `clientSecret` before storing

See `examples/multi-tenant-sso.js` for a complete implementation.

**Best for:** Internal admin-controlled tenant registration.

### Self-Service Registration

> ⚠️ **Security Warning**: Self-service registration requires domain ownership verification (DNS TXT records, email confirmation) to prevent attackers from registering domains they don't own. Implement verification BEFORE enabling self-service.

Self-service flow:

1. Validate OAuth credentials (test token exchange)
2. Send verification email to admin@{domain}
3. Store tenant as 'pending' status
4. Activate after verification confirmed

**Best for:** Large-scale B2B SaaS with proper security controls.

## Supported Providers

The OAuth plugin supports any OAuth 2.0 / OIDC provider:

### Built-in Presets

These providers have built-in URL templates (just provide domain):

- **Okta** - `provider: 'okta'`, `domain: 'company.okta.com'`
- **Azure AD** - `provider: 'azure'`, `azureTenantId: 'tenant-guid'`
- **Auth0** - `provider: 'auth0'`, `domain: 'company.auth0.com'`
- **Google** - `provider: 'google'` (no domain needed)
- **GitHub** - `provider: 'github'` (no domain needed)

### Custom Providers

Use `provider: 'custom'` for any OAuth 2.0 provider:

```typescript
{
  provider: 'custom',
  authorizationUrl: 'https://sso.company.com/oauth/authorize',
  tokenUrl: 'https://sso.company.com/oauth/token',
  userInfoUrl: 'https://sso.company.com/oauth/userinfo',
  clientId: '...',
  clientSecret: '...',
  scope: 'openid profile email',
}
```

Works with: OneLogin, Ping Identity, Keycloak, Salesforce, custom OAuth servers, etc.

## Security

### OAuth Plugin Handles

The OAuth plugin automatically provides:

- ✅ CSRF protection with state tokens
- ✅ Token validation and refresh
- ✅ Session isolation per tenant
- ✅ Path length limits (DoS prevention)
- ✅ Secure token storage (never logged)

### Your Application Must Handle

Multi-tenant systems require additional security:

#### 1. Domain Ownership Verification

**Only required for self-service registration**: If you allow public tenant registration (see "Self-Service Registration" above), you MUST verify that registrants own the domains they claim.

**Not required if:**

- You manually add tenants (Static Configuration)
- Admins add tenants through internal tools (Admin API)
- You work directly with customer IT teams to configure SSO

**Verification Methods** (for self-service only):

- **DNS TXT record** - Add verification code to DNS, query to confirm
- **Email verification** - Send link to `admin@domain.com`
- **Manual approval** - Admin reviews each registration

**Why verification matters for self-service:** Without it, attackers can register "gmail.com" with their own OAuth server and intercept all Gmail users attempting to log in.

#### 2. Secret Management

OAuth client secrets must be protected:

```typescript
// Good: Encrypt secrets in database
const encrypted = await encrypt(clientSecret);
await tables.tenants.put({ client_secret: encrypted });

// Good: Use secrets manager
const secret = await secretsManager.getSecret(`tenant/${id}/oauth-secret`);

// Bad: Store plaintext
await tables.tenants.put({ client_secret: 'plaintext' }); // ❌
```

**Options:**

- Environment variables (static tenants)
- Secrets manager (AWS, Azure, HashiCorp Vault)
- Database encryption (dynamic tenants)

#### 3. Access Control

- Rate limit login attempts
- Restrict admin endpoints to admins only
- Never expose complete tenant list publicly

## Session Structure

After successful OAuth login, the session contains:

```typescript
{
  user: 'username',          // Your app's username
  oauthUser: {               // OAuth profile
    username: string,
    email: string,
    name: string,
    role: string,
    provider: 'okta-acme-corp'
  },
  oauth: {                   // Token metadata
    provider: 'acme-corp',
    accessToken: string,
    refreshToken: string,
    expiresAt: number,
    // ...
  }
}
```

Access session data in your API endpoints via `request.session`:

```typescript
// In your Resource methods
async get(_target, request) {
	const username = request.session?.user;
	const email = request.session?.oauthUser?.email;
	const tenantId = request.session?.oauth?.provider;

	if (!username) {
		return { status: 401, body: { error: 'Not authenticated' } };
	}

	// ... return user's data
}
```

## Validation Utilities

The plugin exports security validation functions:

```typescript
import {
	validateDomainSafety, // Blocks suspicious domains
	validateEmailDomain, // Validates email format safely
	validateTenantId, // Validates tenant ID format
	sanitizeTenantName, // Sanitizes for HTML display
	validateAzureTenantId, // Validates Azure tenant GUID
} from '@harperfast/oauth';

// Example: Validate tenant registration
const result = validateDomainSafety(domain);
if (!result.safe) {
	return { status: 400, body: { error: result.reason } };
}
```

See [Security Best Practices](./security.md) for details.

## Lifecycle Hooks

Customize behavior with additional hooks (inside `handleApplication` where you have access to `scope.tables`):

```typescript
const { tables } = scope;

registerHooks({
	// Required: Resolve provider config
	async onResolveProvider(tenantId, logger) {
		// ... (shown above)
	},

	// Optional: User provisioning
	async onLogin(user, tokenResponse, session, request) {
		// Create/update user record in your database
		const userRecord = await tables.users.get(user.email);
		if (!userRecord) {
			await tables.users.put({
				id: user.email,
				name: user.name,
				role: user.role || 'user',
				tenant: session.oauth.provider,
			});
		}

		// Return custom session data
		return {
			user: user.email, // Override session username
			customField: 'value',
		};
	},

	// Optional: Cleanup on logout
	async onLogout(session, request) {
		// Log logout event
		await tables.audit_log.put({
			action: 'logout',
			user: session.user,
			timestamp: Date.now(),
		});
	},

	// Optional: Post-refresh actions
	async onTokenRefresh(session, refreshed, request) {
		if (refreshed) {
			// Token was refreshed
			logger.info('Token refreshed for user', session.user);
		}
	},
});
```

See [Lifecycle Hooks](./lifecycle-hooks.md) for details.

## Troubleshooting

### Tenant Not Found (404)

**Cause:** `onResolveProvider` returned `null`

**Fix:**

- Verify tenant ID in database matches URL
- Check tenant status is 'active'
- Confirm hook is registered

### OAuth Error: invalid_client

**Cause:** Client ID or secret incorrect

**Fix:**

- Verify credentials in database match OAuth app
- Check environment variables loaded
- Ensure no extra whitespace in secrets

### Session Lost After Restart

**Cause:** Dynamic providers not resolved from database

**Fix:** The plugin automatically re-resolves providers from your hook - no action needed. If sessions are lost, check session storage configuration.

## Next Steps

- [Lifecycle Hooks](./lifecycle-hooks.md) - User provisioning and custom logic
- [Token Refresh](./token-refresh-and-sessions.md) - Automatic token refresh
- [Security Best Practices](./security.md) - Production security checklist
- [API Reference](./api-reference.md) - Complete API documentation
