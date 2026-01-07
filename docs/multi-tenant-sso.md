# Multi-Tenant SSO with Okta

Enable multiple enterprises to sign in using their own Okta instances. Perfect for B2B SaaS applications where each customer has their own identity provider.

## Overview

The multi-tenant SSO system allows you to:

- **Register multiple tenants** - Each enterprise customer brings their own Okta
- **Automatic tenant discovery** - Route users by email domain
- **Tenant selection UI** - Beautiful selection page when users have multiple orgs
- **Zero configuration changes** - Add new tenants without redeploying

## Architecture

```
User visits app → Enters email → Discovers tenant → Redirects to tenant's Okta → Returns authenticated
```

## Quick Start

### 1. Install and Import

```typescript
import { TenantManager } from '@harperdb/oauth';
```

### 2. Configure Tenants

Create a configuration file or store in your database. Supports Okta, Azure AD, Auth0, and any OAuth provider:

```typescript
const tenants = [
	// Okta tenant
	{
		tenantId: 'acme-corp',
		name: 'Acme Corporation',
		provider: 'okta',
		domain: 'acme-corp.okta.com',
		clientId: process.env.ACME_CLIENT_ID,
		clientSecret: process.env.ACME_CLIENT_SECRET,
		emailDomains: ['acme.com', 'acmecorp.com'],
	},
	// Azure AD tenant
	{
		tenantId: 'globex',
		name: 'Globex Industries',
		provider: 'azure',
		azureTenantId: process.env.GLOBEX_TENANT_ID,
		clientId: process.env.GLOBEX_CLIENT_ID,
		clientSecret: process.env.GLOBEX_CLIENT_SECRET,
		emailDomains: ['globex.com'],
	},
	// Auth0 tenant
	{
		tenantId: 'initech',
		name: 'Initech',
		provider: 'auth0',
		domain: 'initech.auth0.com',
		clientId: process.env.INITECH_CLIENT_ID,
		clientSecret: process.env.INITECH_CLIENT_SECRET,
		emailDomains: ['initech.com'],
	},
];
```

### 3. Setup in Your Harper Application

```typescript
// In your Harper application entry point
import { TenantManager, sanitizeTenantName } from '@harperdb/oauth';

export async function handleApplication(scope) {
	// Initialize tenant manager
	const tenantManager = TenantManager.fromConfig({
		tenants,
		logger: scope.logger,
	});

	// Convert tenants to provider registry
	const tenantProviders = tenantManager.toProviderRegistry();

	// Initialize OAuth plugin with tenant providers
	scope.options.providers = {
		// Static providers (optional)
		github: {
			provider: 'github',
			clientId: process.env.GITHUB_CLIENT_ID,
			clientSecret: process.env.GITHUB_CLIENT_SECRET,
		},
		// Merge tenant providers
		...Object.fromEntries(Object.entries(tenantProviders).map(([id, entry]) => [id, entry.config])),
	};

	// Add login page with tenant selection
	// Note: Discovery should be internal to your app, not a public API
	scope.resources.set('login', {
		async get(_target, request) {
			// If user is already authenticated, redirect to app
			if (request.session?.user) {
				return { status: 302, headers: { Location: '/dashboard' } };
			}

			// Get list of configured tenants for selection UI
			const tenants = tenantManager.getAllTenants().map((t) => ({
				id: t.tenantId,
				name: t.name,
				loginUrl: `/oauth/${t.tenantId}/login`,
			}));

			// Return HTML tenant selection page
			// IMPORTANT: Use sanitizeTenantName() to prevent XSS attacks
			// In production, customize this UI to match your brand
			return {
				status: 200,
				headers: { 'Content-Type': 'text/html' },
				body: `
          <!DOCTYPE html>
          <html>
            <head><title>Sign In</title></head>
            <body>
              <h1>Sign in to Your Organization</h1>
              ${tenants
								.map(
									(t) => `
                <a href="${t.loginUrl}">${sanitizeTenantName(t.name)}</a>
              `
								)
								.join('')}
            </body>
          </html>
        `,
			};
		},
	});
}
```

## OAuth Endpoints

Once configured, each tenant gets these OAuth endpoints:

### Tenant-Specific Login

**GET /oauth/{tenantId}/login**

Initiates OAuth login flow for a specific tenant. Redirects to the tenant's OAuth provider (Okta, Azure AD, Auth0, etc.).

Example: `/oauth/acme-corp/login`

### OAuth Callback

**GET /oauth/callback**

Handles the OAuth callback from all providers. This is shared across all tenants.

### Logout

**POST /oauth/logout**

Clears the user's session.

## User Experience Flows

### Flow 1: Email-Based Discovery

```typescript
// In your frontend
async function handleLogin(email) {
	const response = await fetch(`/sso/discover?email=${email}`);
	const result = await response.json();

	if (result.found) {
		// Redirect to their organization's login
		window.location.href = result.loginUrl;
	} else {
		// Show error: "No organization found for this email"
	}
}
```

### Flow 2: Organization Selector

```html
<!-- Link to the tenant selection page -->
<a href="/login">Sign in with SSO</a>
```

Users see a beautiful page listing all organizations and can search/select theirs.

### Flow 3: Direct Link

For users who know their organization:

```html
<a href="/oauth/acme-corp/login">Sign in as Acme Corporation</a>
```

## Frontend Integration Example

### React Component

```typescript
import { useState } from 'react';

function SSOLogin() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch(`/sso/discover?email=${encodeURIComponent(email)}`);
      const result = await response.json();

      if (result.found) {
        // Redirect to their Okta login
        window.location.href = result.loginUrl;
      } else {
        setError('No organization found for this email address');
      }
    } catch (err) {
      setError('Failed to discover organization');
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter your work email"
        required
      />
      <button type="submit" disabled={loading}>
        {loading ? 'Discovering...' : 'Continue with SSO'}
      </button>
      {error && <p className="error">{error}</p>}

      <a href="/login">Or choose your organization</a>
    </form>
  );
}
```

## Dynamic Tenant Registration

Load tenants from database at runtime:

```typescript
// Load from Harper table
const tenantsTable = tables.tenants;
const tenantRecords = await tenantsTable.search();

const tenants = tenantRecords.map((record) => ({
	tenantId: record.id,
	name: record.name,
	provider: record.provider || 'okta',
	domain: record.okta_domain || record.domain,
	azureTenantId: record.azure_tenant_id,
	clientId: record.client_id,
	clientSecret: record.client_secret,
	emailDomains: record.email_domains,
}));

const tenantManager = TenantManager.fromConfig({
	tenants,
	logger: scope.logger,
});
```

## Adding New Tenants

### Option 1: Pre-Configured Tenants

**Best for:** Small number of enterprise customers where you manage the configuration.

Add to your tenants array and restart:

```typescript
const tenants = [
	// ... existing tenants
	{
		tenantId: 'new-customer',
		name: 'New Customer Inc',
		provider: 'okta',
		domain: 'new-customer.okta.com',
		clientId: process.env.NEW_CUSTOMER_CLIENT_ID,
		clientSecret: process.env.NEW_CUSTOMER_CLIENT_SECRET,
		emailDomains: ['newcustomer.com'],
	},
];
```

### Option 2: Admin API

**Best for:** Moderate number of customers, admin-controlled registration.

Create an admin endpoint to add tenants dynamically:

```typescript
scope.resources.set('admin/tenants', {
	async post(data, target, request) {
		// Verify admin access
		if (request.user?.role !== 'admin') {
			return { status: 403, body: { error: 'Forbidden' } };
		}

		// Register new tenant
		tenantManager.registerTenant({
			tenantId: data.tenantId,
			name: data.name,
			provider: data.provider,
			domain: data.domain,
			azureTenantId: data.azureTenantId,
			clientId: data.clientId,
			clientSecret: data.clientSecret,
			emailDomains: data.emailDomains,
		});

		// Persist to database
		await tenantsTable.put(data);

		return { message: 'Tenant registered successfully' };
	},
});
```

### Option 3: Self-Service Registration (Allow Any Tenant)

> ⚠️ **IMPORTANT: Application-Level Security Required**
>
> Self-service tenant registration is a **reference example** showing how to dynamically register OAuth providers.
> Your application MUST implement these security controls before production use:
>
> - **Domain ownership verification** (DNS TXT records, email confirmation, etc.)
> - **Admin approval workflows**
> - **Rate limiting** on registration endpoints
>
> The OAuth plugin handles authentication; tenant management security is your application's responsibility.

**Best for:** Large-scale B2B SaaS where enterprises self-onboard (with application-enforced security).

Instead of pre-configuring tenants, let enterprises register their own OAuth provider through your application:

```typescript
scope.resources.set(
	'register-org',
	createTenantRegistrationResource(tenantManager, tables.tenants, providerRegistry, logger)
);
```

**User Flow:**

1. Enterprise admin visits `/register-org`
2. Fills in form:
   - Organization name
   - OAuth provider (Okta/Azure/Auth0)
   - Provider-specific details (domain, tenant ID)
   - Client ID & Secret from their OAuth app
   - Email domains for auto-discovery
   - Admin email for verification
3. System validates OAuth credentials
4. Sends verification email
5. Once verified, organization is active
6. Their users can now sign in via SSO

**Benefits:**

- **Zero manual work** - Enterprises onboard themselves
- **Scales infinitely** - Support unlimited organizations
- **No deployment** - New tenants added without code changes
- **Validation built-in** - Test OAuth credentials before accepting

**Example Registration Form Response:**

```json
{
	"message": "Organization registered successfully",
	"tenantId": "acme-corp",
	"loginUrl": "/oauth/acme-corp/login",
	"nextSteps": ["Verify your email address", "Test the login flow", "Add your team members"]
}
```

**Implementation Requirements:**

- Registration form with provider-specific fields
- OAuth credential validation before acceptance
- Email verification flow
- Database persistence for tenant configurations
- Admin approval workflow (recommended)

## Supported Identity Providers

The multi-tenant system works with **any OAuth 2.0 / OIDC provider**. Here are commonly requested enterprise providers:

### Built-in Support

- **Okta** - Most popular enterprise SSO
- **Azure AD / Microsoft Entra ID** - Microsoft enterprise
- **Auth0** - Developer-friendly identity platform
- **Google** - Google Workspace for enterprises

### Easy to Add

These providers work with the generic OAuth configuration:

- **OneLogin** - `provider: 'generic'` with OneLogin endpoints
- **Ping Identity** - PingOne/PingFederate with custom domains
- **Keycloak** - Self-hosted, custom domain per tenant
- **AWS Cognito** - Different user pool per tenant
- **Salesforce Identity** - Each Salesforce org
- **SAP Cloud Identity** - SAP enterprise customers
- **Custom OAuth Servers** - IdentityServer, Ory, etc.

### Example: OneLogin Tenant

```typescript
{
  tenantId: 'acme-corp',
  name: 'Acme Corporation',
  provider: 'generic',
  domain: 'acme-corp.onelogin.com',
  clientId: process.env.ACME_CLIENT_ID,
  clientSecret: process.env.ACME_CLIENT_SECRET,
  emailDomains: ['acme.com'],
  additionalConfig: {
    authorizationUrl: 'https://acme-corp.onelogin.com/oidc/2/auth',
    tokenUrl: 'https://acme-corp.onelogin.com/oidc/2/token',
    userInfoUrl: 'https://acme-corp.onelogin.com/oidc/2/me',
    scope: 'openid profile email',
  }
}
```

### Adding New Provider Presets

To add a new built-in provider (like OneLogin):

1. Create `src/lib/providers/onelogin.ts`:

```typescript
export const OneLoginProvider: OAuthProviderConfig = {
	provider: 'onelogin',
	authorizationUrl: '', // Set by configure()
	tokenUrl: '', // Set by configure()
	userInfoUrl: '', // Set by configure()
	scope: 'openid profile email',

	configure: (domain: string) => {
		const cleanDomain = domain.replace(/^https?:\/\//, '');
		return {
			authorizationUrl: `https://${cleanDomain}/oidc/2/auth`,
			tokenUrl: `https://${cleanDomain}/oidc/2/token`,
			userInfoUrl: `https://${cleanDomain}/oidc/2/me`,
		};
	},
};
```

2. Add to `src/lib/providers/index.ts`
3. Use like any other provider: `provider: 'onelogin'`

## Security Considerations

### OAuth Plugin Responsibilities

The OAuth plugin provides secure authentication:

- **Secure OAuth flows** - CSRF protection, token validation, automatic refresh
- **Email format validation** - Prevents injection attacks on discovery endpoints
- **Session isolation** - Each tenant's tokens and sessions are isolated
- **Token security** - Never logs tokens, never exposes in error messages
- **Configurable endpoint exposure** - Control which discovery endpoints are publicly accessible

### Your Application's Responsibilities

Multi-tenant systems require application-level security controls beyond OAuth:

#### 1. Domain Ownership Verification (Required for Production)

**The only reliable security control:** Verify that registrants actually own the domains they claim.

Methods (use at least one):

- **DNS TXT record verification** - Require adding a verification code to DNS
  - Example: `_acme-challenge.company.com TXT "verification-code-12345"`
  - Query DNS to confirm before activating tenant
- **Email-based verification** - Send confirmation link to `admin@domain.com` or `postmaster@domain.com`
  - Requires recipient to have access to domain email
- **Manual admin approval** - Review and approve each new tenant registration
  - Scalability trade-off but strongest assurance

**Why this matters:** Without domain verification:

- Attacker registers "gmail.com" and intercepts all Gmail users
- Attacker claims competitor domains
- Anyone can impersonate any organization

#### 2. Security Best Practices

**Tenant Discovery:**

- Keep tenant discovery internal to your application
- Look up organizations in your own database, not via public API
- Never expose complete tenant lists publicly to prevent customer enumeration

**Access Control:**

- Rate limit login attempts for standard brute force protection
- Validate all tenant configuration automatically (TenantManager handles this)
- Only allow organization admins to configure OAuth settings

#### 3. Secret Management

OAuth client secrets require protection:

- **Environment variables** - For static tenant configurations
- **Secrets manager** - AWS Secrets Manager, Azure Key Vault, HashiCorp Vault
- **Encryption at rest** - If storing in database, encrypt the `client_secret` field
- **Never log** - Ensure secrets never appear in application logs

```javascript
// Good: Load from environment or secrets manager
const clientSecret = await secretsManager.getSecret(`tenant/${tenantId}/oauth-secret`);

// Bad: Store in plaintext database
await db.put({ clientSecret: 'plain-text-secret' }); // ❌ Don't do this
```

### Built-in OAuth Plugin Security

For reference, the OAuth plugin automatically handles:

- ✅ CSRF protection with state tokens (10-minute expiry)
- ✅ Token security (never logged or exposed)
- ✅ Email injection prevention
- ✅ Path length limits (DoS prevention)
- ✅ Session isolation per tenant

## Testing

### Test Tenant Discovery

```bash
# Discover tenant by email
curl "http://localhost:9926/sso/discover?email=user@acme.com"

# List all tenants
curl "http://localhost:9926/sso/tenants"
```

### Test Login Flow

1. Visit `/login` to see tenant selection page
2. Enter email or select organization
3. Complete Okta authentication
4. Verify session contains tenant info

## Enterprise Onboarding Workflow

1. **Customer creates Okta application**
   - Follow [Okta setup guide](./providers.md#okta-oidc)
   - Provide you with: domain, client ID, client secret, email domains

2. **You register the tenant**
   - Add configuration to your app
   - Deploy or use admin API to register

3. **Customer's users can log in**
   - Via email discovery
   - Via organization selector
   - Via direct link

## Troubleshooting

### Tenant Not Found

**Issue:** User email doesn't match any tenant

**Solution:**

- Verify email domain is in `emailDomains` array
- Check for typos in domain configuration
- Ensure domain matching is case-insensitive

### Wrong OAuth Provider Instance

**Issue:** User redirected to wrong OAuth provider

**Solution:**

- Verify `domain` (or `azureTenantId` for Azure) is correct for tenant
- Check for multiple tenants with overlapping domains
- Review email domain mapping

### Client Credentials Invalid

**Issue:** OAuth flow fails with invalid_client

**Solution:**

- Verify client ID and secret are correct
- Ensure credentials match the Okta application
- Check environment variables are loaded

## Next Steps

- [Configure lifecycle hooks](./lifecycle-hooks.md) for custom tenant logic
- [Review token refresh](./token-refresh-and-sessions.md) for session management
- [API reference](./api-reference.md) for advanced configuration
