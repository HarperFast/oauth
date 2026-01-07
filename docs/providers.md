# OAuth Provider Setup

Detailed setup instructions for each supported OAuth provider.

## Built-in Providers vs Active Providers

**Important distinction:**

- **Built-in providers** - Provider templates included in the OAuth plugin code (GitHub, Google, Azure, Auth0, Okta)
  - Zero runtime overhead - code presence ≠ execution
  - Not active until you configure them
  - No security risk from unused providers

- **Active providers** - Providers you explicitly configure with credentials
  - Only configured providers are instantiated and available for authentication
  - Each requires `clientId`, `clientSecret`, and OAuth URLs
  - Only these providers accept login requests

**Example:** The OAuth plugin includes Okta code, but Okta authentication is **not available** unless you configure an Okta provider with credentials. Built-in providers are templates, not active endpoints.

## GitHub OAuth

### 1. Create OAuth App

1. Go to GitHub Settings > Developer settings > [OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details:
   - **Application name:** Your app name
   - **Homepage URL:** `https://yourdomain.com`
   - **Authorization callback URL:** `https://yourdomain.com/oauth/github/callback`
4. Click "Register application"
5. Copy the **Client ID** and generate a **Client Secret**

### 2. Configure Plugin

```yaml
'@harperdb/oauth':
  providers:
    github:
      clientId: ${OAUTH_GITHUB_CLIENT_ID}
      clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
      scope: 'user:email' # Optional, default: 'user:email'
```

### 3. Environment Variables

```bash
export OAUTH_GITHUB_CLIENT_ID="your_client_id"
export OAUTH_GITHUB_CLIENT_SECRET="your_client_secret"
```

### Available Scopes

- `user` - Access user profile data
- `user:email` - Access user email addresses (default)
- `read:user` - Read-only access to user profile

[GitHub OAuth Scopes Documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)

---

## Google OAuth (OIDC)

### 1. Create OAuth Client

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Go to APIs & Services > Credentials
4. Click "Create Credentials" > "OAuth 2.0 Client ID"
5. Configure OAuth consent screen if prompted
6. Select "Web application" as application type
7. Add authorized redirect URI: `https://yourdomain.com/oauth/google/callback`
8. Copy the **Client ID** and **Client Secret**

### 2. Configure Plugin

```yaml
'@harperdb/oauth':
  providers:
    google:
      clientId: ${OAUTH_GOOGLE_CLIENT_ID}
      clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
      scope: 'openid profile email' # Optional, this is the default
```

### 3. Environment Variables

```bash
export OAUTH_GOOGLE_CLIENT_ID="your_client_id"
export OAUTH_GOOGLE_CLIENT_SECRET="your_client_secret"
```

### Available Scopes

- `openid` - OpenID Connect (required)
- `profile` - Access basic profile information
- `email` - Access email address

[Google OAuth Scopes Documentation](https://developers.google.com/identity/protocols/oauth2/scopes)

---

## Azure AD (OIDC)

### 1. Register Application

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to Azure Active Directory > App registrations
3. Click "New registration"
4. Fill in:
   - **Name:** Your application name
   - **Supported account types:** Choose appropriate option
   - **Redirect URI:** Web - `https://yourdomain.com/oauth/azure/callback`
5. Click "Register"
6. Copy the **Application (client) ID** and **Directory (tenant) ID**
7. Go to Certificates & secrets > New client secret
8. Copy the **Client Secret** value

### 2. Configure Plugin

```yaml
'@harperdb/oauth':
  providers:
    azure:
      clientId: ${OAUTH_AZURE_CLIENT_ID}
      clientSecret: ${OAUTH_AZURE_CLIENT_SECRET}
      tenantId: ${OAUTH_AZURE_TENANT_ID}
      scope: 'openid profile email' # Optional, this is the default
```

### 3. Environment Variables

```bash
export OAUTH_AZURE_CLIENT_ID="your_client_id"
export OAUTH_AZURE_CLIENT_SECRET="your_client_secret"
export OAUTH_AZURE_TENANT_ID="your_tenant_id"
```

### Available Scopes

- `openid` - OpenID Connect (required)
- `profile` - Access profile information
- `email` - Access email address
- `User.Read` - Read user profile

[Microsoft Graph Permissions](https://learn.microsoft.com/en-us/graph/permissions-reference)

---

## Auth0 (OIDC)

### 1. Create Application

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to Applications > Applications
3. Click "Create Application"
4. Choose "Regular Web Application"
5. Go to Settings tab
6. Copy **Domain**, **Client ID**, and **Client Secret**
7. Add to Allowed Callback URLs: `https://yourdomain.com/oauth/auth0/callback`
8. Add to Allowed Logout URLs: `https://yourdomain.com` (optional)
9. Save changes

### 2. Configure Plugin

```yaml
'@harperdb/oauth':
  providers:
    auth0:
      domain: ${OAUTH_AUTH0_DOMAIN}
      clientId: ${OAUTH_AUTH0_CLIENT_ID}
      clientSecret: ${OAUTH_AUTH0_CLIENT_SECRET}
      scope: 'openid profile email' # Optional, this is the default
```

### 3. Environment Variables

```bash
export OAUTH_AUTH0_DOMAIN="yourapp.auth0.com"
export OAUTH_AUTH0_CLIENT_ID="your_client_id"
export OAUTH_AUTH0_CLIENT_SECRET="your_client_secret"
```

### Available Scopes

- `openid` - OpenID Connect (required)
- `profile` - Access profile information
- `email` - Access email address

[Auth0 Scopes Documentation](https://auth0.com/docs/get-started/apis/scopes)

---

## Okta (OIDC)

### 1. Create Application

1. Go to [Okta Developer Console](https://developer.okta.com/)
2. Navigate to Applications > Applications
3. Click "Create App Integration"
4. Choose "OIDC - OpenID Connect"
5. Select "Web Application"
6. Fill in:
   - **App integration name:** Your application name
   - **Sign-in redirect URIs:** `https://yourdomain.com/oauth/okta/callback`
   - **Sign-out redirect URIs:** `https://yourdomain.com` (optional)
7. Click "Save"
8. Copy the **Client ID** and **Client Secret**
9. Note your **Okta domain** (e.g., `dev-12345.okta.com`)

### 2. Configure Plugin

```yaml
'@harperdb/oauth':
  providers:
    okta:
      domain: ${OAUTH_OKTA_DOMAIN}
      clientId: ${OAUTH_OKTA_CLIENT_ID}
      clientSecret: ${OAUTH_OKTA_CLIENT_SECRET}
      scope: 'openid profile email groups' # Optional, this is the default
```

### 3. Environment Variables

```bash
export OAUTH_OKTA_DOMAIN="dev-12345.okta.com"
export OAUTH_OKTA_CLIENT_ID="your_client_id"
export OAUTH_OKTA_CLIENT_SECRET="your_client_secret"
```

### Available Scopes

- `openid` - OpenID Connect (required)
- `profile` - Access profile information
- `email` - Access email address
- `groups` - Access user's group memberships (for role mapping)

### Group-Based Role Mapping

Okta supports mapping user groups to roles. The plugin will use the first group as the user's role:

```yaml
'@harperdb/oauth':
  providers:
    okta:
      domain: ${OAUTH_OKTA_DOMAIN}
      clientId: ${OAUTH_OKTA_CLIENT_ID}
      clientSecret: ${OAUTH_OKTA_CLIENT_SECRET}
      scope: 'openid profile email groups'
      # First group will be used as role, falls back to defaultRole
      defaultRole: 'user'
```

To include groups in the ID token:

1. In Okta Admin Console, go to Security > API > Authorization Servers
2. Select your authorization server (or "default")
3. Go to Claims tab
4. Add a claim with:
   - **Name:** `groups`
   - **Include in token type:** ID Token, Always
   - **Value type:** Groups
   - **Filter:** Matches regex `.*` (or filter to specific groups)

[Okta OAuth Documentation](https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/)

---

## Custom OIDC Provider

For other OpenID Connect compatible providers:

### Configuration

```yaml
'@harperdb/oauth':
  providers:
    custom:
      clientId: ${OAUTH_CUSTOM_CLIENT_ID}
      clientSecret: ${OAUTH_CUSTOM_CLIENT_SECRET}
      authorizationUrl: 'https://provider.com/oauth/authorize'
      tokenUrl: 'https://provider.com/oauth/token'
      userInfoUrl: 'https://provider.com/oauth/userinfo'
      jwksUrl: 'https://provider.com/.well-known/jwks.json'
      scope: 'openid profile email'
```

### Environment Variables

```bash
export OAUTH_CUSTOM_CLIENT_ID="your_client_id"
export OAUTH_CUSTOM_CLIENT_SECRET="your_client_secret"
export OAUTH_CUSTOM_AUTHORIZATION_URL="https://provider.com/oauth/authorize"
export OAUTH_CUSTOM_TOKEN_URL="https://provider.com/oauth/token"
export OAUTH_CUSTOM_USERINFO_URL="https://provider.com/oauth/userinfo"
export OAUTH_CUSTOM_JWKS_URL="https://provider.com/.well-known/jwks.json"
```

---

## Testing Your Configuration

1. Start your Harper application
2. Navigate to `http://localhost:9926/oauth/{provider}/login`
3. Complete the OAuth flow
4. Check your session for OAuth data

## Common Issues

### Redirect URI Mismatch

**Error:** `redirect_uri_mismatch` or similar

**Solution:** Ensure the redirect URI in your provider settings exactly matches:

```
https://yourdomain.com/oauth/{provider}/callback
```

### Invalid Client Credentials

**Error:** `invalid_client` or `unauthorized_client`

**Solution:**

- Verify client ID and secret are correct
- Check environment variables are set
- Ensure client secret hasn't expired

### Missing Email Address

**Error:** User email not available

**Solution:**

- Verify email scope is requested
- Check provider consent screen configuration
- Ensure user has granted email permission

## Next Steps

- [Configure lifecycle hooks](./lifecycle-hooks.md)
- [Review API reference](./api-reference.md)
