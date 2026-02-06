# Token Refresh and Session Management

How OAuth tokens and Harper sessions work together, including automatic refresh, expiration, and provider-specific behavior.

## How It Works

The plugin manages two related but separate things:

1. **OAuth tokens** - Access/refresh tokens from providers (GitHub, Google, etc.)
2. **Harper sessions** - Server-side session storage

They have different lifecycles and work together to keep users authenticated.

## Token Lifecycle

### Initial Login

When a user logs in via OAuth:

1. Authorization code exchanged for tokens
2. Token response includes:
   - `access_token` - For accessing provider APIs
   - `refresh_token` - For getting new access tokens (optional)
   - `expires_in` - Token lifetime in seconds (usually 3600 = 1 hour)
   - `id_token` - OIDC identity claims (OIDC providers only)

3. Session metadata stored:
   ```javascript
   {
     accessToken: "ya29...",
     refreshToken: "1//...",
     expiresAt: Date.now() + (expires_in * 1000),
     refreshThreshold: Date.now() + (expires_in * 800), // 80% of lifetime
     lastRefreshed: Date.now()
   }
   ```

### Automatic Token Refresh

Tokens refresh automatically via HTTP middleware:

- Runs on every HTTP request after authentication
- Refreshes at 80% of token lifetime (proactive, not reactive)
- Transparent to the application
- No user interaction required

```
Token lifetime: 3600 seconds (1 hour)
├─────────────────────────────────────────────┤
|                                       3600s
|                           │
0s                     2880s (80%)
                    refreshThreshold

Fresh     →    Valid     →   Needs Refresh  →  Expired
0-2880s        2880-3600s    (auto-refresh)    (logout if no refresh)
```

**What happens:**

- **0-80% lifetime**: Token valid, no action
- **80-100% lifetime**: Token still valid but approaching expiration
  - Refresh succeeds → new token, continue
  - Refresh fails → session stays valid (token not expired yet)
- **Past 100% (expired)**: Token no longer valid
  - Has refresh token → try refresh
    - Success → new token, continue
    - Failure → logout
  - No refresh token → logout immediately

See sessionValidator.ts:109 for the 80% refresh threshold calculation.

### Implementation

Middleware is registered in index.ts:151:

```typescript
scope.server.http(async (request, next) => {
	if (!request.session?.oauth) {
		return next(request);
	}

	// Validate and refresh if needed (automatic, transparent)
	const validation = await validateAndRefreshSession(request, provider, logger, hookManager);

	if (!validation.valid) {
		// Session cleared, user logged out
	} else if (validation.refreshed) {
		// Token refreshed, session updated
	}

	return next(request);
});
```

## Harper Sessions vs OAuth Tokens

### Session Storage

OAuth data lives in Harper's session system (`hdb_session` table):

```javascript
request.session = {
	id: 'session_abc123',
	user: 'user@example.com',
	oauthUser: {
		username: 'user@example.com',
		email: 'user@example.com',
		name: 'User Name',
		provider: 'google',
		role: 'user',
	},
	oauth: {
		provider: 'google',
		accessToken: 'ya29...',
		refreshToken: '1//...',
		expiresAt: 1700000000000,
		refreshThreshold: 1699920000000,
		scope: 'openid profile email',
		tokenType: 'Bearer',
		lastRefreshed: 1699919200000,
	},
};
```

### Different Lifecycles

Harper sessions persist longer than OAuth tokens. Sessions stay valid while tokens refresh multiple times:

```
Harper Session: ═══════════════════════════════════════════════════
OAuth Token 1:  ══════════════╗
OAuth Token 2:                ╚════════════════╗
OAuth Token 3:                                 ╚═══════════════╗
                Time ──────────────────────────────────────────→
                     1hr       2hr       3hr       4hr
```

### When Sessions End

Harper sessions expire based on Harper config (default 24 hours, configurable idle timeout). When tokens expire and can't be refreshed, the entire session is deleted from `hdb_session`.

See handlers.ts:clearOAuthSession() for cleanup implementation.

## Provider-Specific Behavior

| Provider     | Access Token Lifetime | Refresh Token     | Token Rotation | ID Token       | Notes                  |
| ------------ | --------------------- | ----------------- | -------------- | -------------- | ---------------------- |
| **GitHub**   | Never expires\*       | Not provided      | N/A            | No (OAuth 2.0) | \*Unless unused 1 year |
| **Google**   | 1 hour                | 6 months idle\*\* | No             | Yes (OIDC)     | \*\*Unless revoked     |
| **Azure AD** | 1-2 hours             | 90 days           | **Yes**        | Yes (OIDC)     | Rotates each refresh   |
| **Auth0**    | Configurable          | Configurable      | Configurable   | Yes (OIDC)     | Set in dashboard       |
| **Custom**   | Varies                | Varies            | Varies         | Varies         | Depends on provider    |

### GitHub (OAuth 2.0)

Tokens never expire (unless unused for 1 year or revoked). No refresh needed, but periodic validation runs to detect revocation.

```yaml
github:
  clientId: ${OAUTH_GITHUB_CLIENT_ID}
  clientSecret: ${OAUTH_GITHUB_CLIENT_SECRET}
  scope: 'user:email'
```

**Notes:**

- Session lasts as long as Harper session is valid
- Plugin fetches email from `/user/emails` if not public
- No `onTokenRefresh` hook calls (nothing to refresh)
- **Periodic validation** runs every 15 minutes to check if token was revoked
  - Makes lightweight HEAD request to `/user` endpoint
  - If invalid (401), session is cleared and user logged out
  - On network errors, validation skipped (no logout)

**Token Revocation:**
If user revokes app access in GitHub settings, the plugin will detect this within 15 minutes and clear the session automatically.

**Official docs:**

- [Authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [Token expiration and revocation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation)

**Config:** providers/github.ts

---

### Google (OpenID Connect)

Tokens expire in 1 hour. Refresh tokens provided with `offline_access` (don't expire unless inactive for 6 months).

```yaml
google:
  clientId: ${OAUTH_GOOGLE_CLIENT_ID}
  clientSecret: ${OAUTH_GOOGLE_CLIENT_SECRET}
  scope: 'openid profile email'
```

**Notes:**

- Token refreshes at 48 minutes (80% of 1 hour)
- Refresh token doesn't rotate
- Plugin automatically adds `access_type=offline` and `prompt=consent`
- ID token verified via JWKS

**Official docs:**

- [Using OAuth 2.0 to Access Google APIs](https://developers.google.com/identity/protocols/oauth2)

**Config:** providers/google.ts

---

### Azure AD (OpenID Connect)

Tokens expire in 1-2 hours (configurable per tenant). Refresh tokens valid for 90 days and rotate on each refresh.

```yaml
azure:
  clientId: ${OAUTH_AZURE_CLIENT_ID}
  clientSecret: ${OAUTH_AZURE_CLIENT_SECRET}
  tenantId: ${OAUTH_AZURE_TENANT_ID} # or 'common' for multi-tenant
  scope: 'openid profile email User.Read'
```

**Notes:**

- Old refresh token invalid after use (rotation)
- Session must be updated with new refresh token
- Tenant-specific JWKS for ID token verification

**Official docs:**

- [Refresh tokens in Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)
- [Access tokens in Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)

**Config:** providers/azure.ts

---

### Auth0 (OpenID Connect)

Token lifetime configurable (default varies by API). Refresh tokens optional with configurable expiration.

```yaml
auth0:
  domain: ${OAUTH_AUTH0_DOMAIN} # e.g., yourapp.auth0.com
  clientId: ${OAUTH_AUTH0_CLIENT_ID}
  clientSecret: ${OAUTH_AUTH0_CLIENT_SECRET}
  scope: 'openid profile email offline_access' # offline_access for refresh
```

**Notes:**

- Must include `offline_access` scope for refresh token
- Token expiration configured in Auth0 dashboard per API
- Refresh token rotation configurable (default: on)
- Supports both absolute and idle refresh token lifetimes

**Official docs:**

- [Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
- [Configure Refresh Token Expiration](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration)

**Config:** providers/auth0.ts

---

### Custom OIDC Provider

Behavior varies by provider. Follows standard OIDC spec.

```yaml
custom:
  clientId: ${OAUTH_CUSTOM_CLIENT_ID}
  clientSecret: ${OAUTH_CUSTOM_CLIENT_SECRET}
  authorizationUrl: 'https://provider.com/oauth/authorize'
  tokenUrl: 'https://provider.com/oauth/token'
  userInfoUrl: 'https://provider.com/oauth/userinfo'
  jwksUrl: 'https://provider.com/.well-known/jwks.json'
  scope: 'openid profile email'
```

## Lifecycle Hooks

### onTokenRefresh

Called after successful token refresh:

```typescript
registerHooks({
	onTokenRefresh: async (session, refreshed, request) => {
		if (refreshed) {
			console.log('Token refreshed for:', session.user);
			console.log('New expiration:', session.oauth.expiresAt);
		}
	},
});
```

**Use cases:** Audit logging, updating external systems, monitoring failures

### onLogout

Called before session is cleared (explicit logout or token expiration):

```typescript
registerHooks({
	onLogout: async (session, request) => {
		console.log('User logged out:', session.user);
		// Clean up temp data, notify external systems, etc.
	},
});
```

See [Lifecycle Hooks](./lifecycle-hooks.md) for details.

## Token Refresh is Automatic

No manual refresh needed or exposed. Middleware handles everything.

Need to force a refresh? Send any authenticated HTTP request to trigger middleware validation. In debug mode, use `GET /oauth/{provider}/refresh`.

## Debugging

Enable debug mode in config:

```yaml
'@harperfast/oauth':
  debug: true
```

### Debug Endpoints

- `GET /oauth/{provider}/user` - View session and token status
- `GET /oauth/{provider}/refresh` - Trigger validation/refresh

### Check Token Status

```bash
curl http://localhost:9926/oauth/google/user
```

Response:

```json
{
	"authenticated": true,
	"username": "user@example.com",
	"oauth": {
		"provider": "google",
		"expiresAt": 1700000000000,
		"refreshThreshold": 1699920000000,
		"lastRefreshed": 1699919200000,
		"hasRefreshToken": true,
		"tokenRefreshed": false
	}
}
```

### Common Issues

**Token refresh fails (401):**

- Refresh token expired or revoked
- Provider credentials changed
- Network issue

**Session cleared unexpectedly:**

- Token expired without valid refresh token
- Refresh failed and token already expired
- User revoked access in provider settings

**Token never refreshes:**

- Provider doesn't support refresh (GitHub)
- Refresh token not requested in initial flow
- Check provider config for refresh requirements

## Frontend Integration

Handle session expiration gracefully:

```javascript
fetch('/api/resource').then((response) => {
	if (response.status === 401) {
		// Session expired, redirect to login
		window.location.href = '/oauth/google/login?redirect=' + encodeURIComponent(window.location.pathname);
	}
	return response.json();
});
```

## Quick Reference

- Harper sessions and OAuth tokens expire independently
- Tokens auto-refresh at 80% lifetime (before expiration)
- Middleware validates tokens on every request
- Session cleared only when tokens expire AND can't refresh
- GitHub tokens never expire; others vary by provider
- Refresh failures at 80-100% don't cause logout
- Only expired tokens + failed refresh = logout

**Key files:**

- index.ts:151 - Middleware registration
- sessionValidator.ts:37 - Refresh logic
- handlers.ts - Session management
- providers/ - Provider-specific configs
