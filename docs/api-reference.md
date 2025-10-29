# API Reference

Complete reference for all OAuth plugin endpoints and programmatic APIs.

## OAuth Flow Endpoints

### Login Endpoint

**Endpoint:** `GET /oauth/{provider}/login`

Initiates the OAuth authentication flow by redirecting to the provider's authorization page.

**Parameters:**

- `provider` - Provider name (github, google, azure, auth0, custom)

**Query Parameters:**

- `redirect` - URL to redirect to after successful authentication (optional)

**Example:**

```
GET /oauth/github/login
GET /oauth/google/login?redirect=/dashboard
```

**Response:**

- HTTP 302 redirect to provider's authorization URL
- Sets CSRF token in database with 10-minute expiration

---

### Callback Endpoint

**Endpoint:** `GET /oauth/{provider}/callback`

Handles the OAuth callback from the provider. This URL must be configured in your OAuth provider settings.

**Parameters:**

- `provider` - Provider name

**Query Parameters:**

- `code` - Authorization code from provider (required)
- `state` - CSRF token state parameter (required)
- `error` - Error code if authentication failed (optional)

**Response:**

- HTTP 302 redirect to original URL or home page
- Sets session cookie with user and OAuth data

**Error Responses:**

- `?error=access_denied` - User denied authorization
- `?error=invalid_state` - CSRF validation failed
- `?error=invalid_code` - Code exchange failed
- `?error=session_expired` - CSRF token expired (>10 minutes)

---

### Logout Endpoint

**Endpoint:** `POST /oauth/{provider}/logout`

Logs out the user and clears their OAuth session.

**Parameters:**

- `provider` - Provider name (optional, any provider works)

**Response:**

```json
{
	"message": "Logged out successfully"
}
```

**Example:**

```bash
curl -X POST http://localhost:9926/oauth/github/logout \
  -H "Cookie: session=your_session_cookie"
```

---

## Debug Endpoints

These endpoints are only available when `debug: true` is configured.

### List Providers

**Endpoint:** `GET /oauth/`

Lists all configured OAuth providers.

**Response:**

```json
{
	"providers": ["github", "google", "azure", "auth0"],
	"debug": true
}
```

---

### Test Page

**Endpoint:** `GET /oauth/test`

Interactive HTML page for testing OAuth providers.

**Response:** HTML page with login buttons for each provider

---

### User Info

**Endpoint:** `GET /oauth/{provider}/user`

Returns current user information and token status.

**Response:**

```json
{
	"authenticated": true,
	"user": "username",
	"oauthUser": {
		"username": "username",
		"email": "user@example.com",
		"name": "User Name",
		"role": "user"
	},
	"oauth": {
		"provider": "github",
		"expiresAt": 1234567890,
		"refreshThreshold": 1234567800,
		"scope": "user:email",
		"tokenType": "Bearer",
		"lastRefreshed": 1234567890,
		"timeUntilExpiry": 3600000,
		"needsRefresh": false
	}
}
```

**Unauthenticated Response:**

```json
{
	"authenticated": false
}
```

---

### Token Refresh Status

**Endpoint:** `GET /oauth/{provider}/refresh`

Checks token status and triggers refresh if needed.

**Response (No refresh needed):**

```json
{
	"refreshed": false,
	"message": "Token still valid",
	"expiresIn": 3600000
}
```

**Response (Token refreshed):**

```json
{
	"refreshed": true,
	"message": "Token refreshed successfully",
	"expiresIn": 3600000
}
```

---

## Programmatic API

### registerHooks()

Register lifecycle hooks programmatically.

**Import:**

```javascript
import { registerHooks } from '@harperdb/oauth';
```

**Signature:**

```typescript
function registerHooks(hooks: { onLogin?: Function; onLogout?: Function; onTokenRefresh?: Function }): void;
```

**Example:**

```javascript
registerHooks({
	onLogin: async (oauthUser, tokenResponse, session, request, provider) => {
		return { userId: user.id };
	},
	onLogout: async (session, request) => {
		console.log('User logged out');
	},
	onTokenRefresh: async (session, refreshed, request) => {
		if (refreshed) console.log('Token refreshed');
	},
});
```

**Note:** Must be called before the OAuth plugin initializes (typically at module load time).

---

## Session Structure

The OAuth plugin stores the following data in `request.session`:

```typescript
interface OAuthSession {
	// Harper username (mapped from OAuth profile)
	user: string;

	// OAuth user profile
	oauthUser: {
		username: string;
		email: string;
		name: string;
		role: string;
	};

	// OAuth token metadata
	oauth: {
		provider: string; // Provider name
		accessToken: string; // OAuth access token
		refreshToken?: string; // OAuth refresh token (if available)
		expiresAt: number; // Token expiration timestamp (ms)
		refreshThreshold: number; // When to refresh (80% of expiry)
		scope: string; // OAuth scopes granted
		tokenType: string; // Usually 'Bearer'
		lastRefreshed: number; // Last refresh timestamp (ms)
	};

	// Custom data from onLogin hook
	[key: string]: any;
}
```

**Accessing session in your code:**

```javascript
export class MyResource extends tables.Resource {
	async get(target, request) {
		// Check if user is authenticated
		if (!request.session?.oauthUser) {
			throw new ClientError('Not authenticated', 401);
		}

		// Access user data
		const email = request.session.oauthUser.email;
		const userId = request.session.userId; // From onLogin hook

		return { email, userId };
	}
}
```

---

## Token Refresh Behavior

The OAuth plugin automatically refreshes tokens on every HTTP request using the following logic:

1. **Check expiration:** If current time > `refreshThreshold`, attempt refresh
2. **Refresh threshold:** Set to 80% of token lifetime
3. **Call onTokenRefresh hook:** After successful refresh
4. **Auto-logout:** If refresh fails (invalid/expired refresh token)

**Example timeline:**

```
Token issued: 0 seconds
Token expires: 3600 seconds (1 hour)
Refresh threshold: 2880 seconds (48 minutes)
First refresh attempt: At 48 minutes
```

**Manual refresh check:**

```javascript
// In your code, token refresh happens automatically
// You don't need to do anything special

export class MyResource extends tables.Resource {
	async get(target, request) {
		// Token is already refreshed if needed before this handler runs
		const token = request.session?.oauth?.accessToken;

		// Use the token (always fresh)
		return await fetchExternalAPI(token);
	}
}
```

---

## Error Handling

### Authentication Errors

```javascript
import { ClientError } from 'harperdb';

export class ProtectedResource extends tables.Resource {
	async get(target, request) {
		if (!request.session?.oauthUser) {
			throw new ClientError('Authentication required', 401);
		}

		// Check custom permissions from onLogin hook
		if (!request.session?.roles?.includes('admin')) {
			throw new ClientError('Insufficient permissions', 403);
		}

		return { data: 'protected' };
	}
}
```

### OAuth Flow Errors

Common error codes in callback URL:

| Error             | Description                        | Solution                         |
| ----------------- | ---------------------------------- | -------------------------------- |
| `access_denied`   | User denied authorization          | User must grant permissions      |
| `invalid_state`   | CSRF validation failed             | Check callback URL configuration |
| `invalid_code`    | Authorization code invalid/expired | Retry authentication flow        |
| `session_expired` | CSRF token expired (>10 min)       | Retry authentication flow        |

---

## Rate Limiting Considerations

OAuth providers have rate limits on their APIs:

- **Token refresh:** Avoid unnecessary refreshes (handled automatically)
- **User info calls:** Cached in session, not called on every request
- **JWKS fetching:** Cached by `jwks-rsa` library

---

## Security Best Practices

### 1. Use HTTPS in Production

OAuth requires HTTPS for callback URLs. Configure your Harper server with TLS:

```yaml
http:
  securePort: 9926

tls:
  certificate: /path/to/cert.pem
  privateKey: /path/to/key.pem
```

### 2. Validate Session Data

Always check authentication before accessing protected resources:

```javascript
if (!request.session?.oauthUser) {
	throw new ClientError('Not authenticated', 401);
}
```

### 3. Don't Expose Tokens

Never return OAuth tokens in API responses:

```javascript
// ❌ Bad - exposes token
return { user: request.session };

// ✅ Good - only return safe data
return {
	email: request.session.oauthUser.email,
	name: request.session.oauthUser.name,
};
```

---

## Next Steps

- [Configuration reference](./configuration.md)
- [Lifecycle hooks](./lifecycle-hooks.md)
- [OAuth provider setup](./providers.md)
