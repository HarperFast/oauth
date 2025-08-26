/**
 * OAuth Plugin Type Definitions
 */

import type { IncomingMessage } from 'node:http';

// ============================================================================
// OAuth Plugin Types
// ============================================================================

/**
 * OAuth Plugin Configuration
 * Runtime configuration for the OAuth plugin
 */
export interface OAuthPluginConfig {
	/** Enable debug mode to expose additional endpoints and information */
	debug?: boolean;
	/** OAuth provider configurations */
	providers?: Record<string, any>;
	/** Default redirect URI for all providers */
	redirectUri?: string;
	/** Default post-login redirect path */
	postLoginRedirect?: string;
	/** Default OAuth scopes */
	scope?: string;
	/** Default username claim path */
	usernameClaim?: string;
	/** Default role assignment */
	defaultRole?: string;
}

/**
 * OAuth Provider Configuration
 * Configuration options for an OAuth 2.0/OIDC provider
 */
export interface OAuthProviderConfig {
	/** Provider identifier (e.g., 'github', 'google', 'azure') */
	provider: string;
	clientId: string;
	clientSecret: string;
	authorizationUrl: string;
	tokenUrl: string;
	userInfoUrl: string;
	redirectUri?: string;
	/** OAuth scopes to request (space-separated) */
	scope?: string;
	/** JWKS URI for ID token validation (OIDC only) */
	jwksUri?: string | null;
	/** Expected token issuer for validation (OIDC only) */
	issuer?: string | null;
	/** Claim to use as username (dot notation supported for nested) */
	usernameClaim?: string;
	/** Claim containing user's email address */
	emailClaim?: string;
	/** Claim containing user's display name */
	nameClaim?: string;
	/** Claim containing user's role/group membership */
	roleClaim?: string;
	/** Default role if not found in claims */
	defaultRole?: string;
	/** URL to redirect after successful login */
	postLoginRedirect?: string;
	/** Prefer ID token claims over userinfo endpoint (OIDC) */
	preferIdToken?: boolean;
	/** Whether to fetch email from provider's dedicated email endpoint */
	fetchEmail?: boolean;
	/** Additional query parameters for authorization URL */
	additionalParams?: Record<string, string>;
	/** Custom function to fetch/transform user info */
	getUserInfo?: (accessToken: string, helpers: GetUserInfoHelpers) => Promise<any>;
	/** Provider-specific configuration function (e.g., for tenant/domain setup) */
	configure?: (param: string) => Partial<OAuthProviderConfig>;
}

/**
 * Helpers passed to custom getUserInfo function
 */
export interface GetUserInfoHelpers {
	/** Default getUserInfo implementation to call */
	getUserInfo: (accessToken: string) => Promise<any>;
	logger?: Logger;
}

/**
 * OAuth User Object
 * Represents a user authenticated via OAuth
 */
export interface OAuthUser {
	/** Username extracted from configured claim */
	username: string;
	role: string;
	/** OAuth provider name */
	provider: string;
	/** User ID from the OAuth provider */
	providerUserId?: string;
	email?: string;
	name?: string;
	/** Additional provider-specific data */
	metadata?: Record<string, any>;
}

/**
 * OAuth Token Response
 * Standard OAuth 2.0 token endpoint response
 */
export interface TokenResponse {
	access_token: string;
	/** Usually 'Bearer' */
	token_type?: string;
	/** Token lifetime in seconds */
	expires_in?: number;
	refresh_token?: string;
	/** ID token for OIDC providers */
	id_token?: string;
	/** Space-separated granted scopes */
	scope?: string;
}

/**
 * CSRF Token Data
 * Metadata stored with CSRF tokens during OAuth flow
 */
export interface CSRFTokenData {
	/** Unix timestamp when token was created */
	timestamp: number;
	/** URL to redirect to after successful authentication */
	originalUrl?: string;
	/** Session ID to link OAuth flow with existing session */
	sessionId?: string;
	[key: string]: any;
}

/**
 * OAuth Provider Interface
 * Methods that OAuthProvider class implements
 */
export interface IOAuthProvider {
	config: OAuthProviderConfig;
	logger?: Logger;
	/** Generate CSRF token for OAuth state parameter */
	generateCSRFToken(metadata: Record<string, any>): Promise<string>;
	/** Verify and consume CSRF token (one-time use) */
	verifyCSRFToken(token: string): Promise<CSRFTokenData | null>;
	/** Build authorization URL with all required parameters */
	getAuthorizationUrl(state: string, redirectUri: string): string;
	/** Exchange authorization code for access/refresh tokens */
	exchangeCodeForToken(code: string, redirectUri: string): Promise<TokenResponse>;
	/** Fetch user information from provider */
	getUserInfo(accessToken: string, idTokenClaims?: any): Promise<any>;
	/** Map provider user info to Harper user format */
	mapUserToHarper(userInfo: any): OAuthUser;
	/** Verify and decode ID token (OIDC only) */
	verifyIdToken?(idToken: string): Promise<any>;
	/** Exchange refresh token for new access token */
	refreshAccessToken?(refreshToken: string): Promise<TokenResponse>;
}

/**
 * Provider Registry Entry
 * Stores initialized provider instance with its config
 */
export interface ProviderRegistryEntry {
	/** Initialized OAuth provider instance */
	provider: IOAuthProvider;
	config: OAuthProviderConfig;
}

/**
 * Provider Registry
 * Collection of all configured OAuth providers keyed by name
 */
export interface ProviderRegistry {
	[providerName: string]: ProviderRegistryEntry;
}

// ============================================================================
// Harper Core Types
// These types are from Harper core and should be removed once the plugin
// can properly import them from Harper
// ============================================================================

/**
 * Harper Plugin Scope
 * The context object passed to plugin initialization
 */
export interface Scope {
	logger?: Logger;
	/** Plugin configuration from config.yaml */
	options: {
		getAll(): Record<string, any>;
	};
	/** Resource registration API */
	resources: {
		set(name: string, resource: any): void;
	};
}

/**
 * Harper User
 * Minimal user interface from Harper core
 */
export interface User {
	username: string;
	// Harper's actual User has more fields but this is the minimal interface
}

/**
 * Harper Table Instance
 * Methods available on a Harper table
 */
export interface Table {
	get(id: string): Promise<any>;
	put(record: any): Promise<any>;
	delete(id: string): Promise<void>;
}

/**
 * Logger Interface
 */
export interface Logger {
	info?: (message: string, ...args: any[]) => void;
	error?: (message: string, ...args: any[]) => void;
	warn?: (message: string, ...args: any[]) => void;
	debug?: (message: string, ...args: any[]) => void;
}

/**
 * Harper HTTP Request
 * Extended Node.js IncomingMessage with Harper additions
 * Note: Harper doesn't have a specific Request type, it adds properties to IncomingMessage
 */
export interface Request extends IncomingMessage {
	/** Authenticated Harper user or username string */
	user?: User | string;
	session?: Session;
	headers: IncomingMessage['headers'];
}

/**
 * Harper Session
 * Session data stored for authenticated users
 */
export interface Session {
	id?: string;
	/** Harper username (string) */
	user?: string;
	/** Full OAuth user object */
	oauthUser?: OAuthUser;
	/** Current OAuth access token */
	oauthToken?: string;
	/** OAuth refresh token for token renewal */
	oauthRefreshToken?: string;
	/** Async session update method (when available) */
	update?: (data: Partial<Session>) => Promise<void>;
}

/**
 * Request Target
 * Harper's RequestTarget extends URLSearchParams with routing information
 * Note: This is a simplified interface - actual RequestTarget extends URLSearchParams
 */
export interface RequestTarget {
	/** Resource identifier from URL path */
	id?: string;
	pathname?: string;
	/** Inherited from URLSearchParams - get query parameter value */
	get(key: string): string | null;
	/** Additional properties exist on the real RequestTarget */
	[key: string]: any;
}
