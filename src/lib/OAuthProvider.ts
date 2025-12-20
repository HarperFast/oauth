/**
 * OAuth Provider Base Class
 *
 * Handles OAuth 2.0 authentication flow with any compliant provider
 */

import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import type {
	OAuthProviderConfig,
	Logger,
	CSRFTokenData,
	TokenResponse,
	OAuthUser,
	GetUserInfoHelpers,
	IOAuthProvider,
} from '../types.ts';
import { csrfTokenManager } from './CSRFTokenManager.ts';

export class OAuthProvider implements IOAuthProvider {
	public config: OAuthProviderConfig;
	public logger?: Logger;
	private jwksClient?: jwksClient.JwksClient;

	constructor(config: OAuthProviderConfig, logger?: Logger) {
		this.config = config;
		this.logger = logger;
		// Pass logger to the singleton csrfTokenManager if not already set
		if (!csrfTokenManager['logger']) {
			csrfTokenManager['logger'] = logger;
		}
		this.validateConfig();
		this.initializeJwksClient();
	}

	private initializeJwksClient(): void {
		// Only initialize if we have a JWKS URI
		if (this.config.jwksUri) {
			this.jwksClient = jwksClient({
				jwksUri: this.config.jwksUri,
				cache: true, // Cache keys to avoid repeated fetches
				cacheMaxEntries: 5, // Max number of keys to cache
				cacheMaxAge: 10 * 60 * 60 * 1000, // 10 hours
				rateLimit: true, // Rate limit to prevent abuse
				jwksRequestsPerMinute: 10,
				// Timeout for JWKS fetch
				timeout: 5000,
			});

			this.logger?.info?.(`JWKS client initialized for ${this.config.provider}`);
		} else if (this.config.provider !== 'generic') {
			this.logger?.warn?.(
				`No JWKS URI configured for ${this.config.provider} - ID token signatures will not be verified`
			);
		}
	}

	private validateConfig(): void {
		const required = ['clientId', 'clientSecret', 'authorizationUrl', 'tokenUrl', 'userInfoUrl'];
		const missing = required.filter((key) => !this.config[key as keyof OAuthProviderConfig]);

		if (missing.length > 0) {
			throw new Error(`OAuth configuration missing required fields: ${missing.join(', ')}`);
		}
	}

	/**
	 * Generate authorization URL for OAuth login
	 */
	getAuthorizationUrl(state: string, redirectUri?: string): string {
		const params = new URLSearchParams({
			client_id: this.config.clientId,
			redirect_uri: redirectUri || this.config.redirectUri || '',
			response_type: 'code',
			scope: this.config.scope || '',
			state: state,
		});

		// Add provider-specific parameters
		if (this.config.additionalParams) {
			Object.entries(this.config.additionalParams).forEach(([key, value]) => {
				params.set(key, value);
			});
		}

		return `${this.config.authorizationUrl}?${params}`;
	}

	/**
	 * Exchange authorization code for access token
	 */
	async exchangeCodeForToken(code: string, redirectUri?: string): Promise<TokenResponse> {
		const params = new URLSearchParams({
			grant_type: 'authorization_code',
			code: code,
			redirect_uri: redirectUri || this.config.redirectUri || '',
			client_id: this.config.clientId,
			client_secret: this.config.clientSecret,
		});

		const response = await fetch(this.config.tokenUrl, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json',
			},
			body: params.toString(),
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Token exchange failed: ${errorText}`);
		}

		const contentType = response.headers.get('content-type');
		if (contentType?.includes('application/json')) {
			return response.json() as Promise<TokenResponse>;
		} else {
			// Some providers (like GitHub) return form-encoded data
			const text = await response.text();
			const tokenParams = new URLSearchParams(text);
			return Object.fromEntries(tokenParams) as unknown as TokenResponse;
		}
	}

	/**
	 * Get user info using access token
	 */
	async getUserInfo(accessToken: string, idTokenClaims: any = null): Promise<any> {
		// Check if provider has custom getUserInfo implementation
		if (typeof this.config.getUserInfo === 'function') {
			const helpers: GetUserInfoHelpers = {
				getUserInfo: this.fetchUserInfo.bind(this),
				logger: this.logger,
			};
			return this.config.getUserInfo.call(this, accessToken, helpers);
		}

		// If we have verified ID token claims and config says to prefer them
		if (idTokenClaims && this.config.preferIdToken !== false) {
			this.logger?.debug?.('Using verified ID token claims for user info');
			// Some providers don't include email in ID token, fetch it separately
			if (!idTokenClaims.email && this.config.fetchEmail) {
				try {
					const additionalInfo = await this.fetchUserInfo(accessToken);
					return { ...idTokenClaims, ...additionalInfo };
				} catch (error) {
					this.logger?.warn?.('Failed to fetch additional user info:', (error as Error).message);
				}
			}
			return idTokenClaims;
		}

		// Fetch from userinfo endpoint
		return this.fetchUserInfo(accessToken);
	}

	/**
	 * Fetch user info from the provider's userinfo endpoint
	 */
	async fetchUserInfo(accessToken: string): Promise<any> {
		const response = await fetch(this.config.userInfoUrl, {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: 'application/json',
			},
		});

		if (!response.ok) {
			throw new Error(`Failed to fetch user info: ${response.statusText}`);
		}

		return response.json();
	}

	/**
	 * Verify ID token with proper signature verification using JWKS
	 */
	async verifyIdToken(idToken: string): Promise<any> {
		// First decode to get the header and payload
		const decoded = jwt.decode(idToken, { complete: true });

		if (!decoded || !decoded.payload || !decoded.header) {
			throw new Error('Invalid ID token format');
		}

		// If we have a JWKS client, verify the signature
		if (this.jwksClient) {
			try {
				// Get the signing key from JWKS
				const kid = decoded.header.kid as string;
				if (!kid) {
					throw new Error('ID token missing key ID (kid) in header');
				}

				// This fetches the key from JWKS endpoint (with caching)
				const key = await this.jwksClient.getSigningKey(kid);
				const publicKey = key.getPublicKey();

				// Verify signature and claims
				const verified = jwt.verify(idToken, publicKey, {
					algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
					audience: this.config.clientId,
					issuer: this.config.issuer || undefined,
					clockTolerance: 60, // Allow 60 seconds clock skew
				});

				this.logger?.debug?.('ID token signature verified successfully');
				return verified;
			} catch (error) {
				// Signature verification failed - this is a security issue
				this.logger?.error?.('ID token signature verification failed:', (error as Error).message);
				throw new Error(`ID token verification failed: ${(error as Error).message}`);
			}
		} else {
			// No JWKS client - fall back to claims validation only
			this.logger?.warn?.('JWKS not configured - verifying claims only, not signature');
			return this.verifyIdTokenClaims(decoded.payload);
		}
	}

	/**
	 * Verify ID token claims without signature verification
	 * Used as fallback when JWKS is not available
	 */
	private verifyIdTokenClaims(payload: any): any {
		const now = Math.floor(Date.now() / 1000);

		// Critical validations
		if (!payload.exp || payload.exp < now) {
			throw new Error('ID token expired');
		}

		if (!payload.iat || payload.iat > now + 60) {
			throw new Error('ID token issued in the future');
		}

		if (!payload.aud) {
			throw new Error('ID token missing audience');
		}

		const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
		if (!audience.includes(this.config.clientId)) {
			throw new Error(`ID token audience mismatch`);
		}

		if (this.config.issuer && payload.iss !== this.config.issuer) {
			throw new Error(`ID token issuer mismatch`);
		}

		if (!payload.sub) {
			throw new Error('ID token missing subject');
		}

		return payload;
	}

	/**
	 * Map OAuth user info to Harper user object
	 */
	mapUserToHarper(userInfo: any): OAuthUser {
		const username = this.extractClaim(userInfo, this.config.usernameClaim);
		if (!username) {
			throw new Error(`Username claim '${this.config.usernameClaim}' not found in user info`);
		}

		const role = this.extractClaim(userInfo, this.config.roleClaim) || this.config.defaultRole || 'user';

		return {
			username,
			role,
			provider: this.config.provider,
			providerUserId: userInfo.sub || userInfo.id || userInfo.user_id,
			email: userInfo.email,
			name: userInfo.name || userInfo.display_name || userInfo.full_name,
			metadata: {
				oauthProvider: this.config.provider,
				oauthClaims: userInfo,
			},
		};
	}

	/**
	 * Extract a claim from user info (supports nested paths)
	 */
	private extractClaim(userInfo: any, claimPath?: string): any {
		if (!claimPath) return null;

		// Support nested paths like "profile.email"
		const parts = claimPath.split('.');
		let value: any = userInfo;

		for (const part of parts) {
			if (value && typeof value === 'object') {
				value = value[part];
			} else {
				return null;
			}
		}

		return value;
	}

	/**
	 * Generate and store CSRF token for protection
	 */
	async generateCSRFToken(metadata: Record<string, any> = {}): Promise<string> {
		const token = crypto.randomBytes(32).toString('hex');
		const tokenData: CSRFTokenData = {
			timestamp: Date.now(),
			...metadata,
		};

		// Store token (Harper handles expiration via table-level setting)
		await csrfTokenManager.set(token, tokenData);

		return token;
	}

	/**
	 * Verify and consume CSRF token
	 */
	async verifyCSRFToken(token: string): Promise<CSRFTokenData | null> {
		// Always use distributed storage
		const tokenData = await csrfTokenManager.get(token);
		if (tokenData) {
			// Delete for one-time use
			await csrfTokenManager.delete(token);
		}

		if (!tokenData) {
			return null;
		}

		return tokenData;
	}

	/**
	 * Refresh an access token using a refresh token
	 */
	async refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
		if (!refreshToken) {
			throw new Error('Refresh token is required');
		}

		const params = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			client_id: this.config.clientId,
			client_secret: this.config.clientSecret,
		});

		// Some providers require scope to be included in refresh
		if (this.config.scope) {
			params.append('scope', this.config.scope);
		}

		const response = await fetch(this.config.tokenUrl, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json',
			},
			body: params.toString(),
		});

		if (!response.ok) {
			const error = await response.text();
			this.logger?.error?.('Token refresh HTTP error:', {
				status: response.status,
				statusText: response.statusText,
				body: error,
			});
			throw new Error(`Token refresh failed: ${error}`);
		}

		const contentType = response.headers.get('content-type');
		let tokenData: TokenResponse;

		if (contentType?.includes('application/json')) {
			tokenData = await response.json();
		} else {
			// Some providers return form-encoded data
			const text = await response.text();
			const tokenParams = new URLSearchParams(text);
			tokenData = Object.fromEntries(tokenParams) as unknown as TokenResponse;
		}

		// Check if response contains an error (some providers return 200 with error object)
		if (tokenData.error) {
			this.logger?.error?.('Token refresh returned error in response:', {
				error: tokenData.error,
				error_description: tokenData.error_description,
				error_uri: tokenData.error_uri,
			});
			throw new Error(`Token refresh failed: ${tokenData.error_description || tokenData.error}`);
		}

		return tokenData;
	}
}
