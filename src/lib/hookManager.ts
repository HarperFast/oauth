/**
 * OAuth Hook Manager
 *
 * Manages loading and calling lifecycle hooks for the OAuth plugin
 */

import type { OAuthHooks, OAuthUser, TokenResponse, Logger, OAuthProviderConfig } from '../types.ts';

/**
 * Hook Manager
 * Loads and executes OAuth lifecycle hooks
 */
export class HookManager {
	private hooks: OAuthHooks = {};
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Register hooks programmatically
	 * Allows applications to register hooks directly without using config
	 */
	register(hooks: OAuthHooks): void {
		this.hooks = hooks;
		this.logger?.debug?.(
			`Registered OAuth hooks: ${Object.keys(hooks)
				.filter((key) => hooks[key as keyof OAuthHooks])
				.join(', ')}`
		);
	}

	/**
	 * Call onLogin hook
	 */
	async callOnLogin(
		oauthUser: OAuthUser,
		tokenResponse: TokenResponse,
		session: any,
		request: any,
		provider: string
	): Promise<Record<string, any> | void> {
		if (!this.hooks.onLogin) return;

		try {
			this.logger?.debug?.(`Calling onLogin hook for provider: ${provider}`);
			const result = await this.hooks.onLogin(oauthUser, tokenResponse, session, request, provider);
			return result;
		} catch (error) {
			this.logger?.error?.('onLogin hook failed:', (error as Error).message);
			// Don't throw - hooks should not break the OAuth flow
			return;
		}
	}

	/**
	 * Call onLogout hook
	 */
	async callOnLogout(session: any, request: any): Promise<void> {
		if (!this.hooks.onLogout) return;

		try {
			this.logger?.debug?.('Calling onLogout hook');
			await this.hooks.onLogout(session, request);
		} catch (error) {
			this.logger?.error?.('onLogout hook failed:', (error as Error).message);
			// Don't throw - hooks should not break logout
		}
	}

	/**
	 * Call onTokenRefresh hook
	 */
	async callOnTokenRefresh(session: any, refreshed: boolean, request?: any): Promise<void> {
		if (!this.hooks.onTokenRefresh) return;

		try {
			this.logger?.debug?.(`Calling onTokenRefresh hook (refreshed: ${refreshed})`);
			await this.hooks.onTokenRefresh(session, refreshed, request);
		} catch (error) {
			this.logger?.error?.('onTokenRefresh hook failed:', (error as Error).message);
			// Don't throw - hooks should not break token refresh
		}
	}

	/**
	 * Check if a specific hook is registered
	 */
	hasHook(hookName: keyof OAuthHooks): boolean {
		return !!this.hooks[hookName];
	}

	/**
	 * Check if any hooks are loaded
	 */
	hasHooks(): boolean {
		return Object.keys(this.hooks).length > 0;
	}

	/**
	 * Call onResolveProvider hook
	 *
	 * Called when a provider is not found in the static registry.
	 * Allows applications to dynamically resolve provider configurations.
	 *
	 * @param providerName - Provider name from URL path (e.g., "okta-org_abc123")
	 * @param logger - Optional logger instance
	 * @returns Provider configuration or null if not found
	 * @throws Error if resolution fails
	 */
	async callResolveProvider(providerName: string, logger?: Logger): Promise<OAuthProviderConfig | null> {
		const hook = this.hooks.onResolveProvider;
		if (!hook) return null;

		try {
			this.logger?.debug?.(`Calling onResolveProvider hook for: ${providerName}`);
			const config = await hook(providerName, logger || this.logger);
			if (config) {
				this.logger?.debug?.(`Provider resolved: ${providerName} → ${config.provider}`);
			}
			return config;
		} catch (error) {
			this.logger?.error?.('onResolveProvider hook failed:', (error as Error).message);
			throw error; // Re-throw for resource to handle (returns 500)
		}
	}
}
