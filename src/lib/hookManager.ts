/**
 * OAuth Hook Manager
 *
 * Manages loading and calling lifecycle hooks for the OAuth plugin
 */

import type { OAuthHooks, OAuthUser, OnLoginResult, TokenResponse, Logger, OAuthProviderConfig } from '../types.ts';

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
	 *
	 * Returns the hook's result verbatim — including a structured outcome
	 * (`{ status: 'denied' | 'needs_confirmation', ... }`, #174) that the
	 * callback handler interprets. A thrown error is caught and logged and
	 * behaves like no return value (login proceeds): deliberate gating is
	 * expressed via the return value, not by throwing.
	 */
	async callOnLogin(
		oauthUser: OAuthUser,
		tokenResponse: TokenResponse,
		session: any,
		request: any,
		provider: string
	): Promise<OnLoginResult | void> {
		if (!this.hooks.onLogin) return;

		try {
			this.logger?.debug?.(`Calling onLogin hook for provider: ${provider}`);
			const result = await this.hooks.onLogin(oauthUser, tokenResponse, session, request, provider);
			return result;
		} catch (error) {
			this.logger?.error?.('onLogin hook failed:', error instanceof Error ? error.message : String(error));
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
			this.logger?.error?.('onLogout hook failed:', error instanceof Error ? error.message : String(error));
			// Don't throw - hooks should not break logout
		}
	}

	/**
	 * Call onMCPTokenIssued hook (fire-and-forget).
	 *
	 * NOT awaited: the hook runs detached after the token is durably issued, so it
	 * can never add latency to — or block — token issuance (per @kriszyp's review
	 * on #141; this also removes the need for a hook-execution timeout, #143). A
	 * rejection, or a synchronous throw, from app code is caught and logged here,
	 * never surfaced to the caller.
	 */
	callOnMCPTokenIssued(
		event: {
			type: 'access' | 'refresh' | 'client_credentials';
			client_id: string;
			sub: string;
			aud: string;
			scope?: string;
			jti: string;
		},
		request: any
	): void {
		const hook = this.hooks.onMCPTokenIssued;
		if (!hook) return;

		this.logger?.debug?.(`Calling onMCPTokenIssued hook for client: ${event.client_id} type: ${event.type}`);
		// Detach with Promise.resolve().then so a SYNCHRONOUS throw in the hook is
		// funneled into the same catch as a rejected promise (and never escapes as
		// an uncaught exception on the issuance path). `void` marks the floating
		// promise intentional. `instanceof Error` (not `as Error`): a hook may throw
		// a non-Error (string, null, undefined) and `(null).message` would itself
		// throw inside the catch.
		void Promise.resolve()
			.then(() => hook(event, request))
			.catch((error) => {
				// Shield the catch body itself: a throwing logger (logging-subsystem
				// I/O error) or a malicious `error.toString()` must NOT throw here —
				// this chain is detached (`void`), so an escaping error would be an
				// unhandled rejection (process crash on Node ≥15). Best-effort, same
				// posture as emitMCPAuditEvent.
				try {
					this.logger?.error?.('onMCPTokenIssued hook failed:', error instanceof Error ? error.message : String(error));
				} catch {
					// Intentionally ignored — logging is best-effort.
				}
			});
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
			this.logger?.error?.('onTokenRefresh hook failed:', error instanceof Error ? error.message : String(error));
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
			this.logger?.error?.('onResolveProvider hook failed:', error instanceof Error ? error.message : String(error));
			throw error; // Re-throw for resource to handle (returns 500)
		}
	}
}
