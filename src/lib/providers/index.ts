/**
 * OAuth Provider Registry
 */

import { GitHubProvider } from './github.ts';
import { GoogleProvider } from './google.ts';
import { AzureADProvider } from './azure.ts';
import { auth0Provider } from './auth0.ts';
import { OktaProvider } from './okta.ts';
import { genericProvider } from './generic.ts';
import type { OAuthProviderConfig } from '../../types.ts';

// Auto-register all providers
const providerModules = {
	github: GitHubProvider,
	google: GoogleProvider,
	azure: AzureADProvider,
	auth0: auth0Provider,
	okta: OktaProvider,
	generic: genericProvider,
};

export const providers: Record<string, OAuthProviderConfig> = {
	...providerModules,
	// Aliases
	microsoft: AzureADProvider,
};

/**
 * Get a pre-configured provider by name
 */
export function getProvider(name: string): OAuthProviderConfig | null {
	const provider = providers[name?.toLowerCase()];

	if (!provider) {
		// Return null to allow custom provider configuration
		return null;
	}

	// Return a shallow copy to avoid direct mutations
	// Note: Functions (getUserInfo, configure, validateToken) are preserved by reference
	return { ...provider };
}

/**
 * Register a custom provider
 */
export function registerProvider(name: string, config: OAuthProviderConfig): void {
	providers[name] = config;
}

/**
 * Get all registered provider names
 */
export function getProviderNames(): string[] {
	return Object.keys(providers);
}
