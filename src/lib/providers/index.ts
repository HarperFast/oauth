/**
 * OAuth Provider Registry
 */

import { GitHubProvider } from './github.ts';
import { GoogleProvider } from './google.ts';
import { AzureADProvider } from './azure.ts';
import { auth0Provider } from './auth0.ts';
import type { OAuthProviderConfig } from '../../types.ts';

export const providers: Record<string, OAuthProviderConfig> = {
	github: GitHubProvider,
	google: GoogleProvider,
	azure: AzureADProvider,
	microsoft: AzureADProvider, // Alias
	auth0: auth0Provider,
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

	// Return a copy to avoid mutations
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
