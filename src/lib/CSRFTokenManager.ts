/**
 * CSRF Token Manager for OAuth flows
 *
 * Manages CSRF protection tokens that prevent cross-site request forgery
 * during OAuth authorization flows. Tokens are stored in Harper table
 * for distributed access across workers and cluster nodes.
 */

import type { CSRFTokenData, Logger, Table } from '../types.ts';

// Harper's databases global contains all databases
declare const databases: any;

// Lazy-load the CSRF token table
let csrfTable: Table;

function getCSRFTable(): Table {
	if (!csrfTable) {
		// Check if oauth database and table exist
		if (!databases?.oauth?.csrf_tokens) {
			throw new Error(
				'OAuth CSRF tokens table (oauth.csrf_tokens) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		csrfTable = databases.oauth.csrf_tokens;
	}
	return csrfTable;
}

/**
 * Reset the cached CSRF table reference (for testing only)
 * @internal
 */
export function resetCSRFTableCache(): void {
	csrfTable = undefined as any;
}

export class CSRFTokenManager {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Store CSRF token with metadata
	 * Table expiration is handled by Harper (10 minutes)
	 */
	async set(token: string, data: CSRFTokenData): Promise<void> {
		const table = getCSRFTable();

		try {
			await table.put({
				token_id: token,
				data: JSON.stringify(data),
				created_at: Date.now(),
			});

			this.logger?.debug?.(`Stored CSRF token: ${token}`);
		} catch (error) {
			this.logger?.error?.('Failed to store CSRF token:', error);
			throw error;
		}
	}

	/**
	 * Retrieve CSRF token
	 * Harper automatically handles expiration via table-level setting
	 */
	async get(token: string): Promise<CSRFTokenData | null> {
		const table = getCSRFTable();

		try {
			const record = await table.get(token);

			if (!record || !record.data) {
				this.logger?.debug?.(`CSRF token not found: ${token}`);
				return null;
			}

			const data = JSON.parse(record.data);
			this.logger?.debug?.(`Retrieved CSRF token: ${token}`);
			return data;
		} catch (error) {
			this.logger?.error?.('Failed to retrieve CSRF token:', error);
			return null;
		}
	}

	/**
	 * Delete CSRF token (after successful verification)
	 */
	async delete(token: string): Promise<void> {
		const table = getCSRFTable();

		try {
			await table.delete(token);
			this.logger?.debug?.(`Deleted CSRF token: ${token}`);
		} catch (error) {
			// Not critical if delete fails (expiration will clean it up)
			this.logger?.warn?.('Failed to delete CSRF token:', error);
		}
	}
}

// Singleton instance that can be shared across providers
export const csrfTokenManager = new CSRFTokenManager();
