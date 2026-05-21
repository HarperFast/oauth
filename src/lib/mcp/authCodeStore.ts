/**
 * MCP Authorization Code Store
 *
 * Persists short-lived authorization codes in the `mcp_auth_codes` Harper
 * table. The table is declared with `@table(expiration: 300)`, so codes
 * auto-expire after 5 minutes — Stage 4's /token endpoint must still
 * delete on successful exchange (single-use), but the TTL is a safety
 * net against codes that are never redeemed.
 *
 * Explicit field access on encode/decode (no `{ ...raw }`) — Harper
 * tracked-object Proxies return empty own-keys, so spread would drop
 * scalar fields. See CLAUDE.md "GenericTrackedObject + spread" gotcha.
 */

import type { Logger, MCPAuthCodeRecord, Table } from '../../types.ts';

declare const databases: any;

let authCodesTable: Table | undefined;

function getAuthCodesTable(): Table {
	if (!authCodesTable) {
		if (!databases?.oauth?.mcp_auth_codes) {
			throw new Error(
				'OAuth MCP auth codes table (oauth.mcp_auth_codes) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		authCodesTable = databases.oauth.mcp_auth_codes;
	}
	return authCodesTable as Table;
}

/**
 * Reset the cached table reference (for testing only)
 * @internal
 */
export function resetMCPAuthCodesTableCache(): void {
	authCodesTable = undefined;
}

function encodeRecord(record: MCPAuthCodeRecord): Record<string, any> {
	return {
		code: record.code,
		client_id: record.client_id,
		user: record.user,
		resource: record.resource,
		code_challenge: record.code_challenge,
		code_challenge_method: record.code_challenge_method,
		redirect_uri: record.redirect_uri,
		scope: record.scope,
		created_at: record.created_at,
	};
}

function decodeRecord(raw: Record<string, any>): MCPAuthCodeRecord {
	return {
		code: raw.code,
		client_id: raw.client_id,
		user: raw.user,
		resource: raw.resource,
		code_challenge: raw.code_challenge,
		code_challenge_method: raw.code_challenge_method,
		redirect_uri: raw.redirect_uri,
		scope: raw.scope ?? undefined,
		created_at: raw.created_at,
	};
}

export class MCPAuthCodeStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	async set(record: MCPAuthCodeRecord): Promise<void> {
		const table = getAuthCodesTable();
		try {
			await table.put(encodeRecord(record));
			this.logger?.debug?.(`Stored MCP auth code for client ${record.client_id}`);
		} catch (error) {
			this.logger?.error?.('Failed to store MCP auth code:', error);
			throw error;
		}
	}

	async get(code: string): Promise<MCPAuthCodeRecord | null> {
		const table = getAuthCodesTable();
		try {
			const raw = await table.get(code);
			if (!raw || !raw.code) {
				return null;
			}
			return decodeRecord(raw);
		} catch (error) {
			this.logger?.error?.('Failed to retrieve MCP auth code:', error);
			return null;
		}
	}

	async delete(code: string): Promise<void> {
		const table = getAuthCodesTable();
		try {
			await table.delete(code);
			this.logger?.debug?.('Deleted MCP auth code');
		} catch (error) {
			// Non-critical: TTL will eventually evict.
			this.logger?.warn?.('Failed to delete MCP auth code:', error);
		}
	}
}
