/**
 * MCP Client Store
 *
 * Persists Dynamic Client Registration (RFC 7591) records in the Harper
 * `harper_oauth_mcp_clients` table. Clients survive Harper restarts so MCP
 * clients (Claude Desktop, Cursor, mcp-remote) that cache their issued
 * client_id continue to authenticate after a deploy.
 *
 * Array-valued fields (redirect_uris, contacts, grant_types, response_types)
 * are JSON-encoded on write and decoded on read, matching the
 * csrf_tokens.data pattern already used in this plugin.
 */

import type { Logger, MCPClientRecord, Table } from '../../types.ts';

// Harper's databases global contains all databases
declare const databases: any;

let clientsTable: Table | undefined;

function getMCPClientsTable(): Table {
	if (!clientsTable) {
		if (!databases?.oauth?.harper_oauth_mcp_clients) {
			throw new Error(
				'OAuth MCP clients table (oauth.harper_oauth_mcp_clients) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		clientsTable = databases.oauth.harper_oauth_mcp_clients;
	}
	return clientsTable as Table;
}

/**
 * Reset the cached table reference (for testing only)
 * @internal
 */
export function resetMCPClientsTableCache(): void {
	clientsTable = undefined;
}

const ARRAY_FIELDS = ['redirect_uris', 'contacts', 'grant_types', 'response_types'] as const;

function encodeRecord(record: MCPClientRecord): Record<string, any> {
	const encoded: Record<string, any> = { ...record };
	for (const field of ARRAY_FIELDS) {
		const value = record[field];
		encoded[field] = value === undefined ? undefined : JSON.stringify(value);
	}
	return encoded;
}

function decodeRecord(raw: Record<string, any>): MCPClientRecord {
	const decoded: Record<string, any> = { ...raw };
	for (const field of ARRAY_FIELDS) {
		const value = raw[field];
		if (typeof value === 'string') {
			try {
				const parsed = JSON.parse(value);
				decoded[field] = Array.isArray(parsed) ? parsed : undefined;
			} catch {
				// Malformed stored data — treat as absent to avoid crashing callers.
				decoded[field] = undefined;
			}
		} else if (value === null) {
			// Normalize null (e.g. from a DB column default) to undefined
			// so the decoded record matches the `string[] | undefined` type.
			decoded[field] = undefined;
		}
	}
	return decoded as MCPClientRecord;
}

export class MCPClientStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Persist a client registration. Overwrites any existing record with the
	 * same client_id (RFC 7591 registration is idempotent at the storage layer;
	 * the registration endpoint allocates a fresh client_id per request).
	 */
	async set(record: MCPClientRecord): Promise<void> {
		const table = getMCPClientsTable();
		try {
			await table.put(encodeRecord(record));
			this.logger?.debug?.(`Stored MCP client: ${record.client_id}`);
		} catch (error) {
			this.logger?.error?.('Failed to store MCP client:', error);
			throw error;
		}
	}

	/**
	 * Look up a client by client_id. Returns null if not found or on read error
	 * (errors logged; we don't surface storage failures to OAuth clients).
	 */
	async get(clientId: string): Promise<MCPClientRecord | null> {
		const table = getMCPClientsTable();
		try {
			const raw = await table.get(clientId);
			if (!raw || !raw.client_id) {
				return null;
			}
			return decodeRecord(raw);
		} catch (error) {
			this.logger?.error?.('Failed to retrieve MCP client:', error);
			return null;
		}
	}

	/**
	 * Remove a client registration.
	 */
	async delete(clientId: string): Promise<void> {
		const table = getMCPClientsTable();
		try {
			await table.delete(clientId);
			this.logger?.debug?.(`Deleted MCP client: ${clientId}`);
		} catch (error) {
			// Not critical if delete fails — admin can retry.
			this.logger?.warn?.('Failed to delete MCP client:', error);
		}
	}
}
