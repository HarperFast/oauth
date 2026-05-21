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

function serializeArrayField(value: unknown): string | undefined {
	return value === undefined ? undefined : JSON.stringify(value);
}

function parseArrayField(value: unknown): string[] | undefined {
	if (typeof value !== 'string') {
		// null, undefined, or anything else from the DB collapses to undefined.
		return undefined;
	}
	try {
		const parsed = JSON.parse(value);
		return Array.isArray(parsed) ? parsed : undefined;
	} catch {
		// Malformed stored data — treat as absent rather than crashing callers.
		return undefined;
	}
}

/**
 * Encode the record for storage. Explicit field access (no spread) so we
 * write a well-typed record even if a caller hands us a tracked object —
 * per CLAUDE.md's "GenericTrackedObject + spread" gotcha.
 */
function encodeRecord(record: MCPClientRecord): Record<string, any> {
	return {
		client_id: record.client_id,
		client_secret: record.client_secret,
		client_name: record.client_name,
		client_uri: record.client_uri,
		logo_uri: record.logo_uri,
		scope: record.scope,
		token_endpoint_auth_method: record.token_endpoint_auth_method,
		application_type: record.application_type,
		software_id: record.software_id,
		software_version: record.software_version,
		client_id_issued_at: record.client_id_issued_at,
		client_secret_expires_at: record.client_secret_expires_at,
		redirect_uris: serializeArrayField(record.redirect_uris),
		contacts: serializeArrayField(record.contacts),
		grant_types: serializeArrayField(record.grant_types),
		response_types: serializeArrayField(record.response_types),
	};
}

/**
 * Decode a stored row. Must use explicit property access — Harper returns
 * GenericTrackedObject Proxies whose own-keys are empty, so { ...raw } drops
 * every scalar field (client_id, client_secret, …) and breaks retrieval.
 * Caught by Gemini review on PR #89; documented in CLAUDE.md.
 */
function decodeRecord(raw: Record<string, any>): MCPClientRecord {
	return {
		client_id: raw.client_id,
		client_secret: raw.client_secret,
		client_name: raw.client_name,
		client_uri: raw.client_uri,
		logo_uri: raw.logo_uri,
		scope: raw.scope,
		token_endpoint_auth_method: raw.token_endpoint_auth_method,
		application_type: raw.application_type,
		software_id: raw.software_id,
		software_version: raw.software_version,
		client_id_issued_at: raw.client_id_issued_at,
		client_secret_expires_at: raw.client_secret_expires_at,
		redirect_uris: parseArrayField(raw.redirect_uris) as string[],
		contacts: parseArrayField(raw.contacts),
		grant_types: parseArrayField(raw.grant_types),
		response_types: parseArrayField(raw.response_types),
	};
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
