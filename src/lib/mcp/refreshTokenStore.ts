/**
 * MCP Refresh-Token Family Store (OAuth 2.1 single-use rotation)
 *
 * Persists one row per refresh-token family in `mcp_refresh_families`. The
 * opaque token handed to the client is `"<family_id>.<secret>"`; only the
 * SHA-256 hash of the whole value is stored (`current_token_hash`). On a valid
 * refresh the hash is overwritten (rotation); a presented token whose hash no
 * longer matches is a replay of a superseded token, which revokes the family.
 *
 * This keeps replay revocation O(1) with a get/put-only table abstraction: we
 * store family state, not individual tokens, so it stays correct even after
 * old tokens age out of any per-token store. Tokens are never stored in the
 * clear.
 *
 * Rotation is not atomic (no compare-and-set on the table, same constraint as
 * authCodeStore.consume): two concurrent refreshes of the same current token
 * both pass the hash check before either write lands, so one of the two new
 * tokens is orphaned (last write wins). The orphan fails safe — its next use is
 * a hash mismatch, which revokes the family. Benign under the real
 * single-client-per-refresh pattern; accepted for v1.
 *
 * Explicit field access on encode/decode (no `{ ...raw }`) — Harper
 * tracked-object Proxies return empty own-keys. See CLAUDE.md gotcha.
 */

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Logger, MCPRefreshFamilyRecord, Table } from '../../types.ts';

declare const databases: any;

let familiesTable: Table | undefined;

function getFamiliesTable(): Table {
	if (!familiesTable) {
		if (!databases?.oauth?.mcp_refresh_families) {
			throw new Error(
				'OAuth MCP refresh families table (oauth.mcp_refresh_families) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		familiesTable = databases.oauth.mcp_refresh_families;
	}
	return familiesTable as Table;
}

/**
 * Reset the cached table reference (for testing only).
 * @internal
 */
export function resetMCPRefreshFamiliesTableCache(): void {
	familiesTable = undefined;
}

/** SHA-256 of a token value, base64url-encoded. */
export function hashRefreshToken(token: string): string {
	return createHash('sha256').update(token).digest('base64url');
}

/** Mint a fresh token for a family and return both the token and its hash. */
export function makeRefreshToken(familyId: string): { token: string; hash: string } {
	const token = `${familyId}.${randomBytes(32).toString('base64url')}`;
	return { token, hash: hashRefreshToken(token) };
}

/**
 * Extract the family id from a presented refresh token. Returns null when the
 * token is not in the expected `<family_id>.<secret>` shape.
 */
export function parseRefreshToken(token: unknown): { familyId: string } | null {
	if (typeof token !== 'string') return null;
	const dot = token.indexOf('.');
	if (dot <= 0 || dot === token.length - 1) return null;
	return { familyId: token.slice(0, dot) };
}

/** Generate a new, unique family id. */
export function newFamilyId(): string {
	return randomUUID();
}

function encodeRecord(record: MCPRefreshFamilyRecord): Record<string, any> {
	return {
		family_id: record.family_id,
		current_token_hash: record.current_token_hash,
		revoked: record.revoked,
		client_id: record.client_id,
		user: record.user,
		resource: record.resource,
		scope: record.scope,
		expires_at: record.expires_at,
	};
}

function decodeRecord(raw: Record<string, any>): MCPRefreshFamilyRecord {
	return {
		family_id: raw.family_id,
		current_token_hash: raw.current_token_hash,
		revoked: raw.revoked ?? false,
		client_id: raw.client_id,
		user: raw.user,
		resource: raw.resource,
		scope: raw.scope ?? undefined,
		expires_at: raw.expires_at,
	};
}

export class MCPRefreshFamilyStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	async set(record: MCPRefreshFamilyRecord): Promise<void> {
		const table = getFamiliesTable();
		try {
			await table.put(encodeRecord(record));
		} catch (error) {
			this.logger?.error?.('Failed to store MCP refresh family:', error);
			throw error;
		}
	}

	async get(familyId: string): Promise<MCPRefreshFamilyRecord | null> {
		const table = getFamiliesTable();
		try {
			const raw = await table.get(familyId);
			if (!raw || !raw.family_id) {
				return null;
			}
			return decodeRecord(raw);
		} catch (error) {
			this.logger?.error?.('Failed to retrieve MCP refresh family:', error);
			return null;
		}
	}

	async delete(familyId: string): Promise<void> {
		const table = getFamiliesTable();
		try {
			await table.delete(familyId);
		} catch (error) {
			// Non-critical: TTL will eventually evict.
			this.logger?.warn?.('Failed to delete MCP refresh family:', error);
		}
	}
}
