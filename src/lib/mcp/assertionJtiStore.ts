/**
 * MCP Client-Assertion Replay Guard (RFC 7523 §3 `jti`)
 *
 * Records seen client-assertion `jti` values in the `mcp_assertion_jtis`
 * Harper table so a captured assertion cannot be redeemed twice (#159 security
 * req 1 — a timestamp-only window is insufficient). The table carries
 * `expiration: 120`, comfortably past the maximum assertion window (60s `exp`
 * + clock tolerance), so rows self-evict; runtime never needs to prune.
 *
 * Keys are `sha256(len:client_id:jti)` — the client_id is length-prefixed so
 * the component boundary is unambiguous (plain delimiter concatenation lets
 * crafted inputs collide). Replay scope is per client (RFC 7523 defines `jti`
 * uniqueness per issuer), and hashing normalizes an arbitrary client-chosen
 * string to a fixed-length key.
 *
 * Accepted race (same precedent as MCPAuthCodeStore.consume): the check is
 * get-then-put with no atomic compare-and-set, and Harper replication is
 * async — two concurrent presentations of the same assertion can both pass on
 * different nodes inside the replication window. Bounded by the ≤60s `exp`
 * and accepted under Harper's single-trust-domain model; do NOT replace this
 * table with a per-process cache, which would not be shared at all.
 *
 * Unlike the other MCP stores, read errors here are NOT swallowed: treating
 * "could not check" as "not seen" would fail open on the one guard whose whole
 * job is rejecting repeats. Callers should map a throw to a 500, not issue.
 */

import { createHash } from 'node:crypto';
import type { Logger, MCPAssertionJtiRecord, Table } from '../../types.ts';

declare const databases: any;

let jtisTable: Table | undefined;

function getJtisTable(): Table {
	if (!jtisTable) {
		if (!databases?.oauth?.mcp_assertion_jtis) {
			throw new Error(
				'OAuth MCP assertion jti table (oauth.mcp_assertion_jtis) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		jtisTable = databases.oauth.mcp_assertion_jtis;
	}
	return jtisTable as Table;
}

/**
 * Reset the cached table reference (for testing only)
 * @internal
 */
export function resetMCPAssertionJtisTableCache(): void {
	jtisTable = undefined;
}

/**
 * Fixed-length, charset-safe primary key for a (client, jti) sighting. The
 * client_id is length-prefixed so the component boundary is unambiguous —
 * plain concatenation with a delimiter would let ("a", "b\nc") and
 * ("a\nb", "c") collide.
 */
export function jtiKey(clientId: string, jti: string): string {
	return createHash('sha256').update(`${clientId.length}:${clientId}:${jti}`).digest('hex');
}

export class MCPAssertionJtiStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Record a (client_id, jti) sighting. Returns true when this is the first
	 * sighting (proceed with issuance), false when the jti was already seen
	 * (replay — reject). Storage errors on either the read or the write
	 * propagate to the caller: this guard must fail closed, never
	 * "couldn't check, assume fresh".
	 */
	async checkAndRecord(clientId: string, jti: string): Promise<boolean> {
		const table = getJtisTable();
		const id = jtiKey(clientId, jti);

		// ANY record under this key means the jti was seen — requiring a
		// well-formed row (e.g. `existing.id`) would turn a malformed record
		// into a fail-open bypass of the one guard that must fail closed.
		const existing = await table.get(id);
		if (existing) {
			this.logger?.warn?.(`MCP assertion replay detected for client ${clientId}`);
			return false;
		}

		const record: MCPAssertionJtiRecord = {
			id,
			client_id: clientId,
			created_at: Math.floor(Date.now() / 1000),
		};
		// Explicit field access (no spread) per the tracked-object gotcha, kept
		// even for this locally-built record so the stores stay uniform.
		await table.put({ id: record.id, client_id: record.client_id, created_at: record.created_at });
		this.logger?.debug?.(`Recorded MCP assertion jti for client ${clientId}`);
		return true;
	}
}
