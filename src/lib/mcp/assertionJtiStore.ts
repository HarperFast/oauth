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
 * Enforcement uses `Table.create()` — Harper's insert-if-absent, which throws
 * a 409 ClientError ("Record already exists") — rather than an awaited
 * get-then-put a concurrent request could interleave.
 *
 * Residual race (documented, accepted): Harper currently enforces create()'s
 * existence check against the pre-staging snapshot only, so concurrent
 * in-flight creates can degrade to last-write-wins with both callers
 * reporting success (HarperFast/harper#1745). Exposure is bounded to
 * presentations in flight simultaneously — within the staging→commit interval
 * on one node, or replication lag across nodes — NOT open reuse across the
 * assertion's ~60s validity window; each duplicate mints one short-TTL token.
 * If harper#1745 lands per-node enforcement, the 409 also surfaces on
 * commit-time conflict and this guard becomes fully atomic per node with no
 * code change here (the catch below already handles it). Do NOT replace this
 * table with a per-process cache, which would not be shared across workers
 * or nodes.
 *
 * Unlike the other MCP stores, storage errors here are NOT swallowed:
 * treating "could not check" as "not seen" would fail open on the one guard
 * whose whole job is rejecting repeats. Callers should map a throw to a 500.
 */

import { createHash } from 'node:crypto';
import type { Logger, Table } from '../../types.ts';

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
	 * (replay — reject). Non-409 storage errors propagate to the caller: this
	 * guard must fail closed, never "couldn't check, assume fresh".
	 */
	async checkAndRecord(clientId: string, jti: string): Promise<boolean> {
		const table = getJtisTable();
		const id = jtiKey(clientId, jti);
		try {
			// Insert-if-absent; ANY existing record under this key is a replay.
			// Only id + client_id are app-owned; `created_at` is stamped by
			// Harper via @createdTime (see schema).
			await table.create({ id, client_id: clientId });
		} catch (error) {
			if ((error as { statusCode?: number })?.statusCode === 409) {
				this.logger?.warn?.(`MCP assertion replay detected for client ${clientId}`);
				return false;
			}
			throw error;
		}
		this.logger?.debug?.(`Recorded MCP assertion jti for client ${clientId}`);
		return true;
	}
}
