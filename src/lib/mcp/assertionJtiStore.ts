/**
 * MCP Client-Assertion Replay Guard (RFC 7523 §3 `jti`)
 *
 * Records seen client-assertion `jti` values in the `mcp_assertion_jtis`
 * Harper table so a captured assertion cannot be redeemed twice (#159 security
 * req 1 — a timestamp-only window is insufficient).
 *
 * Retention is explicit per record. Expires at the later of assertion `exp` and insertion time, plus 60 seconds.
 * The margin is REPLAY_RETENTION_MARGIN_SECONDS, written as Harper's per-record
 * `expiresAt` (and mirrored in `expires_at`). Because it derives from the
 * accepted `exp` rather than from configuration, a row always outlives the
 * window in which its assertion could still be accepted, whatever the window
 * setting was when it was written or is later changed to, and the margin
 * exceeds any clock tolerance the verifier applies. The table's
 * `expiration: 120` remains only as the default for rows written without an
 * explicit expiry (earlier versions, whose assertions live at most 65 s).
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

/**
 * Retention beyond an assertion's `exp`, in seconds. Must exceed the largest
 * clock tolerance the verifier applies (5 s today) so an assertion accepted
 * at `exp + tolerance` still finds its row.
 */
export const REPLAY_RETENTION_MARGIN_SECONDS = 60;
/** Fallback retention when a caller supplies no usable `exp` (the pre-existing table default). */
const FALLBACK_RETENTION_SECONDS = 120;

/**
 * Epoch-ms expiry for a replay row: the later of the assertion's `exp` and
 * now, plus the retention margin. A missing or non-finite `exp` falls back to
 * now + 120 s.
 */
export function replayRetentionExpiresAt(expSeconds: number | undefined, nowMs: number = Date.now()): number {
	const nowSeconds = Math.floor(nowMs / 1000);
	if (typeof expSeconds !== 'number' || !Number.isFinite(expSeconds)) {
		return (nowSeconds + FALLBACK_RETENTION_SECONDS) * 1000;
	}
	return (Math.max(expSeconds, nowSeconds) + REPLAY_RETENTION_MARGIN_SECONDS) * 1000;
}

export class MCPAssertionJtiStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Record a (client_id, jti) sighting. Returns true when this is the first
	 * sighting (proceed with issuance), false when the jti was already seen
	 * (replay — reject). `expSeconds` is the verified assertion's `exp`; the
	 * row is retained until `exp` plus the retention margin. Non-409 storage
	 * errors propagate to the caller: this guard must fail closed, never
	 * "couldn't check, assume fresh".
	 */
	async checkAndRecord(clientId: string, jti: string, expSeconds?: number): Promise<boolean> {
		const table = getJtisTable();
		const id = jtiKey(clientId, jti);
		const expiresAt = replayRetentionExpiresAt(expSeconds);
		try {
			// Insert-if-absent; ANY existing record under this key is a replay.
			// Only id, client_id and expires_at are app-owned; `created_at` is
			// stamped by Harper via @createdTime (see schema). The context's
			// `expiresAt` sets this row's expiry, overriding the table default.
			await table.create({ id, client_id: clientId, expires_at: expiresAt }, { expiresAt });
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
