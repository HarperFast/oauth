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
 * Enforcement is an atomic counter: each presentation adds 1 to the row's
 * `uses` with a partial update (`patch` with an `add` operation), which Harper
 * applies at commit on top of the row as then stored, retrying on a
 * conflicting write. Only the presentation that reads back `uses === 1` is
 * accepted; every other is refused as a replay, including concurrent ones. A
 * row that already exists before the increment (one written by an earlier
 * version carries no `uses`) is a replay.
 *
 * The patch commits in its own transaction. The existence check reads in the
 * caller's transaction, which inside a REST request is the request's: its
 * snapshot does not include the patch. The read-back therefore passes a new
 * context object, so it opens its own transaction and sees the committed
 * count. Harper writes `context.transaction` onto the object it is given, so
 * each read-back gets a fresh object, never a shared one.
 *
 * Single use holds per node: within the replication delay, each node can
 * accept one presentation. Do NOT replace this table with a per-process cache,
 * which would not be shared across workers or nodes.
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
	 * row is retained until `exp` plus the retention margin. Storage errors
	 * propagate to the caller: this guard must fail closed, never "couldn't
	 * check, assume fresh".
	 */
	async checkAndRecord(clientId: string, jti: string, expSeconds?: number): Promise<boolean> {
		const table = getJtisTable();
		const id = jtiKey(clientId, jti);
		const expiresAt = replayRetentionExpiresAt(expSeconds);
		if (!(await table.get(id))) {
			// Only id, client_id, expires_at and uses are app-owned; `created_at`
			// is stamped by Harper via @createdTime (see schema). The context's
			// `expiresAt` sets this row's expiry, overriding the table default.
			await table.patch(
				id,
				{ client_id: clientId, expires_at: expiresAt, uses: { __op__: 'add', value: 1 } },
				{ expiresAt }
			);
			// A new context: the read opens its own transaction and sees the
			// committed patch (see the module comment).
			if ((await table.get(id, {}))?.uses === 1) {
				this.logger?.debug?.(`Recorded MCP assertion jti for client ${clientId}`);
				return true;
			}
		}
		this.logger?.warn?.(`MCP assertion replay detected for client ${clientId}`);
		return false;
	}
}
