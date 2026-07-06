/**
 * MCP JWT Signing Key Store
 *
 * Persists RS256 signing keypairs in the `harper_oauth_mcp_keys` Harper table,
 * keyed by random UUID `kid` (the legacy `rs256-default` row stays valid — no
 * migration). Every node's key is published at the JWKS endpoint so cross-node
 * tokens verify regardless of which node signed them — eliminating the
 * clustered first-boot race from v1.
 *
 * Signer selection: the key with the newest `created_at` wins. Tie-break on
 * `kid` descending (lexicographic) for determinism.
 *
 * Rotation (opt-in via `mcp.keyRotationInterval`): lazy check at token mint —
 * if the newest key is older than the interval a fresh UUID-kid keypair is
 * generated and persisted. Old keys are GC'd once no token they signed can
 * still be valid (2× accessTokenTtl after a newer key supersedes them).
 *
 * `mcp.signingKeyPem` (pin wins): when a pinned key is configured, rotation
 * is skipped; a warning is logged at startup if both are set. Only the pinned
 * key uses the fixed `rs256-default` kid (identical content on every node, so
 * the shared primary key is safe); GENERATED first-boot keys get a UUID kid —
 * a shared kid would let racing nodes overwrite each other and strand the
 * loser's already-signed tokens with an unverifiable kid.
 *
 * The private half never leaves the server; only the public half is published
 * at /.well-known/jwks.json.
 *
 * IMPORTANT: Harper tracked-object Proxies return empty own-keys — NO spread
 * (`{ ...raw }`). Always use explicit field access (decodeRecord).
 */

import { createPublicKey, generateKeyPair, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import type { Logger, MCPConfig, MCPSigningKeyRecord, Table } from '../../types.ts';

const generateKeyPairAsync = promisify(generateKeyPair);

/** Fixed primary key for the legacy v1 singleton signing key. */
export const SIGNING_KEY_ID = 'rs256-default';

const DEFAULT_ACCESS_TOKEN_TTL = 3600;

declare const databases: any;

let keysTable: Table | undefined;

function getKeysTable(): Table {
	if (!keysTable) {
		if (!databases?.oauth?.harper_oauth_mcp_keys) {
			throw new Error(
				'OAuth MCP keys table (oauth.harper_oauth_mcp_keys) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		keysTable = databases.oauth.harper_oauth_mcp_keys;
	}
	return keysTable as Table;
}

/**
 * Reset cached table reference (for testing only).
 * @internal
 */
export function resetMCPKeysTableCache(): void {
	keysTable = undefined;
}

function encodeRecord(record: MCPSigningKeyRecord): Record<string, any> {
	return {
		kid: record.kid,
		alg: record.alg,
		public_key_pem: record.public_key_pem,
		private_key_pem: record.private_key_pem,
		created_at: record.created_at,
	};
}

function decodeRecord(raw: Record<string, any>): MCPSigningKeyRecord {
	return {
		kid: raw.kid,
		alg: raw.alg,
		public_key_pem: raw.public_key_pem,
		private_key_pem: raw.private_key_pem,
		created_at: raw.created_at,
	};
}

async function generateRsaKeyPair(): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
	const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	return { publicKeyPem: publicKey as string, privateKeyPem: privateKey as string };
}

/**
 * Coerce a configured interval/TTL to a positive number of seconds.
 * Returns 0 (disabled) for any non-positive, non-finite, or absent value.
 */
function coerceInterval(value: unknown): number {
	const n = typeof value === 'number' ? value : Number(value);
	return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Select the active signing key from a non-empty set.
 * Newest `created_at` wins; tie-break on `kid` descending (lexicographic).
 */
function selectNewestKey(keys: MCPSigningKeyRecord[]): MCPSigningKeyRecord {
	return keys.reduce((winner, candidate) => {
		if (candidate.created_at > winner.created_at) return candidate;
		if (candidate.created_at === winner.created_at && candidate.kid > winner.kid) return candidate;
		return winner;
	});
}

export class MCPKeyStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Enumerate all rows in the keys table.
	 * Returns an empty array on any error (JWKS fetch must not 500).
	 */
	private async enumerateKeys(): Promise<MCPSigningKeyRecord[]> {
		const table = getKeysTable();
		const records: MCPSigningKeyRecord[] = [];
		for await (const raw of table.search({})) {
			if (raw?.kid) {
				records.push(decodeRecord(raw));
			}
		}
		return records;
	}

	/** Read the persisted signing key by its fixed legacy id, or null if absent. */
	async get(): Promise<MCPSigningKeyRecord | null> {
		const table = getKeysTable();
		try {
			const raw = await table.get(SIGNING_KEY_ID);
			if (!raw || !raw.kid) {
				return null;
			}
			return decodeRecord(raw);
		} catch (error) {
			this.logger?.error?.('Failed to retrieve MCP signing key:', error);
			return null;
		}
	}

	/**
	 * Resolve the active signing key:
	 *
	 * 1. Enumerate all persisted keys.
	 * 2. If empty → first-boot: generate and persist a key (pinned PEM under the
	 *    fixed `rs256-default` kid; a fresh random keypair under a UUID kid),
	 *    then re-read to adopt the winner.
	 * 3. Select the newest key by `created_at` (tie-break: `kid` desc).
	 * 4. If rotation is enabled (and pinning is NOT active) and the newest key is
	 *    older than `keyRotationInterval` → generate a fresh keypair under a new
	 *    UUID kid, persist, re-enumerate, re-select.
	 * 5. GC: delete keys superseded long enough ago that no token they signed can
	 *    still be unexpired (2× accessTokenTtl after their immediate successor's
	 *    created_at). GC errors are logged and never block minting.
	 *
	 * Enumeration errors PROPAGATE (minting fails loudly) — treating a transient
	 * read error as an empty table would generate spurious keys on every failed
	 * mint. The JWKS read path (`getAllPublicKeys`) stays best-effort instead.
	 *
	 * Not cached in-process — always reads persisted state so clustered nodes
	 * converge to the same key set without a coordinator.
	 */
	async getSigningKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord> {
		const rotationInterval = coerceInterval(mcpConfig?.keyRotationInterval);
		const accessTtl = coerceInterval(mcpConfig?.accessTokenTtl) || DEFAULT_ACCESS_TOKEN_TTL;
		const pinned = !!mcpConfig?.signingKeyPem;

		let allKeys = await this.enumerateKeys();

		// First boot: no keys in the table yet.
		if (allKeys.length === 0) {
			allKeys = await this.generateAndPersistFirstKey(mcpConfig);
		}

		let signerKey = selectNewestKey(allKeys);

		// Rotation — only when not pinned and interval > 0.
		if (!pinned && rotationInterval > 0) {
			const nowSeconds = Math.floor(Date.now() / 1000);
			const keyAgeSeconds = nowSeconds - signerKey.created_at;
			if (keyAgeSeconds > rotationInterval) {
				allKeys = await this.rotateTo(allKeys);
				signerKey = selectNewestKey(allKeys);
			}
		}

		// GC in the background (errors must not block minting).
		this.garbageCollect(allKeys, signerKey, accessTtl).catch((err) => {
			this.logger?.error?.('MCP key GC failed (non-fatal):', err instanceof Error ? err.message : String(err));
		});

		return signerKey;
	}

	/**
	 * Public keys to publish at the JWKS endpoint.
	 *
	 * Returns all persisted keys (public halves only). Read-only — never triggers
	 * generation (an unauthenticated JWKS fetch must not mint key material).
	 * Returns an empty set when the table isn't ready yet (first boot, table not
	 * created) rather than 500-ing the discovery endpoint.
	 */
	async getAllPublicKeys(): Promise<MCPSigningKeyRecord[]> {
		try {
			return await this.enumerateKeys();
		} catch (error) {
			this.logger?.error?.(
				'Failed to read MCP signing keys for JWKS:',
				error instanceof Error ? error.message : String(error)
			);
			return [];
		}
	}

	// ---- private helpers ----

	/**
	 * Generate and persist the first signing key (first-boot path).
	 * Re-reads after persisting to adopt the converged winner under concurrency.
	 */
	private async generateAndPersistFirstKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord[]> {
		let publicKeyPem: string;
		let privateKeyPem: string;
		let kid: string;

		if (mcpConfig?.signingKeyPem) {
			// Pinned key: the SHARED fixed kid is required — every node derives the
			// identical record from the same PEM, so concurrent writes are harmless
			// and all nodes agree on the signer.
			privateKeyPem = mcpConfig.signingKeyPem;
			publicKeyPem = createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }) as string;
			kid = SIGNING_KEY_ID;
		} else {
			// Generated key: a UNIQUE kid is required — two nodes racing first boot
			// generate different keypairs, and writing both under a shared kid would
			// have one overwrite the other, leaving the loser's already-signed tokens
			// carrying a kid whose JWKS entry is a different public key (they would
			// never verify). Distinct kids let both rows survive; JWKS publishes
			// both, and newest-created_at converges future signing.
			({ publicKeyPem, privateKeyPem } = await generateRsaKeyPair());
			kid = randomUUID();
		}

		const record: MCPSigningKeyRecord = {
			kid,
			alg: 'RS256',
			public_key_pem: publicKeyPem,
			private_key_pem: privateKeyPem,
			created_at: Math.floor(Date.now() / 1000),
		};

		const table = getKeysTable();
		try {
			await table.put(encodeRecord(record));
		} catch (error) {
			this.logger?.error?.('Failed to persist MCP signing key:', error);
			throw error;
		}
		this.logger?.info?.('MCP: generated and persisted RS256 signing key');

		// Re-read so we adopt the persisted winner (another node/request may have
		// written concurrently — write-then-re-read convergence). A failed re-read
		// falls back to the local record: the write above already succeeded.
		let afterWrite: MCPSigningKeyRecord[] = [];
		try {
			afterWrite = await this.enumerateKeys();
		} catch {
			// fall through to the local record
		}
		return afterWrite.length > 0 ? afterWrite : [record];
	}

	/**
	 * Generate a new keypair under a UUID kid, persist, and re-enumerate.
	 * Returns the updated key set (re-read from table to adopt converged state).
	 */
	private async rotateTo(currentKeys: MCPSigningKeyRecord[]): Promise<MCPSigningKeyRecord[]> {
		const { publicKeyPem, privateKeyPem } = await generateRsaKeyPair();
		const newKey: MCPSigningKeyRecord = {
			kid: randomUUID(),
			alg: 'RS256',
			public_key_pem: publicKeyPem,
			private_key_pem: privateKeyPem,
			created_at: Math.floor(Date.now() / 1000),
		};
		const table = getKeysTable();
		try {
			await table.put(encodeRecord(newKey));
			this.logger?.info?.('MCP: rotated signing key, new kid:', newKey.kid);
		} catch (error) {
			this.logger?.error?.(
				'MCP: failed to persist rotated signing key:',
				error instanceof Error ? error.message : String(error)
			);
			// Return existing keys unchanged so minting still works with the old key.
			return currentKeys;
		}
		// A failed re-read falls back to the known set + the key we just wrote.
		let afterRotate: MCPSigningKeyRecord[] = [];
		try {
			afterRotate = await this.enumerateKeys();
		} catch {
			// fall through to the local fallback
		}
		return afterRotate.length > 0 ? afterRotate : [...currentKeys, newKey];
	}

	/**
	 * Delete retired signing keys that are safe to remove.
	 *
	 * A key stopped signing the moment its IMMEDIATE SUCCESSOR (the next-newer
	 * key) was created, so the last token it signed expires at
	 * `successor.created_at + accessTtl`. It is deletable once
	 * `now - successor.created_at > 2 × accessTtl` — one full TTL of margin over
	 * that bound, covering replication lag between clustered nodes.
	 *
	 * Keying the window off each key's own successor (not the current signer)
	 * matters: with a rotation interval shorter than the GC threshold the signer
	 * is always young, and a signer-age rule would never fire — retired keys
	 * would accumulate forever. If a successor was itself GC'd earlier, the
	 * next-newer surviving key is used, which only makes the window later
	 * (conservative, never early).
	 *
	 * The current signer is never deleted (it is the newest key, so the loop
	 * below never visits it; the kid check is defense-in-depth). A retired
	 * `rs256-default` superseded by rotation IS eligible — correct, since
	 * rotation only runs when no pin is configured.
	 *
	 * GC errors are always caught by the caller via .catch().
	 */
	private async garbageCollect(
		allKeys: MCPSigningKeyRecord[],
		signerKey: MCPSigningKeyRecord,
		accessTtl: number
	): Promise<void> {
		if (allKeys.length <= 1) return;

		const nowSeconds = Math.floor(Date.now() / 1000);
		const gcThreshold = 2 * accessTtl;
		const table = getKeysTable();

		// Newest first, same ordering as signer selection (created_at, kid desc) —
		// sorted[0] is the signer; each key's immediate successor is sorted[i - 1].
		const sorted = [...allKeys].sort((a, b) => {
			if (b.created_at !== a.created_at) return b.created_at - a.created_at;
			return b.kid > a.kid ? 1 : -1;
		});

		for (let i = 1; i < sorted.length; i++) {
			const key = sorted[i];
			if (key.kid === signerKey.kid) continue;
			const successor = sorted[i - 1];
			if (nowSeconds - successor.created_at > gcThreshold) {
				try {
					await table.delete(key.kid);
					this.logger?.info?.('MCP: GC deleted retired signing key:', key.kid);
				} catch (gcErr) {
					this.logger?.warn?.(
						'MCP: GC failed to delete key:',
						key.kid,
						gcErr instanceof Error ? gcErr.message : String(gcErr)
					);
				}
			}
		}
	}
}
