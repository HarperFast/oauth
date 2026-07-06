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
 * still be valid (2× accessTokenTtl after their immediate successor's
 * created_at). GC runs detached via setImmediate so it never holds the request's
 * transaction context.
 *
 * `mcp.signingKeyPem` (pin wins — ALWAYS): when a pinned key is configured,
 * getSigningKey looks for an existing record whose public_key_pem matches the
 * configured PEM. If found → that record signs (regardless of age/created_at).
 * If not found → the pinned key is persisted (under `rs256-default` when that
 * row is absent; under a deterministic fingerprint kid otherwise so concurrent
 * writes from clustered nodes are idempotent). This means the configured PEM
 * becomes the signer even if the table already has generated keys — not just on
 * first boot. Rotation is skipped while a pin is active; a startup warning is
 * logged if both are set.
 *
 * Fingerprint kid: `pinned-<first 16 hex chars of sha256(publicKeyPem)>`.
 * Every node derives the same kid from the same PEM, so concurrent writes are
 * safe (idempotent put under the same primary key).
 *
 * The private half never leaves the server; only the public half is published
 * at /.well-known/jwks.json.
 *
 * IMPORTANT: Harper tracked-object Proxies return empty own-keys — NO spread
 * (`{ ...raw }`). Always use explicit field access (decodeRecord).
 */

import { createHash, createPublicKey, generateKeyPair, randomUUID } from 'node:crypto';
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

/**
 * Deterministic kid for a pinned key when `rs256-default` is already taken by
 * different material. Derived from the public key so every node computes the
 * same kid from the same PEM — concurrent puts are idempotent.
 */
function pinnedKidFromPem(publicKeyPem: string): string {
	const fingerprint = createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16);
	return `pinned-${fingerprint}`;
}

export class MCPKeyStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Enumerate all rows in the keys table.
	 * PROPAGATES errors — callers on the mint path (getSigningKey) let them
	 * surface; callers on the read path (getAllPublicKeys) catch and return [].
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
	 * **When `mcpConfig.signingKeyPem` is set (pin wins — always):**
	 * 1. Derive the pinned public key from the PEM.
	 * 2. Search the key set for a record whose `public_key_pem` matches.
	 *    - Found → that record is the signer (ignoring `created_at`).
	 *    - Not found → persist the pinned key (under `rs256-default` when absent,
	 *      otherwise under a deterministic fingerprint kid), re-enumerate, select
	 *      by material match.
	 * 3. Rotation is skipped. Old keys remain for JWKS overlap; GC fires as usual.
	 *
	 * **Otherwise (rotation/generation path):**
	 * 1. Enumerate all persisted keys.
	 * 2. If empty → first-boot: generate under a UUID kid, persist, re-enumerate.
	 * 3. Select newest by `created_at` (tie-break: `kid` desc).
	 * 4. If `keyRotationInterval > 0` and newest key is older than the interval
	 *    → generate a fresh UUID-kid keypair, persist, re-enumerate, re-select.
	 * 5. GC fires detached (setImmediate) to clean up retired keys.
	 *
	 * Enumeration errors PROPAGATE on the mint path — a transient read failure
	 * must not trigger spurious key generation. The JWKS read path stays
	 * best-effort (getAllPublicKeys catches errors and returns []).
	 *
	 * Not cached in-process — always reads persisted state so clustered nodes
	 * converge to the same key set without a coordinator.
	 */
	async getSigningKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord> {
		const accessTtl = coerceInterval(mcpConfig?.accessTokenTtl) || DEFAULT_ACCESS_TOKEN_TTL;

		// Pin path: always wins when signingKeyPem is configured.
		if (mcpConfig?.signingKeyPem) {
			return this.getOrPersistPinnedKey(mcpConfig.signingKeyPem, accessTtl);
		}

		const rotationInterval = coerceInterval(mcpConfig?.keyRotationInterval);

		let allKeys = await this.enumerateKeys();

		// First boot: no keys in the table yet.
		if (allKeys.length === 0) {
			allKeys = await this.generateAndPersistFirstKey();
		}

		let signerKey = selectNewestKey(allKeys);

		// Rotation when interval > 0 and newest key is stale.
		if (rotationInterval > 0) {
			const nowSeconds = Math.floor(Date.now() / 1000);
			if (nowSeconds - signerKey.created_at > rotationInterval) {
				allKeys = await this.rotateTo(allKeys);
				signerKey = selectNewestKey(allKeys);
			}
		}

		// GC detached — must not hold request context.
		setImmediate(() => {
			this.garbageCollect(allKeys, signerKey, accessTtl).catch((err) => {
				this.logger?.error?.('MCP key GC failed (non-fatal):', err instanceof Error ? err.message : String(err));
			});
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
	 * Find or persist the key for a configured `signingKeyPem`. This is the
	 * pin-wins path: the configured PEM always signs, regardless of whether other
	 * keys exist in the table and regardless of their `created_at`.
	 *
	 * - Match by `public_key_pem` string equality (both sides exported via the
	 *   same Node.js canonical SPKI path, so the comparison is stable).
	 * - Kid assignment when persisting:
	 *   - `rs256-default` if that row is absent (legacy compat; every node derives
	 *     the same record from the same PEM → idempotent concurrent writes).
	 *   - `pinned-<sha256 fingerprint>` if `rs256-default` already holds different
	 *     material — deterministic from the PEM, so concurrent writes are also
	 *     idempotent.
	 * - Old keys are NOT removed — they stay for JWKS overlap so tokens they
	 *   signed keep verifying until they expire.
	 */
	private async getOrPersistPinnedKey(signingKeyPem: string, accessTtl: number): Promise<MCPSigningKeyRecord> {
		const pinnedPublicKeyPem = createPublicKey(signingKeyPem).export({ type: 'spki', format: 'pem' }) as string;

		let allKeys = await this.enumerateKeys();

		// If the pinned key is already in the table, use it.
		const existing = allKeys.find((k) => k.public_key_pem === pinnedPublicKeyPem);
		if (existing) {
			setImmediate(() => {
				this.garbageCollect(allKeys, existing, accessTtl).catch((err) => {
					this.logger?.error?.('MCP key GC failed (non-fatal):', err instanceof Error ? err.message : String(err));
				});
			});
			return existing;
		}

		// Not in table — choose kid and persist.
		const existingDefault = allKeys.find((k) => k.kid === SIGNING_KEY_ID);
		const kid = existingDefault ? pinnedKidFromPem(pinnedPublicKeyPem) : SIGNING_KEY_ID;

		const record: MCPSigningKeyRecord = {
			kid,
			alg: 'RS256',
			public_key_pem: pinnedPublicKeyPem,
			private_key_pem: signingKeyPem,
			created_at: Math.floor(Date.now() / 1000),
		};

		const table = getKeysTable();
		try {
			await table.put(encodeRecord(record));
			this.logger?.info?.('MCP: persisted pinned RS256 signing key as signer, kid:', kid);
		} catch (error) {
			this.logger?.error?.('Failed to persist pinned MCP signing key:', error);
			throw error;
		}

		// Re-enumerate to adopt the converged state.
		let afterWrite: MCPSigningKeyRecord[] = [];
		try {
			afterWrite = await this.enumerateKeys();
		} catch {
			// fall through to the local record
		}
		const allAfterWrite = afterWrite.length > 0 ? afterWrite : [...allKeys, record];

		// Find the pinned key in the post-write set by material match.
		const signerKey = allAfterWrite.find((k) => k.public_key_pem === pinnedPublicKeyPem) ?? record;

		setImmediate(() => {
			this.garbageCollect(allAfterWrite, signerKey, accessTtl).catch((err) => {
				this.logger?.error?.('MCP key GC failed (non-fatal):', err instanceof Error ? err.message : String(err));
			});
		});

		return signerKey;
	}

	/**
	 * Generate and persist the first signing key under a UUID kid (no-pin
	 * first-boot path). Re-enumerates after persisting to adopt the converged
	 * winner under concurrent first-boot races.
	 */
	private async generateAndPersistFirstKey(): Promise<MCPSigningKeyRecord[]> {
		const { publicKeyPem, privateKeyPem } = await generateRsaKeyPair();

		// UUID kid: two nodes racing first boot generate different keypairs; a
		// shared kid would let one overwrite the other, stranding the loser's
		// already-signed tokens with a kid whose JWKS entry is a different key.
		const record: MCPSigningKeyRecord = {
			kid: randomUUID(),
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
		this.logger?.info?.('MCP: generated and persisted RS256 signing key, kid:', record.kid);

		// Re-enumerate to adopt the persisted state (convergence).
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
	 * Returns the updated key set.
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
			return currentKeys;
		}
		let afterRotate: MCPSigningKeyRecord[] = [];
		try {
			afterRotate = await this.enumerateKeys();
		} catch {
			// fall through
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
	 * The current signer is never deleted (kid check). Errors are caught by the
	 * caller's setImmediate .catch().
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

		// Sort newest first (same ordering as signer selection).
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
