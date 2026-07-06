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
 * is skipped; a warning is logged at startup if both are set. The pinned key
 * is still stored under `rs256-default` for legacy compat.
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
	 * 2. If empty → first-boot: generate and persist a key (pinned PEM or fresh
	 *    random keypair under `rs256-default`), then re-read to adopt the winner.
	 * 3. Select the newest key by `created_at` (tie-break: `kid` desc).
	 * 4. If rotation is enabled (and pinning is NOT active) and the newest key is
	 *    older than `keyRotationInterval` → generate a fresh keypair under a new
	 *    UUID kid, persist, re-enumerate, re-select.
	 * 5. GC: delete keys superseded long enough ago that no token they signed can
	 *    still be unexpired (2× accessTokenTtl after a newer key's created_at).
	 *    GC errors are logged and never block minting.
	 *
	 * Not cached in-process — always reads persisted state so clustered nodes
	 * converge to the same key set without a coordinator.
	 */
	async getSigningKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord> {
		const rotationInterval = coerceInterval(mcpConfig?.keyRotationInterval);
		const accessTtl = coerceInterval(mcpConfig?.accessTokenTtl) || DEFAULT_ACCESS_TOKEN_TTL;
		const pinned = !!mcpConfig?.signingKeyPem;

		let allKeys = await this.safeEnumerate();

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
			return await this.safeEnumerate();
		} catch (error) {
			this.logger?.error?.('Failed to read MCP signing keys for JWKS:', error);
			return [];
		}
	}

	// ---- private helpers ----

	/** Enumerate all keys, returning [] on error (JWKS must not 500). */
	private async safeEnumerate(): Promise<MCPSigningKeyRecord[]> {
		try {
			return await this.enumerateKeys();
		} catch {
			return [];
		}
	}

	/**
	 * Generate and persist the first signing key (first-boot path).
	 * Re-reads after persisting to adopt the converged winner under concurrency.
	 */
	private async generateAndPersistFirstKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord[]> {
		let publicKeyPem: string;
		let privateKeyPem: string;

		if (mcpConfig?.signingKeyPem) {
			privateKeyPem = mcpConfig.signingKeyPem;
			publicKeyPem = createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }) as string;
		} else {
			({ publicKeyPem, privateKeyPem } = await generateRsaKeyPair());
		}

		const record: MCPSigningKeyRecord = {
			kid: SIGNING_KEY_ID,
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
		// written concurrently — write-then-re-read convergence).
		const afterWrite = await this.safeEnumerate();
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
		const afterRotate = await this.safeEnumerate();
		return afterRotate.length > 0 ? afterRotate : [...currentKeys, newKey];
	}

	/**
	 * Delete retired signing keys that are safe to remove.
	 *
	 * A key is deletable when ALL of the following are true:
	 *   - It is not the current signer (`signerKey.kid`).
	 *   - A newer key exists (the `signerKey` was created after it).
	 *   - The newer key has been active long enough that no token signed by the
	 *     old key can still be unexpired: `now - signerKey.created_at > 2 × accessTtl`.
	 *   - It is NOT the pinned `rs256-default` key (handled via: if the current
	 *     signer IS the pinned key it survives the "not current signer" check;
	 *     the only edge case is a retired rs256-default that has been superseded by
	 *     rotation — those ARE eligible for GC once the window passes, which is the
	 *     correct behavior since the pin is no longer configured in this path).
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

		for (const key of allKeys) {
			if (key.kid === signerKey.kid) continue;
			// The signer was created after this key — use signer's created_at as
			// "superseded time" (the moment a newer key took over).
			const supersededAge = nowSeconds - signerKey.created_at;
			if (supersededAge > gcThreshold) {
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
