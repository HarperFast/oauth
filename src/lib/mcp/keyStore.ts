/**
 * MCP JWT Signing Key Store
 *
 * Persists the RS256 signing keypair in the `harper_oauth_mcp_keys` Harper
 * table so every replicated node shares one key set (file storage would
 * diverge). v1 keeps a SINGLE key under a fixed primary key (`SIGNING_KEY_ID`)
 * because the plugin's table abstraction is get/put/delete only — no
 * enumeration — and #86 defers key rotation. The private half never leaves the
 * server; only the public half is published at /.well-known/jwks.json.
 *
 * The key is resolved lazily (first token mint) from the persisted row — not
 * cached in-process, so a node always picks up the converged value. First boot
 * generates a keypair unless one is provided via `mcp.signingKeyPem`.
 *
 * CLUSTERED PRODUCTION should set `mcp.signingKeyPem` (the same PEM on every
 * node). Without it, two nodes can both miss the row on their first mint and
 * generate different keys; until replication converges, a node may sign tokens
 * with a key JWKS does not publish (so those tokens fail verification). A
 * configured key is identical everywhere and removes the race entirely.
 *
 * Explicit field access on encode/decode (no `{ ...raw }`) — Harper
 * tracked-object Proxies return empty own-keys. See CLAUDE.md gotcha.
 */

import { createPublicKey, generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';
import type { Logger, MCPConfig, MCPSigningKeyRecord, Table } from '../../types.ts';

const generateKeyPairAsync = promisify(generateKeyPair);

/** Fixed primary key for the singleton v1 signing key. */
export const SIGNING_KEY_ID = 'rs256-default';

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
 * Reset cached table reference and resolved key (for testing only).
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

export class MCPKeyStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/** Read the persisted signing key, or null if none exists yet. */
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
	 * Resolve the active signing key, generating and persisting one on first use
	 * if absent.
	 *
	 * Deliberately NOT cached in-process: in a replicated deployment without a
	 * configured `mcp.signingKeyPem`, two nodes can both miss the row on their
	 * first mint and generate different keys. Always reading the persisted row
	 * (and re-reading after a generate) means a node adopts the converged winner
	 * on its next mint instead of being stuck signing with a key JWKS no longer
	 * publishes. The narrow pre-convergence window where a node signs with a
	 * soon-to-be-overwritten key is only fully avoided by setting
	 * `mcp.signingKeyPem` (identical on every node) — required for clustered
	 * production; see the module header.
	 */
	async getSigningKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord> {
		const existing = await this.get();
		if (existing) {
			return existing;
		}

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
		// Re-read so we adopt the persisted value (the winner if another node or
		// request wrote concurrently) rather than our local candidate.
		const persisted = await this.get();
		return persisted ?? record;
	}

	/**
	 * Public keys to publish at the JWKS endpoint. Read-only — never triggers
	 * generation (an unauthenticated JWKS fetch must not mint key material), so
	 * the set is empty until the first token is issued.
	 */
	async getAllPublicKeys(): Promise<MCPSigningKeyRecord[]> {
		try {
			const existing = await this.get();
			return existing ? [existing] : [];
		} catch (error) {
			// Don't 500 the public discovery endpoint if the table isn't ready —
			// publish an empty set. Token minting (which needs the key) still errors.
			this.logger?.error?.('Failed to read MCP signing keys for JWKS:', error);
			return [];
		}
	}
}
