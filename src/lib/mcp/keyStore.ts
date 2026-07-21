/**
 * MCP JWT Signing Key Store
 *
 * Persists signing keypairs (RS256 or ES256, per `mcp.signingAlgorithm` /
 * pinned key material) in the `harper_oauth_mcp_keys` Harper table,
 * keyed by random UUID `kid` (the legacy `rs256-default` row stays valid — no
 * migration). Every node's key is published at the JWKS endpoint so cross-node
 * tokens verify regardless of which node signed them — eliminating the
 * clustered first-boot race from v1.
 *
 * Signer selection: the key with the newest `created_at` wins. Tie-break on
 * `kid` descending (lexicographic) for determinism.
 *
 * Single-flight guard: an in-process `pendingWrite` promise serializes
 * concurrent key writes (first-boot, rotation, pin-persist) so N concurrent
 * mints don't each generate a redundant keypair. Cross-node races are handled
 * by convergence — multi-key JWKS + double-checked locking inside the write
 * lambda; the guard is per-process only.
 *
 * Rotation (opt-in via `mcp.keyRotationInterval`): lazy check at token mint —
 * if the newest key is older than the interval a fresh UUID-kid keypair is
 * generated and persisted. Old keys are GC'd once no token they signed can
 * still be valid (2× accessTokenTtl after their immediate successor's
 * created_at). GC runs detached via setImmediate so it never holds the
 * request's transaction context.
 *
 * Read-time retirement: `getAllPublicKeys` applies the same successor-age rule
 * to EXCLUDE retired keys from the JWKS and from `withMCPAuth` verification —
 * trust expires by time, not by traffic. Physical deletion (garbageCollect)
 * still only runs on the mint path; the read path never writes.
 *
 * Enumeration cache: raw key records are cached for 5 s to avoid a full-table
 * scan on every auth-hot-path JWKS or verification call. Any local `put` or
 * `delete` through `MCPKeyStore` invalidates the cache immediately so a
 * just-minted key verifies on this node without waiting for TTL expiry. The
 * retirement filter runs per-call on the cached records (cheap CPU, accurate
 * time).
 *
 * `mcp.signingKeyPem` (pin wins — ALWAYS): when a pinned key is configured,
 * getSigningKey looks for an existing record whose public_key_pem matches the
 * configured PEM. If found and already the newest key → sign directly. If
 * found but NOT the newest → bump created_at (same kid, same material) so the
 * pin leads the sorted order and the successor-based GC loop can clean up keys
 * that post-dated the pin. If not found at all → persist under `rs256-default`
 * (when free) or a deterministic fingerprint kid (when rs256-default holds
 * different material). Rotation is skipped while a pin is active.
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

import { createHash, createPrivateKey, createPublicKey, generateKeyPair, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import type { Logger, MCPConfig, MCPPublicKeyRecord, MCPSigningKeyRecord, Table } from '../../types.ts';
import type { SupportedSigningAlg } from './tokenIssuer.ts';

const generateKeyPairAsync = promisify(generateKeyPair);

/** Fixed primary key for the legacy v1 singleton signing key. */
export const SIGNING_KEY_ID = 'rs256-default';

/**
 * The algorithm generated keys should use, from `mcp.signingAlgorithm`.
 * Anything other than an explicit 'ES256' resolves to the RS256 default.
 */
export function resolveConfiguredAlg(mcpConfig?: MCPConfig): SupportedSigningAlg {
	return mcpConfig?.signingAlgorithm === 'ES256' ? 'ES256' : 'RS256';
}

/**
 * Derive the signing algorithm from pinned private-key material: RSA → RS256,
 * EC P-256 → ES256. Throws on any other key type/curve — a pin the issuer
 * cannot sign with must fail loudly at mint time, not emit broken tokens.
 */
export function algFromPrivateKeyPem(privateKeyPem: string): SupportedSigningAlg {
	const key = createPrivateKey(privateKeyPem);
	if (key.asymmetricKeyType === 'rsa') return 'RS256';
	if (key.asymmetricKeyType === 'ec') {
		const curve = key.asymmetricKeyDetails?.namedCurve;
		if (curve === 'prime256v1') return 'ES256';
		throw new Error(`MCP: unsupported EC curve for signingKeyPem: ${curve} (only P-256/prime256v1 is supported)`);
	}
	throw new Error(`MCP: unsupported signingKeyPem key type: ${key.asymmetricKeyType} (only RSA and EC P-256)`);
}

/**
 * The algorithm access tokens are (or will be) signed with, for metadata
 * advertisement: the pinned key's derived alg when a pin is configured
 * (falling back to the configured alg if the PEM is unparseable — the mint
 * path will surface that error), otherwise the configured alg.
 */
export function resolveEffectiveAlg(mcpConfig?: MCPConfig): SupportedSigningAlg {
	if (mcpConfig?.signingKeyPem) {
		try {
			return algFromPrivateKeyPem(mcpConfig.signingKeyPem);
		} catch {
			return resolveConfiguredAlg(mcpConfig);
		}
	}
	return resolveConfiguredAlg(mcpConfig);
}

const DEFAULT_ACCESS_TOKEN_TTL = 3600;
const ENUM_CACHE_TTL_MS = 5_000;

// Minimum age of the newest key before an alg-switch rotation may replace it.
// During a rolling config rollout, nodes briefly disagree on signingAlgorithm;
// without this floor each side would rotate the other's key away on every
// token mint (key generation proportional to mint rate). With it, a mixed
// window costs at most one rotation per direction per interval, and a
// converged config still switches within this bound.
const ALG_SWITCH_MIN_KEY_AGE_SECONDS = 300;

declare const databases: any;

let keysTable: Table | undefined;

// Enumeration cache: stores raw decoded records; retirement filter runs per-call.
let enumCache: { records: MCPSigningKeyRecord[]; fetchedAt: number } | null = null;

// In-process single-flight guard for key writes. Cross-node races are handled
// by convergence (multi-key JWKS + double-checked locking inside write lambdas),
// not by this guard — this is per-process only.
let pendingWrite: Promise<MCPSigningKeyRecord[]> | null = null;

// Single-entry memo: derive public key from PEM only when PEM changes.
let pinnedPublicKeyMemo: { pem: string; publicPem: string } | null = null;

// Cache timestamp function — overridable in tests via _setCacheNowMs.
let _getCacheNowMs: () => number = () => Date.now();

/**
 * Override the cache clock for testing. Pass null to restore the default.
 * Not part of the public API.
 * @internal
 */
export function _setCacheNowMs(fn: (() => number) | null): void {
	_getCacheNowMs = fn ?? (() => Date.now());
}

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
 * Reset all module-level state (for testing only).
 * @internal
 */
export function resetMCPKeysTableCache(): void {
	keysTable = undefined;
	enumCache = null;
	pendingWrite = null;
	pinnedPublicKeyMemo = null;
}

function invalidateEnumCache(): void {
	enumCache = null;
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

async function generateSigningKeyPair(
	alg: SupportedSigningAlg
): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
	const encoding = {
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	} as const;
	const { publicKey, privateKey } =
		alg === 'ES256'
			? await generateKeyPairAsync('ec', { namedCurve: 'P-256', ...encoding })
			: await generateKeyPairAsync('rsa', { modulusLength: 2048, ...encoding });
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

/** Sort keys newest-first: `created_at` desc, `kid` desc tie-break. */
function sortByNewest(keys: MCPSigningKeyRecord[]): MCPSigningKeyRecord[] {
	return [...keys].sort((a, b) => {
		if (b.created_at !== a.created_at) return b.created_at - a.created_at;
		return b.kid > a.kid ? 1 : -1;
	});
}

/**
 * Select the active signing key from a non-empty set.
 * Newest `created_at` wins; tie-break on `kid` descending (lexicographic).
 */
function selectNewestKey(keys: MCPSigningKeyRecord[]): MCPSigningKeyRecord {
	if (keys.length === 0) throw new Error('MCP: selectNewestKey called with empty key set');
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

/**
 * Partition keys into live and retired sets using the successor-age rule.
 *
 * PRECONDITION: `keys` must already be sorted newest-first (created_at desc,
 * kid-desc tie-break) — both call sites receive `enumerateKeys` output (or the
 * sorted local fallbacks), which is pre-sorted at cache population, so no
 * re-sort happens on the verification/JWKS hot path.
 *
 * `keys[0]` is always live (the current signer or candidate). A key at
 * position `i` is retired when its immediate successor (`keys[i-1]`) was
 * created more than `2 × accessTtl` seconds ago — meaning no token it signed
 * can still be valid, with margin for replication lag.
 *
 * Used by both `getAllPublicKeys` (read-time trust expiry) and `garbageCollect`
 * (physical deletion on the mint path).
 */
function partitionRetired(
	keys: MCPSigningKeyRecord[],
	accessTtl: number,
	nowSeconds: number
): { live: MCPSigningKeyRecord[]; retired: MCPSigningKeyRecord[] } {
	if (keys.length <= 1) return { live: keys.slice(), retired: [] };
	const live: MCPSigningKeyRecord[] = [keys[0]];
	const retired: MCPSigningKeyRecord[] = [];
	const gcThreshold = 2 * accessTtl;
	for (let i = 1; i < keys.length; i++) {
		const successor = keys[i - 1];
		if (nowSeconds - successor.created_at > gcThreshold) {
			retired.push(keys[i]);
		} else {
			live.push(keys[i]);
		}
	}
	return { live, retired };
}

export class MCPKeyStore {
	private logger?: Logger;

	constructor(logger?: Logger) {
		this.logger = logger;
	}

	/**
	 * Enumerate all rows in the keys table.
	 *
	 * Results are cached for `ENUM_CACHE_TTL_MS` (5 s). Any local write
	 * (put/delete) invalidates the cache immediately via `invalidateEnumCache()`.
	 *
	 * @param bypassCache - Skip the cache and read from the table (used inside
	 *   write lambdas for double-checked locking). The fresh result still refills
	 *   the cache for subsequent callers.
	 *
	 * PROPAGATES errors — callers on the mint path (getSigningKey) let them
	 * surface; callers on the read path (getAllPublicKeys) catch and return [].
	 */
	private async enumerateKeys(bypassCache = false): Promise<MCPSigningKeyRecord[]> {
		const nowMs = _getCacheNowMs();
		if (!bypassCache && enumCache && nowMs - enumCache.fetchedAt < ENUM_CACHE_TTL_MS) {
			return enumCache.records;
		}
		const table = getKeysTable();
		const records: MCPSigningKeyRecord[] = [];
		for await (const raw of table.search({})) {
			if (raw?.kid) {
				records.push(decodeRecord(raw));
			}
		}
		// Pre-sort so downstream callers (partitionRetired, selectNewestKey) receive
		// records in newest-first order without redundant sorts.
		const sorted = sortByNewest(records);
		enumCache = { records: sorted, fetchedAt: nowMs };
		return sorted;
	}

	/**
	 * Run `fn` inside the in-process single-flight guard.
	 *
	 * If another write is in flight, await it and re-evaluate `condition` against
	 * its result — the concurrent write likely satisfied our trigger (e.g. another
	 * request already generated the first-boot key or rotated). If the condition
	 * IS satisfied we return early without running `fn`. If NOT satisfied (e.g. a
	 * concurrent rotation write finished but we need to persist a pinned key), we
	 * proceed to our own write under a new `pendingWrite`.
	 *
	 * Double-checked locking inside `fn`: `fn` receives the result of a fresh
	 * `enumerateKeys(true)` call and can short-circuit if the condition is now
	 * satisfied (another process may have written between the outer check and now).
	 */
	private async runSingleFlight(
		condition: (keys: MCPSigningKeyRecord[]) => boolean,
		fn: (freshKeys: MCPSigningKeyRecord[]) => Promise<MCPSigningKeyRecord[]>
	): Promise<MCPSigningKeyRecord[]> {
		// If a write is in flight, await it and re-evaluate. Loop: a chain of
		// concurrent waiters may each trigger a new pendingWrite; keep waiting
		// until there's no in-flight write before starting our own.
		while (pendingWrite !== null) {
			const concurrent = await pendingWrite;
			if (condition(concurrent)) return concurrent;
			// Condition not satisfied by the concurrent write — fall through.
		}

		// Our write: re-check from the DB first (double-checked locking).
		pendingWrite = (async () => {
			const freshKeys = await this.enumerateKeys(true);
			if (condition(freshKeys)) return freshKeys;
			return fn(freshKeys);
		})().finally(() => {
			pendingWrite = null;
		});
		return pendingWrite;
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
	 * 1. Derive the pinned public key from the PEM (memoized per PEM string).
	 * 2. Search the key set for a record whose `public_key_pem` matches.
	 *    - Found AND already the newest → sign directly, no write.
	 *    - Found but NOT newest → bump `created_at` (single-flight write) so the
	 *      successor-based GC loop starts from the pin. Without the bump the
	 *      previously-newer generated key sits permanently at sorted[0] with no
	 *      older successor, and garbageCollect never visits it.
	 *    - Not found → persist (single-flight write) under `rs256-default` when
	 *      absent, otherwise under the deterministic fingerprint kid.
	 * 3. Rotation is skipped. Old keys remain for JWKS overlap; GC fires as usual.
	 *
	 * **Otherwise (rotation/generation path):**
	 * 1. Enumerate all persisted keys.
	 * 2. If empty → first-boot: single-flight write under a UUID kid.
	 * 3. Select newest by `created_at` (tie-break: `kid` desc).
	 * 4. If `keyRotationInterval > 0` and newest key is older than the interval
	 *    → single-flight rotation write.
	 * 5. GC fires detached (setImmediate) to clean up retired keys.
	 *
	 * Enumeration errors PROPAGATE on the mint path — a transient read failure
	 * must not trigger spurious key generation.
	 */
	async getSigningKey(mcpConfig?: MCPConfig): Promise<MCPSigningKeyRecord> {
		const accessTtl = coerceInterval(mcpConfig?.accessTokenTtl) || DEFAULT_ACCESS_TOKEN_TTL;

		// Pin path: always wins when signingKeyPem is configured.
		if (mcpConfig?.signingKeyPem) {
			return this.getOrPersistPinnedKey(mcpConfig.signingKeyPem, accessTtl);
		}

		const configuredAlg = resolveConfiguredAlg(mcpConfig);
		const rotationInterval = coerceInterval(mcpConfig?.keyRotationInterval);
		let allKeys = await this.enumerateKeys();

		// First boot: no keys in the table yet.
		if (allKeys.length === 0) {
			allKeys = await this.runSingleFlight(
				(keys) => keys.length > 0,
				(_freshKeys) => this.generateAndPersistFirstKey(configuredAlg)
			);
		}

		let signerKey = selectNewestKey(allKeys);

		// Algorithm switch: when `signingAlgorithm` no longer matches the newest
		// key, rotate to a fresh key under the configured alg so the config takes
		// effect on a running deployment. Old keys stay in the JWKS until retired,
		// so outstanding tokens keep verifying — additive, no migration (#127).
		// The age floor bounds churn while a rolling rollout leaves nodes with
		// disagreeing configs (see ALG_SWITCH_MIN_KEY_AGE_SECONDS).
		if ((signerKey.alg ?? 'RS256') !== configuredAlg) {
			const nowSeconds = Math.floor(Date.now() / 1000);
			if (nowSeconds - signerKey.created_at > ALG_SWITCH_MIN_KEY_AGE_SECONDS) {
				allKeys = await this.runSingleFlight(
					(keys) => keys.length > 0 && (selectNewestKey(keys).alg ?? 'RS256') === configuredAlg,
					(freshKeys) => this.rotateTo(freshKeys, configuredAlg)
				);
				signerKey = selectNewestKey(allKeys);
			}
		}

		// Rotation when interval > 0 and newest key is stale.
		if (rotationInterval > 0) {
			const nowSeconds = Math.floor(Date.now() / 1000);
			if (nowSeconds - signerKey.created_at > rotationInterval) {
				allKeys = await this.runSingleFlight(
					(keys) => nowSeconds - selectNewestKey(keys).created_at <= rotationInterval,
					(freshKeys) => this.rotateTo(freshKeys, configuredAlg)
				);
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
	 * Public keys to publish at the JWKS endpoint and use for token verification.
	 *
	 * Returns only the LIVE key set — retired keys (whose immediate successor was
	 * created more than `2 × accessTokenTtl` seconds ago) are excluded so trust
	 * expires by time even when no mint traffic triggers physical GC deletion.
	 *
	 * Results are served from the enumeration cache (5 s TTL); the retirement
	 * filter is applied per-call on the cached records (cheap, time-accurate).
	 *
	 * Read-only: never triggers key generation. Returns [] on table errors so the
	 * JWKS endpoint doesn't 500 before the first key is minted.
	 */
	async getAllPublicKeys(mcpConfig?: MCPConfig): Promise<MCPPublicKeyRecord[]> {
		try {
			const records = await this.enumerateKeys();
			const accessTtl = coerceInterval(mcpConfig?.accessTokenTtl) || DEFAULT_ACCESS_TOKEN_TTL;
			const nowSeconds = Math.floor(Date.now() / 1000);
			const { live } = partitionRetired(records, accessTtl, nowSeconds);
			// Strip private_key_pem: the private half must never leave the key store.
			return live.map((k) => ({ kid: k.kid, alg: k.alg, public_key_pem: k.public_key_pem, created_at: k.created_at }));
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
	 * Find or persist/bump the key for a configured `signingKeyPem`. Pin-wins
	 * path: the configured PEM always signs, regardless of other keys in the table.
	 *
	 * Match by `public_key_pem` string equality (both sides exported via the same
	 * Node.js canonical SPKI path — stable).
	 *
	 * When the pin is found but is NOT the newest key: re-persist with
	 * `created_at = now` (same kid, same material, nothing stranding). This makes
	 * the pin `sorted[0]` in `garbageCollect`, giving the previously-newer key a
	 * fresh successor timestamp so the existing successor-based GC loop cleans it
	 * up on schedule. Without the bump, that key leaks permanently — `sorted[0]`
	 * has no older successor entry, so `garbageCollect`'s `i=1` loop never reaches
	 * it. The bump is idempotent across nodes (same kid, same condition).
	 *
	 * Kid assignment when persisting:
	 * - `rs256-default` for an RSA pin when absent (legacy compat; deterministic
	 *   across nodes).
	 * - `pinned-<sha256 fingerprint>` when `rs256-default` holds different
	 *   material, or for a non-RSA pin — also deterministic, so concurrent puts
	 *   from clustered nodes are idempotent.
	 *
	 * Old keys are NOT removed — they stay for JWKS overlap so tokens they signed
	 * keep verifying until the retirement window closes.
	 */
	private async getOrPersistPinnedKey(signingKeyPem: string, accessTtl: number): Promise<MCPSigningKeyRecord> {
		// Memo: recompute public key derivation only when PEM changes.
		if (!pinnedPublicKeyMemo || pinnedPublicKeyMemo.pem !== signingKeyPem) {
			pinnedPublicKeyMemo = {
				pem: signingKeyPem,
				publicPem: createPublicKey(signingKeyPem).export({ type: 'spki', format: 'pem' }) as string,
			};
		}
		const pinnedPublicKeyPem = pinnedPublicKeyMemo.publicPem;

		let allKeys = await this.enumerateKeys();
		const existing = allKeys.find((k) => k.public_key_pem === pinnedPublicKeyPem);

		// Fast path: pin is already in the table AND is already the newest key.
		if (existing && existing.kid === selectNewestKey(allKeys).kid) {
			setImmediate(() => {
				this.garbageCollect(allKeys, existing, accessTtl).catch((err) => {
					this.logger?.error?.('MCP key GC failed (non-fatal):', err instanceof Error ? err.message : String(err));
				});
			});
			return existing;
		}

		// Write path — single-flight (handles both pin-persist and created_at bump).
		const pinnedIsNewest = (keys: MCPSigningKeyRecord[]) => {
			const ex = keys.find((k) => k.public_key_pem === pinnedPublicKeyPem);
			return ex != null && ex.kid === selectNewestKey(keys).kid;
		};

		allKeys = await this.runSingleFlight(pinnedIsNewest, async (freshKeys) => {
			const freshExisting = freshKeys.find((k) => k.public_key_pem === pinnedPublicKeyPem);

			if (freshExisting) {
				// Pin is in the table but not the newest — bump created_at.
				const bumped: MCPSigningKeyRecord = { ...freshExisting, created_at: Math.floor(Date.now() / 1000) };
				const table = getKeysTable();
				try {
					await table.put(encodeRecord(bumped));
					invalidateEnumCache();
					this.logger?.info?.('MCP: bumped pinned key created_at so it leads GC order, kid:', bumped.kid);
				} catch (error) {
					this.logger?.error?.('Failed to bump pinned MCP signing key created_at:', error);
					return freshKeys; // Non-fatal: return without bump.
				}
				let afterBump: MCPSigningKeyRecord[] = [];
				try {
					afterBump = await this.enumerateKeys(true);
				} catch {
					// Fall through to local fallback.
				}
				if (afterBump.length === 0) {
					afterBump = sortByNewest(freshKeys.map((k) => (k.kid === bumped.kid ? bumped : k)));
					enumCache = { records: afterBump, fetchedAt: _getCacheNowMs() };
				}
				return afterBump;
			}

			// Pin not in table — choose kid and persist. The alg comes from the key
			// material itself (throws on unsupported types). Only an RSA pin may
			// claim the legacy `rs256-default` kid; EC pins always get the
			// deterministic fingerprint kid.
			const alg = algFromPrivateKeyPem(signingKeyPem);
			const existingDefault = freshKeys.find((k) => k.kid === SIGNING_KEY_ID);
			const kid = existingDefault || alg !== 'RS256' ? pinnedKidFromPem(pinnedPublicKeyPem) : SIGNING_KEY_ID;
			const record: MCPSigningKeyRecord = {
				kid,
				alg,
				public_key_pem: pinnedPublicKeyPem,
				private_key_pem: signingKeyPem,
				created_at: Math.floor(Date.now() / 1000),
			};
			const table = getKeysTable();
			try {
				await table.put(encodeRecord(record));
				invalidateEnumCache();
				this.logger?.info?.(`MCP: persisted pinned ${alg} signing key as signer, kid:`, kid);
			} catch (error) {
				this.logger?.error?.('Failed to persist pinned MCP signing key:', error);
				throw error;
			}
			let afterWrite: MCPSigningKeyRecord[] = [];
			try {
				afterWrite = await this.enumerateKeys(true);
			} catch {
				// Fall through.
				this.logger?.debug?.('MCP keys: post-write re-enumeration failed; using local fallback');
			}
			if (afterWrite.length === 0) {
				afterWrite = sortByNewest([...freshKeys, record]);
				enumCache = { records: afterWrite, fetchedAt: _getCacheNowMs() };
			}
			return afterWrite;
		});

		const signerKey = allKeys.find((k) => k.public_key_pem === pinnedPublicKeyPem) ?? existing;
		if (!signerKey) {
			// Should not happen — the single-flight write either persisted or bumped.
			throw new Error('MCP: pinned key not found after write; check table access');
		}

		setImmediate(() => {
			this.garbageCollect(allKeys, signerKey, accessTtl).catch((err) => {
				this.logger?.error?.('MCP key GC failed (non-fatal):', err instanceof Error ? err.message : String(err));
			});
		});

		return signerKey;
	}

	/**
	 * Generate and persist the first signing key under a UUID kid (no-pin
	 * first-boot path). Re-enumerates after persisting to adopt the converged
	 * winner under concurrent first-boot races from other processes.
	 */
	private async generateAndPersistFirstKey(alg: SupportedSigningAlg): Promise<MCPSigningKeyRecord[]> {
		const { publicKeyPem, privateKeyPem } = await generateSigningKeyPair(alg);

		// UUID kid: two nodes racing first boot generate different keypairs; a
		// shared kid would let one overwrite the other, stranding the loser's
		// already-signed tokens with a kid whose JWKS entry is a different key.
		const record: MCPSigningKeyRecord = {
			kid: randomUUID(),
			alg,
			public_key_pem: publicKeyPem,
			private_key_pem: privateKeyPem,
			created_at: Math.floor(Date.now() / 1000),
		};

		const table = getKeysTable();
		try {
			await table.put(encodeRecord(record));
			invalidateEnumCache();
		} catch (error) {
			this.logger?.error?.('Failed to persist MCP signing key:', error);
			throw error;
		}
		this.logger?.info?.(`MCP: generated and persisted ${alg} signing key, kid:`, record.kid);

		// Re-enumerate to adopt the persisted state (convergence under cross-process races).
		let afterWrite: MCPSigningKeyRecord[] = [];
		try {
			afterWrite = await this.enumerateKeys();
		} catch (error) {
			this.logger?.debug?.(
				'MCP keys: post-write re-enumeration failed; using local fallback:',
				error instanceof Error ? error.message : String(error)
			);
		}
		// If the DB read didn't reflect the write yet (timing), seed the cache with
		// the local record so subsequent getAllPublicKeys calls see it immediately
		// instead of serving a stale-empty cache entry.
		if (afterWrite.length === 0) {
			afterWrite = [record];
			enumCache = { records: afterWrite, fetchedAt: _getCacheNowMs() };
		}
		return afterWrite;
	}

	/**
	 * Generate a new keypair under a UUID kid, persist, and re-enumerate.
	 * Returns the updated key set.
	 */
	private async rotateTo(currentKeys: MCPSigningKeyRecord[], alg: SupportedSigningAlg): Promise<MCPSigningKeyRecord[]> {
		const { publicKeyPem, privateKeyPem } = await generateSigningKeyPair(alg);
		const newKey: MCPSigningKeyRecord = {
			kid: randomUUID(),
			alg,
			public_key_pem: publicKeyPem,
			private_key_pem: privateKeyPem,
			created_at: Math.floor(Date.now() / 1000),
		};
		const table = getKeysTable();
		try {
			await table.put(encodeRecord(newKey));
			invalidateEnumCache();
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
		} catch (error) {
			this.logger?.debug?.(
				'MCP keys: post-rotation re-enumeration failed; using local fallback:',
				error instanceof Error ? error.message : String(error)
			);
		}
		if (afterRotate.length === 0) {
			afterRotate = sortByNewest([...currentKeys, newKey]);
			enumCache = { records: afterRotate, fetchedAt: _getCacheNowMs() };
		}
		return afterRotate;
	}

	/**
	 * Delete retired signing keys (physical cleanup; mint-path only).
	 *
	 * Delegates to `partitionRetired` for the same successor-age rule used by
	 * `getAllPublicKeys`. The current signer is additionally protected by a
	 * kid-check (defense-in-depth in case the pin path hands an unexpected signer).
	 * Errors are caught by the caller's `setImmediate .catch()`.
	 */
	private async garbageCollect(
		allKeys: MCPSigningKeyRecord[],
		signerKey: MCPSigningKeyRecord,
		accessTtl: number
	): Promise<void> {
		const nowSeconds = Math.floor(Date.now() / 1000);
		const { retired } = partitionRetired(allKeys, accessTtl, nowSeconds);
		if (retired.length === 0) return;
		const table = getKeysTable();
		for (const key of retired) {
			if (key.kid === signerKey.kid) continue; // Defense-in-depth.
			try {
				await table.delete(key.kid);
				invalidateEnumCache();
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
