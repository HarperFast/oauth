/**
 * Harper Core Bearer-Token Validator (`createMCPBearerValidator` / `registerMCPBearerValidator`)
 *
 * Bridges this plugin's MCP OAuth 2.1 authorization server into Harper's core
 * authentication pipeline via `scope.server.registerBearerValidator`
 * (`HarperFast/harper#3313`). When registered, Harper's native `/mcp` endpoint
 * (and any other core-authenticated surface) accepts access tokens minted by
 * this plugin without requiring a separate `withMCPAuth` wrapper.
 *
 * Ownership & fail-closed rules:
 * 1. If MCP is disabled (`!cfg?.enabled`), or the presented Bearer token is not
 *    a three-part JWT whose unverified payload `iss` matches this plugin's
 *    resolved issuer (`resolveIssuer(request, cfg)`), the validator returns
 *    `undefined` ("not mine") so non-plugin tokens (Harper operation tokens or
 *    another plugin's tokens) continue through the chain unaffected.
 * 2. Once `iss` matches this plugin's issuer, the plugin owns the token: any
 *    verification failure (bad signature, wrong `typ`/`alg`/`kid`, expired,
 *    wrong `aud`, malformed claims, no signing keys, or a quarantined
 *    `unverified:<claim>#<hash>` subject) emits `oauth.mcp.token.rejected` and
 *    throws a `credentialRejectionError` (`statusCode: 401`) so Harper core
 *    fails closed in place rather than falling through.
 * 3. Successful validation returns `{ username: payload.sub, authExpiresAt: payload.exp, authCacheable: false }`.
 *    `authCacheable: false` opts out of Harper's worker-local `authorizationCache`
 *    (which is keyed by `Authorization` header alone across all routes/hosts),
 *    because RFC 8707 audience verification is request-dependent.
 */

import * as harper from 'harper';
import type { Logger, MCPConfig, MCPPublicKeyRecord, Request } from '../../types.ts';
import { OAuthResource } from '../resource.ts';
import { isQuarantinePrincipal } from '../quarantinePrincipal.ts';
import { MCPKeyStore } from './keyStore.ts';
import { verifyAccessTokenWithKeySet } from './tokenIssuer.ts';
import { resolveIssuer, resolveResource } from './wellKnown.ts';
import { emitMCPAuditEvent, type MCPTokenRejectedAuditPayload } from './audit.ts';

/** Minimal surface the bearer validator needs from a key source (injectable for tests). */
interface KeySource {
	getAllPublicKeys(mcpConfig?: MCPConfig): Promise<MCPPublicKeyRecord[]>;
}

/**
 * Result returned to Harper's `runBearerValidators` (`security/bearerValidators.ts`).
 * Harper strictly validates that no extra properties are present beyond
 * `username`, `authExpiresAt`, and `authCacheable`.
 */
export interface MCPBearerValidationResult {
	username: string;
	authExpiresAt?: number;
	authCacheable?: boolean;
}

export type MCPBearerValidator = (token: string, request: Request) => Promise<MCPBearerValidationResult | undefined>;

export interface MCPBearerValidatorOptions {
	/**
	 * MCP config source, read per request so live config changes apply. Defaults
	 * to the plugin's live config (`() => OAuthResource.mcpConfig`).
	 */
	getConfig?: () => MCPConfig | undefined;
	/** Logger. Defaults to the plugin logger (`OAuthResource.logger`). */
	logger?: Logger;
	/**
	 * Signing-key source. Defaults to the plugin's `MCPKeyStore` (reads the
	 * published public keys from `harper_oauth_mcp_keys`). Injectable for tests.
	 */
	keyStore?: KeySource;
	/**
	 * Audit sink for `oauth.mcp.token.rejected` events, invoked when an owned
	 * bearer token (`iss` matches this plugin) is rejected. Defaults to the
	 * plugin's `emitMCPAuditEvent`. Injectable for tests.
	 */
	emitAudit?: (payload: MCPTokenRejectedAuditPayload) => void;
}

/**
 * Maximum token length inspected during unverified `iss` extraction, bounding
 * base64url + JSON work on arbitrary non-plugin Bearer headers.
 */
const MAX_TOKEN_LENGTH = 16384;

/**
 * Decode ONLY the unverified payload's `iss` claim from a compact JWS (`a.b.c`)
 * to determine whether this plugin owns the token. Returns `undefined` for any
 * non-JWT or payload without a non-empty string `iss`.
 *
 * Security note: this value is used strictly as a routing/ownership discriminator
 * (`unverifiedIss === resolveIssuer(...)`). Cryptographic verification of the
 * full token (including `iss`) runs immediately afterward via
 * `verifyAccessTokenWithKeySet`.
 */
function extractUnverifiedIssuer(token: string): string | undefined {
	if (typeof token !== 'string' || !token || token.length > MAX_TOKEN_LENGTH) {
		return undefined;
	}
	const firstDot = token.indexOf('.');
	if (firstDot <= 0) return undefined;
	const secondDot = token.indexOf('.', firstDot + 1);
	if (secondDot <= firstDot + 1 || secondDot >= token.length - 1) return undefined;
	if (token.indexOf('.', secondDot + 1) !== -1) return undefined;

	const payloadSegment = token.slice(firstDot + 1, secondDot);
	try {
		const json = Buffer.from(payloadSegment, 'base64url').toString('utf8');
		const parsed = JSON.parse(json);
		if (
			parsed &&
			typeof parsed === 'object' &&
			!Array.isArray(parsed) &&
			typeof parsed.iss === 'string' &&
			parsed.iss
		) {
			return parsed.iss;
		}
	} catch {
		// Not a valid JSON payload — not our JWT.
	}
	return undefined;
}

/**
 * Build a Harper-tagged credential-rejection error (`HarperFast/harper#3313`).
 * Falls back to a statusCode-401 Error on Harper versions that predate
 * `credentialRejectionError` / `markCredentialRejection` so the module loads
 * cleanly under any `harper >=5.0.0` peer.
 */
function credentialRejection(reason: string): Error {
	const harperAny = harper as any;
	if (typeof harperAny.credentialRejectionError === 'function') {
		return harperAny.credentialRejectionError(reason, 401);
	}
	const err = new Error(reason) as Error & { statusCode: number };
	err.name = 'CredentialRejectionError';
	err.statusCode = 401;
	if (typeof harperAny.markCredentialRejection === 'function') {
		return harperAny.markCredentialRejection(err);
	}
	return err;
}

/**
 * Create a Harper core Bearer-token validator for this plugin's MCP access tokens.
 */
export function createMCPBearerValidator(options: MCPBearerValidatorOptions = {}): MCPBearerValidator {
	const getConfig = options.getConfig ?? (() => OAuthResource.mcpConfig);

	return async function mcpBearerValidator(
		token: string,
		request: Request
	): Promise<MCPBearerValidationResult | undefined> {
		const cfg = getConfig();
		if (!cfg?.enabled) {
			return undefined;
		}

		const unverifiedIss = extractUnverifiedIssuer(token);
		if (!unverifiedIss) {
			return undefined;
		}

		const issuer = resolveIssuer((request ?? {}) as any, cfg);
		if (unverifiedIss !== issuer) {
			return undefined;
		}

		// From this point on, the token claims our issuer: we own it and MUST fail
		// closed (never return `undefined` to fall through to subsequent validators
		// or core JWT verification).
		const logger = options.logger ?? OAuthResource.logger;
		const emitAudit = options.emitAudit ?? emitMCPAuditEvent;

		// Repo invariant (AGENTS.md; OAuthResource.parseRoute & withMCPAuth cap
		// paths at 2048 chars for DoS mitigation): enforce before key/crypto work.
		if ((request?.pathname ?? request?.url ?? '').length > 2048) {
			throw credentialRejection('request path exceeds the maximum allowed length');
		}

		const resource = resolveResource((request ?? {}) as any, cfg);

		const reject = (reason: string): never => {
			try {
				emitAudit({
					event: 'oauth.mcp.token.rejected',
					reason,
					aud: resource,
					timestamp: new Date().toISOString(),
				});
			} catch {
				// Audit is best-effort; never let it prevent the fail-closed 401.
			}
			throw credentialRejection(reason);
		};

		let keys: MCPPublicKeyRecord[];
		try {
			const keyStore: KeySource = options.keyStore ?? new MCPKeyStore(logger);
			keys = await keyStore.getAllPublicKeys(cfg);
		} catch (error) {
			logger?.error?.(
				'MCP bearer validator: failed to load MCP signing keys:',
				error instanceof Error ? error.message : String(error)
			);
			keys = [];
		}
		if (keys.length === 0) {
			return reject('no signing keys available to verify token');
		}

		let payload: any;
		try {
			payload = verifyAccessTokenWithKeySet(token, keys, { audience: resource, issuer });
		} catch (error) {
			logger?.debug?.(
				'MCP bearer validator: token verification failed:',
				error instanceof Error ? error.message : String(error)
			);
			return reject('access token is invalid, expired, or not issued for this resource');
		}

		if (typeof payload.sub !== 'string' || !payload.sub) return reject('token missing subject');
		if (typeof payload.client_id !== 'string' || !payload.client_id) return reject('token missing client_id');
		if (typeof payload.aud !== 'string' || !payload.aud) return reject('token audience is invalid');
		if (payload.scope !== undefined && typeof payload.scope !== 'string') {
			return reject('token scope is invalid');
		}

		// Quarantine invariant (src/lib/quarantinePrincipal.ts, #231): a synthetic
		// `unverified:<claim>#<16-hex>` subject must never resolve to a Harper
		// user in `hdb_user`. Core bearer validation resolves the returned
		// `username` through `server.getUser(username, null, request)`, so refuse
		// quarantined subjects here before core ever looks up `hdb_user`.
		if (isQuarantinePrincipal(payload.sub)) {
			return reject('unverified subject cannot authenticate as a Harper user');
		}

		return {
			username: payload.sub,
			...(typeof payload.exp === 'number' && Number.isFinite(payload.exp) ? { authExpiresAt: payload.exp } : {}),
			// Harper's authorizationCache is keyed by Authorization header alone
			// across all routes/hosts on the worker; because RFC 8707 audience
			// verification depends on the request target, opt out of caching.
			authCacheable: false,
		};
	};
}

/**
 * Register the MCP bearer validator with `server.registerBearerValidator` when
 * the host Harper runtime supports it (`HarperFast/harper#3313`). Returns the
 * unregister disposer when registered, or `undefined` when the host runtime
 * does not expose `server.registerBearerValidator`.
 */
export function registerMCPBearerValidator(
	server: any,
	getConfig: () => MCPConfig | undefined = () => OAuthResource.mcpConfig,
	options: Omit<MCPBearerValidatorOptions, 'getConfig'> = {}
): (() => void) | undefined {
	if (typeof server?.registerBearerValidator !== 'function') {
		return undefined;
	}
	const validator = createMCPBearerValidator({ ...options, getConfig });
	return server.registerBearerValidator(validator);
}
