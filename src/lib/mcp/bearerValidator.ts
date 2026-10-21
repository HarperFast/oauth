/**
 * Harper Core Bearer-Token Validator (`createMCPBearerValidator` / `registerMCPBearerValidator`)
 *
 * Bridges this plugin's MCP OAuth 2.1 authorization server into Harper's core
 * authentication pipeline via `scope.server.registerBearerValidator`
 * (`HarperFast/harper#3313`).
 */

import * as harper from 'harper';
import type { Logger, MCPConfig, Request } from '../../types.ts';
import { OAuthResource } from '../resource.ts';
import { isQuarantinePrincipal } from '../quarantinePrincipal.ts';
import { MCPKeyStore } from './keyStore.ts';
import { resolveIssuer, resolveResource } from './wellKnown.ts';
import { emitMCPAuditEvent, type MCPTokenRejectedAuditPayload } from './audit.ts';
import { pathOwned, verifyMCPAccessToken, type KeySource } from './withMCPAuth.ts';

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

export type MCPBearerValidator = (
	token: string,
	request: Request
) => Promise<MCPBearerValidationResult | undefined> | undefined;

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
 * `verifyMCPAccessToken`.
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

function extractResourcePathname(resourceUrl: string): string {
	try {
		const { pathname } = new URL(resourceUrl);
		const normalized = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
		return normalized || '/';
	} catch {
		return '/mcp';
	}
}

function credentialRejection(reason: string): Error {
	const harperAny = harper as any;
	if (typeof harperAny.credentialRejectionError === 'function') {
		return harperAny.credentialRejectionError(reason, 401);
	}
	const err = new Error(reason) as Error & { statusCode: number };
	err.name = 'CredentialRejectionError';
	err.statusCode = 401;
	return err;
}

/**
 * Create a Harper core Bearer-token validator for this plugin's MCP access tokens.
 */
export function createMCPBearerValidator(options: MCPBearerValidatorOptions = {}): MCPBearerValidator {
	const getConfig = options.getConfig ?? (() => OAuthResource.mcpConfig);
	let defaultKeyStore: MCPKeyStore | undefined;
	let cachedCfg: MCPConfig | undefined;
	let cachedIssuerInput: string | undefined;
	let cachedResourceInput: string | undefined;
	let cachedIssuer: string | undefined;
	let cachedResource: string | undefined;
	let cachedResourcePathname: string | undefined;

	return function mcpBearerValidator(
		token: string,
		request: Request
	): Promise<MCPBearerValidationResult | undefined> | undefined {
		const cfg = getConfig();
		if (!cfg?.enabled) {
			return undefined;
		}

		const unverifiedIss = extractUnverifiedIssuer(token);
		if (!unverifiedIss) {
			return undefined;
		}

		let issuer: string;
		let resource: string;
		let resourcePathname: string;
		if (cfg.issuer) {
			if (
				cfg !== cachedCfg ||
				cfg.issuer !== cachedIssuerInput ||
				cfg.resource !== cachedResourceInput ||
				!cachedIssuer ||
				!cachedResource ||
				!cachedResourcePathname
			) {
				cachedCfg = cfg;
				cachedIssuerInput = cfg.issuer;
				cachedResourceInput = cfg.resource;
				cachedIssuer = resolveIssuer({} as any, cfg);
				cachedResource = resolveResource({} as any, cfg);
				cachedResourcePathname = extractResourcePathname(cachedResource);
			}
			issuer = cachedIssuer;
			resource = cachedResource;
			resourcePathname = cachedResourcePathname;
		} else {
			const reqObj = (request ?? {}) as any;
			issuer = resolveIssuer(reqObj, cfg);
			resource = resolveResource(reqObj, cfg);
			resourcePathname = extractResourcePathname(resource);
		}

		if (unverifiedIss !== issuer) {
			return undefined;
		}

		const logger = options.logger ?? OAuthResource.logger;
		const emitAudit = options.emitAudit ?? emitMCPAuditEvent;
		const keyStore: KeySource = options.keyStore ?? (defaultKeyStore ??= new MCPKeyStore(logger));

		return (async (): Promise<MCPBearerValidationResult> => {
			if ((request?.pathname ?? request?.url ?? '').length > 2048) {
				throw credentialRejection('request path exceeds the maximum allowed length');
			}

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

			const requestPathname =
				request?.pathname ?? (typeof request?.url === 'string' ? request.url.split('?')[0] : undefined);
			if (!pathOwned(requestPathname, resourcePathname)) {
				return reject('token audience does not match the requested resource');
			}

			const verified = await verifyMCPAccessToken(token, {
				cfg,
				getConfig,
				keyStore,
				resource,
				issuer,
				logger,
				caller: 'MCP bearer validator',
			});
			if (!verified.ok) {
				return reject(verified.reason);
			}

			// Refuse quarantined subjects before Harper resolves `username` through
			// `server.getUser` (which an application may override).
			if (isQuarantinePrincipal(verified.claims.sub)) {
				return reject('unverified subject cannot authenticate as a Harper user');
			}

			return {
				username: verified.claims.sub,
				...(verified.exp !== undefined ? { authExpiresAt: verified.exp } : {}),
				// Harper's authorizationCache is keyed by Authorization header alone
				// across all routes on the worker; opt out when pathOwned restricts
				// acceptance to a sub-path (e.g. '/mcp') or when issuer is host-derived.
				authCacheable: Boolean(cfg.issuer) && resourcePathname === '/',
			};
		})();
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
	const disposer = server.registerBearerValidator(validator);
	return typeof disposer === 'function' ? disposer : undefined;
}
