/**
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
import { getRequestPathname, hasAmbiguousPathSegments, verifyMCPAccessToken, type KeySource } from './withMCPAuth.ts';

interface MCPBearerValidationResult {
	username: string;
	authExpiresAt?: number;
	authCacheable?: boolean;
}

type MCPBearerValidator = (
	token: string,
	request: Request
) => Promise<MCPBearerValidationResult | undefined> | undefined;

interface MCPBearerValidatorOptions {
	getConfig?: () => MCPConfig | undefined;
	logger?: Logger;
	keyStore?: KeySource;
	emitAudit?: (payload: MCPTokenRejectedAuditPayload) => void;
}

const MAX_TOKEN_LENGTH = 16384;
const MAX_AUTH_EXPIRY_OFFSET_SECONDS = 365 * 24 * 60 * 60;

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
		return undefined;
	} catch {
		return undefined;
	}
}

function extractResourcePathname(resourceUrl: string): string | null {
	try {
		const { pathname } = new URL(resourceUrl);
		const normalized = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
		return normalized || '/';
	} catch {
		return null;
	}
}

function isCredentialRejectionError(err: unknown): err is Error {
	return (
		err instanceof Error &&
		Object.getOwnPropertySymbols(err).some(
			(s) => s.description === 'harper.credentialRejection' && (err as any)[s] === true
		)
	);
}

function credentialRejection(reason: string): Error {
	return (harper as any).credentialRejectionError(reason, 401);
}

export function createMCPBearerValidator(options: MCPBearerValidatorOptions = {}): MCPBearerValidator {
	const getConfig = options.getConfig ?? (() => OAuthResource.mcpConfig);
	let defaultKeyStore: MCPKeyStore | undefined;
	const verifiedTokenMemo = new Map<string, any>();
	let cachedCfg: MCPConfig | undefined;
	let cachedIssuerInput: string | undefined;
	let cachedResourceInput: string | undefined;
	let cachedIssuer: string | undefined;
	let cachedResource: string | undefined;
	let cachedResourcePathname: string | null | undefined;
	let cachedResourcePrefix: string | undefined;
	let loggedSyncError = false;
	let warnedQuarantineSubject = false;

	return function mcpBearerValidator(
		token: string,
		request: Request
	): Promise<MCPBearerValidationResult | undefined> | undefined {
		let cfg: MCPConfig | undefined;
		let issuer: string;
		let resource: string;
		let resourcePathname: string | null;
		let resourcePrefix: string | undefined;
		let requestPathname: string | undefined;
		try {
			cfg = getConfig();
			if (!cfg?.enabled || !cfg.issuer) {
				return undefined;
			}

			if (
				cfg !== cachedCfg ||
				cfg.issuer !== cachedIssuerInput ||
				cfg.resource !== cachedResourceInput ||
				!cachedIssuer ||
				!cachedResource ||
				cachedResourcePathname === undefined
			) {
				const nextIssuer = resolveIssuer({} as any, cfg);
				const nextResource = resolveResource({} as any, cfg);
				const nextResourcePathname = extractResourcePathname(nextResource);
				const nextResourcePrefix =
					nextResourcePathname && nextResourcePathname !== '/' ? `${nextResourcePathname}/` : undefined;
				cachedCfg = cfg;
				cachedIssuerInput = cfg.issuer;
				cachedResourceInput = cfg.resource;
				cachedIssuer = nextIssuer;
				cachedResource = nextResource;
				cachedResourcePathname = nextResourcePathname;
				cachedResourcePrefix = nextResourcePrefix;
			}
			issuer = cachedIssuer;
			resource = cachedResource;
			resourcePathname = cachedResourcePathname;
			resourcePrefix = cachedResourcePrefix;

			requestPathname = getRequestPathname(request);
			const p = requestPathname ?? '/';
			if (
				resourcePathname === '/' ||
				hasAmbiguousPathSegments(p) ||
				(resourcePathname !== null && p !== resourcePathname && (!resourcePrefix || !p.startsWith(resourcePrefix)))
			) {
				return undefined;
			}

			const memoHit = verifiedTokenMemo.get(token);
			if (!memoHit || memoHit.issuer !== issuer) {
				const unverifiedIss = extractUnverifiedIssuer(token);
				if (!unverifiedIss || unverifiedIss !== issuer) {
					return undefined;
				}
			}
		} catch (err) {
			if (!loggedSyncError) {
				loggedSyncError = true;
				(options.logger ?? OAuthResource.logger)?.error?.(
					'MCP bearer validator: unexpected error in synchronous ownership check:',
					err instanceof Error ? err.message : String(err)
				);
			}
			return undefined;
		}

		const activeCfg = cfg;
		const logger = options.logger ?? OAuthResource.logger;
		const emitAudit = options.emitAudit ?? emitMCPAuditEvent;
		const keyStore: KeySource = options.keyStore ?? (defaultKeyStore ??= new MCPKeyStore(logger));

		return (async (): Promise<MCPBearerValidationResult> => {
			try {
				if ((requestPathname ?? request?.url ?? '').length > 2048) {
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
						// Ignore audit sink errors so rejection still completes.
					}
					throw credentialRejection(reason);
				};

				if (resourcePathname === null) {
					return reject('MCP resource URL is invalid');
				}

				const verified = await verifyMCPAccessToken(token, {
					cfg: activeCfg,
					getConfig,
					keyStore,
					resource,
					issuer,
					logger,
					caller: 'MCP bearer validator',
					verifiedTokenMemo,
				});
				if (!verified.ok) {
					if (verified.transientError) {
						throw credentialRejection(verified.reason);
					}
					return reject(verified.reason);
				}

				if (isQuarantinePrincipal(verified.claims.sub)) {
					if (!warnedQuarantineSubject) {
						warnedQuarantineSubject = true;
						logger?.warn?.(
							'MCP bearer validator: rejected token with quarantined unverified subject; ' +
								'configure an onLogin hook or verified identity claim so MCP tokens resolve to a Harper user.'
						);
					}
					return reject('unverified subject cannot authenticate as a Harper user');
				}

				const authExpiresAt =
					verified.exp !== undefined
						? Math.min(verified.exp, Math.floor(Date.now() / 1000) + MAX_AUTH_EXPIRY_OFFSET_SECONDS)
						: undefined;
				return {
					username: verified.claims.sub,
					...(authExpiresAt !== undefined ? { authExpiresAt } : {}),
					// Harper's authorizationCache is keyed by Authorization header alone without re-checking path.
					authCacheable: false,
				};
			} catch (err) {
				if (isCredentialRejectionError(err)) {
					throw err;
				}
				logger?.error?.(
					'MCP bearer validator: unexpected validation error:',
					err instanceof Error ? err.message : String(err)
				);
				throw credentialRejection('MCP bearer token validation failed');
			}
		})();
	};
}

export function registerMCPBearerValidator(
	server: any,
	getConfig: () => MCPConfig | undefined = () => OAuthResource.mcpConfig,
	options: Omit<MCPBearerValidatorOptions, 'getConfig'> = {}
): (() => void) | undefined {
	if (
		typeof server?.registerBearerValidator !== 'function' ||
		typeof (harper as any).credentialRejectionError !== 'function'
	) {
		return undefined;
	}
	let probe: unknown;
	try {
		probe = (harper as any).credentialRejectionError('probe', 401);
	} catch {
		return undefined;
	}
	if (!isCredentialRejectionError(probe)) {
		return undefined;
	}
	const validator = createMCPBearerValidator({ ...options, getConfig });
	const disposer = server.registerBearerValidator(validator);
	return typeof disposer === 'function' ? disposer : () => {};
}
