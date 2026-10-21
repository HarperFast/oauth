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
import { getRequestPathname, pathOwned, verifyMCPAccessToken, type KeySource } from './withMCPAuth.ts';

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

/** Decode ONLY the unverified payload's `iss` claim from a compact JWS (`a.b.c`). */
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

	return function mcpBearerValidator(
		token: string,
		request: Request
	): Promise<MCPBearerValidationResult | undefined> | undefined {
		const cfg = getConfig();
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
			cachedCfg = cfg;
			cachedIssuerInput = cfg.issuer;
			cachedResourceInput = cfg.resource;
			cachedIssuer = nextIssuer;
			cachedResource = nextResource;
			cachedResourcePathname = nextResourcePathname;
		}
		const issuer = cachedIssuer;
		const resource = cachedResource;
		const resourcePathname = cachedResourcePathname;

		const requestPathname = getRequestPathname(request);
		if (resourcePathname !== null && resourcePathname !== '/' && !pathOwned(requestPathname, resourcePathname)) {
			return undefined;
		}

		const unverifiedIss = extractUnverifiedIssuer(token);
		if (!unverifiedIss || unverifiedIss !== issuer) {
			return undefined;
		}

		const logger = options.logger ?? OAuthResource.logger;
		const emitAudit = options.emitAudit ?? emitMCPAuditEvent;
		const keyStore: KeySource = options.keyStore ?? (defaultKeyStore ??= new MCPKeyStore(logger));

		return (async (): Promise<MCPBearerValidationResult> => {
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
					void 0;
				}
				throw credentialRejection(reason);
			};

			if (resourcePathname === null) {
				return reject('MCP resource URL is invalid');
			}

			const verified = await verifyMCPAccessToken(token, {
				cfg,
				getConfig,
				keyStore,
				resource,
				issuer,
				logger,
				caller: 'MCP bearer validator',
				verifiedTokenMemo,
			});
			if (!verified.ok) {
				return reject(verified.reason);
			}

			// Refuse quarantined subjects before Harper resolves `username` through
			// `server.getUser` (which an application may override).
			if (isQuarantinePrincipal(verified.claims.sub)) {
				return reject('unverified subject cannot authenticate as a Harper user');
			}

			const authExpiresAt =
				verified.exp !== undefined
					? Math.min(verified.exp, Math.floor(Date.now() / 1000) + MAX_AUTH_EXPIRY_OFFSET_SECONDS)
					: undefined;
			return {
				username: verified.claims.sub,
				...(authExpiresAt !== undefined ? { authExpiresAt } : {}),
				// Harper's authorizationCache is keyed by Authorization header alone without re-checking pathOwned.
				authCacheable: false,
			};
		})();
	};
}

/** Register the MCP bearer validator with `server.registerBearerValidator` when supported. */
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
	const validator = createMCPBearerValidator({ ...options, getConfig });
	const disposer = server.registerBearerValidator(validator);
	return typeof disposer === 'function' ? disposer : () => {};
}
