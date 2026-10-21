/**
 * MCP Bearer-Token Guard (`withMCPAuth`)
 *
 * Wraps an app-owned MCP route handler so every request must present a valid
 * signed access token minted by this plugin's Stage 4 issuer before the handler
 * runs. On any failure it returns the spec-mandated
 * `401 + WWW-Authenticate: Bearer resource_metadata="..."` (RFC 9728 §5.1) that
 * closes the MCP discovery loop, pointing clients at the Protected Resource
 * Metadata document Stage 2 serves. This is the bearer-token counterpart to the
 * cookie/session `withOAuthValidation` wrapper.
 *
 * ── Registration (READ THIS — core auth will eat the token otherwise) ────────
 *
 * Harper's core auth is a default-group HTTP middleware that consumes
 * `Authorization: Bearer` and 401s any token it can't validate, stamping
 * `WWW-Authenticate: Basic` (security/auth.ts) — NOT the Bearer challenge MCP
 * clients require. On Harper versions without `server.registerBearerValidator`
 * (or when you want the RFC 9728 `WWW-Authenticate: Bearer resource_metadata="..."`
 * challenge and `request.mcp` claims on a custom route), `withMCPAuth` must own
 * the response for its route.
 *
 * PRIMARY — register on a urlPath subroute (recommended):
 *
 *   // In config.yaml: mcp.resource: https://<origin>/custom-mcp
 *   server.http(withMCPAuth(myMcpHandler), { urlPath: '/custom-mcp' });
 *
 *   Harper's routed dispatch (server/middlewareChain.ts) runs ONLY the matched
 *   subroute's chain and returns — the default chain (where core auth lives)
 *   never runs for '/custom-mcp', so the Bearer challenge can't be clobbered. This is
 *   the same isolation the `/.well-known/*` discovery endpoints rely on to stay
 *   unauthenticated. No `path` option and no ordering hint are needed.
 *
 * FALLBACK — register in the default group, ahead of core auth:
 *
 *   // In config.yaml: mcp.resource: https://<origin>/custom-mcp
 *   server.http(withMCPAuth(myMcpHandler, { path: '/custom-mcp' }), { before: 'authentication' });
 *
 *   When the route shares the default chain with auth (no urlPath), pass `path`
 *   so the wrapper guards only that path and calls `next()` for everything else
 *   (otherwise it would 401 unrelated routes), and register with
 *   `{ before: 'authentication' }` so it runs outermost — ahead of core auth.
 *   This mirrors the precedent in Harper's own server/static.ts. In this mode
 *   the wrapped handler MUST terminate the request (not call `next`): when
 *   `withMCPAuth` leaves `request.user` unset (for example on a role-less
 *   `client_credentials` agent or a quarantined subject), calling `next` hands
 *   the request to core `authentication()`, which rejects the bearer token
 *   (`401 WWW-Authenticate: Basic` on Harpers without `registerBearerValidator`,
 *   or a deferred `401` without `WWW-Authenticate` when the validator is
 *   registered); and when `withMCPAuth` has populated `request.user`, core
 *   `authentication()` treats the request as already authenticated and runs the
 *   rest of the default chain as that Harper user without enforcing the token's
 *   `scope`.
 */

import * as harper from 'harper';
import type { Logger, MCPConfig, MCPPublicKeyRecord, MCPRequestClaims, Request } from '../../types.ts';
import { OAuthResource } from '../resource.ts';
import { isQuarantinePrincipal } from '../quarantinePrincipal.ts';
import { MCPKeyStore } from './keyStore.ts';
import { verifyAccessTokenWithKeySet } from './tokenIssuer.ts';
import { protectedResourceMetadataUrl, resolveIssuer, resolveResource } from './wellKnown.ts';
import { emitMCPAuditEvent, type MCPTokenRejectedAuditPayload } from './audit.ts';
import { getRequestHeader } from '../requestHeaders.ts';

/** Minimal surface MCP token verifiers need from a key source (lets tests inject one). */
export interface KeySource {
	getAllPublicKeys(mcpConfig?: MCPConfig): Promise<MCPPublicKeyRecord[]>;
}

export type VerifyMCPAccessTokenResult =
	| { ok: true; claims: MCPRequestClaims; exp?: number }
	| { ok: false; reason: string };

/**
 * Shared access-token verification used by both `withMCPAuth` and the Harper
 * core bearer validator (`bearerValidator.ts`). Loads signing keys, re-checks
 * live `mcp.enabled` after the key lookup await, verifies signature/`aud`/`iss`,
 * and validates required MCP claim shapes.
 */
export async function verifyMCPAccessToken(
	token: string,
	params: {
		cfg: MCPConfig;
		getConfig: () => MCPConfig | undefined;
		keyStore: KeySource;
		resource: string;
		issuer: string;
		logger?: Logger;
		caller: string;
	}
): Promise<VerifyMCPAccessTokenResult> {
	const { cfg, getConfig, keyStore, resource, issuer, logger, caller } = params;
	let keys: MCPPublicKeyRecord[];
	try {
		keys = await keyStore.getAllPublicKeys(cfg);
	} catch (error) {
		logger?.error?.(
			`${caller}: failed to load MCP signing keys:`,
			error instanceof Error ? error.message : String(error)
		);
		keys = [];
	}
	if (!getConfig()?.enabled) {
		return { ok: false, reason: 'MCP authentication is not enabled' };
	}
	if (keys.length === 0) {
		return { ok: false, reason: 'no signing keys available to verify token' };
	}

	let payload: any;
	try {
		payload = verifyAccessTokenWithKeySet(token, keys, { audience: resource, issuer });
	} catch (error) {
		logger?.debug?.(`${caller}: token verification failed:`, error instanceof Error ? error.message : String(error));
		return { ok: false, reason: 'access token is invalid, expired, or not issued for this resource' };
	}

	// Audience binding (RFC 8707): jwt.verify already enforced `aud` contains
	// `resource`, but require a single string `aud` so a multi-audience token
	// minted elsewhere can't ride in.
	if (typeof payload.sub !== 'string' || !payload.sub) return { ok: false, reason: 'token missing subject' };
	if (typeof payload.client_id !== 'string' || !payload.client_id) {
		return { ok: false, reason: 'token missing client_id' };
	}
	if (typeof payload.aud !== 'string' || !payload.aud) return { ok: false, reason: 'token audience is invalid' };
	if (payload.scope !== undefined && typeof payload.scope !== 'string') {
		return { ok: false, reason: 'token scope is invalid' };
	}

	return {
		ok: true,
		claims: {
			sub: payload.sub,
			client_id: payload.client_id,
			aud: payload.aud,
			scope: payload.scope,
		},
		exp: typeof payload.exp === 'number' && Number.isFinite(payload.exp) ? payload.exp : undefined,
	};
}

export interface WithMCPAuthOptions {
	/**
	 * Path this guard owns. Only set this for the default-group registration
	 * (no `urlPath`): the wrapper then guards only requests whose pathname is
	 * `path` or a sub-path of it and calls `next()` for everything else. Leave
	 * unset for the urlPath-subroute registration, where Harper has already
	 * scoped the route (and strips the prefix), so every request that reaches
	 * the wrapper should be guarded.
	 */
	path?: string;
	/**
	 * MCP config source, read per request so live config changes apply. Defaults
	 * to the plugin's live config (`OAuthResource.mcpConfig`).
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
	 * Custom denial handler, invoked on every rejection (mirrors
	 * `withOAuthValidation.onValidationError`). Receives the request and a
	 * human-readable reason. If it returns a falsy value the wrapper still
	 * returns its default `401` — a no-return handler can never accidentally
	 * turn a denial into a pass (fail closed by construction).
	 */
	onAuthError?: (request: Request, error: string) => any;
	/**
	 * Audit sink for `oauth.mcp.token.rejected` events, invoked when a *presented*
	 * bearer token is rejected (not for missing-token probes or the pre-token
	 * guards). Defaults to the plugin's `emitMCPAuditEvent`. Injectable for tests.
	 */
	emitAudit?: (payload: MCPTokenRejectedAuditPayload) => void;
	/** Resolver used to populate `request.user`; defaults to `server.getUser`. */
	getUser?: (username: string, password: string | null, request: Request) => Promise<any> | any;
}

type HttpListener = (request: Request, next: (req: Request) => any) => any;

const USER_LOOKUP_TIMEOUT_MS = 5_000;
const USER_LOOKUP_TIMEOUT = Symbol('oauth.mcp.userLookupTimeout');

function isPlainObject(value: unknown): value is Record<string, any> {
	return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

async function resolveUserWithDeadline<T>(promiseOrValue: T | Promise<T>, timeoutMs: number): Promise<T> {
	if (promiseOrValue == null || typeof (promiseOrValue as Promise<T>).then !== 'function') {
		return promiseOrValue as T;
	}
	const pending = Promise.resolve(promiseOrValue);
	pending.catch(() => {});
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		return await Promise.race([
			pending,
			new Promise<never>((_resolve, reject) => {
				timer = setTimeout(() => {
					const err = new Error(`server.getUser timed out after ${timeoutMs}ms`) as Error & {
						[USER_LOOKUP_TIMEOUT]?: boolean;
					};
					err[USER_LOOKUP_TIMEOUT] = true;
					reject(err);
				}, timeoutMs);
				timer.unref?.();
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Extract a bearer token from the `Authorization` header. Header-only by design
 * (RFC 6750 §2.1): query-string and body tokens are never read, so they are
 * treated as "no token presented". Returns undefined for a missing or malformed
 * header (anything that isn't `Bearer <non-empty-token>`).
 */
function extractBearerToken(headers: any): string | undefined {
	const authz = getRequestHeader(headers, 'authorization');
	if (!authz) return undefined;
	// Scheme is case-insensitive (RFC 7235); the token must be non-empty.
	const match = /^Bearer[ \t]+(\S.*)$/i.exec(authz.trim());
	const token = match?.[1]?.trim();
	return token ? token : undefined;
}

/**
 * Read the unstripped pathname from a Harper request. When Harper dispatches a
 * `urlPath` subroute with `after: 'authentication'` (such as native `/mcp`),
 * `stripPrefix(request, urlPath)` wraps the request before running `authentication`
 * so `request.pathname` is stripped (`'/'`) while `request.originalPathname`
 * preserves the unstripped target pathname (`'/mcp'`).
 */
export function getRequestPathname(request: Request | undefined): string | undefined {
	const reqAny = request as any;
	return (
		reqAny?.originalPathname ??
		request?.pathname ??
		(typeof request?.url === 'string' ? request.url.split('?')[0] : undefined)
	);
}

/**
 * True when `pathname` is `routePath` or a segment-bounded sub-path of it
 * ('/mcp' matches '/mcp' and '/mcp/x' but not '/mcponaut'). Trailing slashes
 * on `routePath` are ignored. Mirrors Harper's `matchesRoute` urlPath semantics
 * so the default-group fallback behaves like the urlPath registration.
 */
export function pathOwned(pathname: string | undefined, routePath: string): boolean {
	const path = routePath.length > 1 && routePath.endsWith('/') ? routePath.slice(0, -1) : routePath;
	const p = pathname ?? '/';
	if (path === '/') return p.startsWith('/');
	return p === path || p.startsWith(path + '/');
}

/**
 * Wrap an app MCP handler with bearer-token validation. See the module header
 * for registration. The returned listener has the standard Harper
 * `(request, next)` shape, so it registers exactly where the unwrapped handler
 * would.
 */
export function withMCPAuth(handler: HttpListener, options: WithMCPAuthOptions = {}): HttpListener {
	if (typeof handler !== 'function') {
		throw new TypeError('withMCPAuth: handler must be a function (request, next) => response');
	}

	const { path, onAuthError } = options;
	const getConfig = options.getConfig ?? (() => OAuthResource.mcpConfig);
	let defaultKeyStore: MCPKeyStore | undefined;

	return async function mcpAuthListener(request: Request, next: (req: Request) => any): Promise<any> {
		const logger = options.logger ?? OAuthResource.logger;
		const requestPathname = getRequestPathname(request);

		// Default-group registration: only guard our own path; let everything
		// else continue down the chain (to core auth and other middleware).
		if (path && !pathOwned(requestPathname, path)) {
			return next(request);
		}

		// Build the spec 401. protectedResourceMetadataUrl derefs mcpConfig
		// (via resolveResource), so guard a missing config with an empty object —
		// a denial must never throw (it would surface as a 500, not a 401). The
		// challenge points at the SAME path-aware PRM URL the well-known handler
		// serves (RFC 9728 §3.1: path-appended when the resource carries a path),
		// so a client using the challenge value verbatim hits a real document.
		const emitAudit = options.emitAudit ?? emitMCPAuditEvent;
		// Flipped true once a bearer token has actually been presented; from that
		// point on, every denial is an audited `oauth.mcp.token.rejected` event.
		// Denials BEFORE it (path-length guard, MCP disabled, no token presented)
		// are NOT audited — those are unauthenticated probes / the normal discovery
		// 401, not rejected tokens, and auditing them would flood the log on probes
		// and DoS floods.
		let tokenPresented = false;

		const deny = async (reason: string): Promise<any> => {
			if (tokenPresented) {
				// Best-effort, secret-free: the reason + the resource the token was
				// presented to. NEVER unverified claims — the token failed validation,
				// so any client_id/sub/jti it carries is attacker-controlled. Shielded
				// in try/catch: emitAudit is part of the exported options surface, so a
				// custom sink that throws must NOT turn this denial into a 500 — deny()
				// must always produce the 401 (fail closed). The default
				// emitMCPAuditEvent already swallows its own errors; this guards a
				// caller-supplied sink too.
				try {
					emitAudit({
						event: 'oauth.mcp.token.rejected',
						reason,
						aud: resolveResource(request as any, getConfig() ?? ({} as MCPConfig)),
						timestamp: new Date().toISOString(),
					});
				} catch {
					// Audit is best-effort; never let it break the fail-closed 401.
				}
			}
			const metadataUrl = protectedResourceMetadataUrl(request as any, getConfig() ?? ({} as MCPConfig));
			const defaultResponse = {
				status: 401,
				headers: {
					'WWW-Authenticate': `Bearer resource_metadata="${metadataUrl}"`,
					'Content-Type': 'application/json',
					// CORS parity with the well-known discovery docs: lets browser-based
					// MCP clients read the challenge (and the WWW-Authenticate header)
					// on a cross-origin 401 so the RFC 9728 discovery loop can proceed.
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Expose-Headers': 'WWW-Authenticate',
				},
				body: JSON.stringify({ error: 'invalid_token', error_description: reason }),
			};
			if (!onAuthError) return defaultResponse;
			const handled = await onAuthError(request, reason);
			// `||` (not `??`): ANY falsy return (undefined, null, false, '', 0) falls
			// back to the default 401. A handler that returns a non-response can never
			// turn a denial into a pass or a malformed response — fail closed.
			return handled || defaultResponse;
		};

		// Repo invariant (AGENTS.md; OAuthResource.parseRoute caps paths at 2048
		// for DoS mitigation): withMCPAuth can be registered outermost and doesn't
		// go through parseRoute, so enforce the limit independently — fail closed
		// before any token work.
		if ((requestPathname ?? request.url ?? '').length > 2048) {
			return deny('request path exceeds the maximum allowed length');
		}

		const cfg = getConfig();
		// Fail closed: a route guarded by withMCPAuth never serves while MCP is
		// disabled or unconfigured.
		if (!cfg?.enabled) {
			return deny('MCP authentication is not enabled');
		}

		const token = extractBearerToken(request.headers);
		if (!token) {
			return deny('missing or malformed Authorization: Bearer header');
		}
		// A bearer token was presented — any denial below is a rejected token (audited).
		tokenPresented = true;

		const resource = resolveResource(request as any, cfg);
		const issuer = resolveIssuer(request as any, cfg);
		const keyStore: KeySource = options.keyStore ?? (defaultKeyStore ??= new MCPKeyStore(logger));

		const verified = await verifyMCPAccessToken(token, {
			cfg,
			getConfig,
			keyStore,
			resource,
			issuer,
			logger,
			caller: 'withMCPAuth',
		});
		if (!verified.ok) {
			return deny(verified.reason);
		}

		const { claims } = verified;
		if (request.user != null) {
			const existingUsername = typeof request.user === 'string' ? request.user : request.user?.username;
			if (
				typeof existingUsername !== 'string' ||
				existingUsername !== claims.sub ||
				isQuarantinePrincipal(claims.sub)
			) {
				return deny('token subject does not match the authenticated user');
			}
		}

		let resolvedUser: any;
		const shouldPopulateUser = request.user == null && !isQuarantinePrincipal(claims.sub);
		if (shouldPopulateUser) {
			const serverObj = (harper as any).server ?? (globalThis as any).server;
			const getUser =
				options.getUser ?? (typeof serverObj?.getUser === 'function' ? serverObj.getUser.bind(serverObj) : undefined);
			if (typeof getUser === 'function') {
				const lookupTimeoutMs = (options as any).userLookupTimeoutMs ?? USER_LOOKUP_TIMEOUT_MS;
				try {
					resolvedUser = await resolveUserWithDeadline(getUser(claims.sub, null, request), lookupTimeoutMs);
				} catch (error) {
					const isRejectedUser =
						(harper as any).isCredentialRejection?.(error) === true ||
						(typeof error === 'object' &&
							error !== null &&
							Object.getOwnPropertySymbols(error).some((s) => s.description === 'harper.credentialRejection')) ||
						(error as any)?.statusCode === 401 ||
						(error as any)?.statusCode === 403;
					if (isRejectedUser) {
						logger?.debug?.(
							'withMCPAuth: Harper user rejected for token subject:',
							error instanceof Error ? error.message : String(error)
						);
						return deny('token subject is not an active user');
					}
					if ((error as any)?.[USER_LOOKUP_TIMEOUT] === true) {
						logger?.error?.(
							'withMCPAuth: timed out resolving Harper user for token subject:',
							error instanceof Error ? error.message : String(error)
						);
						return {
							status: 503,
							headers: {
								'Content-Type': 'application/json',
								'Retry-After': '5',
								'Access-Control-Allow-Origin': '*',
								'Access-Control-Expose-Headers': 'Retry-After',
							},
							body: JSON.stringify({
								error: 'temporarily_unavailable',
								error_description: 'unable to verify user status, please retry',
							}),
						};
					}
					logger?.error?.(
						'withMCPAuth: failed to resolve Harper user for token subject:',
						error instanceof Error ? error.message : String(error)
					);
					return deny('failed to resolve Harper user');
				}
				if (!getConfig()?.enabled) {
					return deny('MCP authentication is not enabled');
				}
				if (resolvedUser && typeof resolvedUser === 'object' && resolvedUser.active === false) {
					return deny('token subject is not an active user');
				}
			}
		}

		request.mcp = claims;
		if (
			shouldPopulateUser &&
			isPlainObject(resolvedUser) &&
			isPlainObject(resolvedUser.role) &&
			isPlainObject(resolvedUser.role.permission)
		) {
			request.user = resolvedUser as any;
		}

		// Token is valid — hand off to the app's handler. Its response is returned
		// verbatim (no double-wrapping). `next` is forwarded so the handler may
		// fall through if it wants (urlPath mode); see the module header for the
		// default-group caveat.
		return handler(request, next);
	};
}
