/**
 * Serve the OAuth routes as HTTP middleware, in addition to the `oauth` REST resource.
 *
 * Harper components that own every path — `@harperfast/nextjs` configured with `files: '*'` is
 * the common case — answer each request themselves and never fall through, so the REST layer that
 * serves resources is never reached and `/oauth/<provider>/login` returns the application's own
 * 404. Registering the same resource through `server.http({ urlPath })` puts the OAuth endpoints
 * in front of that handler, which is how the MCP well-known endpoints are already served
 * (see ./mcp/wellKnown.ts).
 *
 * Opt-in: without `httpRoutes.enabled` nothing is mounted and resource routing is unchanged.
 */

import { OAuthResource } from './resource.ts';
import type { OAuthHttpRoutesConfig } from '../types.ts';

export const DEFAULT_HTTP_ROUTES_MOUNT_PATH = '/oauth';

interface HarperServer {
	http?: (handler: (request: any, next: (request: any) => any) => any, options?: Record<string, unknown>) => unknown;
}

interface Logger {
	info?: (message: string, ...args: any[]) => void;
	warn?: (message: string, ...args: any[]) => void;
	debug?: (message: string, ...args: any[]) => void;
}

/**
 * Mount the OAuth endpoints as HTTP middleware.
 *
 * `getConfig` is read per request, so enabling or disabling the option through a live config
 * change takes effect without a restart. The mount path is fixed at registration time because
 * Harper's `server.http()` has no deregistration.
 */
export function registerOAuthHttpRoutes(
	server: HarperServer,
	getConfig: () => OAuthHttpRoutesConfig | undefined,
	logger?: Logger
): string | undefined {
	if (typeof server?.http !== 'function') {
		logger?.warn?.('OAuth HTTP routes: server.http() not available; skipping route registration');
		return undefined;
	}

	const mountPath = normalizeMountPath(getConfig()?.mountPath);

	server.http(
		async (request: any, next: (request: any) => any) => {
			if (!getConfig()?.enabled) return next(request);

			// POST endpoints (logout, MCP) still go through the REST resource: a middleware
			// handler receives the body as a stream, and parsing it here would duplicate the
			// content-type handling the REST layer already does. The browser OAuth flow —
			// /<provider>/login and /<provider>/callback — is GET only.
			if (request.method !== 'GET' && request.method !== 'HEAD') return next(request);

			// `urlPath` matching is prefix-based and passes the path RELATIVE to the mount, so
			// `/oauth/azure/login` arrives here as `/azure/login`, which is the resource id.
			const id = (request.pathname ?? '/').replace(/^\/+/, '');

			return new OAuthResource(id, request).get({ id } as any);
		},
		{
			// Harper's own authentication middleware populates `request.session`, which the
			// callback writes the signed-in user into.
			after: 'authentication',
			urlPath: mountPath,
		}
	);

	logger?.info?.(`OAuth HTTP routes mounted at ${mountPath}`);

	return mountPath;
}

/**
 * Harper normalizes `urlPath` itself, so this is about the value we report and compare: it keeps
 * the logged mount path and a later config comparison in the same form the router uses.
 */
export function normalizeMountPath(value: string | undefined): string {
	let path = (value ?? '').trim();
	while (path.endsWith('/')) path = path.slice(0, -1);
	if (!path) return DEFAULT_HTTP_ROUTES_MOUNT_PATH;
	return path.startsWith('/') ? path : `/${path}`;
}
