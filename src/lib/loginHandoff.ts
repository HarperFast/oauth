/**
 * Sign-in handoff to an allowlisted origin (HarperFast/central-manager#911)
 *
 * The provider callback always lands on the registered `redirectUri`, so a
 * session written there is keyed to that host's origin. Harper core names the
 * session cookie after the request's `Origin` header (falling back to `Host`),
 * so a static app served from ANOTHER origin (a Studio PR preview, say) never
 * sees it and stays signed out.
 *
 * With `postLoginRedirectOrigins` set, a login whose `redirect` parameter names
 * an absolute https URL on an allowlisted origin finishes in two steps:
 *
 * 1. The callback builds the session exactly as it would have, but stores it
 *    server-side under a one-time code instead of writing it to the callback
 *    request's session, then redirects to the target URL with the code in the
 *    URL fragment (`#…?oauth_handoff=<code>`). The fragment never reaches a
 *    server log or a `Referer`.
 * 2. The target page's JS calls `POST /oauth/handoff` on this host with
 *    `credentials: 'include'` and `{ code }`. The browser sends the page's own
 *    `Origin`, so Harper core binds `request.session.update` to that origin's
 *    cookie name, and the redeem writes the stored session through it.
 *
 * The code is single-use (an atomic counter, as in assertionJtiStore.ts), lives
 * 60 seconds, is stored only as its SHA-256, and is bound to the target origin
 * (the redeem's `Origin` must equal it) and to the browser that started the
 * login (the redeem must carry the same `__Host-oauth_browser` cookie the
 * callback verified). The browser binding closes the login-CSRF shape a bare
 * code would reopen: an attacker's code planted in a victim's page fails,
 * because the victim's browser secret differs. That cookie is `SameSite=Lax`,
 * so the target origin must be same-site with this host; a cross-site target
 * would also hit third-party-cookie blocking on the session cookie itself.
 *
 * An empty or absent allowlist leaves every path byte-identical to before:
 * absolute redirects are reduced to their path, and `POST /oauth/handoff` is a
 * 404.
 */

import { createHash, randomBytes } from 'node:crypto';
import { expandEnvVarsDeep, isUnresolvedEnvPlaceholder } from './config.ts';
import { browserSecretMatches, readBrowserSecret } from './mcp/consentBinding.ts';
import { readRawHeader } from './requestHeaders.ts';
import type { Logger, Request, Table } from '../types.ts';

declare const databases: any;

/** Plugin option name; also used in config errors and log lines. */
export const POST_LOGIN_REDIRECT_ORIGINS_OPTION = 'postLoginRedirectOrigins';

/** Fragment query parameter that carries the one-time code to the target page. */
export const HANDOFF_FRAGMENT_PARAM = 'oauth_handoff';

/** Lifetime of a handoff code, from issue at the callback to redeem. */
export const LOGIN_HANDOFF_TTL_MS = 60_000;

/** A handoff target longer than this is not handed off (falls back to path-only). */
const MAX_HANDOFF_TARGET_LENGTH = 2048;

/** 32 random bytes, base64url: exactly 43 characters from this set. */
const HANDOFF_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** One DNS label: letters, digits and inner hyphens (LDH), at most 63 characters. */
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * A parsed `postLoginRedirectOrigins` entry.
 * `https://*.app.example.com` matches `https://<one label>.app.example.com` only.
 */
export interface OriginPattern {
	/** The normalized entry, e.g. `https://*.app.example.com` */
	source: string;
	/** Exact hostname, or for a wildcard the suffix after `*.` */
	host: string;
	wildcard: boolean;
	/** Explicit port, or '' for https's default (443) */
	port: string;
}

/**
 * Parse one allowlist entry. Accepts `https://host[:port]` and
 * `https://*.suffix[:port]` (the wildcard is the whole leftmost label, and the
 * suffix has at least two labels). Anything else throws, naming the option.
 */
export function parseOriginPattern(entry: string): OriginPattern {
	const invalid = (why: string) =>
		new Error(
			`${POST_LOGIN_REDIRECT_ORIGINS_OPTION}: ${JSON.stringify(entry)} is not a valid origin pattern (${why}). ` +
				'Use "https://host" or "https://*.example.com", with no path, query, fragment or credentials.'
		);
	const raw = entry.trim().toLowerCase();
	const match = /^https:\/\/([^/?#@\\]+)\/?$/.exec(raw);
	if (!match) {
		throw invalid(raw.startsWith('https://') ? 'only an origin is allowed' : 'it must start with https://');
	}
	let host = match[1];
	let port = '';
	const colon = host.lastIndexOf(':');
	if (colon !== -1) {
		port = host.slice(colon + 1);
		host = host.slice(0, colon);
		if (!/^[0-9]{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) throw invalid('bad port');
		port = String(Number(port));
		if (port === '443') port = '';
	}
	let wildcard = false;
	if (host.startsWith('*.')) {
		wildcard = true;
		host = host.slice(2);
	}
	const labels = host.split('.');
	if (!labels.every((label) => DNS_LABEL.test(label))) {
		throw invalid('the host must be DNS labels, with "*" only as the whole leftmost label');
	}
	if (/^[0-9]+$/.test(labels[labels.length - 1])) throw invalid('IP addresses are not supported');
	if (wildcard && labels.length < 2) throw invalid('a wildcard needs at least two labels after "*."');
	return { source: `https://${wildcard ? '*.' : ''}${host}${port ? `:${port}` : ''}`, host, wildcard, port };
}

/**
 * Normalize the `postLoginRedirectOrigins` option. Accepts a YAML list, a
 * single string, or a comma/whitespace-separated string (so one env var can
 * carry several entries); `${VAR}` placeholders are expanded.
 *
 * Empty, absent, or an unresolved `${VAR}` placeholder (the variable is unset in
 * this environment) all mean an EMPTY allowlist: today's behavior. That is the
 * fail-closed direction for this setting, unlike allowlists where empty means
 * "allow any", so it does not throw. An unresolved placeholder entry inside a
 * list is dropped with a warning. Any other invalid entry throws naming it.
 */
export function normalizePostLoginRedirectOrigins(value: unknown, logger?: Logger): OriginPattern[] {
	const option = POST_LOGIN_REDIRECT_ORIGINS_OPTION;
	const expanded = expandEnvVarsDeep(value);
	if (expanded === undefined || expanded === null) return [];
	if (isUnresolvedEnvPlaceholder(expanded)) {
		logger?.info?.(
			`OAuth: ${option} references ${String(expanded).trim()}, which is not set; sign-in completes on this origin only`
		);
		return [];
	}
	let entries: unknown[];
	if (typeof expanded === 'string') {
		entries = [expanded];
	} else if (Array.isArray(expanded)) {
		entries = expanded;
	} else {
		throw new Error(`${option} must be a list of origin patterns or a comma-separated string`);
	}
	const patterns = new Map<string, OriginPattern>();
	for (const entry of entries) {
		if (typeof entry !== 'string') {
			throw new Error(`${option} entries must be strings (got ${JSON.stringify(entry)})`);
		}
		if (isUnresolvedEnvPlaceholder(entry)) {
			logger?.warn?.(`OAuth: ${option} entry ${entry.trim()} references an unset variable; ignoring that entry`);
			continue;
		}
		for (const piece of entry.split(/[\s,]+/)) {
			if (piece === '') continue;
			const pattern = parseOriginPattern(piece);
			patterns.set(pattern.source, pattern);
		}
	}
	return [...patterns.values()];
}

/**
 * The serialized origin of `candidate` when it is an absolute https URL with
 * no credentials whose origin an allowlist pattern matches; otherwise null.
 * Matching runs on the WHATWG-parsed URL, so it judges the host a browser would
 * actually navigate to (`https:\\x`, `%2e`, mixed case and IDNA all normalize
 * first), and the caller redirects to that same parsed URL.
 */
export function matchAllowedOrigin(candidate: unknown, patterns: readonly OriginPattern[]): string | null {
	if (patterns.length === 0 || typeof candidate !== 'string') return null;
	let url: URL;
	try {
		url = new URL(candidate);
	} catch {
		return null;
	}
	if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') return null;
	const host = url.hostname;
	for (const pattern of patterns) {
		if (url.port !== pattern.port) continue;
		if (pattern.wildcard) {
			if (!host.endsWith(`.${pattern.host}`)) continue;
			// Exactly one label in front of the suffix: `a.b.<suffix>` does not match.
			if (DNS_LABEL.test(host.slice(0, host.length - pattern.host.length - 1))) return url.origin;
		} else if (host === pattern.host) {
			return url.origin;
		}
	}
	return null;
}

/**
 * True when `url` is an absolute https URL on an origin the allowlist permits.
 * `allowlist` takes the same shapes as the `postLoginRedirectOrigins` option
 * (a list, or a comma/whitespace-separated string), so an application can test
 * its configured value with the plugin's own matcher. Throws on an invalid entry.
 */
export function isAllowedPostLoginOrigin(url: unknown, allowlist: unknown): boolean {
	return matchAllowedOrigin(url, normalizePostLoginRedirectOrigins(allowlist)) !== null;
}

/** Where a sign-in hands off to: the target URL and its origin. */
export interface HandoffTarget {
	origin: string;
	target: string;
}

/**
 * Resolve a login's `redirect` parameter to a handoff target, or null when it
 * is not an absolute URL on an allowlisted origin (the caller then keeps
 * today's path-only handling).
 */
export function resolveHandoffTarget(redirect: unknown, patterns: readonly OriginPattern[]): HandoffTarget | null {
	if (typeof redirect !== 'string' || redirect.length > MAX_HANDOFF_TARGET_LENGTH) return null;
	const origin = matchAllowedOrigin(redirect, patterns);
	return origin ? { origin, target: new URL(redirect).href } : null;
}

/**
 * Resolve the handoff recorded in a verified state token at the callback. The
 * origin is re-checked against the CURRENT allowlist: one removed by a config
 * reload since the login started is no longer handed to (the flow falls back
 * to today's path-only redirect on this origin). A state without a browser
 * binding hash is never handed off: the redeem's browser check needs it (and
 * every state handleLogin mints carries one).
 */
export function resolveStateHandoff(
	tokenData: { originalUrl?: unknown; handoffOrigin?: unknown; browserNonceHash?: unknown },
	patterns: readonly OriginPattern[]
): HandoffTarget | null {
	if (typeof tokenData.handoffOrigin !== 'string' || typeof tokenData.browserNonceHash !== 'string') return null;
	const handoff = resolveHandoffTarget(tokenData.originalUrl, patterns);
	return handoff && handoff.origin === tokenData.handoffOrigin ? handoff : null;
}

/**
 * Append the code to the target's fragment as a query parameter: after `?` when
 * the fragment has none yet, else after `&` (a hash router's
 * `#/check-oauth` becomes `#/check-oauth?oauth_handoff=<code>`; an empty
 * fragment becomes `#?oauth_handoff=<code>`). Any `oauth_handoff` the target
 * already carried is dropped first, so the page can never read a planted value
 * ahead of the real one.
 */
export function appendHandoffCode(target: string, code: string): string {
	const url = new URL(target);
	const fragment = url.hash.slice(1);
	const queryStart = fragment.indexOf('?');
	const head = queryStart === -1 ? fragment : fragment.slice(0, queryStart);
	const query = queryStart === -1 ? '' : fragment.slice(queryStart + 1);
	const kept = query
		.split('&')
		.filter((part) => part !== '' && part !== HANDOFF_FRAGMENT_PARAM && !part.startsWith(`${HANDOFF_FRAGMENT_PARAM}=`));
	kept.push(`${HANDOFF_FRAGMENT_PARAM}=${code}`);
	url.hash = `${head}?${kept.join('&')}`;
	return url.href;
}

/**
 * An error redirect for a handoff flow: the target URL on the allowlisted
 * origin, with the same `error`/`reason` query parameters (before the
 * fragment) that a same-origin flow gets on its path.
 */
export function buildHandoffErrorRedirect(target: string, params: Record<string, string>): string {
	const url = new URL(target);
	for (const [key, value] of Object.entries(params)) {
		url.searchParams.set(key, value);
	}
	return url.href;
}

// ---------------------------------------------------------------------------
// Code store (oauth.login_handoffs)
// ---------------------------------------------------------------------------

let handoffTable: Table | undefined;

function getHandoffTable(): Table {
	if (!handoffTable) {
		if (!databases?.oauth?.login_handoffs) {
			throw new Error(
				'OAuth login handoff table (oauth.login_handoffs) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		handoffTable = databases.oauth.login_handoffs;
	}
	return handoffTable as Table;
}

/**
 * Reset the cached table reference (for testing only)
 * @internal
 */
export function resetLoginHandoffTableCache(): void {
	handoffTable = undefined;
}

/** Primary key for a code: its SHA-256, so a table read never yields a redeemable code. */
export function handoffKey(code: string): string {
	return createHash('sha256').update(code).digest('hex');
}

/** What a code stands for; `session` is the object the callback would have written. */
export interface LoginHandoffRecord {
	origin: string;
	browserNonceHash: string;
	provider: string;
	session: Record<string, any>;
	expiresAt: number;
}

/** A storage failure while issuing a code; the callback maps it to `server_error` / `handoff_storage`. */
export class LoginHandoffStorageError extends Error {
	readonly reason = 'handoff_storage';
	constructor(cause: unknown) {
		super('Failed to store the sign-in handoff');
		this.cause = cause;
	}
}

export type RedeemRefusal = 'unknown' | 'expired' | 'replayed';

/**
 * Issue a code for `record` and return it. Storage errors throw
 * {@link LoginHandoffStorageError}; the code itself is never logged.
 */
export async function issueLoginHandoff(record: Omit<LoginHandoffRecord, 'expiresAt'>): Promise<string> {
	const code = randomBytes(32).toString('base64url');
	const expiresAt = Date.now() + LOGIN_HANDOFF_TTL_MS;
	const id = handoffKey(code);
	try {
		// Its own context: the row commits on its own transaction, before the
		// redirect that carries the code goes out. The per-record expiresAt
		// overrides the table default.
		await getHandoffTable().put(
			{
				id,
				origin: record.origin,
				browser_hash: record.browserNonceHash,
				provider: record.provider,
				session: JSON.stringify(record.session),
				expires_at: expiresAt,
			},
			{ expiresAt }
		);
	} catch (error) {
		throw new LoginHandoffStorageError(error);
	}
	return code;
}

/**
 * Consume a code. Exactly one presentation of a live code gets its record:
 * each presentation adds 1 to the row's `uses` with an atomic patch and only
 * the one that reads back 1 wins (see assertionJtiStore.ts for why the reads
 * pass a fresh context). A losing or late presentation is refused; the winner
 * deletes the row. Storage errors propagate: a redeem that could not check
 * must not succeed.
 */
export async function redeemLoginHandoff(
	code: string
): Promise<{ record: LoginHandoffRecord } | { refused: RedeemRefusal }> {
	const table = getHandoffTable();
	const id = handoffKey(code);
	// Explicit field access below: Harper records are tracked objects that
	// spread copies nothing from (AGENTS.md).
	const row = await table.get(id, {});
	if (!row || typeof row.origin !== 'string') return { refused: 'unknown' };
	const expiresAt = Number(row.expires_at);
	if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return { refused: 'expired' };
	await table.patch(id, { uses: { __op__: 'add', value: 1 } }, { expiresAt });
	if ((await table.get(id, {}))?.uses !== 1) return { refused: 'replayed' };
	const record: LoginHandoffRecord = {
		origin: row.origin,
		browserNonceHash: String(row.browser_hash ?? ''),
		provider: String(row.provider ?? ''),
		session: JSON.parse(String(row.session)),
		expiresAt,
	};
	try {
		await table.delete(id, {});
	} catch {
		// The counter already refuses every later presentation; the row's
		// expiry reaps it.
	}
	return { record };
}

// ---------------------------------------------------------------------------
// POST /oauth/handoff
// ---------------------------------------------------------------------------

function errorResponse(status: number, error: string, message: string) {
	return { status, headers: { 'Cache-Control': 'no-store' }, body: { error, message } };
}

/**
 * Redeem a handoff code into a Harper session for the calling origin.
 *
 * Request: `POST /oauth/handoff`, JSON (or form) body `{ "code": "<code>" }`,
 * sent with credentials from the allowlisted page. Responses:
 * - 200 `{ authenticated: true, provider }` and Harper's `Set-Cookie` for the
 *   calling origin's session.
 * - 404 `{ error: 'Not found' }` while the allowlist is empty (as before).
 * - 403 `origin_not_allowed`: `Origin` missing, repeated, `null`, or not allowlisted.
 * - 400 `invalid_request`: no `code`, a repeated one, or not code-shaped.
 * - 400 `invalid_grant`: unknown, expired or already used; or bound to another
 *   origin or another browser. Every presentation of a live code that passes
 *   the Origin check consumes it, whether or not it then succeeds.
 * - 500 `server_error`: storage or session write failed, or sessions are off.
 *
 * Refusals are logged with the reason and origin, never the code.
 */
export async function handleLoginHandoffRedeem(
	request: Request,
	body: any,
	patterns: readonly OriginPattern[],
	logger?: Logger
): Promise<any> {
	if (patterns.length === 0) {
		return { status: 404, body: { error: 'Not found' } };
	}

	// The Origin check runs first, before any storage read. A browser cannot
	// forge Origin; the browser binding below covers a non-browser caller that can.
	const origin = readRawHeader(request.headers, 'origin');
	if (typeof origin !== 'string' || matchAllowedOrigin(origin, patterns) !== origin) {
		logger?.warn?.(
			`OAuth handoff refused: Origin ${JSON.stringify(origin ?? null)} is not an allowlisted origin (${POST_LOGIN_REDIRECT_ORIGINS_OPTION})`
		);
		return errorResponse(403, 'origin_not_allowed', 'This origin may not complete a sign-in handoff');
	}

	const code = body && typeof body === 'object' && !Array.isArray(body) ? body.code : undefined;
	if (typeof code !== 'string' || !HANDOFF_CODE_PATTERN.test(code)) {
		logger?.warn?.(
			`OAuth handoff refused for ${JSON.stringify(origin)}: ${Array.isArray(code) ? 'repeated' : 'missing or malformed'} code`
		);
		return errorResponse(400, 'invalid_request', 'A single handoff code is required');
	}

	if (typeof request.session?.update !== 'function') {
		logger?.error?.('OAuth handoff: request.session.update is unavailable (are Harper sessions enabled?)');
		return errorResponse(500, 'server_error', 'Sessions are not available');
	}

	let result: Awaited<ReturnType<typeof redeemLoginHandoff>>;
	try {
		result = await redeemLoginHandoff(code);
	} catch (error) {
		logger?.error?.(
			`OAuth handoff for ${JSON.stringify(origin)}: storage error:`,
			error instanceof Error ? error.message : String(error)
		);
		return errorResponse(500, 'server_error', 'Unable to complete the sign-in, please try again');
	}

	const refuse = (reason: string) => {
		logger?.warn?.(`OAuth handoff refused for ${JSON.stringify(origin)}: ${reason}`);
		return errorResponse(400, 'invalid_grant', 'The handoff code is invalid, expired or already used');
	};
	if ('refused' in result) {
		return refuse(
			result.refused === 'replayed'
				? 'code already used'
				: result.refused === 'expired'
					? 'code expired'
					: 'unknown code'
		);
	}
	const { record } = result;
	if (record.origin !== origin) {
		return refuse(`code was issued for ${JSON.stringify(record.origin)}`);
	}
	if (!browserSecretMatches(readBrowserSecret(request), record.browserNonceHash)) {
		return refuse('browser binding mismatch (not the browser that started the sign-in)');
	}

	try {
		await request.session.update(record.session);
	} catch (error) {
		logger?.error?.(
			`OAuth handoff for ${JSON.stringify(origin)}: session write failed:`,
			error instanceof Error ? error.message : String(error)
		);
		return errorResponse(500, 'server_error', 'Unable to complete the sign-in, please try again');
	}

	logger?.info?.(`OAuth login handed off to ${JSON.stringify(origin)} (provider ${JSON.stringify(record.provider)})`);
	return {
		status: 200,
		headers: { 'Cache-Control': 'no-store' },
		body: { authenticated: true, provider: record.provider },
	};
}
