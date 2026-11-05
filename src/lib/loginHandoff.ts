/**
 * Sign-in handoff to an allowlisted origin (`postLoginRedirectOrigins`; flow and
 * contract in docs/configuration.md). Constraints the code cannot state:
 *
 * - Harper core names the session cookie after the request's `Origin`, so only
 *   a request the target page itself makes can create its session; the
 *   callback (a top-level navigation) cannot.
 * - The code is bound to the `__Host-oauth_browser` secret the callback
 *   verified. That cookie is `SameSite=Lax`, so the target must be same-site
 *   with this host.
 */

import { createHash, randomBytes } from 'node:crypto';
import { expandEnvVarsDeep, isUnresolvedEnvPlaceholder } from './config.ts';
import { browserSecretMatches, readBrowserSecret } from './mcp/consentBinding.ts';
import { readRawHeader } from './requestHeaders.ts';
import type { Logger, Request, Table } from '../types.ts';

declare const databases: any;

export const POST_LOGIN_REDIRECT_ORIGINS_OPTION = 'postLoginRedirectOrigins';

/** Fragment query parameter that carries the one-time code to the target page. */
export const HANDOFF_FRAGMENT_PARAM = 'oauth_handoff';

/** Lifetime of a handoff code, from issue at the callback to redeem. */
export const LOGIN_HANDOFF_TTL_MS = 60_000;

/** Applies to the normalized href, which is what the state stores and the callback re-checks. */
const MAX_HANDOFF_TARGET_LENGTH = 2048;

/** 32 random bytes, base64url: exactly 43 characters from this set. */
const HANDOFF_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The shape `generateBrowserSecret()` mints; anything else cannot match a binding. */
const BROWSER_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

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
 * list or a comma-separated string is dropped with a warning. Any other invalid
 * entry throws naming it.
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
		for (const piece of entry.split(/[\s,]+/)) {
			if (piece === '') continue;
			if (isUnresolvedEnvPlaceholder(piece)) {
				logger?.warn?.(`OAuth: ${option} entry ${piece} references an unset variable; ignoring that entry`);
				continue;
			}
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
	if (!origin) return null;
	const target = new URL(redirect).href;
	return target.length > MAX_HANDOFF_TARGET_LENGTH ? null : { origin, target };
}

/**
 * Resolve the handoff recorded in a verified state token against the CURRENT
 * allowlist; null when the origin has been removed since the login started
 * (the callback then refuses the sign-in). A state without a browser binding
 * hash is never handed off: the redeem's browser check needs it.
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
	// Compare decoded names, as the page's URLSearchParams will read them.
	const kept = query
		.split('&')
		.filter((part) => part !== '' && new URLSearchParams(part).keys().next().value !== HANDOFF_FRAGMENT_PARAM);
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
	constructor() {
		// No `cause`: the write carried provider tokens, and a storage
		// diagnostic must not carry them into the callback's error log.
		super('Failed to store the sign-in handoff');
	}
}

export type RedeemRefusal = 'unknown' | 'expired' | 'replayed' | 'mismatch';

/**
 * Issue a code for `record` and return it. Storage errors throw
 * {@link LoginHandoffStorageError}; the code itself is never logged.
 */
export async function issueLoginHandoff(
	record: Omit<LoginHandoffRecord, 'expiresAt'>,
	logger?: Logger
): Promise<string> {
	const code = randomBytes(32).toString('base64url');
	const expiresAt = Date.now() + LOGIN_HANDOFF_TTL_MS;
	const id = handoffKey(code);
	try {
		// Its own context: the row commits on its own transaction, before the
		// redirect that carries the code goes out.
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
		logger?.error?.(
			'OAuth handoff: failed to store the code:',
			error instanceof Error ? `${error.name}: ${error.message}` : 'unknown error'
		);
		throw new LoginHandoffStorageError();
	}
	return code;
}

/**
 * Re-reads of a code not found yet, in ms. The page redeems moments after the
 * callback's redirect, possibly on another node than the one that wrote the
 * row, so a miss waits out replication briefly before it is final.
 */
let missRetryDelaysMs: readonly number[] = [100, 300];

/** Redeems re-reading a miss at once; past this, a miss is final at once. */
const MAX_MISS_RETRIERS = 32;
let missRetriers = 0;

/**
 * Override the miss re-read delays (for testing only)
 * @internal
 */
export function setLoginHandoffMissRetryDelays(delays: readonly number[]): void {
	missRetryDelaysMs = delays;
}

/**
 * Consume a code. `check` runs on the stored record BEFORE anything is
 * consumed, so a presentation from the wrong origin or browser leaves the code
 * for the right page; it returns a refusal reason, or null to proceed.
 *
 * Single use: the winner adds 1 to `uses` with an atomic patch that also
 * clears the stored session, and only a presenter that reads back 1 proceeds
 * (assertionJtiStore.ts explains the fresh-context reads). The row is kept,
 * scrubbed, until its expiry: deleting it would let a presenter that read the
 * live row before the delete re-create it at `uses: 1` and also win. Two
 * presentations whose patches both land before either read-back are both
 * refused (fail closed), and, as for every table-backed guard here, single
 * use holds per node within the replication delay; every winner is still
 * bound to the same origin and browser. Storage errors propagate.
 */
export async function redeemLoginHandoff(
	code: string,
	check: (record: LoginHandoffRecord) => string | null = () => null
): Promise<{ record: LoginHandoffRecord } | { refused: RedeemRefusal; detail?: string }> {
	const table = getHandoffTable();
	const id = handoffKey(code);
	// Explicit field access below: Harper records are tracked objects that
	// spread copies nothing from (AGENTS.md).
	let row = await table.get(id, {});
	if (!row && missRetriers < MAX_MISS_RETRIERS) {
		missRetriers++;
		try {
			for (const delay of missRetryDelaysMs) {
				await new Promise((resolve) => setTimeout(resolve, delay));
				row = await table.get(id, {});
				if (row) break;
			}
		} finally {
			missRetriers--;
		}
	}
	if (!row || typeof row.origin !== 'string') return { refused: 'unknown' };
	const expiresAt = Number(row.expires_at);
	if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return { refused: 'expired' };
	if (Number(row.uses) > 0 || typeof row.session !== 'string') return { refused: 'replayed' };
	let session: Record<string, any>;
	try {
		session = JSON.parse(row.session);
	} catch {
		// A parse error quotes its input, which holds provider tokens.
		throw new Error('stored handoff session is not valid JSON');
	}
	const record: LoginHandoffRecord = {
		origin: row.origin,
		browserNonceHash: String(row.browser_hash ?? ''),
		provider: String(row.provider ?? ''),
		session,
		expiresAt,
	};
	const mismatch = check(record);
	if (mismatch) return { refused: 'mismatch', detail: mismatch };
	await table.patch(id, { uses: { __op__: 'add', value: 1 }, session: null }, { expiresAt });
	if ((await table.get(id, {}))?.uses !== 1) return { refused: 'replayed' };
	if (expiresAt <= Date.now()) return { refused: 'expired' };
	return { record };
}

function errorResponse(status: number, error: string, message: string) {
	return { status, headers: { 'Cache-Control': 'no-store' }, body: { error, message } };
}

const ORIGIN_REMOVED = 'origin removed from the allowlist';

const REFUSAL_LOG: Record<Exclude<RedeemRefusal, 'mismatch'>, string> = {
	unknown: 'unknown code',
	expired: 'code expired',
	replayed: 'code already used',
};

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
 *   origin or another browser. Only a presentation that passes every check
 *   consumes the code.
 * - 500 `server_error`: storage or session write failed, or sessions are off.
 *
 * Refusals are logged with the reason and origin, never the code.
 */
export async function handleLoginHandoffRedeem(
	request: Request,
	body: any,
	allowlist: readonly OriginPattern[] | (() => readonly OriginPattern[]),
	logger?: Logger
): Promise<any> {
	const currentPatterns = typeof allowlist === 'function' ? allowlist : () => allowlist;
	const patterns = currentPatterns();
	if (patterns.length === 0) {
		return { status: 404, body: { error: 'Not found' } };
	}

	// Before any storage read. A browser cannot forge Origin; the browser
	// binding covers a non-browser caller that can.
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

	const browserSecret = readBrowserSecret(request);
	if (!browserSecret || !BROWSER_SECRET_PATTERN.test(browserSecret)) {
		logger?.warn?.(`OAuth handoff refused for ${JSON.stringify(origin)}: no well-formed browser binding cookie`);
		return errorResponse(400, 'invalid_grant', 'The handoff code is invalid, expired or already used');
	}
	let result: Awaited<ReturnType<typeof redeemLoginHandoff>>;
	try {
		result = await redeemLoginHandoff(code, (record) => {
			if (matchAllowedOrigin(origin, currentPatterns()) !== origin) return ORIGIN_REMOVED;
			if (record.origin !== origin) return `code was issued for ${JSON.stringify(record.origin)}`;
			if (!browserSecretMatches(browserSecret, record.browserNonceHash)) {
				return 'browser binding mismatch (not the browser that started the sign-in)';
			}
			return null;
		});
	} catch (error) {
		logger?.error?.(
			`OAuth handoff for ${JSON.stringify(origin)}: storage error:`,
			error instanceof Error ? `${error.name}: ${error.message}` : 'unknown error'
		);
		return errorResponse(500, 'server_error', 'Unable to complete the sign-in, please try again');
	}

	if ('refused' in result && result.detail === ORIGIN_REMOVED) {
		logger?.warn?.(`OAuth handoff refused for ${JSON.stringify(origin)}: ${ORIGIN_REMOVED}`);
		return errorResponse(403, 'origin_not_allowed', 'This origin may not complete a sign-in handoff');
	}
	if ('refused' in result) {
		const reason = result.refused === 'mismatch' ? result.detail : REFUSAL_LOG[result.refused];
		logger?.warn?.(`OAuth handoff refused for ${JSON.stringify(origin)}: ${reason}`);
		return errorResponse(400, 'invalid_grant', 'The handoff code is invalid, expired or already used');
	}
	const { record } = result;
	// A reload during the storage round trips may have removed this origin.
	if (matchAllowedOrigin(origin, currentPatterns()) !== origin) {
		logger?.warn?.(`OAuth handoff refused for ${JSON.stringify(origin)}: ${ORIGIN_REMOVED}`);
		return errorResponse(403, 'origin_not_allowed', 'This origin may not complete a sign-in handoff');
	}

	try {
		await request.session.update(record.session);
	} catch (error) {
		logger?.error?.(
			`OAuth handoff for ${JSON.stringify(origin)}: session write failed:`,
			error instanceof Error ? `${error.name}: ${error.message}` : 'unknown error'
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
