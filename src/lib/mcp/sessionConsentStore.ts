/**
 * Consents shown in `mcp.sessionLogin` mode, awaiting the user's approve/deny POST. A token is
 * redeemed at most once, by the browser and session it was shown to; storage failures throw so the
 * caller refuses rather than mints.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { MCPAuthorizeState, Table } from '../../types.ts';

declare const databases: any;

/** How long a consent page stays approvable. */
export const SESSION_CONSENT_TTL_MS = 10 * 60_000;

/** 32 random bytes, base64url: exactly 43 characters from this set. */
export const SESSION_CONSENT_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

let consentsTable: Table | undefined;

function getConsentsTable(): Table {
	if (!consentsTable) {
		if (!databases?.oauth?.mcp_session_consents) {
			throw new Error(
				'OAuth MCP session consents table (oauth.mcp_session_consents) not found. ' +
					'Please ensure the OAuth plugin is properly installed with its schema.'
			);
		}
		consentsTable = databases.oauth.mcp_session_consents;
	}
	return consentsTable as Table;
}

/** @internal test seam */
export function resetMCPSessionConsentsTableCache(): void {
	consentsTable = undefined;
}

function consentKey(token: string): string {
	return createHash('sha256').update(token).digest('hex');
}

export interface SessionConsent {
	user: string;
	clientId: string;
	browserNonceHash: string;
	state: MCPAuthorizeState;
	expiresAt: number;
}

/** Store a consent and return its token; the row commits on its own transaction before the page goes out. */
export async function issueSessionConsent(consent: Omit<SessionConsent, 'expiresAt'>): Promise<string> {
	const token = randomBytes(32).toString('base64url');
	const expiresAt = Date.now() + SESSION_CONSENT_TTL_MS;
	await getConsentsTable().put(
		{
			id: consentKey(token),
			user: consent.user,
			client_id: consent.clientId,
			browser_hash: consent.browserNonceHash,
			state: JSON.stringify(consent.state),
			expires_at: expiresAt,
			uses: 0,
		},
		{ expiresAt }
	);
	return token;
}

export type SessionConsentRefusal = 'unknown' | 'expired' | 'replayed' | 'mismatch';

/**
 * Redeem a consent. `check` runs on the stored consent before anything is consumed, so a presentation
 * from the wrong browser or session leaves the consent for the right one; it returns a refusal reason or
 * null. Single use: the winner adds 1 to `uses` atomically and only a presenter that reads back 1
 * proceeds (fresh-context reads, as in assertionJtiStore.ts). The row is kept, scrubbed, until it expires:
 * deleting it would let a presenter that read the live row first re-create it at `uses: 1` and also win.
 */
export async function redeemSessionConsent(
	token: string,
	check: (consent: SessionConsent) => string | null
): Promise<{ consent: SessionConsent } | { refused: SessionConsentRefusal; detail?: string }> {
	const table = getConsentsTable();
	const id = consentKey(token);
	const row = await table.get(id, {});
	if (!row || typeof row.user !== 'string' || typeof row.state !== 'string') return { refused: 'unknown' };
	const expiresAt = Number(row.expires_at);
	if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return { refused: 'expired' };
	if (Number(row.uses) > 0) return { refused: 'replayed' };
	const consent: SessionConsent = {
		user: row.user,
		clientId: String(row.client_id ?? ''),
		browserNonceHash: String(row.browser_hash ?? ''),
		state: JSON.parse(row.state) as MCPAuthorizeState,
		expiresAt,
	};
	const mismatch = check(consent);
	if (mismatch) return { refused: 'mismatch', detail: mismatch };
	await table.patch(id, { uses: { __op__: 'add', value: 1 }, state: null }, { expiresAt });
	if ((await table.get(id, {}))?.uses !== 1) return { refused: 'replayed' };
	if (expiresAt <= Date.now()) return { refused: 'expired' };
	return { consent };
}
