/**
 * Consents shown in `mcp.sessionLogin` mode, awaiting the user's approve/deny POST. Storage failures throw,
 * so the caller refuses rather than mints.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { MCPAuthorizeState, Table } from '../../types.ts';

declare const databases: any;

const SESSION_CONSENT_TTL_MS = 10 * 60_000;

export const SESSION_CONSENT_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** Re-reads of a consent not found yet, in ms: the POST can reach a node the GET's write has not replicated to. */
const MISS_RETRY_DELAYS_MS: readonly number[] = [100, 300];

const MAX_MISS_RETRIERS = 32;
let missRetriers = 0;

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

/** @internal */
export function resetMCPSessionConsentsTableCache(): void {
	consentsTable = undefined;
}

function consentKey(token: string): string {
	return createHash('sha256').update(token).digest('hex');
}

export interface SessionConsent {
	user: string;
	clientId: string;
	clientName?: string;
	browserNonceHash: string;
	state: MCPAuthorizeState;
	expiresAt: number;
}

export async function issueSessionConsent(consent: Omit<SessionConsent, 'expiresAt'>): Promise<string> {
	const token = randomBytes(32).toString('base64url');
	const expiresAt = Date.now() + SESSION_CONSENT_TTL_MS;
	await getConsentsTable().put(
		{
			id: consentKey(token),
			user: consent.user,
			client_id: consent.clientId,
			client_name: consent.clientName,
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

async function readConsentRow(table: Table, id: string): Promise<any> {
	let row = await table.get(id, {});
	if (row || missRetriers >= MAX_MISS_RETRIERS) return row;
	missRetriers++;
	try {
		for (const delay of MISS_RETRY_DELAYS_MS) {
			await new Promise((resolve) => setTimeout(resolve, delay));
			row = await table.get(id, {});
			if (row) break;
		}
	} finally {
		missRetriers--;
	}
	return row;
}

/**
 * Redeem a consent. `check` runs before anything is consumed, so a presentation from the wrong browser or
 * session leaves the consent for the right one; it returns a refusal reason or null.
 *
 * Single use is the `login_handoffs` counter (loginHandoff.ts explains the fresh-context reads and why the
 * scrubbed row is kept until it expires). It holds per node: within the replication delay a presentation on
 * each node can win, and every winner is still bound to the same browser, session user and PKCE challenge.
 */
export async function redeemSessionConsent(
	token: string,
	check: (consent: SessionConsent) => string | null
): Promise<{ consent: SessionConsent } | { refused: SessionConsentRefusal; detail?: string }> {
	const table = getConsentsTable();
	const id = consentKey(token);
	const row = await readConsentRow(table, id);
	if (!row || typeof row.user !== 'string') return { refused: 'unknown' };
	const expiresAt = Number(row.expires_at);
	if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return { refused: 'expired' };
	if (Number(row.uses) > 0 || typeof row.state !== 'string') return { refused: 'replayed' };
	const consent: SessionConsent = {
		user: row.user,
		clientId: String(row.client_id ?? ''),
		clientName: typeof row.client_name === 'string' ? row.client_name : undefined,
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
