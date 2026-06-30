/**
 * MCP Audit Channel
 *
 * Emits structured audit records for MCP token lifecycle events via Harper's
 * global logger at `.info`. Mirrors how Harper core audits auth events in
 * security/auth.ts (authEventLog.info?.(log)). Each record is prefixed
 * `MCP audit:` and carries an `event` discriminator field, so operators filter
 * by that prefix / the `event` value — Harper's logger doesn't expose a tag/
 * named-level facility to plugins here (the `dcr.ts` audit logs are untagged
 * for the same reason).
 *
 * Why .info and not .notify:
 *   - `notify` sits above `fatal` (level 7) in Harper's hierarchy and is
 *     reserved for operational broadcast events (service started, fatal state
 *     changes). Token issuance is routine success-path activity — it should be
 *     auditable at the standard info level, just like Harper core's
 *     auth-success events.
 *   - Using harperLogger (Harper's global structured logger) rather than the
 *     scoped plugin logger routes these to hdb.log alongside Harper's own
 *     auth audit trail, not to system.log.
 *
 * Keep ALL string formatting inside the logger call so the optional-call
 * short-circuit (`?.`) avoids JSON.stringify work when info is suppressed
 * (same lazy-logging pattern as dcr.ts).
 *
 * The `rejected` event (oauth.mcp.token.rejected) is NOT implemented here yet
 * — it belongs in withMCPAuth (Stage 5, PR #134, not on main). The helper is
 * written to accept any event type so adding it later is a one-liner.
 */

import { logger as harperLogger } from 'harper';

export type MCPAuditEventType = 'oauth.mcp.token.issued' | 'oauth.mcp.token.refreshed' | 'oauth.mcp.token.rejected';

export interface MCPAuditPayload {
	/** Discriminator for the audit event type. */
	event: MCPAuditEventType;
	/** Registered MCP client identifier. */
	client_id: string;
	/** Subject claim — the Harper user the token was issued to. */
	sub: string;
	/** Audience claim — the resource URI the token is bound to. */
	aud: string;
	/** OAuth scope string (may be undefined for unscoped tokens). */
	scope?: string;
	/** JWT ID — uniquely identifies this token. Safe to log (not the token). */
	jti: string;
	/** ISO-8601 UTC timestamp of the event. */
	timestamp: string;
}

/**
 * Emit a structured MCP audit event via Harper's global logger.
 *
 * Failure to log MUST NOT propagate — this is fire-and-forget. The call site
 * is responsible for the try/catch if needed, but this function itself does
 * not throw.
 *
 * SECURITY: payload must never include token strings (access_token,
 * refresh_token, client_secret). Only the jti (token identifier) is included.
 */
export function emitMCPAuditEvent(payload: MCPAuditPayload): void {
	// Fire-and-forget: a logging failure MUST NOT propagate. Callers emit AFTER
	// token state is durably committed (e.g. a rotated refresh family), so a
	// thrown logger error here would deny the client its new token and strand
	// the family on a hash the client never received. Swallow everything.
	try {
		// Keep JSON.stringify inside the optional call so it is only evaluated
		// when the info level is active (optional-call short-circuit).
		harperLogger?.info?.(`MCP audit: ${JSON.stringify(payload)}`);
	} catch {
		// Intentionally ignored — audit logging is best-effort.
	}
}
