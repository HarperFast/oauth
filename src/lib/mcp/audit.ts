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
 * The payload is passed as a second argument (`harperLogger?.info?.('MCP audit:', payload)`)
 * so the structured object is never serialised unless the logger renders it.
 * This matches how Harper core's auth-event logger is called. The `'MCP audit:'`
 * prefix string stays greppable / filterable in hdb.log.
 *
 * Three event types: `issued` / `refreshed` (success path, from the token
 * endpoint — carry the verified claims) and `rejected` (from the withMCPAuth
 * guard when a presented bearer token fails validation). A rejected token has
 * NO verified claims, so its payload is a distinct shape (reason + resource).
 */

import { logger as harperLogger } from 'harper';

export type MCPAuditEventType = 'oauth.mcp.token.issued' | 'oauth.mcp.token.refreshed' | 'oauth.mcp.token.rejected';

/**
 * Audit record for a successfully issued or refreshed token. Carries the
 * verified claims (the token validated, so these are trustworthy) — but never
 * the token strings themselves; only the `jti` identifier.
 */
export interface MCPTokenIssuedAuditPayload {
	/** Discriminator: success-path token events. */
	event: 'oauth.mcp.token.issued' | 'oauth.mcp.token.refreshed';
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
 * Audit record for a bearer token rejected at the withMCPAuth guard. The token
 * FAILED validation (bad signature / expired / wrong audience / malformed
 * claims), so it has no trustworthy claims: we log only the denial reason and
 * the resource it was presented to — never an unverified `client_id`/`sub`/`jti`,
 * which would be attacker-controlled, spoofable input.
 */
export interface MCPTokenRejectedAuditPayload {
	/** Discriminator: a presented token was rejected. */
	event: 'oauth.mcp.token.rejected';
	/** Human-readable denial reason (the same text returned in the 401 body). */
	reason: string;
	/** Resource URI the token was presented to (best-effort, from MCP config). */
	aud: string;
	/** ISO-8601 UTC timestamp of the event. */
	timestamp: string;
}

export type MCPAuditPayload = MCPTokenIssuedAuditPayload | MCPTokenRejectedAuditPayload;

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
		// Pass payload as a second arg so serialisation is deferred to the logger.
		harperLogger?.info?.('MCP audit:', payload);
	} catch {
		// Intentionally ignored — audit logging is best-effort.
	}
}
