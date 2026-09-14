import { randomBytes } from 'node:crypto';

/**
 * Build a non-resolvable "quarantine" principal for a roleless, untrusted login.
 *
 * The random suffix makes the value unpredictable, so no `hdb_user` can be
 * created to match it — a privileged account of the claim's name created later
 * can never be adopted by this session. The claim is embedded (before the `#`)
 * purely for log/debug observability; it is never parsed back out.
 */
export function makeQuarantinePrincipal(claim: string): string {
	return `unverified:${claim}#${randomBytes(8).toString('hex')}`;
}

const QUARANTINE_SUFFIX_RE = /#[0-9a-f]{16}$/;

/**
 * True for a principal minted by {@link makeQuarantinePrincipal}. Checks the
 * prefix and the random suffix independently so an embedded claim containing any
 * character (line terminators, `#`, regex metacharacters) is matched correctly.
 */
export function isQuarantinePrincipal(value: unknown): boolean {
	return typeof value === 'string' && value.startsWith('unverified:') && QUARANTINE_SUFFIX_RE.test(value);
}

/**
 * Redact the random suffix of a quarantine principal for logging, so the
 * unpredictable value never reaches a log line. Non-quarantine values are
 * returned unchanged.
 */
export function redactQuarantinePrincipal(value: string): string {
	return isQuarantinePrincipal(value) ? value.replace(QUARANTINE_SUFFIX_RE, '#<redacted>') : value;
}
