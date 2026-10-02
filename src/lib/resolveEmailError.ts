/**
 * Thrown whenever an `onResolveEmail` hook cannot be trusted to pick the login's email — it
 * threw, timed out, or returned something outside the verified candidate set (#228). Callers
 * must fail the login on this (never fall back to the default selection), and may use
 * `instanceof ResolveEmailError` to classify the failure without parsing the message.
 */
export class ResolveEmailError extends Error {
	/** Matches the `reason` query param handlers.ts puts on the login-failure redirect. */
	readonly reason = 'email_selection';
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'ResolveEmailError';
	}
}

/** Sibling of {@link ResolveEmailError}, not a subtype — two or more verified candidates each
 *  match a different existing Harper account; refuses rather than guessing which one. */
export class AmbiguousEmailError extends Error {
	readonly reason = 'email_ambiguous';
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'AmbiguousEmailError';
	}
}

/** An `hdb_user` read for a verified candidate failed — never treated as a confirmed match or
 *  non-match, only as "unknown". */
export class EmailLookupError extends Error {
	readonly reason = 'email_lookup_failed';
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'EmailLookupError';
	}
}
