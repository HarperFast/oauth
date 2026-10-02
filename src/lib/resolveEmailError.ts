/**
 * Thrown whenever an `onResolveEmail` hook cannot be trusted to pick the login's email — it
 * threw, timed out, or returned something outside the verified candidate set (#228). Callers
 * must fail the login on this (never fall back to the default selection), and may use
 * `instanceof ResolveEmailError` to classify the failure without parsing the message.
 */
export class ResolveEmailError extends Error {
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'ResolveEmailError';
	}
}

/**
 * Thrown when two or more verified candidate emails each match a DIFFERENT existing Harper
 * account (the built-in default-resolution step, #228) — refuses the login rather than
 * guessing which account the user meant. A sibling of {@link ResolveEmailError}, not a
 * subtype: the two are classified into distinct redirect reasons (`email_selection` vs
 * `email_ambiguous`), and callers should check `instanceof AmbiguousEmailError` first.
 */
export class AmbiguousEmailError extends Error {
	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = 'AmbiguousEmailError';
	}
}
