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
