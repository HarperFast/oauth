/**
 * Read a request header across the shapes a Harper request can carry.
 *
 * The live Harper runtime passes component resources a headers wrapper that
 * exposes only `.asObject` (not enumerable header properties), so reading
 * `request.headers.<name>` directly returns undefined in production even though
 * it works against the plain `IncomingMessage.headers` object used in unit
 * tests. Every header read on a Harper request must go through here.
 *
 * Handles three shapes:
 *   - a Web `Headers` object (`.get()`),
 *   - Harper's runtime headers wrapper (`.asObject`),
 *   - a plain Node `IncomingMessage.headers` object (tests).
 *
 * Header names are matched case-insensitively; the first value is returned when
 * a header is multi-valued.
 */
export function getRequestHeader(headers: unknown, name: string): string | undefined {
	const raw = readRawHeader(headers, name);
	if (raw == null) return undefined;
	// Take the first value for a multi-valued header, and always coerce to string
	// (or undefined) so the declared return type holds even for a malformed
	// headers object with a non-string / empty-array value.
	const value = Array.isArray(raw) ? raw[0] : raw;
	return value == null ? undefined : String(value);
}

/**
 * Read the RAW header value from the container without collapsing multi-value —
 * the shared wrapper-shape detection (Web `Headers` `.get()`, Harper `.asObject`,
 * plain object) behind `getRequestHeader`. Callers decide first-value vs. join
 * (the `Cookie` header must join all crumbs; see consentBinding.ts). Returns a
 * string, an array, or undefined.
 */
export function readRawHeader(headers: unknown, name: string): unknown {
	if (!headers) return undefined;
	const h = headers as any;
	if (typeof h.get === 'function') return h.get(name);
	const obj = h.asObject ?? h;
	return obj?.[name.toLowerCase()] ?? obj?.[name];
}
