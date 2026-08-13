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
	if (!headers) return undefined;
	const h = headers as any;
	let raw: unknown;
	if (typeof h.get === 'function') {
		raw = h.get(name);
	} else {
		const obj = h.asObject ?? h;
		raw = obj?.[name.toLowerCase()] ?? obj?.[name];
	}
	if (raw == null) return undefined;
	return Array.isArray(raw) ? raw[0] : String(raw);
}
