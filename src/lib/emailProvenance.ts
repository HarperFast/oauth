/**
 * A private channel for a provider adapter to assert email provenance to the
 * `OAuthProvider.getUserInfo` wrapper, which the wrapper trusts as proof of an
 * authenticated fetch.
 *
 * The channel is a Symbol, deliberately: a JSON userinfo/emails response cannot
 * carry a symbol key (`JSON.parse` never produces one), so a remote body cannot
 * forge a trusted value, and a custom adapter that does not import this Symbol
 * cannot set one either — trust therefore originates only in in-process adapter
 * code that actually performed the work (the built-in GitHub adapter, which sets
 * it from its `/user/emails` fetch result). The adapter sets it as a **non-enumerable**
 * property, so a spread (`{ ...adapterResult, email: attacker }`) cannot copy the
 * assertion onto a substituted email; the wrapper reads it by key (which works
 * regardless of enumerability) and, being non-enumerable, it never travels downstream
 * through the wrapper's own object rest/spread.
 */
export const ADAPTER_EMAIL_PROVENANCE = Symbol('adapterEmailProvenance');
