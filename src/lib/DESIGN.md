# Design notes for `src/lib`

Invariants that aren't obvious from reading the code in isolation.

## Azure multi-tenant adoption never consults the shared key pool (HarperFast/oauth#264)

`azureIssuer.ts`'s `resolveAzureIssuerBinding` rewrites a pinned alias authority
(`common`/`organizations`/`consumers`) to the pinned tenant's own,
non-shared `/{guid}/discovery/v2.0/keys` endpoint, and `OAuthProvider` then
verifies against that rewritten `jwksUri` through the exact same code path as
any ordinary single-tenant config. This is deliberate, not a simplification
taken for convenience: Microsoft's tenant-independent endpoints (`/common`,
`/organizations`) serve a _shared_ key set where a key's cryptographic
validity does not, by itself, prove which tenant it was intended for — only a
per-key `issuer` property in the raw JWKS response does, and that property
isn't reachable through `jwks-rsa`'s public API. Redirecting to the one
pinned tenant's own endpoint sidesteps that ambiguity entirely instead of
trying to parse around it. **Do not reintroduce a path that fetches keys from
`/common`/`/organizations`/`consumers` directly for a pinned provider** — it
would reopen the gap this design closes.

A multi-tenant authority with **no** pin is left completely untouched
(`issuer` never set, `jwksUri` never rewritten) — adoption-eligibility for an
Azure alias is opt-in, one tenant at a time, by design (an array pin is
rejected at config-build/`OAuthProvider`-construction time for the same
reason: it would let two of an operator's own pinned tenants adopt each
other's Harper account if they ever shared a verified email).

## Where OIDC discovery is scheduled from (`src/index.ts`)

Discovery for a statically configured, issuer-less JWKS provider is scheduled
from `updateConfiguration` immediately after `Object.assign(providers,
newProviders)` — not after `resources.set('oauth', OAuthResource)`, and not
as the function's last statement. That specific line is the earliest point
guaranteed to be _definitely late enough_ (a build that fails inside
`initializeProviders`, e.g. the reserved `'mcp'` provider name, never reaches
it) and _definitely not too late_ (on a **reload**, `OAuthResource.providers`
already references this same object from a prior `configure()` call, so the
registry is already being served the instant this line runs — before
`resources.set` or any later log statement, which can therefore no longer
retroactively make the schedule "too late"). Moving this call later (e.g.
after `resources.set`, or to the end of the function) silently reintroduces a
window where an already-live, already-serving provider never gets discovery
scheduled for it, because a later, unrelated statement (a throwing logger
on the "ready" message, for instance) made the overall reload report failure.

## Module layering: `azureIssuer.ts` and `discovery.ts` do not import `config.ts`/`OAuthProvider.ts`

Both modules are called from `config.ts`'s `buildProviderConfig` **and** from
`OAuthProvider`'s own constructor (the latter is the only enforcement point a
config built outside `buildProviderConfig` — e.g. `TenantManager` — ever
crosses). Keeping them dependency-free of both callers avoids a three-way
import cycle; each duplicates the few trivial predicates it needs (e.g.
`hasUsableIssuer`) rather than importing them.
