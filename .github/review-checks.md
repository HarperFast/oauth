---
layers: universal, harper/common, harper/v5, repo-type/plugin
---

## Repo-specific checks (OAuth plugin)

On top of the layered scope above, these are OAuth-only
semantics not covered by the shared layers:

- CSRF state tokens present on every OAuth flow; 10-minute
  expiry is enforced; state is single-use
- Redirect URI validation on callback endpoints
- Provider-of-record enforcement (cross-provider CSRF
  protection should redirect with error, not 403)
- Session field preservation across token refresh
  (`provider`, `providerConfigId`, `providerType`)
- Path length validation (≤ 2048 chars) where user input
  can reach a path
