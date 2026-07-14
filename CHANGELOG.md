# Changelog — 1.x line

Notable changes to the `@harperfast/oauth` **1.x maintenance line** are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). History prior to 1.6.0 lives in the [GitHub release notes](https://github.com/HarperFast/oauth/releases); the 2.x line has its own changelog on `main`.

## [1.6.0] - 2026-07-14

### Added

- **`onLogin` controls the login outcome** (#174, backported from 2.x/#175): the hook may return `{ status: 'denied', error?, redirect? }` or `{ status: 'needs_confirmation', redirect }` to stop a session from being created (deny the login, or defer it to an onboarding/confirmation step). Plain-object and `undefined` returns behave exactly as before; `{ status: 'ok', ... }` is the explicit equivalent. New exported types: `OnLoginResult`, `OnLoginResultOk`, `OnLoginResultDenied`, `OnLoginResultNeedsConfirmation`.
  - ⚠️ **Compatibility edge:** the status values `denied` and `needs_confirmation` are newly reserved. A hook that previously returned `status` with exactly one of those values as ordinary session-enrichment data now gates the login instead. Any other `status` value keeps the legacy merge-into-session behavior (with a warning logged, since it may be a typo'd gating attempt).
  - ⚠️ **Migration note — throw-to-deny never worked:** earlier docs suggested throwing from `onLogin` to prevent a login (e.g. suspended accounts). Thrown errors have **always** been caught and logged with the login proceeding — that pattern was fail-open in every release, and it still is. If your hook throws to deny, it is not denying anything: migrate to `return { status: 'denied', ... }`, which is the first mechanism that actually gates.
- **`oauthUser.emailVerified`**: normalized boolean on the mapped user (from the provider's `email_verified` claim); `undefined` when the provider didn't attest.

### Fixed

- **GitHub provider: `email_verified` is now dependable** (#174): `/user/emails` is always consulted, so the claim is populated for users with a public profile email too. The request is bounded by a 5s timeout, and a non-OK response (e.g. missing `user:email` scope) logs a warning while degrading gracefully.
- **`onLogin` hooks that throw `null`/`undefined` no longer break the login**: the hook-error catch itself threw a `TypeError` when reading `.message` off a non-Error value (matches the 2.x hardening from #142/#147).
