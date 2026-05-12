# Changelog

All notable changes to `@harperfast/oauth` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0-alpha.2] — 2026-05-12

### Breaking

- **`withOAuthValidation` now wraps a Resource _class_, not an instance.** This aligns with the Harper v5 Resource API v2 dispatch model, where the framework can call either the user's instance method or a static method on the class. The previous instance-wrapping shape only intercepted the instance-method path; the class-wrapping shape covers both. Callers must update the wrap call to pass the class (or use the new entry-point re-export — see Fixed). The pattern is documented in the JSDoc and exercised throughout the new test suite.

### Security

- **Fail-closed when `requireAuth: true` and no request context is available.** Previously a missing context could fall through to the wrapped method without validation. Now returns 401.
- **Fail-closed when `onValidationError` returns `undefined`.** `undefined` was indistinguishable from "no override, continue" in the surrounding dispatch; a caller-supplied `onValidationError` that returned `undefined` (intentionally or otherwise) could bypass the deny path. Now `undefined` is treated as the default deny.
- **Closed a static-method dispatch bypass.** Wrappers that intercepted only the instance method were silently bypassed when the user adopted the static-method pattern (where Harper's REST dispatcher calls `Class.get(target, request)` directly). Both surfaces are now covered, with dedup so a single dispatch doesn't run validation twice.
- **`onValidationError` no longer sees a mutated request.** Earlier, certain verbs (`put` / `patch` / `delete`) would mutate the request object before invoking the callback, leaking partial state. The callback now receives the un-mutated request consistently across all verbs.
- **`onValidationError` is not invoked without a request.** A no-context invocation could pass `undefined` as the request argument. The call site now skips the callback in this case (and falls back to the standard deny path).

### Fixed

- **`withOAuthValidation` is re-exported from the package entry point** (`src/index.ts`). Previously, importing from `@harperfast/oauth` did not surface the wrapper directly; consumers had to reach into the package's internal paths.
- **`withOAuthValidation` reads request from `getContext()`.** Aligns with the Harper v5 context model. Closes [#33](https://github.com/HarperFast/oauth/issues/33).
- **Preserve `405 Method Not Allowed` for unimplemented verbs.** The wrapper previously replaced unimplemented base-class methods with a function that returned `undefined`, which Harper then serialized as `204 No Content`. Now wraps only the verbs the parent class actually implements.
- **Preserve `405` against Harper-shaped base classes** and harden dedup across dispatch normalization (the path the framework takes when both static and instance methods are present).
- **`package-lock.json` regenerated with all optional native dependencies** — prior lockfile was missing platform-conditional entries that broke cross-platform `npm ci`.

### Added

- **Test coverage for the refactored `withOAuthValidation`.** New test suite at `test/lib/withOAuthValidation.test.js` (+1247 lines) covers each verb, the static + instance dispatch paths, fail-closed branches, `onValidationError` callback contract, expired-token paths, and the class-wrap pattern.
- **Integration test harness.** New `integrationTests/` tree with Harper v5 integration fixtures, including `env-var-substitution.test.ts`. Runs via `harper-integration-test-run` from the integration testing toolchain.
- **`harper-mock` test helper** at `test/helpers/harper-mock.mjs` enables Node-only unit tests without requiring a running Harper instance. Loaded via `node --import` in the `npm test` script.

### Changed

- **Node.js 20 is no longer supported.** The Harper mock helper relies on Node 22+ features. Supported Node range matches Harper v5.
- **`onValidationError` contract documented in JSDoc.** Includes the `requireAuth` coupling and the request-state visibility rules introduced by the fixes above.

## [2.0.0-alpha.1] — 2026-05-01

### Breaking

- **Migrated to Harper v5 (`harper` npm package).** Previously depended on `harperdb` (v4); now depends on the `harper` peer-dependency for Harper v5. This requires consuming applications to upgrade to Harper v5. See the Harper v5 migration guide for the underlying API changes.

### Added

- Test coverage for `scope.resources` / `scope.server` guard (the typed-as-optional-but-always-assigned shape from Harper v5's Scope constructor).

## [1.4.0] — 2026-02-18

- Simple in-memory cache for dynamic provider configs (`cacheDynamicProviders`).
- Updated Okta issuer handling.

## [1.3.0] — 2026-02-18

- Added `cacheDynamicProviders` option.

## [1.2.1] — 2026-02-10

- Format fix.

## [1.2.0] — 2026-02-10

- Initial public release on `@harperfast/oauth` scope.

[2.0.0-alpha.2]: https://github.com/HarperFast/oauth/compare/v2.0.0-alpha.1...v2.0.0-alpha.2
[2.0.0-alpha.1]: https://github.com/HarperFast/oauth/compare/v1.4.0...v2.0.0-alpha.1
[1.4.0]: https://github.com/HarperFast/oauth/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/HarperFast/oauth/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/HarperFast/oauth/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/HarperFast/oauth/releases/tag/v1.2.0
