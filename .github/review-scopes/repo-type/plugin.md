# Harper plugin repo

Applies to repos that ship as npm packages consumed by Harper applications — OAuth, and future plugins. These repos have a distinct review surface because they extend Harper rather than being Harper itself.

## Registration and lifecycle

- **Plugin entry** is `handleApplication(scope)` exported from `src/index.ts`. Verify the PR preserves this signature and doesn't rename or re-shape it.
- **Resource registration** uses `scope.resources.set('<name>', Class)`. Harper's dispatch logic requires the registered value to be a class (with `static getResource` inherited from `Resource`), not an instance, not a plain object.
- **HTTP middleware** registration uses `scope.server.http?.(handler)`. Verify new middleware handles the "no OAuth / no auth data" passthrough case correctly — middleware runs on every HTTP request, including requests that don't need the plugin's semantics.
- **Close handlers**: Plugins that hold resources (cache instances, timers, sockets) should register a cleanup listener on `scope.on('close', ...)`. Verify new long-lived state has a corresponding cleanup path.

## Public API surface

- **Everything exported from `src/index.ts` is public.** Re-exports need JSDoc and semver care.
- **New public symbols require tests.** Silent no-test public API was a recurring gap in the OAuth plugin's review history.
- **Breaking changes require a major version bump.** For plugins with a maintenance branch (e.g. `v1.x` for harperdb-v4 support), check whether the fix needs a backport. Surface the backport question in the PR description if non-trivial.

## Dependencies

- **Zero or justified runtime dependencies.** Every new runtime dep needs explicit justification in the PR description. Plugins that previously claimed zero runtime deps and then added one (e.g. `jsonwebtoken` for JWT-based providers) must update their README / docs accordingly.
- **Peer dep version range** should match the plugin's compatibility promise. v5-only plugin → `harper >=5.0.0`. Multi-version plugin → union range or separate release lines.

## Wrapping and decorating patterns

Plugins frequently offer a wrapper function that user resources opt into (e.g. `withOAuthValidation`). Review such wrappers against the full dispatch surface audit in `universal.md` and the v5 static-vs-instance guidance in `harper/v5.md`. Common bypass shapes we've seen:

- Proxy-based wrappers that don't intercept class-level dispatch.
- Subclass wrappers that only override instance methods and miss user-defined statics.
- Subclass wrappers that define all five verbs unconditionally and break Harper's 405 Method Not Allowed semantics for verbs the parent doesn't implement.
- Wrappers whose `onValidationError` (or equivalent) callback accepts `undefined` as a "no problem" sentinel — giving an integrator's no-op logger silent auth-bypass powers.

## Docs expectations

- README's "Quick Start" is local-dev guidance — `.env` or shell `export`. Production guidance should point to Fabric (see `harper/v5.md`), not generic deployment patterns.
- `docs/` covers integration patterns. Doc-only PRs still need to be consistent with the `harper/v5.md` deployment model.
- `CLAUDE.md` captures non-obvious local gotchas. Any new wrinkle discovered during review (especially one that bit an earlier PR) should be proposed for `CLAUDE.md` in the same or follow-up PR.
