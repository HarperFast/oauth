# Universal review scope

Applies to every PR regardless of the repo. Read this first and apply everything below to the diff you're reviewing.

## Architecture

- **API contracts.** Does this change alter a public API (signature, return shape, error type, side effects)? Is the alteration intentional? Is it documented?
- **Dispatch surfaces.** If the PR introduces or modifies a wrapper, decorator, middleware, or Proxy over a third-party API, verify it intercepts **all** call surfaces the wrapped API exposes. For class-based APIs this typically means:
  - Instance methods
  - Static methods (frameworks may dispatch directly to statics, bypassing instances)
  - Lifecycle hooks or registration-time callbacks
  - Protocol-specific handlers (HTTP verbs, subscription, etc.)

  A wrapper that covers only one dispatch surface is a silent bypass waiting to happen. Trace through `node_modules/<framework>/` if the dispatch shape isn't obvious from the wrapper's code alone — don't assume the documented behavior is the *only* behavior.
- **Public/private boundaries.** Are new exports from `src/index.ts` (or equivalent) intentional? Do they need JSDoc? Do internals stay scoped?
- **Breaking changes.** Is this one? Is the version bumped? Is a migration path documented? For repos with maintenance branches (e.g. `v1.x`), does the fix need a backport?
- **Observable behavior changes.** If behavior changes on a code path integrators depend on, the change needs to be documented in JSDoc, a CHANGELOG, or a PR body readable by release-notes tooling.

## Security

- **Authentication bypass.** Can the change cause auth to be silently skipped? Look especially for:
  - "No context / no session → pass through" paths — are they fail-closed when auth is required?
  - Wrappers that sit between a framework's dispatcher and a user's method — do they cover every path the framework uses to reach the method?
  - Callbacks that return `undefined` where the code expects a response object — is `undefined` a "no problem" sentinel anywhere? If so, does the surrounding code fall back to a deny?
- **Input validation.** All untrusted input (URL params, headers, bodies, query strings) validated?
- **Secret handling.** Tokens, credentials, session IDs, or PII — never logged, never returned in responses, never stored in error messages.
- **Error handling.** Do error paths avoid leaking internals (stack traces to clients, SQL/query fragments, file paths)?
- **Dependency trust.** New runtime dependencies: justified in the PR description? Trusted publisher? Any post-install scripts?
- **Cross-site hygiene.** CSRF state where relevant? Redirect URI validation? Open-redirect paths closed?

## Testing

- **New public APIs have tests.** For each new exported symbol: at least one test exercising the happy path and one for the primary failure path.
- **Tests exercise real code paths, not only mocks.** If the code has a "production path" and a "test/fallback path" (e.g. `if (typeof session.delete === 'function') { ... } else { ... }`), both need coverage. A test that only lands in the fallback gives false confidence.
- **Failure-path coverage matches the severity.** Security-relevant branches (deny paths, 401 returns, auth-required enforcement) need explicit tests, not implicit "it probably works."
- **String identifiers and verb lists.** If the code iterates over a list of method names (`'get'`, `'post'`, etc.) and a typo in one name would silently disable a feature, each name needs direct coverage.

## Documentation

- **JSDoc examples match the current API.** If the signature changed, the example changed too.
- **Code that references a doc path** (`CLAUDE.md`, migration guides, skills) — verify the referenced section still exists.
- **Gotchas section updates.** If this PR introduces a new foot-gun, it belongs in the repo's `CLAUDE.md` or equivalent.

## What to ignore

- `package-lock.json`, `bun.lock`, `yarn.lock` — lockfile regens are deterministic from `package.json`.
- `package.json` edits that ONLY bump patch/minor versions of existing deps. `engines`, `peerDependencies`, and new `dependencies` entries DO need review.
- `dist/` compiled output.

## Output discipline

- Blocker-severity findings only. No nits, no style, no "consider adding a comment."
- Structured format: `### <N>. <title>` + `**File:** path:line` + `**What:** …` + `**Why it matters:** …` + `**Suggested fix:** …`.
- If zero blockers: one short comment, "No blockers found.", then stop.
- Never `REQUEST_CHANGES` or `APPROVE` during calibration — comments only.
