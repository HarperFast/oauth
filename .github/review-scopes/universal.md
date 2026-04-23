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

Only flag gaps the PR **itself** creates. Pre-existing coverage gaps in code the PR merely touches are NOT this PR's problem — flagging them is a scaling trap on repos that are still catching up on coverage.

- **NEW public API symbols need a happy-path test.** If the PR adds a new export from `src/index.ts` (or equivalent) and no test file exercises it at all, that's a blocker. A missing *edge-case* test on an otherwise-tested new API is a nit — don't post it.
- **NEW security-critical branches need explicit tests.** Deny paths, 401 returns, auth-required enforcement, silent-bypass guards — if the PR adds one, the branch needs to be directly exercised (including that the protected method is NOT invoked on the deny path). Blocker.
- **NEW "production vs fallback" splits.** If the PR introduces a runtime-shape branch (e.g. `if (typeof x.delete === 'function')`), both legs need coverage. A test that only lands in the fallback gives false confidence on the production path. Blocker.
- **NEW iterated string identifiers.** If the PR adds code that iterates over method names, verb lists, event names, etc. and a typo in one would silently disable a feature, each name needs direct coverage. Blocker.

Pre-existing gaps are NOT findings. "This function has no tests" on code the PR touches but didn't add is a repo-maintenance issue, not a PR blocker.

## Documentation

- **JSDoc examples match the current API.** If the signature changed, the example changed too. Blocker when the example would mislead; prose polish is not.
- **Code that references a doc path** (`CLAUDE.md`, migration guides, skills) — verify the referenced section still exists.
- **Gotchas section updates.** If this PR introduces a new foot-gun, it belongs in the repo's `CLAUDE.md` or equivalent.

## What to ignore

- `package-lock.json`, `bun.lock`, `yarn.lock` — lockfile regens are deterministic from `package.json`.
- `package.json` edits that ONLY bump patch/minor versions of existing deps. `engines`, `peerDependencies`, and new `dependencies` entries DO need review.
- `dist/` compiled output.

## Output discipline

**What counts as a blocker:**

- Correctness bugs (the code does the wrong thing)
- Security issues (auth bypass, token exposure, missing CSRF, unvalidated redirect or path, injection)
- Broken public API contracts (signature / return shape / error type changed without a migration path)
- Missing tests the PR itself should have added — per the scoping rules in the Testing section above
- Documentation drift that would actively mislead integrators

**What is NOT a blocker** (do not post these, even if they're true):

- Pre-existing coverage gaps in code the PR merely touches but didn't add
- Style, naming, or formatting preferences
- "Consider adding a comment" / "Could be more readable"
- Missing edge-case tests when happy-path and primary failure-path are covered
- Minor JSDoc prose polish (the *example matching the API* is a blocker; wording is not)
- Architectural suggestions the current code doesn't call for

If a finding doesn't have concrete impact on correctness, security, contract, or integrator experience — it's a nit. Don't post it.

**How to post:**

- Structured format: `### <N>. <title>` + `**File:** path:line` + `**What:** …` + `**Why it matters:** …` + `**Suggested fix:** …`.
- If zero blockers: one short comment — "No blockers found." — then stop.
- Never `REQUEST_CHANGES` or `APPROVE` during calibration — comments only.
