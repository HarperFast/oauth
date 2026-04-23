# Harper common conventions

Version-agnostic review guidance for repos in the Harper ecosystem. The repo's own `CLAUDE.md` may duplicate or extend this — when in conflict, the repo's CLAUDE.md wins (it's closer to the source).

## Non-obvious behavior

- **`GenericTrackedObject` + spread.** `{ ...obj }` on a Harper *generic* tracked object (the shape for `session.oauth`, `session.oauthUser`, and any tracked object without a declared schema) copies nothing — properties are served through a Proxy `get` trap, not as own enumerable properties. `Object.keys(obj)` returns `[]`. Use explicit property access: `{ provider: obj.provider, ... }`. Typed TrackedObjects (table rows with declared attributes) may behave differently; verify against the specific tracked type rather than assuming either way. Any test using spread on session fields is testing a plain object, not the production shape.
- **`session.oauth` vs `session.delete()`.** Some session objects expose `.delete(id)` (Harper production shape — destroys the DB record). Some don't (in-memory test mocks). Code calling `clearOAuthSession` or similar may mutate `.oauth`/`.oauthUser` in-memory on test shapes but destroy the entire session record in production. Tests that exercise only one shape hide the divergence.
- **`npm run build` tolerance.** Many Harper repos use `tsc || true` so the build passes even with type errors. "Build passes" ≠ "types are sound." Type correctness must be verified separately (editor diagnostics, a dedicated typecheck script, or CI step).
- **`npm run lint` is ESLint-only**, not a typecheck.

## Code conventions

- TypeScript strict mode; ES modules with `.js` extensions in imports; named exports only (no default exports).
- Logging uses the optional-chain pattern `logger?.info?.()` — the `logger` argument is frequently undefined in library code, so code must not assume it's present.
- Error classes come from each repo's `src/errors.ts` OR the framework package (`harper` v5 / `harperdb` v4). All custom errors include a `statusCode` property.
- Tokens, passwords, session IDs — **never** log, never return in responses, never include in error messages.

## Review checks specific to Harper

- **`scope.resources` / `scope.server` usage.** Declared optional in the Harper type but always assigned in the Scope constructor. Code should either guard once at entry or use narrowed locals, not sprinkle `?.` / `!` throughout.
- **`static loadAsInstance = false` (Resource API v2).** Harper instantiates the class per request; do NOT rely on shared mutable instance state across requests. If per-request state is stored, it belongs on the context (`this.getContext()`).
- **Unused runtime dependencies.** Harper repos target minimal runtime deps. New ones require explicit justification in the PR description (some repos maintain a `dependencies.md` for this).
