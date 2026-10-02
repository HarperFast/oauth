# Maintaining `@harperfast/oauth`

For a Harper maintainer cutting releases, triaging CI, or picking up an open design decision.

## Releasing

1. Open a PR titled `Release X.Y.Z` that only touches `package.json`, `package-lock.json`, and `CHANGELOG.md` — see #257 ("Release 2.8.0") and #261 ("Release 2.8.1") for the shape.
   - Bump the version (`npm version X.Y.Z --no-git-tag-version`). The diff in `package.json` and `package-lock.json` is version metadata only — no dependency-graph churn.
   - In `CHANGELOG.md`, turn the `## [Unreleased]` heading into `## [X.Y.Z] - YYYY-MM-DD`. Every entry needs its upgrade note written before the heading changes, not after.
2. Merge the release PR, then publish a GitHub Release tagged `vX.Y.Z`. That `release: published` event is what triggers `.github/workflows/release.yml` — there's no separate publish step. Nothing checks that `X.Y.Z` matches the tagged commit's `package.json` version — get the version bump merged first.
   - Auth is npm trusted publishing (OIDC `id-token: write`), so no `NODE_AUTH_TOKEN` secret to manage; the workflow runs `npm publish --provenance --access public`.
   - The dist-tag is derived from the tag name: anything containing a hyphen (`v2.9.0-beta.1`) publishes to `next`; anything else publishes to `latest`.
   - The workflow re-runs lint, format-check, and `npm test` before publishing — that's the build plus the mocked Node unit tests only. It does **not** run the Bun tests or the real-Harper integration tests (those are separate `pr-checks.yml` / `integration-tests.yml` jobs on `main`), so a release can publish from a commit whose integration run never passed on that exact SHA. Confirm `main`'s integration CI is green before tagging.

**Versioning in practice:** `CHANGELOG.md` states the project follows Semantic Versioning, but 2.6.0, 2.7.0, and 2.8.0 each shipped a contract-tightening change — a setting that used to have a default now required, an exported interface's return shape changed — as a **minor**, with an explicit upgrade note in the CHANGELOG entry, rather than as a major. That's a real precedent (see those CHANGELOG entries and each release PR's description), not a documented house exception to the semver claim above it — the two are in tension. Know the precedent before deciding how to version a similar change, and decide explicitly rather than defaulting to it.

## Before each release

- **Re-run the ChatGPT capture from #244.** Interactive `private_key_jwt` stays opt-in because ChatGPT signs its client assertions with the token-endpoint URL as `aud` (forbidden by RFC 7523bis), not the issuer. The release gate for flipping the default on is ChatGPT switching to the issuer `aud` — there's no vendor changelog to watch, so capture a real code exchange before cutting a release and check the signed `aud`. On deployments that already opted in, a successful `private_key_jwt` verification logs the accepted `aud` form at info level (`src/lib/mcp/token.ts`); a rejected token-endpoint-`aud` assertion instead goes through a separate, rate-limited warning that doesn't include the `aud` form.
- **Check #258 once old tokens have aged out.** `typAccepted()` in `src/lib/mcp/tokenIssuer.ts` still accepts the legacy `typ: JWT` header alongside RFC 9068's `at+jwt`, to avoid invalidating tokens minted mid-rollout by an older node. Once every node has been on `at+jwt`-only minting for at least one full access-token TTL, remove the `JWT` branch and update the corresponding note in `docs/mcp-oauth-conformance.md`.

## CI and review automation

- `.github/workflows/claude-review.yml` and `gemini-review.yml` are thin callers of `HarperFast/ai-review-prompts`' reusable workflows. The `ai-review-prompts-ref` commit SHA is pinned twice in each file (the `uses:` line and the `with:` input) — reusable workflows can't read their own ref inside `workflow_call`, so the caller has to pass it explicitly to check out the matching prompt/script version.
- **A PR that edits `claude-review.yml` itself fails its own Claude-review check by design** (an anti-tamper guard on the caller workflow) — merge through that failure rather than trying to fix it; see PR #251's description.
- `.github/workflows/validate-caller-workflows.yml` runs on every PR and push to `main` (no path filter, so it's always a satisfiable required check). It calls `ai-review-prompts`' validator, which rejects shadow jobs next to the reusable `uses:` call and any mutable (non-SHA) ref in `uses:` or `ai-review-prompts-ref`.
- Dependency updates go through Renovate (`renovate.json`): weekly, Mondays before 9am ET; 14-day minimum release age, except a vulnerability-alert PR which has none (`minimumReleaseAge: "0 days"`); every dependency update — including patches, dev deps, and vulnerability alerts — is `automerge: false` (a deliberate supply-chain guard for an auth plugin, so a security PR still waits for a human); GitHub Action refs are pinned to digests.
- Pushing a change to a file under `.github/workflows/` needs a token with the `workflow` OAuth scope. A plain SSH push (keyed to your account, not an OAuth token) doesn't need that scope — prefer it for workflow-file changes so you don't have to carry a broader token.

## Harper compatibility

- `package.json`'s `peerDependencies.harper` is `>=5.0.0`.
- That floor moves only when a change needs a core primitive this version doesn't have. Example in flight: #212 (closing a session-update race) needs an `ifVersion` condition on `request.session.update()`, filed as `HarperFast/harper#2983`; landing that core change, and then raising the peer minimum to the first core release that contains it, is a precondition for shipping #212's fix.
- `lock()` is not an option for anything targeting the current peer range — it throws `Not yet implemented` as of Harper v5.0.0 (see the rejected alternatives in #212).

## Where design decisions live

Non-trivial issues carry their design and status directly in the issue body, updated in place as work lands — read the issue before re-deriving a decision it already made. Current examples: #231 (account-adoption hardening follow-ups, tracking which sub-items are shipped vs. still open), #244 (ChatGPT/CIMD `private_key_jwt` — the release-gate checklist lives here), #212 (session-update race, core dependency), #213 (stale `request.user` after a session is invalidated mid-request), #264 (deriving the ID-token issuer from presets/discovery instead of operator config).

`docs/mcp-oauth-conformance.md` maps every MCP OAuth requirement to the code and test that satisfies it. Update it in the same PR as any behavior change that adds, removes, or alters a requirement — see its own "Keeping this current" section.
