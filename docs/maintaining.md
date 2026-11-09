# Maintaining `@harperfast/oauth`

For a Harper maintainer shipping releases, triaging CI, or picking up an open design decision.

## Releasing

Merging to `main` releases. Every push to `main` runs `.github/workflows/release.yml`: the real-Harper integration tests, lint, format check and unit tests, then [semantic-release](https://semantic-release.gitbook.io/semantic-release/) (`.releaserc.json`), then npm.

- **The version comes from the commit messages** since the last `v*` tag ([Conventional Commits](https://www.conventionalcommits.org/)): `fix:` or `perf:` is a patch, `feat:` a minor, and a `!` after the type (`feat!:`) or a `BREAKING CHANGE:` footer a major. `docs:`, `test:`, `chore:`, `ci:`, `refactor:` and `style:` alone release nothing. Renovate's commits follow suit: `fix(deps):` (runtime) releases a patch, `chore(deps):` (dev) nothing.
- **On a release**, semantic-release commits the version to `package.json` and `package-lock.json` (`chore(release): X.Y.Z [skip ci]`), tags `vX.Y.Z`, and publishes a GitHub Release whose notes are generated from the commits. The workflow then publishes to npm with provenance through trusted publishing (OIDC; configured at npmjs.com for this repo, `release.yml`, `Release` environment, so keep that file name and environment).
- **Commit messages are checked on every PR** (`verify-commits.yml`, `commitlint.config.cjs`). A squash merge uses the PR title as the commit message, so title PRs the same way.
- **Upgrade notes** belong in a `BREAKING CHANGE:` footer, which is the text the release notes carry. Releases up to 2.10.0 shipped some contract-tightening changes as minors with an upgrade note in `CHANGELOG.md`; that file now ends at 2.11.0, so decide per change whether it is breaking and mark it so.
- **A failed publish** (npm down, say) leaves the tag and GitHub Release in place. Re-run the Release workflow on `main` (`workflow_dispatch`): it publishes whenever `package.json`'s version isn't on npm yet.

## Recurring checks

- **Re-run the ChatGPT capture from #244.** Interactive `private_key_jwt` stays opt-in because ChatGPT signs its client assertions with the token-endpoint URL as `aud` (forbidden by RFC 7523bis), not the issuer. The release gate for flipping the default on is ChatGPT switching to the issuer `aud` — there's no vendor changelog to watch, so capture a real code exchange now and then (and before flipping the default) and check the signed `aud`. On deployments that already opted in, a successful `private_key_jwt` verification logs the accepted `aud` form at info level; a rejected token-endpoint-`aud` assertion logs a separate warning (rate-limited per client) that names the token-endpoint form explicitly rather than the issuer (`src/lib/mcp/token.ts`).
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
