# review-scopes (layered prompts for the AI review workflow)

Layered prompt content consumed by `.github/workflows/claude-review.yml`. Composed into a single prompt block at workflow runtime, most-general first, most-specific last.

## Provenance

Copied from `HarperFast/ai-review-log/review-scopes/` at merge SHA `ef8d99458c27094a6fac97f373ebddee2abc5376` (PR #19). The expectation is that these layer files will eventually live in a single shared location (either the original `ai-review-log` repo once it goes public, or a dedicated `HarperFast/ai-review-prompts` repo) — but for now each consumer repo keeps its own copy so we can evaluate the layered-scope approach across 2–3 repos without committing to a shared-repo architecture prematurely. When syncing from an upstream copy is needed, diff against the source and bring over any reviewer-discipline improvements.

## Layout

```
review-scopes/
  universal.md           # architecture, security, dispatch, public-API
                         # discipline — applies to EVERY PR
  harper/
    common.md            # gotchas that cross Harper versions
    v5.md                # v5-specific (harper package, Resource API v2,
                         # static vs instance dispatch, Fabric deployment)
  repo-type/
    plugin.md            # oauth, future npm-published plugins
```

## How the workflow consumes these

`.github/workflows/claude-review.yml` declares which layers apply via the `REVIEW_LAYERS` env var, then composes the prompt at runtime:

```yaml
env:
  REVIEW_LAYERS: |
    universal
    harper/common
    harper/v5
    repo-type/plugin
```

Each named layer resolves to `.github/review-scopes/<name>.md`. The "Compose review scope from layers" step concatenates them (with blank-line separators) and exposes the result as a step output that's interpolated into the `prompt:` input of `anthropics/claude-code-action`.

## Writing / editing layers

Each layer file is a markdown document that reads as review guidance. Each bullet should be something a reviewer can check on a PR — specific, not generic. Keep layers tight (aim for ~1–2 KB each). Claude reads all included layers before working through the diff; bigger = slower + more token-expensive.
