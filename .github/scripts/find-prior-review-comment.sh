#!/usr/bin/env bash
# Find a prior marker'd top-level review comment on a PR (if any) and
# write its integer database ID to $GITHUB_OUTPUT under key `id`.
# Empty when no prior exists.
#
# Provider-agnostic: callers pass the MARKER they want to find. Each
# reviewer workflow uses its own sentinel — `<!-- claude-review:v1 -->`
# for `_claude-review.yml`, `<!-- gemini-review:v1 -->` for
# `_gemini-review.yml`, etc. The marker is what discriminates the
# review comment from anything else on the PR; we don't filter by
# author identity. Marker collision risk (a manually-posted comment
# starting with the sentinel) is vanishingly small and self-healing
# (next review run edits it; nothing lost).
#
# Inputs:
#   MARKER               — required. Comment-body prefix to match,
#                          e.g. `<!-- claude-review:v1 -->`.
#   GH_TOKEN             — token with `pull-requests: read`
#   GITHUB_REPOSITORY    — owner/repo (auto-set by GitHub Actions)
#   PR_NUMBER            — pull request number
#   GITHUB_OUTPUT        — output file path
set -uo pipefail

if [ -z "${MARKER:-}" ]; then
  echo "::error::MARKER env var is required (e.g. '<!-- claude-review:v1 -->')."
  exit 1
fi

EXISTING_ID=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
  | jq -r --arg marker "$MARKER" \
    '[.[] | select(.body | startswith($marker))] | last | .id // empty')

if [ -n "$EXISTING_ID" ]; then
  echo "Prior review comment ($MARKER): $EXISTING_ID"
else
  echo "No prior review comment ($MARKER) found — agent will post fresh."
fi
echo "id=${EXISTING_ID}" >> "$GITHUB_OUTPUT"
