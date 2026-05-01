#!/usr/bin/env bash
# Find the prior `claude-review:v1`-marker'd top-level review comment
# on a PR (if any) and write its integer database ID to
# $GITHUB_OUTPUT under key `id`. Empty when no prior exists.
#
# Why marker-based lookup: `--edit-last` filters by authenticated
# identity (`claude[bot]`) only — so after a `@claude` mention, the
# most recent claude[bot] comment is the mention response, and
# `--edit-last` clobbers it. Every review comment starts with
# `<!-- claude-review:v1 -->`; mention responses never carry the
# marker, so this lookup targets only the review comment.
#
# Inputs:
#   GH_TOKEN             — token with `pull-requests: read`
#   GITHUB_REPOSITORY    — owner/repo (auto-set by GitHub Actions)
#   PR_NUMBER            — pull request number
#   GITHUB_OUTPUT        — output file path
set -uo pipefail

EXISTING_ID=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
  --jq '[.[] | select(.user.login == "claude[bot]") | select(.body | startswith("<!-- claude-review:v1 -->"))] | last | .id // empty')

if [ -n "$EXISTING_ID" ]; then
  echo "Prior review comment: $EXISTING_ID"
else
  echo "No prior review comment found — agent will post fresh."
fi
echo "id=${EXISTING_ID}" >> "$GITHUB_OUTPUT"
