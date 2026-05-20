#!/usr/bin/env bash
# Log this run's PR review to the central HarperFast/ai-review-log
# tracker — finds the per-PR issue by stable title prefix and
# appends a comment, or creates a new issue if none exists. Driven
# by the "Log review to ai-review-log" step in _claude-review.yml
# and _gemini-review.yml.
#
# Provider-agnostic: callers pass MARKER (sentinel that discriminates
# the review comment), MODEL (for the body header), and optionally
# PROVIDER_LABEL (selects the per-provider title format and label —
# empty preserves the legacy Claude-only format, non-empty creates
# one issue per (PR, provider) so each reviewer's verdict and cost
# stays unambiguous) and NOTES_FILE_BASENAME (the agent's run-notes
# filename under $RUNNER_TEMP).
#
# When PROVIDER_LABEL is set:
#   * Title shape: `[<repo>] PR #<N> (<provider>): <count>`. Disjoint
#     prefix from the legacy `[<repo>] PR #<N>:` shape — lookups
#     scope cleanly to each provider's own issues.
#   * `provider:<label>` is added to the issue's labels on creation,
#     making sweep queries like
#     `label:repo:harper label:provider:gemini label:verdict:noise`
#     trivial.
#   * Body header includes a **Peers:** field linking to a GitHub
#     issue search that finds every provider's issue for the same
#     PR — cross-reference without needing run-time lookups.
#
# When PROVIDER_LABEL is empty (default — Claude's caller):
#   * Title shape stays `[<repo>] PR #<N>: <count>` (unchanged from
#     pre-Gemini history; no migration of existing issues).
#   * No `provider:` label, no **Peers:** field.
#
# Best-effort: never fails the job. A missing AI_REVIEW_LOG_TOKEN
# secret, an absent marker'd review comment, or a stale comment
# all exit cleanly with a notice/warning rather than failing.
#
# Inputs:
#   MARKER                — required. Comment-body prefix to match
#                           (e.g. `<!-- claude-review:v1 -->`).
#   MODEL                 — required. Model id for the body header
#                           (e.g. "claude-sonnet-4-6", "gemini-2.5-pro").
#   PROVIDER_LABEL        — optional. When non-empty, prefixed to
#                           the title's count part (e.g. "gemini").
#                           Empty preserves the legacy Claude title
#                           format.
#   NOTES_FILE_BASENAME   — optional. Run-notes filename under
#                           $RUNNER_TEMP. Defaults to
#                           "claude-review-notes.md".
#   GH_TOKEN              — token with `pull-requests: read`
#   AI_REVIEW_LOG_TOKEN   — fine-grained PAT scoped to
#                           ai-review-log with `issues: write`
#                           (optional — missing skips logging
#                           with a warning)
#   PR_NUMBER             — pull request number
#   PR_URL                — html URL of the PR
#   REVIEW_STATUS         — outcome of the review step
#                           (success / failure / cancelled / etc.)
#   REPO_SHORT            — short repo name (e.g. "harper")
#   GITHUB_REPOSITORY     — owner/repo of the PR's repo
#   GITHUB_RUN_ID         — current Actions run ID (for staleness
#                           guard)
#   RUNNER_TEMP           — runner temp dir (where the agent's
#                           optional run-notes file lives)
set -uo pipefail

if [ -z "${MARKER:-}" ]; then
  echo "::error::MARKER env var is required (e.g. '<!-- claude-review:v1 -->')."
  exit 1
fi
if [ -z "${MODEL:-}" ]; then
  echo "::error::MODEL env var is required (e.g. 'claude-sonnet-4-6')."
  exit 1
fi

PROVIDER_LABEL="${PROVIDER_LABEL:-}"
NOTES_FILE_BASENAME="${NOTES_FILE_BASENAME:-claude-review-notes.md}"

if [ -z "${AI_REVIEW_LOG_TOKEN:-}" ]; then
  echo "::warning::AI_REVIEW_LOG_TOKEN secret not set; skipping log entry."
  exit 0
fi

# When this workflow job started. Used to filter out stale review
# comments from previous runs so a cancelled in-flight run (e.g.
# from a force-push) doesn't re-log a prior run's content as a
# fresh finding.
JOB_STARTED=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}" --jq '.run_started_at // empty')

# Fetch the marker'd review comment via raw API. We can't use
# `gh pr view --json comments` because (a) it doesn't expose
# `updated_at` (which we need below for the staleness guard now
# that comments are edited in place), and (b) we need the marker
# filter — author-only filtering would catch unrelated comments
# from the same identity (e.g. @claude mention responses on the
# Claude side, or any github-actions[bot] comment on the Gemini
# side).
REVIEW_JSON=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
  | jq --arg marker "$MARKER" \
    '[.[] | select(.body | startswith($marker))] | last // empty')

if [ -z "$REVIEW_JSON" ] || [ "$REVIEW_JSON" = "null" ]; then
  echo "No marker'd review comment ($MARKER) found on PR #$PR_NUMBER (review_status=$REVIEW_STATUS); skipping log."
  exit 0
fi

REVIEW_BODY=$(printf '%s' "$REVIEW_JSON" | jq -r '.body // empty')
# Prefer updated_at (reflects the most recent edit) over created_at
# (frozen at original post time) — comments are now edited in place
# across runs.
REVIEW_AT=$(printf '%s' "$REVIEW_JSON" | jq -r '.updated_at // .created_at // empty')

if [ -z "$REVIEW_BODY" ]; then
  echo "Review comment had empty body; skipping log."
  exit 0
fi

# ISO-8601 lexicographic compare — both are UTC timestamps in the
# same shape, so string comparison is sound.
if [ -n "$JOB_STARTED" ] && [ -n "$REVIEW_AT" ] && [ "$REVIEW_AT" \< "$JOB_STARTED" ]; then
  echo "::notice::Latest review comment update ($REVIEW_AT) predates this job's start ($JOB_STARTED); skipping to avoid re-logging stale content."
  exit 0
fi

# Title: count findings (lines starting with `### <digit>`).
# Zero findings always titles as "no blockers" regardless of the
# prose phrasing — relying on a sentence-grep against the prompt's
# `Reviewed; no blockers found.` example caused early issues (88,
# 89, 104) to fall through to "0 finding(s) — triage pending" when
# the bot used a slight phrasing variation. Counting the section
# headers is deterministic.
FINDING_COUNT=$(printf '%s\n' "$REVIEW_BODY" | grep -c '^### [0-9]' || true)
if [ "$FINDING_COUNT" = "0" ]; then
  COUNT_PART="no blockers"
else
  COUNT_PART="${FINDING_COUNT} finding(s) — triage pending"
fi

# Title prefix and shape branch on PROVIDER_LABEL. Empty
# (legacy Claude) keeps the original format; non-empty inserts
# `(<provider>)` before the colon, giving each provider its own
# disjoint title-prefix namespace so lookups don't cross-match.
if [ -n "$PROVIDER_LABEL" ]; then
  TITLE_PREFIX="[$REPO_SHORT] PR #$PR_NUMBER ($PROVIDER_LABEL):"
else
  TITLE_PREFIX="[$REPO_SHORT] PR #$PR_NUMBER:"
fi

if [ "$REVIEW_STATUS" = "success" ]; then
  TITLE="$TITLE_PREFIX $COUNT_PART"
else
  TITLE="$TITLE_PREFIX $COUNT_PART (review $REVIEW_STATUS — may be incomplete)"
fi

# Run URL — one click to the action run page where usage / cost
# data is shown (token counts, estimated $). Useful for both
# providers; included unconditionally.
RUN_URL="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

# Peers link — only included when PROVIDER_LABEL is set, since
# legacy Claude-only flows don't have peer issues to point at.
# This URL is a GitHub issue-search prefiltered to the same
# `[<repo>] PR #<N>` token, so each provider's issue can link
# back to the search that finds all of them.
if [ -n "$PROVIDER_LABEL" ]; then
  PEERS_QUERY=$(printf '%s' "[$REPO_SHORT] PR #$PR_NUMBER" | jq -sRr @uri)
  PEERS_URL="https://github.com/HarperFast/ai-review-log/issues?q=is%3Aissue+${PEERS_QUERY}"
  BODY=$(printf '**Source:** %s\n**Repo:** %s\n**PR:** #%s\n**Provider:** %s\n**Model:** %s\n**Run:** %s\n**Peers:** %s\n**Phase:** baseline\n**Review job status:** %s\n**Date:** %s\n\n---\n\n%s\n' \
    "$PR_URL" "$REPO_SHORT" "$PR_NUMBER" "$PROVIDER_LABEL" "$MODEL" "$RUN_URL" "$PEERS_URL" "$REVIEW_STATUS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REVIEW_BODY")
else
  BODY=$(printf '**Source:** %s\n**Repo:** %s\n**PR:** #%s\n**Model:** %s\n**Run:** %s\n**Phase:** baseline\n**Review job status:** %s\n**Date:** %s\n\n---\n\n%s\n' \
    "$PR_URL" "$REPO_SHORT" "$PR_NUMBER" "$MODEL" "$RUN_URL" "$REVIEW_STATUS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REVIEW_BODY")
fi

# Structured run notes from the agent (optional). This is the
# channel that keeps verbose context off the PR — the agent writes
# to a fixed path under $RUNNER_TEMP, and we append here so the log
# issue gets the full picture while the PR comment stays concise.
# Absent file is fine; means the run had nothing structured to
# capture.
NOTES_FILE="${RUNNER_TEMP:-/tmp}/${NOTES_FILE_BASENAME}"
if [ -f "$NOTES_FILE" ]; then
  NOTES_CONTENT=$(cat "$NOTES_FILE")
  BODY=$(printf '%s\n\n---\n\n%s\n' "$BODY" "$NOTES_CONTENT")
  echo "Appended $(wc -c < "$NOTES_FILE") bytes of run notes from $NOTES_FILE"
else
  echo "No run notes file at $NOTES_FILE — skipping notes append"
fi

# One ai-review-log issue per (PR, provider). The TITLE_PREFIX
# constructed above is provider-scoped when PROVIDER_LABEL is set
# — each provider's lookup hits only its own issues. List API
# (not search) is used because search is eventually-consistent —
# a same-day second review run might fire before the first issue
# is indexed.
EXISTING_NUMBER=$(curl -sS \
  -H "Authorization: Bearer $AI_REVIEW_LOG_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/HarperFast/ai-review-log/issues?labels=repo:$REPO_SHORT&state=all&per_page=100&sort=created&direction=desc" \
  | jq -r --arg prefix "$TITLE_PREFIX" \
    '[.[] | select(.title | startswith($prefix))] | first | .number // empty')

if [ -n "$EXISTING_NUMBER" ] && [ "$EXISTING_NUMBER" != "null" ]; then
  # Existing issue: append a comment, refresh the title to reflect
  # this run's status. Title refresh is best-effort — we still
  # report success on the comment alone.
  COMMENT_PAYLOAD=$(jq -nc --arg body "$BODY" '{body: $body}')
  HTTP_C=$(curl -sS -o /tmp/ai-log-comment-resp.json -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $AI_REVIEW_LOG_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/HarperFast/ai-review-log/issues/$EXISTING_NUMBER/comments" \
    -d "$COMMENT_PAYLOAD")

  PATCH_PAYLOAD=$(jq -nc --arg title "$TITLE" '{title: $title}')
  HTTP_T=$(curl -sS -o /tmp/ai-log-patch-resp.json -w '%{http_code}' -X PATCH \
    -H "Authorization: Bearer $AI_REVIEW_LOG_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/HarperFast/ai-review-log/issues/$EXISTING_NUMBER" \
    -d "$PATCH_PAYLOAD")

  if [ "$HTTP_C" -ge 200 ] && [ "$HTTP_C" -lt 300 ]; then
    COMMENT_URL=$(jq -r '.html_url' /tmp/ai-log-comment-resp.json)
    echo "Logged review as comment on existing issue: $COMMENT_URL"
  else
    echo "::warning::ai-review-log comment POST failed (HTTP $HTTP_C):"
    cat /tmp/ai-log-comment-resp.json
  fi

  if [ "$HTTP_T" -lt 200 ] || [ "$HTTP_T" -ge 300 ]; then
    echo "::warning::ai-review-log title PATCH failed (HTTP $HTTP_T):"
    cat /tmp/ai-log-patch-resp.json
  fi
else
  # No existing issue for this (PR, provider) — create one.
  # `provider:<label>` is added alongside the existing labels when
  # PROVIDER_LABEL is set; this is what makes sweep queries like
  # `label:provider:gemini label:verdict:noise` work.
  if [ -n "$PROVIDER_LABEL" ]; then
    CREATE_PAYLOAD=$(jq -nc \
      --arg title "$TITLE" \
      --arg repo_label "repo:$REPO_SHORT" \
      --arg provider_label "provider:$PROVIDER_LABEL" \
      --arg body "$BODY" \
      '{title: $title, body: $body, labels: [$repo_label, $provider_label, "verdict:pending", "phase:baseline"]}')
  else
    CREATE_PAYLOAD=$(jq -nc \
      --arg title "$TITLE" \
      --arg repo_label "repo:$REPO_SHORT" \
      --arg body "$BODY" \
      '{title: $title, body: $body, labels: [$repo_label, "verdict:pending", "phase:baseline"]}')
  fi

  HTTP=$(curl -sS -o /tmp/ai-log-resp.json -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $AI_REVIEW_LOG_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/HarperFast/ai-review-log/issues \
    -d "$CREATE_PAYLOAD")

  if [ "$HTTP" -ge 200 ] && [ "$HTTP" -lt 300 ]; then
    ISSUE_URL=$(jq -r '.html_url' /tmp/ai-log-resp.json)
    echo "Logged review to new issue: $ISSUE_URL"
  else
    echo "::warning::ai-review-log POST failed (HTTP $HTTP):"
    cat /tmp/ai-log-resp.json
  fi
fi
