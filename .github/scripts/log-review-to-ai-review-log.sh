#!/usr/bin/env bash
# Log this run's PR review to the central HarperFast/ai-review-log
# tracker — finds the per-PR issue by stable title prefix and
# appends a comment, or creates a new issue if none exists. Driven
# by claude-review.yml's "Log review to ai-review-log" step.
#
# Best-effort: never fails the job. A missing `AI_REVIEW_LOG_TOKEN`
# secret, an absent claude review comment, or a stale comment all
# exit cleanly with a notice/warning rather than failing.
#
# Inputs:
#   GH_TOKEN              — token with `pull-requests: read`
#   AI_REVIEW_LOG_TOKEN   — fine-grained PAT scoped to ai-review-log
#                           with `issues: write` (optional — missing
#                           skips logging with a warning)
#   PR_NUMBER             — pull request number
#   PR_URL                — html URL of the PR
#   REVIEW_STATUS         — outcome of the Claude review step
#                           (success / failure / cancelled / etc.)
#   REPO_SHORT            — short repo name (e.g. "harper")
#   GITHUB_REPOSITORY     — owner/repo of the PR's repo
#   GITHUB_RUN_ID         — current Actions run ID (for staleness
#                           guard)
#   RUNNER_TEMP           — runner temp dir (where the agent's
#                           optional run-notes file lives)
set -uo pipefail

if [ -z "${AI_REVIEW_LOG_TOKEN:-}" ]; then
  echo "::warning::AI_REVIEW_LOG_TOKEN secret not set; skipping log entry."
  exit 0
fi

# When this workflow job started. Used to filter out stale Claude
# review comments from previous runs so a cancelled in-flight run
# (e.g. from a force-push) doesn't re-log a prior run's content as
# a fresh finding.
JOB_STARTED=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}" --jq '.run_started_at // empty')

# Fetch the marker'd review comment via raw API. We can't use
# `gh pr view --json comments` because (a) it doesn't expose
# `updated_at` (which we need below for the staleness guard now
# that comments are edited in place), and (b) we need the marker
# filter to ignore `@claude` mention responses that share the
# `claude[bot]` identity.
CLAUDE_JSON=$(gh api "repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
  --jq '[.[] | select(.user.login == "claude[bot]") | select(.body | startswith("<!-- claude-review:v1 -->"))] | last // empty')

if [ -z "$CLAUDE_JSON" ] || [ "$CLAUDE_JSON" = "null" ]; then
  echo "No marker'd Claude review comment found on PR #$PR_NUMBER (review_status=$REVIEW_STATUS); skipping log."
  exit 0
fi

CLAUDE_BODY=$(printf '%s' "$CLAUDE_JSON" | jq -r '.body // empty')
# Prefer updated_at (reflects the most recent edit) over created_at
# (frozen at original post time) — comments are now edited in place
# across runs.
CLAUDE_AT=$(printf '%s' "$CLAUDE_JSON" | jq -r '.updated_at // .created_at // empty')

if [ -z "$CLAUDE_BODY" ]; then
  echo "Claude review comment had empty body; skipping log."
  exit 0
fi

# ISO-8601 lexicographic compare — both are UTC timestamps in the
# same shape, so string comparison is sound.
if [ -n "$JOB_STARTED" ] && [ -n "$CLAUDE_AT" ] && [ "$CLAUDE_AT" \< "$JOB_STARTED" ]; then
  echo "::notice::Latest Claude review comment update ($CLAUDE_AT) predates this job's start ($JOB_STARTED); skipping to avoid re-logging stale content."
  exit 0
fi

# Title: count findings (lines starting with `### <digit>`). The
# "no blockers" branch matches the sentinel phrase anywhere in the
# body — the concise prompt's `Reviewed; no blockers found.` doesn't
# start with "no blockers", so an anchored regex would miss it.
# Anywhere-match is safe because the phrase is a deliberate output
# from the prompt.
if printf '%s' "$CLAUDE_BODY" | grep -qi 'no blockers found'; then
  COUNT_PART="no blockers"
else
  FINDING_COUNT=$(printf '%s\n' "$CLAUDE_BODY" | grep -c '^### [0-9]' || true)
  COUNT_PART="${FINDING_COUNT} finding(s) — triage pending"
fi

if [ "$REVIEW_STATUS" = "success" ]; then
  TITLE="[$REPO_SHORT] PR #$PR_NUMBER: $COUNT_PART"
else
  TITLE="[$REPO_SHORT] PR #$PR_NUMBER: $COUNT_PART (review $REVIEW_STATUS — may be incomplete)"
fi

BODY=$(printf '**Source:** %s\n**Repo:** %s\n**PR:** #%s\n**Model:** claude-sonnet-4-6\n**Phase:** baseline\n**Review job status:** %s\n**Date:** %s\n\n---\n\n%s\n' \
  "$PR_URL" "$REPO_SHORT" "$PR_NUMBER" "$REVIEW_STATUS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CLAUDE_BODY")

# Structured run notes from the agent (optional). This is the
# channel that keeps verbose context off the PR — the agent writes
# to a fixed path under $RUNNER_TEMP, and we append here so the log
# issue gets the full picture while the PR comment stays concise.
# Absent file is fine; means the run had nothing structured to
# capture.
NOTES_FILE="${RUNNER_TEMP:-/tmp}/claude-review-notes.md"
if [ -f "$NOTES_FILE" ]; then
  NOTES_CONTENT=$(cat "$NOTES_FILE")
  BODY=$(printf '%s\n\n---\n\n%s\n' "$BODY" "$NOTES_CONTENT")
  echo "Appended $(wc -c < "$NOTES_FILE") bytes of run notes from $NOTES_FILE"
else
  echo "No run notes file at $NOTES_FILE — skipping notes append"
fi

# One ai-review-log issue per PR. Stable prefix `[<repo>] PR #<N>:`
# lets us look up an existing issue for this PR across runs even
# though the count/status portion past the colon changes per run.
# List API (not search) is used because search is eventually-
# consistent — a same-day second review run might fire before the
# first issue is indexed.
TITLE_PREFIX="[$REPO_SHORT] PR #$PR_NUMBER:"

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
  # No existing issue for this PR — create one.
  CREATE_PAYLOAD=$(jq -nc \
    --arg title "$TITLE" \
    --arg repo_label "repo:$REPO_SHORT" \
    --arg body "$BODY" \
    '{title: $title, body: $body, labels: [$repo_label, "verdict:pending", "phase:baseline"]}')

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
