#!/usr/bin/env bash
# Decide whether the trigger (PR author, comment author, labeler) is
# authorized to spawn a Claude workflow on this repo. Driven by the
# `authorize` job in claude-review.yml / claude-mention.yml /
# claude-issue-to-pr.yml.
#
# Trust set: every `@HarperFast/<team>` handle in this repo's
# `.github/CODEOWNERS`. Same set as the people we trust to review code,
# aligned by construction. Falls back to `@HarperFast/developers` if
# CODEOWNERS is missing, empty, unparseable, or contains no HarperFast
# handles. External-org handles in CODEOWNERS are deliberately ignored
# — only HarperFast members are admitted.
#
# Inputs:
#   USERS_TO_CHECK     — newline-separated logins; ALL must pass.
#                        Empty / whitespace-only entries are skipped.
#   ADMIT_CLAUDE_BOT   — "true" admits `claude[bot]` without a team
#                        check (used by claude-review for AI-authored
#                        PRs from the issue-to-PR pipeline). Anything
#                        else requires team membership for every user.
#   DEFAULT_TOKEN      — token for the CODEOWNERS read (typically
#                        $GITHUB_TOKEN; needs `contents: read`).
#   ORG_TOKEN          — token for `orgs/.../teams/.../memberships/...`
#                        (App-installation token with `Members: Read`,
#                        scoped to this `authorize` job only).
#   GITHUB_REPOSITORY  — owner/repo (auto-set by GitHub Actions).
#   GITHUB_OUTPUT      — output file path.
#
# Outputs (to $GITHUB_OUTPUT):
#   authorized=true|false
set -uo pipefail

# Resolve the trust set from CODEOWNERS. The default token reads the
# workflow repo's own .github/CODEOWNERS via the contents API.
# Anything missing / empty / unparseable / containing no HarperFast
# handles falls back to the default team.
CODEOWNERS=$(GH_TOKEN="$DEFAULT_TOKEN" gh api \
  "repos/${GITHUB_REPOSITORY}/contents/.github/CODEOWNERS" \
  --jq '.content' 2>/dev/null | base64 -d 2>/dev/null || true)
TEAMS=$(printf '%s' "$CODEOWNERS" | grep -oE '@HarperFast/[a-zA-Z0-9_-]+' | sort -u | sed 's|@HarperFast/||' || true)

if [ -z "$TEAMS" ]; then
  echo "::notice::No @HarperFast/<team> handles found in .github/CODEOWNERS (missing, empty, or only external orgs). Defaulting to developers."
  TEAMS="developers"
fi

# Fail closed if USERS_TO_CHECK is empty or whitespace-only. The
# main loop below skips empty entries with `[ -z "$user" ] && continue`
# and would otherwise fall through to `authorized=true` if there was
# nothing to check. An authorize job that forgot to set USERS_TO_CHECK
# (or a malicious change that removed it) must NOT silently admit
# every event — refuse here.
if [ -z "${USERS_TO_CHECK//[[:space:]]/}" ]; then
  echo "::error::USERS_TO_CHECK is empty or whitespace-only — denying by default. The authorize job must explicitly pass at least one login (PR author, commenter, labeler, etc.)."
  echo "authorized=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

echo "Trust set (HarperFast teams from CODEOWNERS):"
for t in $TEAMS; do echo "  - @HarperFast/$t"; done

# is_authorized <login>
# Admits claude[bot] iff ADMIT_CLAUDE_BOT=true; otherwise tries each
# team in the trust set in order. Returns 0 on the first hit.
is_authorized() {
  local user="$1"

  if [ "${ADMIT_CLAUDE_BOT:-false}" = "true" ] && [ "$user" = "claude[bot]" ]; then
    echo "  → admitted: claude[bot]"
    return 0
  fi

  for team in $TEAMS; do
    # /orgs/{org}/teams/{team_slug}/memberships/{username}
    # returns 200 for active members, 404 otherwise.
    if GH_TOKEN="$ORG_TOKEN" gh api "orgs/HarperFast/teams/${team}/memberships/${user}" --silent >/dev/null 2>&1; then
      echo "  → admitted via @HarperFast/${team} membership"
      return 0
    fi
  done

  echo "  → not a member of any HarperFast team in the trust set"
  return 1
}

while IFS= read -r raw_user; do
  user="$(printf '%s' "$raw_user" | awk '{$1=$1;print}')"
  [ -z "$user" ] && continue
  echo "Checking: $user"
  if ! is_authorized "$user"; then
    echo "User '$user' not authorized. Skipping the gated job."
    echo "authorized=false" >> "$GITHUB_OUTPUT"
    exit 0
  fi
done <<< "${USERS_TO_CHECK:-}"

echo "authorized=true" >> "$GITHUB_OUTPUT"
