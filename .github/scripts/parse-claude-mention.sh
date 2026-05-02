#!/usr/bin/env bash
# Decide whether to proceed with an `@claude` mention and which model
# to use, based on the comment body. Driven by claude-mention.yml's
# "Parse mention" step.
#
# Rules (the precision gate; the job-level `if:` is a cheap
# pre-filter that only checks substring containment):
#   1. `@claude` must be the FIRST non-whitespace token (word-
#      boundary after) — rules out `@claudette`, inline prose
#      mentions ("saw @claude's fix"), and quoted replies
#      (`> @claude ...`) where the reply is addressing a human.
#   2. Case-insensitive word-boundary `deep` anywhere in the body
#      escalates to Opus. Sonnet is the default.
#
# Inputs:
#   BODY           — comment body (verbatim)
#   GITHUB_OUTPUT  — output file path
#
# Outputs (to $GITHUB_OUTPUT):
#   proceed=true|false
#   model=claude-opus-4-7|claude-sonnet-4-6  (only when proceed=true)
set -uo pipefail

if ! printf '%s' "$BODY" | grep -Pqz '\A\s*@claude\b'; then
  echo "Comment does not start with @claude; skipping."
  echo "proceed=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

if printf '%s' "$BODY" | grep -Piq '\bdeep\b'; then
  echo "model=claude-opus-4-7" >> "$GITHUB_OUTPUT"
  echo "Selected claude-opus-4-7 (deep requested)"
else
  echo "model=claude-sonnet-4-6" >> "$GITHUB_OUTPUT"
  echo "Selected claude-sonnet-4-6 (default)"
fi
echo "proceed=true" >> "$GITHUB_OUTPUT"
