#!/usr/bin/env bash
# Compose the layered review scope from individual layer files into a
# single markdown blob, and emit it as the `composed` output via
# $GITHUB_OUTPUT. Driven by claude-review.yml's "Compose review scope
# from layers" step.
#
# Inputs:
#   LAYERS         — newline-separated layer names (e.g. "universal\nharper/v5")
#   LAYERS_DIR     — directory layer files live in (default: .github/review-layers).
#                    Originally hardcoded to .ai-review-prompts/ in the reusable-workflow
#                    version of this script — parameterized here so the inlined oauth
#                    calibration setup can point at local .github/review-layers/.
#   GITHUB_OUTPUT  — path to the GitHub Actions output file
#
# Missing layers emit a workflow warning and continue; an empty
# composed result fails the step (no review scope = no review
# discipline).
set -euo pipefail

OUT=/tmp/composed-scope.md
: > "$OUT"
while IFS= read -r raw_layer; do
  # Trim whitespace around each layer name.
  layer="$(printf '%s' "$raw_layer" | awk '{$1=$1;print}')"
  [ -z "$layer" ] && continue
  file="${LAYERS_DIR:-.github/review-layers}/${layer}.md"
  if [ ! -f "$file" ]; then
    echo "::warning::Review layer '$layer' not found at $file; skipping."
    continue
  fi
  {
    cat "$file"
    printf '\n\n'
  } >> "$OUT"
done <<< "${LAYERS:-}"

BYTES=$(wc -c < "$OUT")
echo "Composed ${BYTES} bytes from review layers"
if [ "$BYTES" -eq 0 ]; then
  echo "::error::Composed review scope is empty — all layers missing or unreadable."
  exit 1
fi

# Random heredoc delimiter — collision-proof against any content a
# future layer file might include. $GITHUB_OUTPUT uses heredoc
# syntax; a fixed marker could be forged (or coincidentally appear)
# in layer content and corrupt the output.
DELIM="EOF_$(openssl rand -hex 16)"
{
  echo "composed<<${DELIM}"
  cat "$OUT"
  echo "${DELIM}"
} >> "$GITHUB_OUTPUT"
