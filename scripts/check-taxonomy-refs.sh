#!/usr/bin/env bash
# check-taxonomy-refs.sh — Verify every taxonomy ref in Shield packs has a
# backing YAML file in the AI_risk_compliance taxonomy tree.
#
# Usage:
#   ./scripts/check-taxonomy-refs.sh <path-to-AI_risk_compliance/taxonomy>
#
# Exit 0: all refs resolve. Exit 1: one or more orphan refs (prints list).
#
# Why this exists: Shield packs reference taxonomy IDs as plain strings.
# The taxonomy YAML files live in the sibling AI_risk_compliance repo. When
# a Shield rule invents a new ID and its companion taxonomy entry never
# lands in compliance (separate repo, separate PRs, often separate agents),
# we get a latent orphan ref that no scanner catches. See comply#1366.

set -euo pipefail

TAXONOMY_DIR="${1:-}"
if [ -z "$TAXONOMY_DIR" ] || [ ! -d "$TAXONOMY_DIR" ]; then
  echo "usage: $0 <path-to-AI_risk_compliance/taxonomy>" >&2
  echo "       the path must exist and contain the taxonomy YAML tree." >&2
  exit 2
fi

# Collect every taxonomy: <id> ref in packs/, one per line, deduped.
# Handles both quoted and unquoted YAML forms:
#   taxonomy: kingdom/sub/thing
#   taxonomy: "kingdom/sub/thing"
#   taxonomy: 'kingdom/sub/thing'
# Ignores comment-only lines (^\s*#) and trailing inline comments.
refs=$(grep -rEh "^[[:space:]]*taxonomy:[[:space:]]" packs/ 2>/dev/null \
         | sed -E 's/^[[:space:]]*taxonomy:[[:space:]]*//' \
         | sed -E 's/[[:space:]]*#.*$//' \
         | sed -E 's/^"(.*)"$/\1/' \
         | sed -E "s/^'(.*)'\$/\1/" \
         | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' \
         | grep -v '^$' \
         | sort -u)

total=$(printf '%s\n' "$refs" | grep -c . || true)
missing=0
missing_list=""

while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  if [ ! -f "$TAXONOMY_DIR/$ref.yaml" ]; then
    missing_list+="  - $ref"$'\n'
    missing=$((missing + 1))
  fi
done <<< "$refs"

if [ "$missing" -gt 0 ]; then
  echo "FAIL: $missing of $total taxonomy ref(s) have no backing file in"
  echo "      $TAXONOMY_DIR/"
  echo ""
  echo "Orphan refs:"
  printf '%s' "$missing_list"
  echo ""
  echo "Fix: add the corresponding taxonomy YAML file(s) in the"
  echo "AI_risk_compliance repo and merge that PR FIRST, then re-run this check."
  exit 1
fi

echo "OK: all $total taxonomy ref(s) in packs/ resolve to files in $TAXONOMY_DIR/"
