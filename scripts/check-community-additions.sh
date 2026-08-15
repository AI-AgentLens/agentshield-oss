#!/usr/bin/env bash
# check-community-additions.sh — CI gate for the community/premium boundary (#2294).
#
# Community packs are curated for the OSS release; all new rules go to
# packs/premium/ (see baby-kai-shield.md). This gate fails a PR that adds a
# net-new "- id:" rule under packs/community/. A deliberate community addition
# must carry the `approved-community` label (Gary applies it) — the workflow
# checks the label and only runs this script when it is absent.
#
# Robust to reordering and to moving a rule OUT of community: it compares the
# SET of community rule ids at the base ref vs HEAD and reports only ids that
# are present in HEAD but not in the base.
#
# Usage: scripts/check-community-additions.sh [BASE_REF]   (default: origin/main)
# Exit:  0 = no net-new community ids; 1 = net-new id(s) found; 2 = usage/git error.
set -uo pipefail

BASE_REF="${1:-origin/main}"

# Resolve pathspecs from the repo root regardless of caller cwd.
TOPLEVEL="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "error: not inside a git repository" >&2; exit 2
}
cd "$TOPLEVEL" || exit 2

if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  echo "error: base ref '$BASE_REF' not found (CI: checkout with fetch-depth: 0)" >&2
  exit 2
fi

# Collect the sorted, unique set of "- id:" values under packs/community/ at a ref.
collect_community_ids() {
  local ref="$1"
  git ls-tree -r --name-only "$ref" -- packs/community 2>/dev/null \
    | grep -E '\.ya?ml$' \
    | while IFS= read -r f; do git show "$ref:$f" 2>/dev/null; done \
    | grep -E '^[[:space:]]*-[[:space:]]+id:' \
    | sed -E 's/^[[:space:]]*-[[:space:]]+id:[[:space:]]*//; s/^["'\'']//; s/["'\'']$//' \
    | grep -v '^[[:space:]]*$' \
    | sort -u
}

before="$(collect_community_ids "$BASE_REF")"
after="$(collect_community_ids HEAD)"

new_ids="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | grep -v '^[[:space:]]*$' || true)"

if [ -n "$new_ids" ]; then
  echo "::error::Net-new rule id(s) added under packs/community/ without the 'approved-community' label:"
  printf '  - %s\n' $new_ids
  echo ""
  echo "Community packs are curated for the OSS release. New rules go to packs/premium/."
  echo "If this community addition is intentional, add the 'approved-community' label to the PR (Gary's call)."
  exit 1
fi

echo "OK: no net-new rule ids under packs/community/ (base: $BASE_REF)."
exit 0
