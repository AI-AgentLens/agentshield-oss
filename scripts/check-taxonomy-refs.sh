#!/usr/bin/env bash
# check-taxonomy-refs.sh — Verify every taxonomy ref Shield references — both
# in packs/ YAML and directly from Go source — has a backing YAML file in the
# AI_risk_compliance taxonomy tree, and optionally report which of those refs
# are not yet in the PUBLISHED taxonomy artifact.
#
# Usage:
#   ./scripts/check-taxonomy-refs.sh <path-to-AI_risk_compliance/taxonomy>
#   ./scripts/check-taxonomy-refs.sh <path-to-taxonomy> <path-to-taxonomy-compliance.json>
#
# Three checks, deliberately different severities:
#
#   tier 1     packs/ ref has no taxonomy/<ref>.yaml -> FAIL (exit 1). A real orphan.
#   go-source  same question, for TaxonomyRef: "..." literals in internal/ and
#              cmd/ Go source (analyzer findings, MCP handler audit events) —
#              a surface invisible to a packs/-only scan (#3508). Ratcheted
#              against scripts/go-ref-baseline.txt: a NEW orphan not in the
#              baseline FAILS; a baselined ref that now resolves ALSO FAILS,
#              so the baseline can only shrink. Refs built by string
#              concatenation (`"prefix/" + variable`) cannot be resolved
#              statically and are excluded by pattern, not by name.
#   tier 2     resolves in taxonomy/ but is absent
#              from the published artifact          -> REPORT only. Exit stays 0.
#
# Exit codes:
#   0  every ref resolves (or is baselined). Tier-2 findings, if any, are
#      reported not enforced.
#   1  a tier-1 orphan ref, a NEW or FIXED go-source baseline entry, OR the
#      check cannot vouch for anything: zero refs extracted from packs/, zero
#      TaxonomyRef literals extracted from Go source, zero entry ids extracted
#      from the artifact, or the extracted entry count disagrees with the
#      artifact's own counts.entries.
#   2  usage error: the taxonomy dir or the artifact path does not exist.
#
# Why tier 1 exists: Shield packs reference taxonomy IDs as plain strings.
# The taxonomy YAML files live in the sibling AI_risk_compliance repo. When
# a Shield rule invents a new ID and its companion taxonomy entry never
# lands in compliance (separate repo, separate PRs, often separate agents),
# we get a latent orphan ref that no scanner catches. See comply#1366.
#
# ── Why tier 2 exists, and why it is NOT fatal (#3429) ──────────────────────
#
# WHAT IT IS FOR: two gates answer "does this ref resolve?" against two
# different sources of truth. This script's tier 1 resolves against the
# taxonomy/ YAML tree on AI_risk_compliance:main — green the moment a node is
# merged. The SaaS test TestEveryShippedRuleTaxonomyResolves resolves against
# the *published artifact* — red until that node is published. Premium pack
# delivery stalls in that gap, silently, in a repo nobody watches; it cost five
# consecutive nights over 2026-08-15..19 (aiagentlens#135). Tier 2 makes the gap
# visible at the point where someone is already looking at CI.
#
# WHAT IT IS *NOT* FOR: blocking a merge. Measured over 28 days the gap was
# non-zero on 14 of 22 measurable days, including one 11-day stretch, and it is
# unbounded during a pending MAJOR bump — precisely the window the outage
# happens in. A fatal tier 2 would therefore block Shield rule merges most days.
# Gary decided on 2026-08-19 that it reports and does not enforce. Do not
# promote it to fatal without re-deciding that trade with him.
#
# WHAT IT DOES NOT KNOW — state this honestly rather than glossing it: CI reads
# the artifact from AI_risk_compliance:main, i.e. what is *published*. The SaaS
# resolves against its own *pinned* copy of that artifact, which may lag main.
# So a clean tier 2 means "this will be deliverable once the SaaS pin catches
# up", not "this is deliverable right now". Main is the right reference point —
# the 4:15 AM nightly delivery chain syncs the pin from main — but the check
# must not claim more than it knows.
#
# WHAT BREAKS IF TIER 2 IS REMOVED: nothing fails; the publication lag simply
# goes back to being invisible until the SaaS build turns red days later.
#
# ── Dependencies ───────────────────────────────────────────────────────────
# The artifact is read with grep/sed only. jq and python3 are NOT installed on
# the self-hosted runner (no workflow in this repo uses either), and a
# `command -v jq || exit 0` guard would turn the whole tier into the vacuous
# always-green check it exists to prevent. Extraction is self-validating
# instead: the number of ids we pull out must equal the artifact's own
# counts.entries, so a renamed field or a restructured schema fails loudly
# rather than reporting "0 awaiting publication" while vouching for nothing.

set -euo pipefail

TAXONOMY_DIR="${1:-}"
ARTIFACT="${2:-}"

usage() {
  echo "usage: $0 <path-to-AI_risk_compliance/taxonomy> [path-to-taxonomy-compliance.json]" >&2
  echo "       the taxonomy path must exist and contain the taxonomy YAML tree." >&2
  echo "       the optional artifact path enables the non-fatal tier-2" >&2
  echo "       'awaiting publication' report." >&2
}

if [ -z "$TAXONOMY_DIR" ] || [ ! -d "$TAXONOMY_DIR" ]; then
  usage
  exit 2
fi

# ── Tier-2 input validation (runs first: a broken check must be loud) ───────
published_ids=""
published_count=0
artifact_version=""
if [ -n "$ARTIFACT" ]; then
  if [ ! -f "$ARTIFACT" ]; then
    echo "FAIL: artifact path '$ARTIFACT' is not a readable file." >&2
    usage
    exit 2
  fi

  # Entry ids are the only ids in the artifact that contain a '/' (taxonomy
  # paths are kingdom/category/node; standard ids and control ids are flat —
  # "eu-ai-act-2024", "Art.15", "AML.T0011"). Verified against artifact v5.0.0:
  # 963 slash-bearing ids, 963 entries, zero slash-bearing non-entry ids.
  published_ids=$(grep -oE '"id"[[:space:]]*:[[:space:]]*"[^"]*/[^"]*"' "$ARTIFACT" 2>/dev/null \
                    | sed -E 's/^"id"[[:space:]]*:[[:space:]]*"//; s/"$//' \
                    | sort -u) || true
  published_count=$(printf '%s\n' "$published_ids" | grep -c . || true)

  # The artifact states its own entry count. Comparing against it is what makes
  # this extraction falsifiable — see the Dependencies note above.
  declared=$(grep -oE '"entries"[[:space:]]*:[[:space:]]*[0-9]+' "$ARTIFACT" 2>/dev/null \
               | head -1 | grep -oE '[0-9]+$' || true)
  artifact_version=$(grep -oE '"artifact_version"[[:space:]]*:[[:space:]]*"[^"]*"' "$ARTIFACT" 2>/dev/null \
                       | head -1 | sed -E 's/^.*"([^"]*)"$/\1/' || true)
  [ -n "$artifact_version" ] || artifact_version="unknown"

  if [ "$published_count" -eq 0 ]; then
    echo "FAIL: extracted 0 published taxonomy entry ids from" >&2
    echo "      $ARTIFACT" >&2
    echo "      Expected hundreds. The file is empty, truncated, not the" >&2
    echo "      taxonomy-compliance artifact, or its schema changed — the" >&2
    echo "      tier-2 publication check cannot vouch for anything in this" >&2
    echo "      state, and reporting '0 awaiting publication' would be a lie." >&2
    exit 1
  fi
  if [ -z "$declared" ]; then
    echo "FAIL: could not read counts.entries from" >&2
    echo "      $ARTIFACT" >&2
    echo "      Without the artifact's own count there is nothing to validate" >&2
    echo "      the extracted $published_count id(s) against. Refusing to" >&2
    echo "      report against an unverified denominator." >&2
    exit 1
  fi
  if [ "$published_count" -ne "$declared" ]; then
    echo "FAIL: extracted $published_count entry id(s) from the artifact but it" >&2
    echo "      declares counts.entries=$declared." >&2
    echo "      $ARTIFACT" >&2
    echo "      The extraction and the schema have diverged. Fix the extraction" >&2
    echo "      in $0 before trusting any tier-2 result." >&2
    exit 1
  fi
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
         | sort -u) || true

total=$(printf '%s\n' "$refs" | grep -c . || true)

# Collecting zero refs means packs/ moved, the YAML key was renamed, or the
# caller is in the wrong directory — never that the packs are clean. Without
# this branch `set -o pipefail` still aborted the run (grep exits 1 on no
# match), but silently: exit 1 with no output, which reads as a flaky CI step
# rather than a broken check. A gate has to fail legibly to be actionable.
if [ "$total" -eq 0 ]; then
  echo "FAIL: found no 'taxonomy:' refs under packs/ at all." >&2
  echo "      Expected hundreds. Either this was run outside the repo root," >&2
  echo "      packs/ has moved, or the YAML key was renamed — the check cannot" >&2
  echo "      vouch for anything in this state." >&2
  echo "      cwd: $(pwd)" >&2
  exit 1
fi
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

# ── Go-source taxonomy refs (tier 1, extended — #3508) ──────────────────────
#
# The scan above covers packs/, which is where a Shield rule cites a taxonomy
# id as a plain YAML string. But Shield also EMITS TaxonomyRef directly from Go
# source — analyzer findings, MCP handler audit events — and that surface is
# structurally invisible to a packs/-only grep. #3508: three internal/mcp
# call sites cited a node that did not exist for two days before anyone
# noticed, because nothing checked this half of the class.
#
# Same ratchet contract as scripts/oss-known-failures.txt via
# scripts/go-ref-baseline.txt: a NEW orphan (not in the baseline) fails; a
# baselined ref that now resolves also fails, forcing the line's removal so
# the baseline can only shrink, never grow silently.
#
# Refs built by string concatenation (TaxonomyRef: "prefix/" + variable)
# cannot be resolved from static text — a customer-defined suffix does not
# exist until runtime. These are detected by PATTERN (a literal immediately
# followed by '+') and excluded from resolution, not excluded by name, so a
# new concatenated ref is silently skipped rather than either false-failing
# the build or masking a real orphan under the same name.
# Relative to cwd, matching the packs/ scan below and every other tier in
# this script — CI always runs from the repo root. NOT relative to this
# script's own location ($0), which would resolve to Shield's real baseline
# even when a test harness runs this exact file against a fake fixture repo.
GO_REF_BASELINE="scripts/go-ref-baseline.txt"

go_ref_lines=$(grep -rhoE 'TaxonomyRef:[[:space:]]*"[^"]*"([[:space:]]*\+)?' --include='*.go' internal/ cmd/ 2>/dev/null) || true
go_line_count=$(printf '%s\n' "$go_ref_lines" | grep -c . || true)

# Same vacuity reasoning as the packs/ guard above: zero matches means the
# field was renamed or this ran from the wrong directory, never that the
# source tree is clean.
if [ "$go_line_count" -eq 0 ]; then
  echo "FAIL: found no 'TaxonomyRef:' literal(s) under internal/ or cmd/ at all." >&2
  echo "      Expected hundreds. Either this ran outside the repo root, the" >&2
  echo "      field was renamed, or internal/ / cmd/ moved — the check cannot" >&2
  echo "      vouch for anything in this state." >&2
  exit 1
fi

go_refs=""
go_concat=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  ref=$(printf '%s' "$line" | sed -E 's/^TaxonomyRef:[[:space:]]*"([^"]*)".*/\1/')
  if printf '%s' "$line" | grep -qE '\+[[:space:]]*$'; then
    go_concat+="$ref"$'\n'
  else
    go_refs+="$ref"$'\n'
  fi
done <<< "$go_ref_lines"

go_refs=$( (printf '%s\n' "$go_refs" | grep -v '^$' | sort -u) || true)
go_concat=$( (printf '%s\n' "$go_concat" | grep -v '^$' | sort -u) || true)
go_total=$(printf '%s\n' "$go_refs" | grep -c . || true)
go_concat_count=$(printf '%s\n' "$go_concat" | grep -c . || true)

baseline_refs=""
if [ -f "$GO_REF_BASELINE" ]; then
  baseline_refs=$( (grep -vE '^[[:space:]]*(#|$)' "$GO_REF_BASELINE" | sed -E 's/[[:space:]]+$//' | sort -u) || true)
fi
baseline_count=$(printf '%s\n' "$baseline_refs" | grep -c . || true)

go_new=""
go_orphan_count=0
while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  if [ ! -f "$TAXONOMY_DIR/$ref.yaml" ]; then
    go_orphan_count=$((go_orphan_count + 1))
    if ! printf '%s\n' "$baseline_refs" | grep -qxF "$ref"; then
      go_new+="  - $ref"$'\n'
    fi
  fi
done <<< "$go_refs"

# FIXED: a baselined ref that resolves now must be removed from the baseline,
# same ratchet-down discipline as scripts/check-oss-baseline.sh.
go_fixed=""
while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  if [ -f "$TAXONOMY_DIR/$ref.yaml" ]; then
    go_fixed+="  - $ref"$'\n'
  fi
done <<< "$baseline_refs"

go_new_count=$(printf '%s' "$go_new" | grep -c . || true)
go_fixed_count=$(printf '%s' "$go_fixed" | grep -c . || true)

echo "Go-source tier 1: $go_total ref(s) checked ($go_concat_count concatenation-built, excluded), $go_orphan_count orphan(s), $baseline_count baselined"

if [ "$go_new_count" -gt 0 ] || [ "$go_fixed_count" -gt 0 ]; then
  if [ "$go_new_count" -gt 0 ]; then
    echo ""
    echo "FAIL: $go_new_count NEW Go-source taxonomy ref(s) do not resolve and are"
    echo "      not in $GO_REF_BASELINE:"
    printf '%s' "$go_new"
    echo ""
    echo "Fix: add the taxonomy YAML in AI_risk_compliance and merge that PR"
    echo "FIRST, or if this is an intentionally synthetic/test-only literal,"
    echo "add it to $GO_REF_BASELINE with a comment explaining why."
  fi
  if [ "$go_fixed_count" -gt 0 ]; then
    echo ""
    echo "FAIL: $go_fixed_count baselined ref(s) now resolve and must be removed"
    echo "      from $GO_REF_BASELINE (the baseline only ever shrinks):"
    printf '%s' "$go_fixed"
  fi
  exit 1
fi

echo "OK: all $go_total Go-source taxonomy ref(s) resolve or are baselined."

# ── Tier 2: resolved, but not yet published (non-fatal) ─────────────────────
[ -n "$ARTIFACT" ] || exit 0

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
printf '%s\n' "$refs" | grep -v '^$' | sort -u > "$TMP/refs"
printf '%s\n' "$published_ids" | grep -v '^$' | sort -u > "$TMP/published"
awaiting=$(comm -23 "$TMP/refs" "$TMP/published") || true
awaiting_count=$(printf '%s\n' "$awaiting" | grep -c . || true)

echo "tier 2: $total refs checked against $published_count published entries (artifact v$artifact_version) — $awaiting_count awaiting publication"

if [ "$awaiting_count" -gt 0 ]; then
  echo ""
  echo "Awaiting publication (resolve in taxonomy/ but are NOT in the published"
  echo "artifact — premium pack delivery to the SaaS stalls on these):"
  printf '%s\n' "$awaiting" | sed 's/^/  - /'
  echo ""
  echo "Non-fatal by design (#3429). Publication is automatic overnight for a"
  echo "MINOR/PATCH artifact bump; a MAJOR bump waits for a human decision."
fi

# Surface the same report in the run summary so the publication lag is visible
# without opening the job log — the invisibility is the whole failure mode.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Taxonomy refs — tier 2 (publication lag)"
    echo ""
    echo "\`$total\` refs checked against \`$published_count\` published entries (artifact \`v$artifact_version\`)."
    echo ""
    if [ "$awaiting_count" -eq 0 ]; then
      echo "**0 awaiting publication.**"
    else
      echo "**$awaiting_count awaiting publication** — these resolve in \`taxonomy/\` but are not in the published artifact, so premium pack delivery to the SaaS stalls on them:"
      echo ""
      printf '%s\n' "$awaiting" | sed 's/^/- `/; s/$/`/'
      echo ""
      echo "Non-fatal by design (#3429)."
    fi
    echo ""
    echo "_Read against \`AI_risk_compliance:main\`, i.e. what is published. The SaaS resolves against its own pinned copy, which may lag main — so a clean result means \"deliverable once the pin catches up\", not \"deliverable right now\"._"
  } >> "$GITHUB_STEP_SUMMARY"
fi

exit 0
