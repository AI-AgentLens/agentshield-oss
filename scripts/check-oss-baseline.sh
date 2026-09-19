#!/usr/bin/env bash
# check-oss-baseline.sh — ratchet for the OSS-stripped distribution suite (#3130, #3136).
#
# `make test-install-oss` builds the tree we actually publish (premium stripped)
# and runs internal/policy + internal/analyzer against it. Since #3130 made that
# gate able to fail, it is RED: the corpus expects BLOCK on ~914 cases whose only
# covering rule lives in packs/premium/, so the community-only rule set cannot
# pass them. That is a product question — how much of the corpus the free tier
# should detect — tracked in #3136, not a bug to fix by relabelling.
#
# A permanently-red job gets muted, which is exactly how the fake-green gate in
# #3130 survived for months. So this script converts "permanently red" into
# "red only when it gets worse": it diffs the failure set against a recorded
# baseline and reports only the delta.
#
#   NEW   — failing now, not in the baseline. OSS coverage regressed, or a new
#           corpus case landed that only a premium rule covers. Actionable.
#   FIXED — in the baseline, passing now. The ratchet: the entry must come out,
#           so the baseline can only ever shrink.
#
# ── 2026-09-14: the ratchet was measured, and it did not hold ───────────────
#
# The design above assumed drift would be rare ("~27% red rate", per the measured
# note in oss-distribution.yml). Over the 12 scheduled runs to 2026-09-13 it was
# red on NINE — 75%. The three greens each came right after a human hand-edited
# the baseline. The cause is structural, not neglect: the squad adds corpus cases
# nightly, a steady fraction of which only a premium rule covers, so the baseline
# goes stale faster than anyone maintains it. A ratchet that requires a manual
# commit at the squad's merge rate is a ratchet that is always red, and an
# always-red job is a muted job — the exact failure #3130 is a monument to.
#
# So --refresh makes the baseline self-maintaining: the delta is still computed
# and still reported, then ABSORBED into the file, which the job commits. The
# record of what the free tier stopped (or started) detecting moves out of red
# CI runs nobody opens and into `git log -p scripts/oss-known-failures.txt`,
# where each night's diff is exactly that measurement.
#
# What stays fatal is the thing that actually means something: exit 2, the suite
# did not run to completion. Coverage drift in the free tier is a product fact we
# record; a suite that proved nothing is a broken check we must not paper over.
#
# The trade, stated plainly: a genuine community regression is now auto-absorbed
# rather than flagged. That is deliberate and Gary's call (2026-09-14) — the OSS
# tier is allowed to lag as long as the lag is visible, and the git diff makes it
# visible in a way nine consecutive ignored reds did not.
#
# Usage:  scripts/check-oss-baseline.sh [--refresh] <go-test-log> [baseline-file]
# Exit:   0 = no delta (or --refresh absorbed it)   1 = NEW and/or FIXED entries
#         2 = usage/unusable log
#
# Entry format (one per line in the baseline; # comments and blanks ignored):
#   case:<subtest path>   a corpus case, deduped across its parent sweeps
#   test:<TestName>       a top-level test with no failing subtests
#
# Both kinds are recorded on purpose. Tracking only `case:` would mean a
# regression in a whole-corpus fitness function (TestCompoundWrappingParity and
# friends emit no per-case subtests) produced an empty delta and a green job —
# the same "gate that cannot fail" shape this script exists to prevent.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

REFRESH=0
if [ "${1:-}" = "--refresh" ]; then
  REFRESH=1
  shift
fi

LOG="${1:-}"
BASELINE="${2:-$SCRIPT_DIR/oss-known-failures.txt}"

if [ -z "$LOG" ]; then
  echo "usage: $0 <go-test-log> [baseline-file]" >&2
  exit 2
fi
if [ ! -r "$LOG" ]; then
  echo "error: cannot read test log '$LOG'" >&2
  exit 2
fi
if [ ! -r "$BASELINE" ]; then
  echo "error: cannot read baseline '$BASELINE'" >&2
  exit 2
fi

# ── Anti-vacuity guard ───────────────────────────────────────────────────────
# The failure mode this whole file is a reaction to is a gate reporting success
# over a suite that never ran. An empty failure set is indistinguishable from a
# container that died during `brew install go` unless we insist on seeing the
# package result line Go prints for the package we care about.
if ! grep -qE '^(ok|FAIL|---)[[:space:]]+github\.com/AI-AgentLens/agentshield/internal/analyzer' "$LOG"; then
  echo "error: '$LOG' contains no go-test result line for internal/analyzer." >&2
  echo "       The OSS suite did not run to completion; refusing to report a delta" >&2
  echo "       over output that proves nothing (see #3130)." >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── Extract the observed failure set ─────────────────────────────────────────
# Go prints "--- FAIL: Parent/Sub (0.00s)" indented under "--- FAIL: Parent".
# A case that fails under both TestAccuracy_AllKingdoms and
# TestPipeline_AllKingdoms is ONE case, so subtests are keyed on the path below
# the parent and deduped. A parent with failing subtests is not recorded
# separately — it is implied, and recording it would double-count every case.
grep -oE '^[[:space:]]*--- FAIL: [^[:space:]]+' "$LOG" \
  | sed -E 's/^[[:space:]]*--- FAIL: //' \
  | sort -u > "$WORK/raw.txt"

: > "$WORK/observed.txt"
while IFS= read -r name; do
  [ -z "$name" ] && continue
  case "$name" in
    */*)
      # Subtest: key on the path below the top-level test.
      echo "case:${name#*/}" >> "$WORK/observed.txt"
      ;;
    *)
      # Top-level test. Record it only if nothing failed *under* it, so the
      # corpus sweeps do not appear alongside their own 914 cases.
      if ! grep -qE "^${name}/" "$WORK/raw.txt"; then
        echo "test:${name}" >> "$WORK/observed.txt"
      fi
      ;;
  esac
done < "$WORK/raw.txt"
sort -u "$WORK/observed.txt" -o "$WORK/observed.txt"

# ── Load the baseline ────────────────────────────────────────────────────────
sed -E 's/[[:space:]]*#.*$//' "$BASELINE" \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
  | grep -v '^$' \
  | sort -u > "$WORK/baseline.txt"

comm -13 "$WORK/baseline.txt" "$WORK/observed.txt" > "$WORK/new.txt"
comm -23 "$WORK/baseline.txt" "$WORK/observed.txt" > "$WORK/fixed.txt"

n_obs=$(grep -c . "$WORK/observed.txt")
n_base=$(grep -c . "$WORK/baseline.txt")
n_new=$(grep -c . "$WORK/new.txt")
n_fixed=$(grep -c . "$WORK/fixed.txt")

emit() { # write to stdout and, in Actions, to the job summary
  echo "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$1" >> "$GITHUB_STEP_SUMMARY"; fi
}

emit "## OSS distribution suite"
emit ""
emit "| | count |"
emit "|---|---|"
emit "| observed failures | $n_obs |"
emit "| baselined (known, #3136) | $n_base |"
emit "| **NEW (regression)** | **$n_new** |"
emit "| **FIXED (ratchet down)** | **$n_fixed** |"
emit ""

if [ "$n_new" -eq 0 ] && [ "$n_fixed" -eq 0 ]; then
  emit "No delta — the OSS build is exactly as covered as \`scripts/oss-known-failures.txt\` records."
  exit 0
fi

if [ "$n_new" -gt 0 ]; then
  emit "### NEW — failing in the OSS build, not baselined"
  emit ""
  emit "Either a community rule regressed, or a new corpus case landed that only a"
  emit "premium rule covers. If it is the latter, add the line to"
  emit "\`scripts/oss-known-failures.txt\` — that file is the running measurement of"
  emit "what the free tier does not detect (#3136)."
  emit ""
  while IFS= read -r l; do [ -n "$l" ] && emit "- \`$l\`"; done < "$WORK/new.txt"
  emit ""
fi

if [ "$n_fixed" -gt 0 ]; then
  emit "### FIXED — baselined but passing now"
  emit ""
  emit "Remove these from \`scripts/oss-known-failures.txt\`. The baseline only shrinks;"
  emit "leaving a stale entry lets a later regression hide behind it."
  emit ""
  while IFS= read -r l; do [ -n "$l" ] && emit "- \`$l\`"; done < "$WORK/fixed.txt"
  emit ""
fi

# ── --refresh: absorb the delta into the baseline ────────────────────────────
# A MERGE, never a rewrite. Six entries carry hand-written `# tier-split`
# rationale and one explanatory comment block sits among the entries; those are
# the most valuable lines in the file, and regenerating it from the observed set
# would silently delete every one of them. So: walk the existing file, keep each
# line verbatim when its entry still fails (annotation and all), drop entries
# that now pass (the ratchet still only shrinks), and append genuinely new ones
# under a dated header so the file records WHEN the free tier lost each case.
if [ "$REFRESH" -eq 1 ]; then
  {
    awk -v obsfile="$WORK/observed.txt" '
      BEGIN { while ((getline l < obsfile) > 0) if (l != "") keep[l] = 1 }
      {
        key = $0
        sub(/[[:space:]]*#.*$/, "", key)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
        if (key == "") { print; next }        # comment or blank — preserve verbatim
        if (key in keep) print                # still failing — keep the line AND its note
      }                                       # otherwise: passes now, ratchet it out
    ' "$BASELINE"

    if [ "$n_new" -gt 0 ]; then
      echo ""
      echo "# --- $(date -u +%Y-%m-%d): $n_new entr$([ "$n_new" -eq 1 ] && echo y || echo ies) added by check-oss-baseline.sh --refresh ---"
      cat "$WORK/new.txt"
    fi
  } > "$WORK/refreshed.txt"

  # Refuse to install a baseline that lost the entries we meant to keep. Writing
  # a truncated file here would silently erase the measurement this whole script
  # exists to maintain, and the next run would report it all as FIXED.
  n_written=$(sed -E 's/[[:space:]]*#.*$//' "$WORK/refreshed.txt" | grep -cE '^[[:space:]]*[^[:space:]]')
  if [ "$n_written" -ne "$n_obs" ]; then
    echo "error: refreshed baseline has $n_written entries, expected $n_obs — refusing to write" >&2
    exit 2
  fi

  mv "$WORK/refreshed.txt" "$BASELINE"
  emit "Baseline refreshed: **+$n_new / -$n_fixed**, now $n_written entries. The diff on"
  emit "\`scripts/oss-known-failures.txt\` is the record of what changed."
  exit 0
fi

exit 1
