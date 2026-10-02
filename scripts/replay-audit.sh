#!/usr/bin/env bash
# replay-audit.sh — replay real traffic through a candidate binary before it
# becomes the deployed one (agentshield-oss #3995).
#
# Every shell command the deployed hook recorded in the audit log is evaluated
# again with the candidate binary via `agentshield check --fixture`, with the
# RECORDED decision as the expectation. A case that fails is a decision flip:
#
#   BLOCK -> AUDIT/ALLOW   the candidate lost a block the deployed binary made
#                          (a regression, or an FP fix — a human decides)
#   AUDIT/ALLOW -> BLOCK   the candidate blocks something real traffic did
#                          (a new false positive, or a closed gap — same)
#
# Why real traffic and not more fixtures: the fixture author and the fix author
# share a blind spot. The only regression this week's fixtures missed (#3998)
# was on a shape nobody would have written as a TN — prose quoting a TP — and
# the audit log held it twice. Real traffic is the corpus nobody authored.
#
# Advisory by design (only deny what you can justify): this script never stops
# a deploy. It prints the flips with the recorded and new rule ids and exits
# non-zero so a caller CAN gate on it. `make deploy` runs it and continues.
#
# Cost: ~75 ms per unique command on a built engine, sharded across --jobs
# processes — about a minute for a day of traffic on 8 cores. A cap (--max)
# bounds the worst case; every recorded BLOCK is always replayed because that
# side has the smallest denominator and the highest cost per miss.
#
# Exit codes (all advisory to `make deploy`):
#   0   replayed, no flips
#   10  replayed, flips found (printed)
#   2   nothing to replay in the window — a vacuous run, said out loud
#   3   the candidate reported failed packs (its own exit 3): results suspect
#   1   usage / missing tool / missing binary
#
# Usage:
#   scripts/replay-audit.sh [--binary PATH] [--log FILE]... [--hours N]
#                           [--max N] [--jobs K] [--keep DIR]
set -euo pipefail

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="$REPO_ROOT/build/agentshield"
LOGS=()
HOURS=24
MAX=2000
JOBS=""
KEEP=""

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --log)    LOGS+=("$2"); shift 2 ;;
    --hours)  HOURS="$2"; shift 2 ;;
    --max)    MAX="$2"; shift 2 ;;
    --jobs)   JOBS="$2"; shift 2 ;;
    --keep)   KEEP="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "replay-audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

for tool in jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "replay-audit: $tool is required" >&2; exit 1; }
done
[ -x "$BINARY" ] || { echo "replay-audit: candidate binary not executable: $BINARY" >&2; exit 1; }
case "$HOURS$MAX" in *[!0-9]*) echo "replay-audit: --hours and --max take integers" >&2; exit 1 ;; esac

if [ ${#LOGS[@]} -eq 0 ]; then
  for f in "$HOME/.agentshield/audit.jsonl.1" "$HOME/.agentshield/audit.jsonl"; do
    [ -f "$f" ] && LOGS+=("$f")
  done
fi
if [ ${#LOGS[@]} -eq 0 ]; then
  echo "replay-audit: no audit log found under ~/.agentshield — nothing to replay (vacuous)"
  exit 2
fi

if [ -z "$JOBS" ]; then
  JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
fi
case "$JOBS" in ''|*[!0-9]*|0) JOBS=4 ;; esac

# Portable "N hours ago" in the log's own UTC format.
if CUTOFF="$(date -u -v-"${HOURS}"H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; then :;
else CUTOFF="$(date -u -d "-${HOURS} hours" +%Y-%m-%dT%H:%M:%SZ)"; fi

WORK="${KEEP:-$(mktemp -d "${TMPDIR:-/tmp}/replay-audit.XXXXXX")}"
mkdir -p "$WORK"
[ -n "$KEEP" ] || trap 'rm -rf "$WORK"' EXIT

START=$(date +%s)

# 1. Select: shell hook events in the window, one entry per distinct command
#    text, the most recent decision winning. Sorted newest first so the cap
#    keeps the traffic closest to what the candidate will meet.
cat "${LOGS[@]}" 2>/dev/null \
  | jq -c --arg cutoff "$CUTOFF" '
      select(type == "object")
      | select((.source // "") | test("^(claude-code-hook|codex-hook)$"))
      | select((.timestamp // "") >= $cutoff)
      | select(((.command // "") | length) > 0)
      | select((.decision // "") | test("^(ALLOW|AUDIT|BLOCK)$"))
      | {command, decision, timestamp, rules: (.triggered_rules // [])}' \
  > "$WORK/events.jsonl" || true

EVENTS=$(wc -l < "$WORK/events.jsonl" | tr -d ' ')
if [ "$EVENTS" -eq 0 ]; then
  echo "replay-audit: 0 shell events in the last ${HOURS}h across ${#LOGS[@]} log(s) — nothing to replay (vacuous)"
  exit 2
fi

jq -s '
  group_by(.command) | map(max_by(.timestamp)) | sort_by(.timestamp) | reverse' \
  "$WORK/events.jsonl" > "$WORK/unique.json"
UNIQUE=$(jq 'length' "$WORK/unique.json")

# 2. Cap: every recorded BLOCK, plus the most recent --max of the rest.
jq --argjson max "$MAX" '
  (map(select(.decision == "BLOCK"))) + (map(select(.decision != "BLOCK")) | .[0:$max])
  | to_entries
  | map({name: ("c" + (.key|tostring)), shell: .value.command, expect: .value.decision,
         recorded_rules: .value.rules, ts: .value.timestamp})' \
  "$WORK/unique.json" > "$WORK/selected.json"
SELECTED=$(jq 'length' "$WORK/selected.json")
BLOCKS=$(jq '[.[] | select(.expect == "BLOCK")] | length' "$WORK/selected.json")

# 3. Shard round-robin and run the candidate on each shard in parallel. The
#    fixture is JSON, which the YAML fixture parser accepts; one case per
#    shard file, nothing else, so the report's names map back to selected.json.
if [ "$JOBS" -gt "$SELECTED" ]; then JOBS="$SELECTED"; fi
DEGRADED=0
i=0
while [ "$i" -lt "$JOBS" ]; do
  jq --argjson k "$JOBS" --argjson i "$i" \
    '{cases: [to_entries[] | select(.key % $k == $i) | .value | {name, shell, expect}]}' \
    "$WORK/selected.json" > "$WORK/shard_$i.json"
  # set +e inside: under the inherited errexit a non-zero candidate would
  # abort the subshell before its exit code is written, and a missing code
  # read as "fixture failures" — which is how a crashed shard passed as green.
  ( set +e; "$BINARY" check --fixture "$WORK/shard_$i.json" > "$WORK/shard_$i.out" 2> "$WORK/shard_$i.err"; echo $? > "$WORK/shard_$i.rc" ) &
  i=$((i+1))
done
wait

i=0
while [ "$i" -lt "$JOBS" ]; do
  rc=$(cat "$WORK/shard_$i.rc" 2>/dev/null || echo missing)
  if [ "$rc" = "3" ]; then DEGRADED=1; fi
  if [ "$rc" != "0" ] && [ "$rc" != "1" ] && [ "$rc" != "3" ]; then
    echo "replay-audit: shard $i exited $rc:" >&2; sed 's/^/    /' "$WORK/shard_$i.err" >&2 | head -20
    exit 1
  fi
  i=$((i+1))
done

# 4. Collect flips. Report lines look like:
#      <path>:<line>: FAIL c12 — expected BLOCK, got AUDIT
#              rules: a, b
cat "$WORK"/shard_*.out \
  | awk '
      /: FAIL c[0-9]+ / {
        if (name != "") print name "\t" expd "\t" got "\t" rules;
        match($0, /FAIL c[0-9]+/); name = substr($0, RSTART+5, RLENGTH-5);
        expd = ""; got = ""; rules = "";
        if (match($0, /expected [A-Z]+, got [A-Z]+/)) {
          s = substr($0, RSTART, RLENGTH); split(s, p, " "); expd = p[2]; sub(",", "", expd); got = p[4];
        } else { got = "ERROR"; }
        next
      }
      /^ +rules: / && name != "" { sub(/^ +rules: /, ""); rules = $0; next }
      { if (name != "") { print name "\t" expd "\t" got "\t" rules; name = "" } }
      END { if (name != "") print name "\t" expd "\t" got "\t" rules }' \
  > "$WORK/flips.tsv"

FLIPS=$(wc -l < "$WORK/flips.tsv" | tr -d ' ')
LOST=0; NEWBLOCK=0; OTHER=0

print_flip() {
  local name="$1" exp="$2" got="$3" newrules="$4"
  local rec snippet
  rec=$(jq -r --arg n "$name" '.[] | select(.name == $n) | (.recorded_rules | join(", "))' "$WORK/selected.json")
  snippet=$(jq -r --arg n "$name" '.[] | select(.name == $n) | .shell' "$WORK/selected.json" \
            | tr '\n' '\r' | sed 's/\r/ ⏎ /g' | cut -c1-160)
  printf '  %s -> %s\n' "$exp" "$got"
  printf '    recorded: %s\n' "${rec:-(no rule)}"
  printf '    now:      %s\n' "${newrules:-(no rule)}"
  printf '    %s\n' "$snippet"
}

if [ "$FLIPS" -gt 0 ]; then
  echo "replay-audit: BLOCK lost (deployed blocked, candidate does not):"
  while IFS=$'\t' read -r name exp got rules; do
    [ "$exp" = "BLOCK" ] && [ "$got" != "BLOCK" ] || continue
    LOST=$((LOST+1)); print_flip "$name" "$exp" "$got" "$rules"
  done < "$WORK/flips.tsv"
  [ "$LOST" -gt 0 ] || echo "  (none)"
  echo "replay-audit: new BLOCK (candidate blocks what real traffic ran):"
  while IFS=$'\t' read -r name exp got rules; do
    [ "$exp" != "BLOCK" ] && [ "$got" = "BLOCK" ] || continue
    NEWBLOCK=$((NEWBLOCK+1)); print_flip "$name" "$exp" "$got" "$rules"
  done < "$WORK/flips.tsv"
  [ "$NEWBLOCK" -gt 0 ] || echo "  (none)"
  OTHER=$((FLIPS - LOST - NEWBLOCK))
  if [ "$OTHER" -gt 0 ]; then
    echo "replay-audit: other flips (ALLOW <-> AUDIT, or evaluation errors):"
    while IFS=$'\t' read -r name exp got rules; do
      { [ "$exp" = "BLOCK" ] && [ "$got" != "BLOCK" ]; } && continue
      { [ "$exp" != "BLOCK" ] && [ "$got" = "BLOCK" ]; } && continue
      print_flip "$name" "$exp" "$got" "$rules"
    done < "$WORK/flips.tsv"
  fi
fi

ELAPSED=$(( $(date +%s) - START ))
echo "replay-audit: window ${HOURS}h · events ${EVENTS} · unique ${UNIQUE} · replayed ${SELECTED} (all ${BLOCKS} recorded BLOCKs + up to ${MAX} others) · jobs ${JOBS} · ${ELAPSED}s"
echo "replay-audit: flips ${FLIPS} (BLOCK lost ${LOST}, new BLOCK ${NEWBLOCK}, other ${OTHER}) · candidate $BINARY"

if [ "$DEGRADED" = "1" ]; then
  echo "replay-audit: ⚠️  the candidate reported failed packs (exit 3) — every result above is suspect"
  exit 3
fi
[ "$FLIPS" -eq 0 ] || exit 10
exit 0
