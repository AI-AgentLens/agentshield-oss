#!/usr/bin/env bash
# route-replay.sh — replay real tool calls through two agentshield binaries
# and report every difference (ADR-001 step 1, #4245).
#
# A routing change must not change what any real call decides. This script
# takes the distinct tool calls the hook recorded in the audit log (shell
# commands and MCP-path tool calls from Claude Code, Codex and Copilot CLI),
# rebuilds the Claude-shaped PreToolUse payload of each, and runs
# `<binary> hook < payload` for a BASE binary (main) and a CANDIDATE binary.
# A flip is any difference in exit code (2 = BLOCK), stdout, stderr, or the
# audit event (decision, rules, taxonomy, source, command, tool name, notes).
# The candidate's routing_gap notes are counted, not flipped: adding them is
# what ADR-001 step 1 does. Each flip carries both sides' decision (the last
# event's, "none" when there is none), and the summary counts decision changes
# by direction, up or down on ALLOW < AUDIT < REQUIRE_APPROVAL < BLOCK, and
# flips by tool: a row that gains a lane (ADR-001 D4) must flip only its own
# tool's calls, and only up.
#
# Safety: every run happens in a throwaway HOME per binary. Only policy,
# config and packs are copied from the config dir (an allowlist:
# policy.yaml, agentshield.yaml, managed.json, mcp-policy.yaml, packs/,
# mcp-packs/). credentials.json is never copied, so nothing reaches the SaaS,
# and the real audit log is only ever read. The environment is cleared
# (env -i) apart from PATH, TMPDIR, USER and LOGNAME, so an AGENTSHIELD_*
# variable of the caller cannot leak in.
#
# What a rebuilt payload cannot reproduce: the tool name of a shell event
# (the log records the command, not the tool; all are replayed as "Bash"),
# a string tool_input (apply_patch is replayed as the object the log
# recorded), and the harness's live cwd (the recorded cwd is sent; one that
# no longer exists is evaluated as the hook does, with a note). Both binaries
# get the same payload, so none of this can cause or hide a flip.
#
# Controls: --base and --candidate may name the same binary (a negative
# control: must report 0 flips), and a deliberately mis-routed candidate is
# the positive control (must report flips).
#
# Exit codes:
#   0   replayed, no flips
#   10  replayed, flips found (listed, details in <work>/flips.jsonl)
#   2   nothing to replay in the window (vacuous)
#   1   usage / missing tool / missing binary
#
# Usage:
#   scripts/route-replay.sh --base BIN --candidate BIN [--days N] [--log FILE]...
#                           [--config-dir DIR] [--jobs K] [--max N] [--keep DIR]
set -euo pipefail

usage() { sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; }

BASE=""
CAND=""
DAYS=7
LOGS=()
CONFIG_DIR="$HOME/.agentshield"
JOBS=""
MAX=0
KEEP=""

while [ $# -gt 0 ]; do
  case "$1" in
    --base)       BASE="$2"; shift 2 ;;
    --candidate)  CAND="$2"; shift 2 ;;
    --days)       DAYS="$2"; shift 2 ;;
    --log)        LOGS+=("$2"); shift 2 ;;
    --config-dir) CONFIG_DIR="$2"; shift 2 ;;
    --jobs)       JOBS="$2"; shift 2 ;;
    --max)        MAX="$2"; shift 2 ;;
    --keep)       KEEP="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "route-replay: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "route-replay: jq is required" >&2; exit 1; }
for b in "$BASE" "$CAND"; do
  [ -n "$b" ] && [ -x "$b" ] || { echo "route-replay: --base and --candidate must name executables (got '$b')" >&2; exit 1; }
done
case "$DAYS$MAX" in *[!0-9]*) echo "route-replay: --days and --max take integers" >&2; exit 1 ;; esac
BASE="$(cd "$(dirname "$BASE")" && pwd)/$(basename "$BASE")"
CAND="$(cd "$(dirname "$CAND")" && pwd)/$(basename "$CAND")"

if [ ${#LOGS[@]} -eq 0 ]; then
  for f in "$CONFIG_DIR/audit.jsonl.1" "$CONFIG_DIR/audit.jsonl"; do
    [ -f "$f" ] && LOGS+=("$f")
  done
fi
if [ ${#LOGS[@]} -eq 0 ]; then
  echo "route-replay: no audit log found — nothing to replay (vacuous)"
  exit 2
fi

if [ -z "$JOBS" ]; then
  JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
fi
case "$JOBS" in ''|*[!0-9]*|0) JOBS=4 ;; esac

if CUTOFF="$(date -u -v-"${DAYS}"d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"; then :;
else CUTOFF="$(date -u -d "-${DAYS} days" +%Y-%m-%dT%H:%M:%SZ)"; fi

WORK="${KEEP:-$(mktemp -d "${TMPDIR:-/tmp}/route-replay.XXXXXX")}"
mkdir -p "$WORK"
[ -n "$KEEP" ] || trap 'rm -rf "$WORK"' EXIT

# 1. Select: one entry per distinct call in the window. A shell event is
#    keyed by agent and command, a tool event by agent, tool and arguments.
cat "${LOGS[@]}" 2>/dev/null | jq -c --arg cutoff "$CUTOFF" '
  select(type == "object")
  | select((.timestamp // "") >= $cutoff)
  | (.source // "") as $src
  | select($src | test("^(claude-code|codex|copilot-cli)(-mcp)?-hook$"))
  | ($src | sub("(-mcp)?-hook$"; "")) as $agent
  | if ((.command // "") | length) > 0 and ($src | test("-mcp-hook$") | not) then
      {kind: "shell", agent: $agent, cwd: (.cwd // ""), ts: .timestamp, tool: "Bash", input: {command: .command}}
    elif ((.tool_name // "") | length) > 0 and ($src | test("-mcp-hook$")) then
      {kind: "tool", agent: $agent, cwd: (.cwd // ""), ts: .timestamp, tool: .tool_name, input: (.arguments // {})}
    else empty end' > "$WORK/events.jsonl" || true

jq -s --argjson max "$MAX" '
  group_by([.kind, .agent, .tool, .input]) | map(max_by(.ts)) | sort_by(.ts) | reverse
  | if $max > 0 then .[:$max] else . end
  | to_entries
  | map(.value + {id: .key})' "$WORK/events.jsonl" > "$WORK/calls.json"

TOTAL=$(jq 'length' "$WORK/calls.json")
if [ "$TOTAL" -eq 0 ]; then
  echo "route-replay: 0 tool calls in the last ${DAYS} day(s) across ${#LOGS[@]} log(s) — nothing to replay (vacuous)"
  exit 2
fi
EARLIEST=$(jq -r 'map(.ts) | min' "$WORK/calls.json")

# 2. Payloads: the Claude-shaped PreToolUse each harness sends. Codex adds
#    turn_id; Copilot CLI's compatible format is named by its hook env.
jq -c '.[] | {
    id,
    env: (if .agent == "copilot-cli" then "AGENTSHIELD_AGENT_ID=copilot-cli" else "" end),
    payload: ({hook_event_name: "PreToolUse", session_id: "route-replay", cwd, tool_name: .tool, tool_input: .input}
              + (if .agent == "codex" then {turn_id: "route-replay"} else {} end))
  }' "$WORK/calls.json" > "$WORK/payloads.jsonl"

# 3. Throwaway HOMEs. An allowlist, so a new secret file in the config dir is
#    never copied by accident.
make_home() {
  local h="$1"
  mkdir -p "$h/.agentshield"
  local f d
  for f in policy.yaml agentshield.yaml managed.json mcp-policy.yaml; do
    [ -f "$CONFIG_DIR/$f" ] && cp "$CONFIG_DIR/$f" "$h/.agentshield/$f"
  done
  for d in packs mcp-packs; do
    [ -d "$CONFIG_DIR/$d" ] && cp -R "$CONFIG_DIR/$d" "$h/.agentshield/$d"
  done
  if [ -n "$(find "$h" -name credentials.json -print -quit)" ]; then
    echo "route-replay: refusing: credentials.json reached the throwaway HOME $h" >&2
    exit 1
  fi
}

# run_one BIN HOME ENVSTR PAYLOADFILE OUTPREFIX: one hook run, its exit
# code, stdout, stderr and the audit lines it appended.
run_one() {
  local bin="$1" home="$2" envstr="$3" pf="$4" out="$5" log before code=0
  log="$home/.agentshield/audit.jsonl"
  before=0
  [ -f "$log" ] && before=$(wc -l < "$log" | tr -d ' ')
  # shellcheck disable=SC2086 # envstr is one NAME=value word or empty
  (cd "$home" && env -i HOME="$home" PATH="$PATH" TMPDIR="${TMPDIR:-/tmp}" USER="${USER:-}" LOGNAME="${LOGNAME:-}" $envstr \
      "$bin" hook < "$pf" > "$out.stdout" 2> "$out.stderr") || code=$?
  echo "$code" > "$out.code"
  if [ -f "$log" ]; then tail -n +"$((before + 1))" "$log"; fi > "$out.events"
}

# project: the audit fields a decision consists of, routing_gap notes aside.
PROJECT='{decision, triggered_rules, taxonomy, original_decision, source, command, tool_name,
          notes: [(.notes // [])[] | select(.kind != "routing_gap")]}'

run_shard() {
  local i="$1" dir="$WORK/shard-$i" line id envstr
  mkdir -p "$dir"
  make_home "$dir/home-base"
  make_home "$dir/home-cand"
  : > "$dir/results.jsonl"
  while IFS= read -r line; do
    id=$(jq -r '.id' <<<"$line")
    envstr=$(jq -r '.env' <<<"$line")
    jq -c '.payload' <<<"$line" > "$dir/payload.json"
    run_one "$BASE" "$dir/home-base" "$envstr" "$dir/payload.json" "$dir/b"
    run_one "$CAND" "$dir/home-cand" "$envstr" "$dir/payload.json" "$dir/c"
    local diffs=() gaps
    cmp -s "$dir/b.code" "$dir/c.code" || diffs+=("exit:$(cat "$dir/b.code")->$(cat "$dir/c.code")")
    cmp -s "$dir/b.stdout" "$dir/c.stdout" || diffs+=("stdout")
    cmp -s "$dir/b.stderr" "$dir/c.stderr" || diffs+=("stderr")
    if ! cmp -s <(jq -c "$PROJECT" "$dir/b.events") <(jq -c "$PROJECT" "$dir/c.events"); then
      diffs+=("event")
    fi
    gaps=$(jq -s '[.[] | (.notes // [])[] | select(.kind == "routing_gap")] | length' "$dir/c.events")
    bdec=$(jq -rs 'map(.decision // "none") | last // "none"' "$dir/b.events")
    cdec=$(jq -rs 'map(.decision // "none") | last // "none"' "$dir/c.events")
    jq -cn --argjson id "$id" --arg code "$(cat "$dir/b.code")" --argjson gaps "$gaps" \
      --arg bdec "$bdec" --arg cdec "$cdec" \
      --arg diffs "${diffs[*]:-}" '{id: $id, base_exit: ($code|tonumber), gaps: $gaps, diffs: $diffs, base_decision: $bdec, cand_decision: $cdec}' >> "$dir/results.jsonl"
  done < "$dir/payloads.jsonl"
}

# 4. Shard round-robin and run.
START=$(date +%s)
for ((i = 0; i < JOBS; i++)); do
  mkdir -p "$WORK/shard-$i"
  awk -v k="$JOBS" -v i="$i" '(NR - 1) % k == i' "$WORK/payloads.jsonl" > "$WORK/shard-$i/payloads.jsonl"
done
for ((i = 0; i < JOBS; i++)); do
  run_shard "$i" &
done
FAIL=0
for job in $(jobs -p); do wait "$job" || FAIL=1; done
[ "$FAIL" -eq 0 ] || { echo "route-replay: a shard failed" >&2; exit 1; }
ELAPSED=$(( $(date +%s) - START ))

cat "$WORK"/shard-*/results.jsonl > "$WORK/results.jsonl"
REPLAYED=$(wc -l < "$WORK/results.jsonl" | tr -d ' ')
SHELL_N=$(jq '[.[] | select(.kind == "shell")] | length' "$WORK/calls.json")
TOOL_N=$(jq '[.[] | select(.kind == "tool")] | length' "$WORK/calls.json")
BLOCKS=$(jq -s '[.[] | select(.base_exit == 2)] | length' "$WORK/results.jsonl")
GAPS=$(jq -s '[.[] | select(.gaps > 0)] | length' "$WORK/results.jsonl")

jq -cs --slurpfile calls "$WORK/calls.json" '
  ($calls[0] | map({key: (.id | tostring), value: .}) | from_entries) as $by
  | .[] | select(.diffs != "")
  | . + {kind: $by[(.id | tostring)].kind, agent: $by[(.id | tostring)].agent, tool: $by[(.id | tostring)].tool,
         text: ($by[(.id | tostring)].input.command // ($by[(.id | tostring)].input | tostring))[:160]}' \
  "$WORK/results.jsonl" > "$WORK/flips.jsonl"
FLIPS=$(wc -l < "$WORK/flips.jsonl" | tr -d ' ')
GAP_TOOLS=$(jq -s --slurpfile calls "$WORK/calls.json" '
  ($calls[0] | map({key: (.id | tostring), value: .tool}) | from_entries) as $tool
  | [.[] | select(.gaps > 0) | $tool[(.id | tostring)]] | group_by(.) | map("\(.[0]) \(length)") | join(", ")' \
  -r "$WORK/results.jsonl")

echo "route-replay: ${REPLAYED}/${TOTAL} distinct calls replayed (${SHELL_N} shell, ${TOOL_N} tool; ${BLOCKS} BLOCK on base) from ${#LOGS[@]} log(s), window ${CUTOFF} (earliest call ${EARLIEST}), ${JOBS} jobs, ${ELAPSED}s"
echo "route-replay: flips ${FLIPS}; candidate routing_gap notes on ${GAPS} call(s)${GAP_TOOLS:+ (${GAP_TOOLS})}"
DIRECTION=$(jq -rs '
  def rank: {"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}[.] // -1;
  [.[] | select(.base_decision != .cand_decision)] as $d
  | "\([$d[] | select((.cand_decision | rank) > (.base_decision | rank))] | length) up, \([$d[] | select((.cand_decision | rank) < (.base_decision | rank))] | length) down, \([$d[] | select((.cand_decision | rank) == (.base_decision | rank))] | length) unranked"' \
  "$WORK/flips.jsonl")
FLIP_TOOLS=$(jq -rs '[.[] | .tool] | group_by(.) | map("\(.[0]) \(length)") | join(", ")' "$WORK/flips.jsonl")
echo "route-replay: decision changes: ${DIRECTION}; flips by tool: ${FLIP_TOOLS:-none}"
[ "$REPLAYED" -eq "$TOTAL" ] || { echo "route-replay: replayed ${REPLAYED} of ${TOTAL}: results incomplete" >&2; exit 1; }
if [ "$FLIPS" -gt 0 ]; then
  echo "route-replay: first flips (details in $WORK/flips.jsonl):"
  jq -r '"  #\(.id) \(.kind) \(.agent) \(.tool): \(.diffs) \(.base_decision)->\(.cand_decision) | \(.text | gsub("\n"; " "))"' "$WORK/flips.jsonl" | head -20
  exit 10
fi
exit 0
