#!/usr/bin/env bash
# route-replay_test.sh — the suite for scripts/route-replay.sh, against fake
# hook binaries. Each case proves the replay can fail for the thing it claims
# to detect (CLAUDE.md "Gates must be able to fail").
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/route-replay.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/route-replay-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT

PASS=0
FAILS=0
ok()   { PASS=$((PASS + 1)); echo "ok   $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL $1"; }

# A fake `agentshield hook`: appends one audit line to $HOME/.agentshield and
# exits 0. MODE=flip exits 2 for tool FlipMe; MODE=raise records BLOCK for
# FlipMe; MODE=gap adds a routing_gap note for tool GapMe. The line records
# the AGENTSHIELD_AGENT_ID it saw.
make_fake() {
  local path="$1" mode="$2"
  cat > "$path" <<EOF
#!/usr/bin/env bash
set -eu
p=\$(cat)
tool=\$(printf '%s' "\$p" | jq -r '.tool_name')
mkdir -p "\$HOME/.agentshield"
notes='[]'
if [ "$mode" = gap ] && [ "\$tool" = GapMe ]; then notes='[{"kind":"routing_gap","detail":"x"}]'; fi
dec=AUDIT
if [ "$mode" = raise ] && [ "\$tool" = FlipMe ]; then dec=BLOCK; fi
jq -cn --arg t "\$tool" --arg a "\${AGENTSHIELD_AGENT_ID:-}" --argjson n "\$notes" --arg d "\$dec" \
  '{decision: \$d, source: "fake", tool_name: \$t, command: \$a, notes: \$n}' >> "\$HOME/.agentshield/audit.jsonl"
if [ "$mode" = flip ] && [ "\$tool" = FlipMe ]; then exit 2; fi
exit 0
EOF
  chmod +x "$path"
}
make_fake "$T/same" same
make_fake "$T/flip" flip
make_fake "$T/gap" gap
make_fake "$T/raise" raise

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CFG="$T/config"
mkdir -p "$CFG/packs"
echo 'version: "0.1"' > "$CFG/policy.yaml"
echo 'rules: []' > "$CFG/packs/p.yaml"
echo '{"token":"must-never-be-copied"}' > "$CFG/credentials.json"
{
  # Five distinct calls: a shell call twice (deduplicated), a Codex shell
  # call, three tool calls, and one Copilot call. One event is outside the
  # window, one is from a source the replay does not read.
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "claude-code-hook", command: "ls -la", cwd: "/tmp"}'
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "claude-code-hook", command: "ls -la", cwd: "/tmp"}'
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "codex-hook", command: "pwd"}'
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "claude-code-mcp-hook", tool_name: "FlipMe", arguments: {command: "x"}}'
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "claude-code-mcp-hook", tool_name: "GapMe", arguments: {command: "y"}}'
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "copilot-cli-mcp-hook", tool_name: "Read", arguments: {path: "/tmp/r"}}'
  jq -cn '{timestamp: "2001-01-01T00:00:00Z", source: "claude-code-hook", command: "old"}'
  jq -cn --arg ts "$NOW" '{timestamp: $ts, source: "cursor-hook", command: "not read"}'
} > "$CFG/audit.jsonl"
LOG_LINES_BEFORE=$(wc -l < "$CFG/audit.jsonl")

run() { # run OUTFILE ARGS... ; sets RC
  RC=0
  bash "$SCRIPT" --config-dir "$CFG" --jobs 2 "${@:2}" > "$1" 2>&1 || RC=$?
}

# 1. Negative control: identical binaries, no flips, the right denominator.
run "$T/o1" --base "$T/same" --candidate "$T/same" --keep "$T/k1"
if [ "$RC" -eq 0 ] && grep -q '5/5 distinct calls replayed (2 shell, 3 tool' "$T/o1" && grep -q 'flips 0;' "$T/o1"; then
  ok "identical binaries: exit 0, 5 calls, 0 flips"
else
  fail "identical binaries (rc=$RC)"; cat "$T/o1"
fi

# 2. Positive control: a candidate that blocks one call is a flip.
run "$T/o2" --base "$T/same" --candidate "$T/flip"
if [ "$RC" -eq 10 ] && grep -q 'flips 1;' "$T/o2" && grep -q 'FlipMe: exit:0->2' "$T/o2"; then
  ok "differing candidate: exit 10, the flip names the call"
else
  fail "differing candidate (rc=$RC)"; cat "$T/o2"
fi

# 2b. Decision changes are counted by direction and flips by tool.
run "$T/o2b" --base "$T/same" --candidate "$T/raise"
if [ "$RC" -eq 10 ] && grep -q 'decision changes: 1 up, 0 down, 0 unranked; flips by tool: FlipMe 1' "$T/o2b" && grep -q 'FlipMe: event AUDIT->BLOCK' "$T/o2b"; then
  ok "raised decision: counted up, named by tool"
else
  fail "raised decision (rc=$RC)"; cat "$T/o2b"
fi
run "$T/o2c" --base "$T/raise" --candidate "$T/same"
if [ "$RC" -eq 10 ] && grep -q 'decision changes: 0 up, 1 down, 0 unranked' "$T/o2c"; then
  ok "lowered decision: counted down"
else
  fail "lowered decision (rc=$RC)"; cat "$T/o2c"
fi
if grep -q 'decision changes: 0 up, 0 down, 0 unranked; flips by tool: FlipMe 1' "$T/o2"; then
  ok "an exit-code flip with the same decision is no decision change"
else
  fail "exit-only flip"; cat "$T/o2"
fi

# 3. A routing_gap note on the candidate is counted, not flipped.
run "$T/o3" --base "$T/same" --candidate "$T/gap"
if [ "$RC" -eq 0 ] && grep -q 'flips 0; candidate routing_gap notes on 1 call(s) (GapMe 1)' "$T/o3"; then
  ok "routing_gap note: counted, not a flip"
else
  fail "routing_gap note (rc=$RC)"; cat "$T/o3"
fi

# 4. Credentials never reach a throwaway HOME, the real log is never written,
#    and the caller's AGENTSHIELD_AGENT_ID never reaches the binary.
if [ -z "$(find "$T/k1" -name credentials.json -print -quit)" ]; then
  ok "credentials.json is not copied"
else
  fail "credentials.json was copied into $T/k1"
fi
if [ "$(wc -l < "$CFG/audit.jsonl")" -eq "$LOG_LINES_BEFORE" ]; then
  ok "the source audit log is unchanged"
else
  fail "the source audit log was written"
fi
AGENTSHIELD_AGENT_ID=leaked run "$T/o4" --base "$T/same" --candidate "$T/same" --keep "$T/k4"
seen=$(cat "$T"/k4/shard-*/home-base/.agentshield/audit.jsonl | jq -r '.command' | sort -u | tr '\n' ' ')
if [ "$RC" -eq 0 ] && [ "$seen" = " copilot-cli " ]; then
  ok "only the payload's own AGENTSHIELD_AGENT_ID reaches the binary"
else
  fail "env leak: binaries saw AGENTSHIELD_AGENT_ID values '$seen' (rc=$RC)"
fi

# 5. An empty window is vacuous, said out loud.
run "$T/o5" --base "$T/same" --candidate "$T/same" --log /dev/null
if [ "$RC" -eq 2 ] && grep -q 'nothing to replay (vacuous)' "$T/o5"; then
  ok "empty window: exit 2"
else
  fail "empty window (rc=$RC)"; cat "$T/o5"
fi

# 6. Usage errors.
run "$T/o6" --base "$T/nope" --candidate "$T/same"
if [ "$RC" -eq 1 ]; then ok "missing binary: exit 1"; else fail "missing binary (rc=$RC)"; fi

echo "route-replay_test: $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
