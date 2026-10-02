#!/usr/bin/env bash
# Tests for replay-audit.sh (#3995) — the decisions, not the engine.
#
# The candidate binary is a fake that honours `check --fixture F`: it prints
# the real report shape and flips a case when its shell text carries a marker
# (FLIP2BLOCK / FLIP2AUDIT). So these cases prove the selection (sources,
# window, dedupe, cap), the sharding (every case reaches a shard), the
# classification and the exit codes — and that a vacuous run says so.
#
# Run: bash scripts/replay-audit_test.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/replay-audit.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

check() { # <desc> <expected_exit> <actual_exit>
  if [ "$2" -eq "$3" ]; then echo "  ok: $1 (exit $3)"
  else echo "  FAIL: $1 — expected exit $2 got $3"; fail=1; fi
}
contains() { # <desc> <file> <needle>
  if grep -qF -- "$3" "$2"; then echo "  ok: $1"
  else echo "  FAIL: $1 — output did not mention '$3'"; fail=1; fi
}
not_contains() { # <desc> <file> <needle>
  if grep -qF -- "$3" "$2"; then echo "  FAIL: $1 — output should not mention '$3'"; fail=1
  else echo "  ok: $1"; fi
}

# ── the fake candidate ──────────────────────────────────────────────────────
FAKE="$TMP/agentshield"
cat > "$FAKE" <<'FAKEEOF'
#!/usr/bin/env bash
# fake agentshield: `check --fixture F` only. Records every case name it saw in
# $FAKE_SEEN so a test can prove the shards cover the selection.
[ "$1" = "check" ] && [ "$2" = "--fixture" ] || { echo "fake: unsupported: $*" >&2; exit 64; }
F="$3"
n=$(jq '.cases|length' "$F"); echo "$F: $n cases"; failed=0
for i in $(seq 0 $((n-1))); do
  name=$(jq -r ".cases[$i].name" "$F"); shell=$(jq -r ".cases[$i].shell" "$F"); exp=$(jq -r ".cases[$i].expect" "$F")
  [ -n "${FAKE_SEEN:-}" ] && echo "$name" >> "$FAKE_SEEN"
  got="$exp"
  case "$shell" in *FLIP2BLOCK*) got=BLOCK ;; *FLIP2AUDIT*) got=AUDIT ;; esac
  if [ "$got" = "$exp" ]; then echo "  PASS  $name ($got)"
  else echo "$F:$((i+2)): FAIL $name — expected $exp, got $got"; echo "        rules: fake-rule-$got"; failed=$((failed+1)); fi
done
echo; echo "$((n-failed)) passed, $failed failed"
[ "${FAKE_EXIT3:-0}" = "1" ] && exit 3
[ "$failed" -eq 0 ] && exit 0 || exit 1
FAKEEOF
chmod +x "$FAKE"

now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ev() { # <source> <decision> <command> [rules-json] [timestamp]
  jq -cn --arg s "$1" --arg d "$2" --arg c "$3" --argjson r "${4:-[]}" --arg t "${5:-$now}" \
    '{source:$s, decision:$d, command:$c, triggered_rules:$r, timestamp:$t}'
}
run() { bash "$SCRIPT" --binary "$FAKE" "$@"; }

echo "replay-audit (#3995):"

# ── 1. vacuous: nothing in the window ───────────────────────────────────────
LOG="$TMP/empty.jsonl"; : > "$LOG"
run --log "$LOG" > "$TMP/o1.txt" 2>&1; check "empty log -> exit 2, not 0" 2 $?
contains "says it was vacuous with the denominator" "$TMP/o1.txt" "0 shell events"

# ── 2. selection: MCP events and non-shell sources are not shell commands ───
LOG="$TMP/l2.jsonl"
{ ev claude-code-mcp-hook AUDIT "mcp FLIP2BLOCK";  ev something-else AUDIT "x FLIP2BLOCK"; ev claude-code-hook AUDIT "ls -la"; } > "$LOG"
run --log "$LOG" > "$TMP/o2.txt" 2>&1; check "only shell hooks replayed -> no flips" 0 $?
contains "replayed exactly the one shell event" "$TMP/o2.txt" "replayed 1 "

# ── 3. dedupe: the most recent decision for a repeated command wins ──────────
LOG="$TMP/l3.jsonl"
{ ev claude-code-hook BLOCK "git push" '["r-old"]' "2020-01-01T00:00:00Z"; ev claude-code-hook AUDIT "git push" '["r-new"]'; } > "$LOG"
run --log "$LOG" --hours 999999 > "$TMP/o3.txt" 2>&1; check "latest decision is the expectation (AUDIT==AUDIT)" 0 $?
contains "one unique command" "$TMP/o3.txt" "unique 1 "

# ── 4. classification + exit 10 + recorded/new rules + snippet ──────────────
LOG="$TMP/l4.jsonl"
{ ev claude-code-hook BLOCK "rm -rf build FLIP2AUDIT" '["ts-block-x"]'
  ev codex-hook AUDIT "echo 'prose' FLIP2BLOCK" '[]'
  ev claude-code-hook ALLOW "ls" ; } > "$LOG"
run --log "$LOG" > "$TMP/o4.txt" 2>&1; check "flips -> exit 10" 10 $?
contains "BLOCK lost section names the recorded rule" "$TMP/o4.txt" "recorded: ts-block-x"
contains "BLOCK lost shows the new decision"           "$TMP/o4.txt" "BLOCK -> AUDIT"
contains "new BLOCK shows the candidate's rule"        "$TMP/o4.txt" "now:      fake-rule-BLOCK"
contains "new BLOCK counts codex-hook traffic too"     "$TMP/o4.txt" "AUDIT -> BLOCK"
contains "snippet shows the command"                   "$TMP/o4.txt" "echo 'prose' FLIP2BLOCK"
contains "summary counts both classes"                 "$TMP/o4.txt" "flips 2 (BLOCK lost 1, new BLOCK 1, other 0)"

# ── 5. cap keeps every BLOCK and the most recent N others ───────────────────
LOG="$TMP/l5.jsonl"
{ ev claude-code-hook BLOCK "old block" '["r"]' "2024-01-01T00:00:00Z"
  ev claude-code-hook AUDIT "older audit" '[]'  "2024-01-02T00:00:00Z"
  ev claude-code-hook AUDIT "newer audit FLIP2BLOCK" '[]' "2024-01-03T00:00:00Z"
  ev claude-code-hook AUDIT "newest audit" '[]' "2024-01-04T00:00:00Z"; } > "$LOG"
run --log "$LOG" --hours 999999 --max 2 > "$TMP/o5.txt" 2>&1; check "capped run still reports the flip" 10 $?
contains "cap: 1 BLOCK + 2 others replayed out of 4" "$TMP/o5.txt" "unique 4 · replayed 3 (all 1 recorded BLOCKs + up to 2 others)"
contains "the newer AUDIT survived the cap"            "$TMP/o5.txt" "newer audit FLIP2BLOCK"
# the older audit fell off; had it been replayed with a marker it would show — prove the cap by count, not absence

# ── 6. window: an event older than --hours is excluded ──────────────────────
LOG="$TMP/l6.jsonl"
{ ev claude-code-hook AUDIT "ancient FLIP2BLOCK" '[]' "2020-01-01T00:00:00Z"; ev claude-code-hook AUDIT "pwd"; } > "$LOG"
run --log "$LOG" --hours 1 > "$TMP/o6.txt" 2>&1; check "old event outside the window -> no flip" 0 $?
contains "window counted one event" "$TMP/o6.txt" "events 1 "

# ── 7. sharding: every selected case reaches exactly one shard ──────────────
LOG="$TMP/l7.jsonl"
for i in $(seq 1 10); do ev claude-code-hook AUDIT "cmd $i"; done > "$LOG"
SEEN="$TMP/seen.txt"; : > "$SEEN"
FAKE_SEEN="$SEEN" run --log "$LOG" --jobs 3 > "$TMP/o7.txt" 2>&1; check "3 shards, no flips" 0 $?
seen_n=$(sort -u "$SEEN" | wc -l | tr -d ' '); dup_n=$(sort "$SEEN" | uniq -d | wc -l | tr -d ' ')
if [ "$seen_n" = "10" ] && [ "$dup_n" = "0" ]; then echo "  ok: all 10 cases evaluated once across 3 shards"
else echo "  FAIL: shards saw $seen_n unique / $dup_n duplicated of 10"; fail=1; fi
contains "jobs clamp is reported" "$TMP/o7.txt" "jobs 3 "

# ── 8. multi-line commands survive the JSON fixture round-trip ──────────────
LOG="$TMP/l8.jsonl"
ev claude-code-hook AUDIT $'cat > f <<EOF\nline two FLIP2BLOCK\nEOF' '[]' > "$LOG"
run --log "$LOG" > "$TMP/o8.txt" 2>&1; check "heredoc body reached the candidate (marker on line 2 flipped it)" 10 $?
contains "snippet folds newlines" "$TMP/o8.txt" "cat > f <<EOF ⏎ line two"

# ── 9. degraded candidate (exit 3) is reported and wins over 'no flips' ─────
LOG="$TMP/l9.jsonl"; ev claude-code-hook AUDIT "ls" > "$LOG"
FAKE_EXIT3=1 run --log "$LOG" > "$TMP/o9.txt" 2>&1; check "failed packs -> exit 3" 3 $?
contains "says results are suspect" "$TMP/o9.txt" "failed packs"

# ── 9b. a crashed candidate is an error, not a green ────────────────────────
# The first version aborted the shard subshell under errexit before writing
# the exit code, and read the missing code as 1 — a crash passed as "no flips".
CRASH="$TMP/crash-shield"; printf '#!/usr/bin/env bash\nexit 64\n' > "$CRASH"; chmod +x "$CRASH"
bash "$SCRIPT" --binary "$CRASH" --log "$TMP/l9.jsonl" > "$TMP/o9b.txt" 2>&1; check "candidate crash (exit 64) -> exit 1, not 0" 1 $?
contains "names the shard exit code" "$TMP/o9b.txt" "exited 64"

# ── 10. usage errors ────────────────────────────────────────────────────────
run --binary "$TMP/does-not-exist" > "$TMP/o10.txt" 2>&1; check "missing binary -> exit 1" 1 $?
run --log "$TMP/l9.jsonl" --hours abc > "$TMP/o10b.txt" 2>&1; check "non-integer --hours -> exit 1" 1 $?

echo
if [ "$fail" -eq 0 ]; then echo "replay-audit_test: all cases passed"; else echo "replay-audit_test: FAILURES"; exit 1; fi
