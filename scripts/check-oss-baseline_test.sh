#!/usr/bin/env bash
# Smoke test for check-oss-baseline.sh — proves the ratchet can actually fail.
#
# This exists because the gate it guards is the one that could not fail (#3130).
# A ratchet whose only observed state is "green" is the same class of defect: it
# launders an unverified claim into a green check. Every branch that is supposed
# to turn the job red is exercised here with a synthetic go-test log.
#
# Run: bash scripts/check-oss-baseline_test.sh
set -uo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/check-oss-baseline.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

check() { # <desc> <expected_exit> <actual_exit>
  if [ "$2" -eq "$3" ]; then echo "  ok: $1 (exit $3)"
  else echo "  FAIL: $1 — expected exit $2 got $3"; fail=1; fi
}
contains() { # <desc> <file> <needle>
  if grep -qF "$3" "$2"; then echo "  ok: $1"
  else echo "  FAIL: $1 — output did not mention '$3'"; fail=1; fi
}

PKG="github.com/AI-AgentLens/agentshield/internal/analyzer"

cat > "$TMP/baseline.txt" <<'EOF'
# header comment, ignored
case:TP-ALPHA-001
case:TP-BETA-002    # trailing comment, ignored
test:TestSomeWholeCorpusSweep
EOF

# A log whose failure set matches the baseline exactly.
cat > "$TMP/match.log" <<EOF
--- FAIL: TestAccuracy_AllKingdoms (5.00s)
    --- FAIL: TestAccuracy_AllKingdoms/TP-ALPHA-001 (0.01s)
    --- FAIL: TestAccuracy_AllKingdoms/TP-BETA-002 (0.01s)
--- FAIL: TestPipeline_AllKingdoms (6.00s)
    --- FAIL: TestPipeline_AllKingdoms/TP-ALPHA-001 (0.01s)
    --- FAIL: TestPipeline_AllKingdoms/TP-BETA-002 (0.01s)
--- FAIL: TestSomeWholeCorpusSweep (9.00s)
FAIL
FAIL	$PKG	160.0s
EOF

echo "check-oss-baseline ratchet (#3130/#3136):"

# Case 1: failure set unchanged -> PASS. Also pins the dedup rule: the same case
# failing under two parent sweeps is ONE entry, and a parent with failing
# subtests is not recorded on its own.
"$GATE" "$TMP/match.log" "$TMP/baseline.txt" > "$TMP/out1.txt" 2>&1
check "unchanged failure set -> green" 0 $?
contains "reports zero delta" "$TMP/out1.txt" "No delta"

# Case 2: a case fails that is not baselined -> FAIL. This is an OSS regression.
sed 's|--- FAIL: TestAccuracy_AllKingdoms/TP-BETA-002 (0.01s)|--- FAIL: TestAccuracy_AllKingdoms/TP-BETA-002 (0.01s)\n    --- FAIL: TestAccuracy_AllKingdoms/TP-GAMMA-003 (0.01s)|' \
  "$TMP/match.log" > "$TMP/new.log"
"$GATE" "$TMP/new.log" "$TMP/baseline.txt" > "$TMP/out2.txt" 2>&1
check "new un-baselined failure -> red" 1 $?
contains "names the new case" "$TMP/out2.txt" "case:TP-GAMMA-003"

# Case 3: a baselined case now passes -> FAIL, so the entry gets removed and the
# baseline can only shrink. Without this, a stale entry is a permanent hiding
# place for a later regression on the same id.
grep -v 'TP-BETA-002' "$TMP/match.log" > "$TMP/fixed.log"
"$GATE" "$TMP/fixed.log" "$TMP/baseline.txt" > "$TMP/out3.txt" 2>&1
check "baselined case now passing -> red (ratchet)" 1 $?
contains "names the fixed case" "$TMP/out3.txt" "case:TP-BETA-002"

# Case 4: a whole-corpus fitness function regresses. It emits no per-case
# subtests, so a case-only ratchet would compute an empty delta and stay green —
# the exact blind spot the `test:` entry kind exists to close.
sed 's|^--- FAIL: TestSomeWholeCorpusSweep (9.00s)$|--- FAIL: TestSomeWholeCorpusSweep (9.00s)\n--- FAIL: TestCompoundWrappingParity (115.00s)|' \
  "$TMP/match.log" > "$TMP/parity.log"
"$GATE" "$TMP/parity.log" "$TMP/baseline.txt" > "$TMP/out4.txt" 2>&1
check "subtest-less fitness function regression -> red" 1 $?
contains "names the parity test" "$TMP/out4.txt" "test:TestCompoundWrappingParity"

# Case 5: THE #3130 case. The suite never ran (container died, build failed,
# timeout). The failure set is empty, which must NOT read as success. Exit 2,
# distinct from both green and a real delta.
cat > "$TMP/truncated.log" <<'EOF'
=== [1/5] Install Go ===
=== [2/5] Build from source ===
Error: build failed
EOF
"$GATE" "$TMP/truncated.log" "$TMP/baseline.txt" > "$TMP/out5.txt" 2>&1
check "suite never ran -> exit 2, not green" 2 $?
contains "says the suite did not run" "$TMP/out5.txt" "did not run to completion"

# Case 6: an empty log is the degenerate form of case 5.
: > "$TMP/empty.log"
"$GATE" "$TMP/empty.log" "$TMP/baseline.txt" >/dev/null 2>&1
check "empty log -> exit 2" 2 $?

# Case 7: a clean OSS run (suite ran, nothing failed) against a NON-empty
# baseline is a 914-entry ratchet-down, not a silent pass. This is what #3136
# landing looks like: the baseline must be emptied in the same change.
cat > "$TMP/clean.log" <<EOF
ok  	$PKG	160.0s
EOF
"$GATE" "$TMP/clean.log" "$TMP/baseline.txt" > "$TMP/out7.txt" 2>&1
check "clean run vs stale baseline -> red (empty the baseline)" 1 $?
contains "reports all entries fixed" "$TMP/out7.txt" "FIXED"

# Case 8: usage errors are distinguishable from findings.
"$GATE" >/dev/null 2>&1;                                   check "no args -> exit 2" 2 $?
"$GATE" "$TMP/nope.log" "$TMP/baseline.txt" >/dev/null 2>&1; check "missing log -> exit 2" 2 $?
"$GATE" "$TMP/match.log" "$TMP/nope.txt" >/dev/null 2>&1;    check "missing baseline -> exit 2" 2 $?

# Case 9: the real baseline file must parse and be non-empty. A truncated or
# renamed baseline would otherwise make every run look like a mass ratchet-down.
REAL="$(cd "$(dirname "$0")" && pwd)/oss-known-failures.txt"
n=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$REAL" | grep -c .)
if [ "$n" -gt 0 ]; then echo "  ok: real baseline parses ($n entries)"
else echo "  FAIL: real baseline parsed to 0 entries"; fail=1; fi

if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit "$fail"
