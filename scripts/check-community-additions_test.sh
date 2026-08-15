#!/usr/bin/env bash
# Smoke test for check-community-additions.sh. Builds a throwaway git repo and
# exercises the gate's exit codes. Run: bash scripts/check-community-additions_test.sh
set -uo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/check-community-additions.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail=0

run_case() { # <desc> <expected_exit>; reads commands from caller, sets last_exit
  :
}
check() { # <desc> <expected_exit> <actual_exit>
  if [ "$2" -eq "$3" ]; then echo "  ok: $1 (exit $3)"; else echo "  FAIL: $1 — expected exit $2 got $3"; fail=1; fi
}

cd "$TMP"
git init -q
git config user.email t@t.test; git config user.name test
mkdir -p packs/community packs/premium
cat > packs/community/terminal-safety.yaml <<'EOF'
version: "0.1"
rules:
- id: ts-existing-one
  decision: BLOCK
- id: ts-existing-two
  decision: BLOCK
EOF
cat > packs/premium/terminal-safety-advanced.yaml <<'EOF'
version: "0.1"
rules:
- id: ts-prem-one
  decision: BLOCK
EOF
git add -A && git commit -qm base
BASE="$(git rev-parse HEAD)"

echo "check-community-additions gate (#2294):"

# Case 1: add a net-new community rule -> FAIL (exit 1)
git checkout -q -b add-community
cat >> packs/community/terminal-safety.yaml <<'EOF'
- id: ts-new-community-rule
  decision: BLOCK
EOF
git add -A && git commit -qm "add community rule"
out="$(bash "$GATE" "$BASE" 2>&1)"; ec=$?
check "net-new community id -> fail" 1 "$ec"
# In-process substring match (not `echo ... | grep -q`): grep -q can exit as
# soon as it finds a match, closing the pipe's read end while echo is still
# writing — SIGPIPE turns a passing case into a spurious FAIL under pipefail.
case "$out" in
  *ts-new-community-rule*) ;;
  *) echo "  FAIL: error did not name the offending id"; fail=1 ;;
esac

# Case 2: move a rule OUT of community into premium -> PASS (exit 0)
git checkout -q "$BASE"; git checkout -q -b move-to-premium
cat > packs/community/terminal-safety.yaml <<'EOF'
version: "0.1"
rules:
- id: ts-existing-two
  decision: BLOCK
EOF
cat >> packs/premium/terminal-safety-advanced.yaml <<'EOF'
- id: ts-existing-one
  decision: BLOCK
EOF
git add -A && git commit -qm "move ts-existing-one to premium"
bash "$GATE" "$BASE" >/dev/null 2>&1; check "move community->premium (no net-new)" 0 $?

# Case 3: reorder community rules, no net-new -> PASS (exit 0)
git checkout -q "$BASE"; git checkout -q -b reorder
cat > packs/community/terminal-safety.yaml <<'EOF'
version: "0.1"
rules:
- id: ts-existing-two
  decision: BLOCK
- id: ts-existing-one
  decision: BLOCK
EOF
git add -A && git commit -qm "reorder community"
bash "$GATE" "$BASE" >/dev/null 2>&1; check "reorder community (no net-new)" 0 $?

# Case 4: add a premium rule only -> PASS (exit 0)
git checkout -q "$BASE"; git checkout -q -b add-premium
cat >> packs/premium/terminal-safety-advanced.yaml <<'EOF'
- id: ts-new-premium-rule
  decision: BLOCK
EOF
git add -A && git commit -qm "add premium rule"
bash "$GATE" "$BASE" >/dev/null 2>&1; check "add premium-only rule" 0 $?

if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit "$fail"
