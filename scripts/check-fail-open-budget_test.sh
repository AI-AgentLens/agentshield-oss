#!/usr/bin/env bash
# Tests for check-fail-open-budget.sh (#3995 step 3): the parsing and the
# ratchet decisions, against synthetic parity files in a temp dir.
#
# Run: bash scripts/check-fail-open-budget_test.sh
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-fail-open-budget.sh"
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

D="$TMP/analyzer"; mkdir -p "$D"; B="$TMP/budget.txt"
run() { bash "$SCRIPT" --dir "$D" --baseline "$B" "$@"; }

# Synthetic parity files covering every declaration shape the real suite uses.
write_fixture() { # <alpha budget> <table row budget> [premium second budget]
  cat > "$D/alpha_parity_test.go" <<EOF
package analyzer
// const maxLeaks = 999 in a comment must not count
func TestAlpha(t *testing.T) {
	const maxLeaks = $1
	_ = maxLeaks
}
EOF
  cat > "$D/beta_parity_test.go" <<EOF
package analyzer
func TestBeta(t *testing.T) {
	leakBudget := 3
	const maxLeaksEval = 40
	maxLeaks := 60
	if premium {
		maxLeaks = ${3:-62}
	}
}
EOF
  cat > "$D/gamma_parity_test.go" <<EOF
package analyzer
func TestGamma(t *testing.T) {
	positions := []struct {
		name     string
		maxLeaks int
		floor    int
	}{
		{"exec-backslash", $2, 1900, func(f []string) bool { return true }},
		{"arg2-backslash", 35, 1500, nil},
	}
	_ = positions
}
EOF
  # a parity file with no budget at all (exact rows) is silently not counted
  printf 'package analyzer\nfunc TestDelta(t *testing.T) { t.Fatalf("CONTROL") }\n' > "$D/delta_parity_test.go"
}

echo "check-fail-open-budget (#3995):"

# ── 1. vacuous: no declarations parsed -> exit 2, never a total of 0 ────────
mkdir -p "$TMP/empty"
bash "$SCRIPT" --dir "$TMP/empty" --baseline "$B" > "$TMP/o1.txt" 2>&1; check "no parity files -> exit 2" 2 $?
contains "says it refused a vacuous total" "$TMP/o1.txt" "vacuous"

# ── 2. no baseline yet -> exit 1 with instructions; --update creates it ─────
write_fixture 21 3
run > "$TMP/o2.txt" 2>&1; check "missing baseline -> exit 1" 1 $?
contains "tells you to --update" "$TMP/o2.txt" "--update"
run --update > "$TMP/o2b.txt" 2>&1; check "--update writes the baseline" 0 $?
# 21 + 3 + 40 + 60 + 62 + 3 + 35 = 224 over 7 budgets
contains "reports the total" "$TMP/o2b.txt" "7 budgets, total 224"
contains "named budget parsed"            "$B" "alpha:maxLeaks 21"
contains "leakBudget := parsed"           "$B" "beta:leakBudget 3"
contains "suffixed const parsed"          "$B" "beta:maxLeaksEval 40"
contains "premium re-assignment is #2"    "$B" "beta:maxLeaks#2 62"
contains "table row parsed by class name" "$B" "gamma:exec-backslash 3"
contains "second table row parsed"        "$B" "gamma:arg2-backslash 35"
not_contains "commented-out constant not counted" "$B" "999"
not_contains "budget-less parity file not counted" "$B" "delta"

# ── 3. unchanged -> exit 0 ──────────────────────────────────────────────────
run > "$TMP/o3.txt" 2>&1; check "unchanged -> exit 0" 0 $?
contains "prints the one number" "$TMP/o3.txt" "total 224 (unchanged)"

# ── 4. a budget goes UP -> exit 1, loud ─────────────────────────────────────
write_fixture 30 3
run > "$TMP/o4.txt" 2>&1; check "budget up -> exit 1" 1 $?
contains "names the rise"        "$TMP/o4.txt" "TOTAL ROSE: 224 -> 233 (+9)"
contains "names the entry"       "$TMP/o4.txt" "alpha:maxLeaks"
contains "marks it UP"           "$TMP/o4.txt" "21 -> 30   (UP)"

# ── 5. a budget goes DOWN -> exit 1 too (baseline must be ratcheted) ────────
write_fixture 10 3
run > "$TMP/o5.txt" 2>&1; check "budget down -> exit 1 until ratcheted" 1 $?
contains "says the total fell"   "$TMP/o5.txt" "total fell: 224 -> 213"
contains "marks it down"         "$TMP/o5.txt" "21 -> 10   (down)"
run --update > /dev/null 2>&1; run > "$TMP/o5b.txt" 2>&1; check "after --update the lower total is the new baseline" 0 $?
contains "new total" "$TMP/o5b.txt" "total 213"

# ── 6. a new class appears -> exit 1, 'add it with its count' ───────────────
printf 'package analyzer\nfunc TestEps(t *testing.T) {\n\tconst maxLeaks = 5\n}\n' > "$D/epsilon_parity_test.go"
run > "$TMP/o6.txt" 2>&1; check "new class -> exit 1" 1 $?
contains "new class named"      "$TMP/o6.txt" "+ epsilon:maxLeaks"
contains "says to add it"       "$TMP/o6.txt" "new class"
rm "$D/epsilon_parity_test.go"

# ── 7. a class disappears -> exit 1, shown as removed ───────────────────────
rm "$D/gamma_parity_test.go"
run > "$TMP/o7.txt" 2>&1; check "removed class -> exit 1" 1 $?
contains "removed entry named" "$TMP/o7.txt" "- gamma:exec-backslash"

# ── 8. usage ────────────────────────────────────────────────────────────────
bash "$SCRIPT" --bogus > "$TMP/o8.txt" 2>&1; check "unknown flag -> exit 1" 1 $?

echo
if [ "$fail" -eq 0 ]; then echo "check-fail-open-budget_test: all cases passed"; else echo "check-fail-open-budget_test: FAILURES"; exit 1; fi
