#!/usr/bin/env bash
# Smoke test for check-taxonomy-refs.sh — proves the gate can fail, and that it
# fails legibly rather than silently.
#
# The gate blocks a merge when a Shield pack references a taxonomy id whose YAML
# has not landed in AI_risk_compliance yet (comply#1366). It runs against a
# cloned taxonomy tree in CI, so this test builds a tiny fake one instead of
# needing the sibling repo.
#
# Run: bash scripts/check-taxonomy-refs_test.sh
set -uo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/check-taxonomy-refs.sh"
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

# Fake taxonomy tree with exactly one resolvable id.
TAX="$TMP/taxonomy"
mkdir -p "$TAX/destructive-ops/fs-destruction"
echo "id: system-directory-delete" > "$TAX/destructive-ops/fs-destruction/system-directory-delete.yaml"

WORK="$TMP/repo"
mkdir -p "$WORK/packs"

echo "check-taxonomy-refs gate (comply#1366):"

# Case 1: every ref resolves -> PASS.
cat > "$WORK/packs/a.yaml" <<'EOF'
rules:
  - id: r1
    taxonomy: destructive-ops/fs-destruction/system-directory-delete
EOF
(cd "$WORK" && bash "$GATE" "$TAX") > "$TMP/out1.txt" 2>&1
check "all refs resolve -> pass" 0 $?

# Case 2: an unresolvable ref -> FAIL, and it must name the offender.
cat >> "$WORK/packs/a.yaml" <<'EOF'
  - id: r2
    taxonomy: bogus-kingdom/not/real
EOF
(cd "$WORK" && bash "$GATE" "$TAX") > "$TMP/out2.txt" 2>&1
check "orphan ref -> fail" 1 $?
contains "names the orphan ref" "$TMP/out2.txt" "bogus-kingdom/not/real"

# Case 3: quoted forms are unquoted before lookup, so a quoted orphan is still
# caught (and a quoted valid ref still passes).
cat > "$WORK/packs/a.yaml" <<'EOF'
rules:
  - id: r1
    taxonomy: "destructive-ops/fs-destruction/system-directory-delete"
  - id: r2
    taxonomy: 'bogus-kingdom/quoted/orphan'
EOF
(cd "$WORK" && bash "$GATE" "$TAX") > "$TMP/out3.txt" 2>&1
check "quoted orphan ref -> fail" 1 $?
contains "names the quoted orphan" "$TMP/out3.txt" "bogus-kingdom/quoted/orphan"

# Case 4: THE vacuity case. packs/ exists but yields no refs — the key was
# renamed, packs/ moved, or the script ran from the wrong directory. This must
# not read as "all refs resolve", and it must say why.
cat > "$WORK/packs/a.yaml" <<'EOF'
rules:
  - id: r1
    decision: BLOCK
EOF
(cd "$WORK" && bash "$GATE" "$TAX") > "$TMP/out4.txt" 2>&1
check "no refs found at all -> fail, not vacuous pass" 1 $?
contains "explains the empty ref set" "$TMP/out4.txt" "found no 'taxonomy:' refs"

# Case 5: no packs/ directory at all — same reasoning as case 4.
rm -rf "$WORK/packs"
(cd "$WORK" && bash "$GATE" "$TAX") > "$TMP/out5.txt" 2>&1
check "no packs/ dir -> fail" 1 $?
contains "explains the empty ref set" "$TMP/out5.txt" "found no 'taxonomy:' refs"

# Case 6: a missing taxonomy dir is a usage error (exit 2), distinct from a
# finding — CI must not read a bad clone as an orphan-ref failure.
mkdir -p "$WORK/packs"
echo 'rules: []' > "$WORK/packs/a.yaml"
(cd "$WORK" && bash "$GATE" "$TMP/no-such-taxonomy") >/dev/null 2>&1
check "missing taxonomy dir -> exit 2" 2 $?
(cd "$WORK" && bash "$GATE") >/dev/null 2>&1
check "no taxonomy arg -> exit 2" 2 $?

if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit "$fail"
