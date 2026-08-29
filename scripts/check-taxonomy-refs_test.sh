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
mkdir -p "$WORK/packs" "$WORK/internal/fake" "$WORK/scripts"
# A resolving Go-source ref so cases 1-6 (which exercise the packs/ tier only)
# don't trip the Go-source tier's own vacuity guard. Real content, not a
# throwaway string: it resolves in $TAX so the Go-source tier reports clean.
cat > "$WORK/internal/fake/x.go" <<'EOF'
package fake
var x = Finding{TaxonomyRef: "destructive-ops/fs-destruction/system-directory-delete"}
EOF
touch "$WORK/scripts/go-ref-baseline.txt"

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

# ── Tier 2: "resolves, but not yet published" (#3429) ───────────────────────
#
# Tier 2 reports refs that resolve in taxonomy/ but are absent from the
# PUBLISHED artifact. It must never change the exit code, and it must never
# report "0 awaiting publication" when it actually extracted nothing — that
# vacuous shape is the whole reason the tier exists (a silently-green gate is
# what let aiagentlens#135 run five nights).

absent() { # <desc> <file> <needle>
  if grep -qF "$3" "$2"; then echo "  FAIL: $1 — output mentioned '$3' and should not"; fail=1
  else echo "  ok: $1"; fi
}

# make_artifact <outfile> <version> <id...>
# Writes a minimal taxonomy-compliance.json shaped like the real one: a
# standards[] block whose control ids are FLAT (no '/'), so the fixture also
# proves the extraction does not mistake control ids for entry ids.
make_artifact() {
  local out="$1"; shift
  local ver="$1"; shift
  local n=$#
  {
    echo '{'
    echo '  "schema_version": "1.0.0",'
    echo "  \"artifact_version\": \"$ver\","
    echo '  "producer": "AI-AgentLens/AI_risk_compliance",'
    echo '  "counts": {'
    echo '    "standards": 1,'
    echo '    "controls": 2,'
    echo "    \"entries\": $n,"
    echo "    \"mapped_entries\": $n,"
    echo '    "mappings": 2'
    echo '  },'
    echo '  "standards": ['
    echo '    {'
    echo '      "id": "iso-42001-2023",'
    echo '      "controls": [ { "id": "A.6.2.2" }, { "id": "AML.T0011" } ]'
    echo '    }'
    echo '  ],'
    echo '  "entries": ['
    local first=1 id
    for id in "$@"; do
      if [ "$first" -eq 1 ]; then first=0; else echo '    ,'; fi
      echo "    { \"id\": \"$id\", \"name\": \"n\", \"compliance\": [] }"
    done
    echo '  ]'
    echo '}'
  } > "$out"
}

echo ""
echo "check-taxonomy-refs tier 2 — publication lag (#3429):"

# A second fake tree with THREE resolvable nodes, and a pack citing all three.
T2="$TMP/tier2"
T2TAX="$T2/taxonomy"
T2WORK="$T2/repo"
mkdir -p "$T2TAX/destructive-ops/fs-destruction" \
         "$T2TAX/credential-exposure/ssh" \
         "$T2WORK/packs" \
         "$T2WORK/internal/fake" \
         "$T2WORK/scripts"
echo "id: a" > "$T2TAX/destructive-ops/fs-destruction/system-directory-delete.yaml"
echo "id: b" > "$T2TAX/credential-exposure/ssh/private-key-read.yaml"
echo "id: c" > "$T2TAX/credential-exposure/ssh/known-hosts-harvest.yaml"

A_ID=destructive-ops/fs-destruction/system-directory-delete
B_ID=credential-exposure/ssh/private-key-read
C_ID=credential-exposure/ssh/known-hosts-harvest

# Same reasoning as $WORK above: tier 2's own cases don't exercise the
# Go-source tier, so give it a resolving ref and an empty baseline.
cat > "$T2WORK/internal/fake/x.go" <<EOF
package fake
var x = Finding{TaxonomyRef: "$A_ID"}
EOF
touch "$T2WORK/scripts/go-ref-baseline.txt"

cat > "$T2WORK/packs/p.yaml" <<EOF
rules:
  - id: r1
    taxonomy: $A_ID
  - id: r2
    taxonomy: $B_ID
  - id: r3
    taxonomy: $C_ID
EOF

# Case 7: BACK-COMPAT. One argument, exactly as ~/dev/CLAUDE.md documents the
# local pre-flight. Exit 0, and not one word of tier-2 output.
(cd "$T2WORK" && bash "$GATE" "$T2TAX") > "$TMP/out7.txt" 2>&1
check "no artifact arg -> pass, unchanged behaviour" 0 $?
absent "no artifact arg -> no tier-2 output" "$TMP/out7.txt" "tier 2"
absent "no artifact arg -> no publication wording" "$TMP/out7.txt" "awaiting publication"

# Case 8: artifact publishes every ref -> exit 0, 0 awaiting, denominator shown.
make_artifact "$T2/full.json" "5.0.0" "$A_ID" "$B_ID" "$C_ID"
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/full.json") > "$TMP/out8.txt" 2>&1
check "fully published -> pass" 0 $?
contains "reports zero awaiting" "$TMP/out8.txt" "0 awaiting publication"
contains "prints the denominator" "$TMP/out8.txt" \
  "3 refs checked against 3 published entries (artifact v5.0.0)"

# Case 9: THE POSITIVE CONTROL. Without this the tier is unfalsifiable — a
# check that can only ever say "0 awaiting" proves nothing. Publish exactly one
# of the three refs; the other two must be named, and the published one must
# not be.
make_artifact "$T2/partial.json" "4.9.0" "$A_ID"
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/partial.json") > "$TMP/out9.txt" 2>&1
check "2 refs unpublished -> STILL exit 0 (non-fatal by design)" 0 $?
contains "counts exactly 2 awaiting" "$TMP/out9.txt" "2 awaiting publication"
contains "names the first unpublished ref" "$TMP/out9.txt" "  - $B_ID"
contains "names the second unpublished ref" "$TMP/out9.txt" "  - $C_ID"
absent "does not name the published ref" "$TMP/out9.txt" "  - $A_ID"

# Case 10: artifact path does not exist -> usage error, loud. Never a silent
# skip: `command -v jq || exit 0` is the anti-pattern this tier must not become.
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/no-such-file.json") > "$TMP/out10.txt" 2>&1
check "missing artifact path -> exit 2" 2 $?
contains "explains the missing artifact" "$TMP/out10.txt" "is not a readable file"

# Case 11: artifact is unparseable / not the artifact at all -> zero ids
# extracted -> FAIL LOUDLY rather than report "0 awaiting publication".
echo "this is not json" > "$T2/garbage.json"
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/garbage.json") > "$TMP/out11.txt" 2>&1
check "unparseable artifact -> exit 1" 1 $?
contains "explains the empty entry set" "$TMP/out11.txt" "extracted 0 published taxonomy entry ids"
# The tier-2 report line itself must never be printed here. (Asserting on the
# words "0 awaiting publication" would be a false pass: the failure message
# quotes that phrase on purpose, to say why it is refusing to print it.)
absent "must not print a tier-2 result line" "$TMP/out11.txt" "refs checked against"

# Case 12: well-formed artifact with an EMPTY entries list -> same reasoning.
make_artifact "$T2/empty.json" "5.0.0"
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/empty.json") > "$TMP/out12.txt" 2>&1
check "zero-entry artifact -> exit 1" 1 $?
contains "explains the empty entry set" "$TMP/out12.txt" "extracted 0 published taxonomy entry ids"

# Case 13: schema drift — the entries are there but counts.entries was renamed,
# so the extraction has no denominator to validate itself against.
sed 's/"entries": 3,/"nodes": 3,/' "$T2/full.json" > "$T2/renamed.json"
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/renamed.json") > "$TMP/out13.txt" 2>&1
check "counts.entries renamed -> exit 1" 1 $?
contains "refuses an unverified denominator" "$TMP/out13.txt" "could not read counts.entries"

# Case 14: schema drift the other way — extraction and counts.entries disagree,
# which means the id heuristic has stopped matching the schema. Must be loud.
sed 's/"entries": 3,/"entries": 7,/' "$T2/full.json" > "$T2/mismatch.json"
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/mismatch.json") > "$TMP/out14.txt" 2>&1
check "count mismatch -> exit 1" 1 $?
contains "names both numbers" "$TMP/out14.txt" "declares counts.entries=7"

# Case 15: a tier-1 orphan still fails even with a valid artifact — tier 2 must
# not soften tier 1.
cat >> "$T2WORK/packs/p.yaml" <<'EOF'
  - id: r4
    taxonomy: bogus-kingdom/not/real
EOF
(cd "$T2WORK" && bash "$GATE" "$T2TAX" "$T2/full.json") > "$TMP/out15.txt" 2>&1
check "orphan ref + valid artifact -> still exit 1" 1 $?
contains "names the orphan ref" "$TMP/out15.txt" "bogus-kingdom/not/real"
# Rewrite rather than sed the orphan back out: `sed -i` and relative line
# addresses differ between GNU and BSD, and this suite runs on both.
cat > "$T2WORK/packs/p.yaml" <<EOF
rules:
  - id: r1
    taxonomy: $A_ID
  - id: r2
    taxonomy: $B_ID
  - id: r3
    taxonomy: $C_ID
EOF

# Case 16: the report reaches $GITHUB_STEP_SUMMARY, which is the only reason a
# non-fatal finding gets seen at all.
SUMMARY="$T2/summary.md"
: > "$SUMMARY"
(cd "$T2WORK" && GITHUB_STEP_SUMMARY="$SUMMARY" bash "$GATE" "$T2TAX" "$T2/partial.json") >/dev/null 2>&1
check "step summary run -> exit 0" 0 $?
contains "summary names the unpublished ref" "$SUMMARY" "$B_ID"
contains "summary states the caveat about the SaaS pin" "$SUMMARY" "pinned copy, which may lag main"

# ── Go-source taxonomy refs (#3508) ──────────────────────────────────────────
#
# Shield emits TaxonomyRef directly from Go source (analyzer findings, MCP
# handler audit events), a surface the packs/ scan above cannot see. This
# section builds its own fixtures per case since each one needs a different
# internal/ tree and go-ref-baseline.txt.

echo ""
echo "check-taxonomy-refs Go-source tier (#3508):"

T3="$TMP/gosrc"
T3TAX="$T3/taxonomy"
mkdir -p "$T3TAX/credential-exposure/private-key-access"
echo "id: x" > "$T3TAX/credential-exposure/private-key-access/ssh-private-key-read.yaml"
REAL_ID=credential-exposure/private-key-access/ssh-private-key-read

new_t3work() { # sets T3WORK to a fresh repo with one resolving pack ref
  T3WORK="$T3/repo-$1"
  mkdir -p "$T3WORK/packs" "$T3WORK/internal/fake" "$T3WORK/scripts"
  cat > "$T3WORK/packs/p.yaml" <<EOF
rules:
  - id: r1
    taxonomy: $REAL_ID
EOF
  touch "$T3WORK/scripts/go-ref-baseline.txt"
}

# Case 17: a Go-source orphan with no baseline entry -> FAIL, names it.
new_t3work 17
cat > "$T3WORK/internal/fake/x.go" <<'EOF'
package fake
var x = Finding{TaxonomyRef: "totally-bogus/not-real/orphan"}
EOF
(cd "$T3WORK" && bash "$GATE" "$T3TAX") > "$TMP/out17.txt" 2>&1
check "Go-source orphan, not baselined -> fail" 1 $?
contains "names the Go-source orphan" "$TMP/out17.txt" "totally-bogus/not-real/orphan"

# Case 18: the same orphan, but baselined -> PASS.
new_t3work 18
cat > "$T3WORK/internal/fake/x.go" <<'EOF'
package fake
var x = Finding{TaxonomyRef: "totally-bogus/not-real/orphan"}
EOF
cat > "$T3WORK/scripts/go-ref-baseline.txt" <<'EOF'
# test fixture
totally-bogus/not-real/orphan
EOF
(cd "$T3WORK" && bash "$GATE" "$T3TAX") > "$TMP/out18.txt" 2>&1
check "Go-source orphan, baselined -> pass" 0 $?

# Case 19: THE RATCHET. A baselined ref that now resolves must FAIL, naming
# the entry that has to come out — the baseline can only ever shrink.
new_t3work 19
cat > "$T3WORK/internal/fake/x.go" <<EOF
package fake
var x = Finding{TaxonomyRef: "$REAL_ID"}
EOF
cat > "$T3WORK/scripts/go-ref-baseline.txt" <<EOF
$REAL_ID
EOF
(cd "$T3WORK" && bash "$GATE" "$T3TAX") > "$TMP/out19.txt" 2>&1
check "baselined ref now resolves (FIXED) -> fail" 1 $?
contains "names the stale baseline entry" "$TMP/out19.txt" "$REAL_ID"
contains "explains the ratchet" "$TMP/out19.txt" "baseline only ever shrinks"

# Case 20: a ref built by string concatenation cannot be resolved statically
# and must be excluded, not treated as an orphan.
new_t3work 20
cat > "$T3WORK/internal/fake/x.go" <<'EOF'
package fake
var x = Finding{TaxonomyRef: "some-prefix/" + suffix}
EOF
(cd "$T3WORK" && bash "$GATE" "$T3TAX") > "$TMP/out20.txt" 2>&1
check "concatenated ref -> excluded, not fatal" 0 $?
contains "reports the exclusion" "$TMP/out20.txt" "1 concatenation-built, excluded"

# Case 21: zero TaxonomyRef literals anywhere in Go source -> the Go-source
# tier's own vacuity guard, distinct from the packs/ one (case 4/5 above).
new_t3work 21
cat > "$T3WORK/internal/fake/x.go" <<'EOF'
package fake
var x = 1
EOF
(cd "$T3WORK" && bash "$GATE" "$T3TAX") > "$TMP/out21.txt" 2>&1
check "no Go-source refs at all -> fail, not vacuous pass" 1 $?
contains "explains the empty Go-source ref set" "$TMP/out21.txt" "found no 'TaxonomyRef:' literal"

# Case 22: no go-ref-baseline.txt file at all (not even empty) -> every
# current orphan reads as NEW. Fail-safe: an absent baseline approves nothing.
new_t3work 22
cat > "$T3WORK/internal/fake/x.go" <<'EOF'
package fake
var x = Finding{TaxonomyRef: "totally-bogus/not-real/orphan"}
EOF
rm -f "$T3WORK/scripts/go-ref-baseline.txt"
(cd "$T3WORK" && bash "$GATE" "$T3TAX") > "$TMP/out22.txt" 2>&1
check "missing baseline file -> orphan still reported as new -> fail" 1 $?
contains "names the orphan with no baseline file present" "$TMP/out22.txt" "totally-bogus/not-real/orphan"

if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES"; fi
exit "$fail"
