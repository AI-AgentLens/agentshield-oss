#!/usr/bin/env bash
# Smoke test for check-oss-issue-templates.sh — proves the check can fail.
#
# The defect this gate exists for (a README link to a template that publish
# strips) survived because the check that covered it could only return green.
# A replacement that is itself unfalsifiable would be no better, so every
# branch that is supposed to exit non-zero is exercised here.
#
# Run: bash scripts/check-oss-issue-templates_test.sh
set -uo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/check-oss-issue-templates.sh"
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

# tree <name> — a root with a README linking one template.
tree() {
  local d="$TMP/$1"
  mkdir -p "$d/.github/ISSUE_TEMPLATE"
  cat > "$d/README.md" <<'MD'
# Sample

- False negative: add a local rule and open a [Rule Request](https://github.com/ORG/REPO/issues/new?template=rule-request.yml)
MD
  echo "$d"
}

echo "check-oss-issue-templates (referenced templates must ship):"

# Case 1: link + template present -> green. Also pins that the template name is
# parsed off the query string rather than the whole URL.
D="$(tree present)"
echo "name: Rule Request" > "$D/.github/ISSUE_TEMPLATE/rule-request.yml"
"$GATE" "$D" > "$TMP/out1.txt" 2>&1
check "link with its template -> green" 0 $?
contains "names the resolved template" "$TMP/out1.txt" "ok:   rule-request.yml"

# Case 2: the real defect — README ships, .github/ does not. This is the exact
# state of the published repo that no reachability probe could see.
D="$(tree stripped)"
rm -rf "$D/.github"
"$GATE" "$D" > "$TMP/out2.txt" 2>&1
check "link whose template was stripped -> red" 1 $?
contains "names the missing path" "$TMP/out2.txt" ".github/ISSUE_TEMPLATE/rule-request.yml"

# Case 3: template dir exists but the referenced file does not (a rename or a
# typo'd link). Distinct from case 2 — an exclude rule is not involved.
D="$(tree renamed)"
echo "name: Other" > "$D/.github/ISSUE_TEMPLATE/rule_request.yml"   # underscore
"$GATE" "$D" > "$TMP/out3.txt" 2>&1
check "referenced name does not match the shipped file -> red" 1 $?

# Case 4: positive control. A README with no template link at all must NOT
# report clean — 0 broken out of 0 extracted is the vacuous-green shape this
# whole check exists to avoid.
D="$(tree nolinks)"
echo "# Sample with no issue links" > "$D/README.md"
"$GATE" "$D" > "$TMP/out4.txt" 2>&1
check "zero extracted links -> red (parser guard)" 1 $?
contains "says the check measured nothing" "$TMP/out4.txt" "not measuring anything"

# Case 5: --expect-min 0 is the deliberate opt-out for a tree that genuinely
# links no template. It must still pass the guard rather than being unreachable.
"$GATE" "$D" --expect-min 0 > "$TMP/out5.txt" 2>&1
check "zero links with --expect-min 0 -> green" 0 $?

# Case 6: several links, one missing. The loop must not stop at the first ok.
D="$(tree multi)"
cat >> "$D/README.md" <<'MD'
Also [Bug](https://github.com/ORG/REPO/issues/new?template=bug_report.md) and
[Feature](https://github.com/ORG/REPO/issues/new?template=feature_request.md).
MD
echo "x" > "$D/.github/ISSUE_TEMPLATE/rule-request.yml"
echo "x" > "$D/.github/ISSUE_TEMPLATE/bug_report.md"
"$GATE" "$D" --expect-min 3 > "$TMP/out6.txt" 2>&1
check "one missing among three -> red" 1 $?
contains "still reports the ok ones" "$TMP/out6.txt" "ok:   bug_report.md"
contains "names only the missing one" "$TMP/out6.txt" "FAIL: feature_request.md"

# Case 7: --expect-min guards against a parser that silently stops matching.
# Three links exist; demanding four must fail even though none are broken.
"$GATE" "$D" --expect-min 4 > "$TMP/out7.txt" 2>&1
check "fewer links than --expect-min -> red" 1 $?

# Case 8: a query string with extra params must not swallow them into the
# filename (?template=x.yml&title=... is a real GitHub form URL).
D="$(tree params)"
cat > "$D/README.md" <<'MD'
[Rule Request](https://github.com/ORG/REPO/issues/new?template=rule-request.yml&title=%5BRULE%5D+)
MD
echo "x" > "$D/.github/ISSUE_TEMPLATE/rule-request.yml"
"$GATE" "$D" > "$TMP/out8.txt" 2>&1
check "trailing &param not parsed into the filename -> green" 0 $?

# Case 9: README_oss.md alone (the private repo's shape before publish renames
# it). Checking only README.md would miss the link entirely.
D="$TMP/ossname"; mkdir -p "$D/.github/ISSUE_TEMPLATE"
cat > "$D/README_oss.md" <<'MD'
[Rule Request](https://github.com/ORG/REPO/issues/new?template=rule-request.yml)
MD
"$GATE" "$D" > "$TMP/out9.txt" 2>&1
check "README_oss.md is scanned too -> red when template absent" 1 $?

# Case 10: no README at all is an error, not a pass.
D="$TMP/empty"; mkdir -p "$D"
"$GATE" "$D" > "$TMP/out10.txt" 2>&1
check "no README -> error" 1 $?

# Case 11: a nonexistent root is a usage error (exit 2), distinct from a
# content failure (exit 1), so a typo'd path in CI cannot read as a defect.
"$GATE" "$TMP/does-not-exist" > "$TMP/out11.txt" 2>&1
check "missing root -> usage error" 2 $?

echo ""
if [ "$fail" -eq 0 ]; then echo "check-oss-issue-templates_test: PASS"; else echo "check-oss-issue-templates_test: FAIL"; fi
exit "$fail"
