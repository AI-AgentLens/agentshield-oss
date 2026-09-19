package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The predicate.
// ---------------------------------------------------------------------------

// preFix3842 is ts-block-cicd-cp-mv as it shipped before #3845 — the regex
// that BLOCKed `echo "mcp packs"; cat .github/workflows/ci.yml`.
const preFix3842 = `(cp|mv)(\s+-\S+)*\s+\S+\s+(\./)?(.*\.github/workflows/|Jenkinsfile|\.gitlab-ci\.yml|\.circleci/config\.yml|\.travis\.yml)`

// postFix3845 is the same rule as merged in #3845.
const postFix3845 = `\b(cp|mv)(\s+-\S+)*\s+\S+\s+(\./)?([^;&|\n]*\.github/workflows/|Jenkinsfile|\.gitlab-ci\.yml|\.circleci/config\.yml|\.travis\.yml)`

func TestClassify(t *testing.T) {
	cases := []struct {
		name  string
		re    string
		verb  bool // half 1
		span  bool // half 2
		flags bool
	}{
		// The two rules the issue is about.
		{"3842 pre-fix regex is flagged", preFix3842, true, true, true},
		{"3845 fixed regex is not flagged", postFix3845, false, false, false},

		// Anchoring on the leading group.
		{"bare group + span", `(cp|mv)\s+.*x`, true, true, true},
		{"word-boundary anchored", `\b(cp|mv)\s+.*x`, false, true, false},
		{"start anchored", `^(cp|mv)\s+.*x`, false, true, false},
		{"command-position group is anchors, not words", `(?:^|\s)(cp|mv)\s+.*x`, false, true, false},
		{"trailing word boundary does not anchor the start", `(curl|wget)\b.*x`, true, true, true},
		{"leading inline flags are stripped", `(?i)(cat|less)\s+.*x`, true, true, true},
		{"several leading flag groups", `(?i)(?s)(cat|less)\s+.*x`, true, true, true},
		{"non-capturing group is still a plain group", `(?:cat|less)\s+.*x`, true, true, true},
		{"flag-scoped group is still a plain group", `(?i:cat|less)\s+.*x`, true, true, true},
		{"leading whitespace is trimmed", `  (cat|less)\s+.*x`, true, true, true},
		{"optional leading group still leads", `(sudo|doas)?\s*(rm|shred)\s+.*x`, true, true, true},

		// The delegated decision: a non-word alternative does NOT
		// disqualify the group, because the bare `cp` branch still carries
		// the hazard. Pinned here so changing it is deliberate.
		{"mixed group with a path alternative", `(cp|mv|/usr/bin/cp)\s+.*x`, true, true, true},
		{"mixed group with a quantified alternative", `(python3?|node|ruby)\s+.*x`, true, true, true},
		{"group with no bare-word alternative", `(\s|^)cp\s+.*x`, false, true, false},
		{"uppercase is not a bare word", `(CAT|LESS)\s+.*x`, false, true, false},

		// The span.
		{"no span", `(cat|less)\s+x`, true, false, false},
		{"escaped dot-star is a literal", `(cp|mv)\s+\.\*x`, true, false, false},
		{"escaped backslash then dot-star is a span", `(cp|mv)\s+\\.*x`, true, true, true},
		{"dot-plus is a span", `(cp|mv)\s+.+x`, true, true, true},
		{"lazy dot-star is a span", `(cp|mv)\s+.*?x`, true, true, true},
		{"dot-star inside a character class is not a span", `(cp|mv)\s+[.*]x`, true, false, false},
		{"bounded negated class is the fix shape", `(cp|mv)\s+[^;&|\n]*x`, true, false, false},
		{"span inside the leading group does not count", `(cp|mv|.*)x`, true, false, false},
		{"span only before a later group", `(cp|mv)\s+[^ ]*\s+(.*)`, true, true, true},

		// Not groups.
		{"no group at all", `cp\s+.*x`, false, true, false},
		{"named group is not inspected", `(?P<v>cat|less)\s+.*x`, false, true, false},
		{"unclosed paren is not a group", `(cp|mv\s+.*x`, false, true, false},
		{"empty regex", ``, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.re)
			if got.LeadingVerbAlternation != tc.verb || got.UnboundedSpan != tc.span {
				t.Fatalf("classify(%q) = {verb:%v span:%v}, want {verb:%v span:%v}",
					tc.re, got.LeadingVerbAlternation, got.UnboundedSpan, tc.verb, tc.span)
			}
			if got.flagged() != tc.flags {
				t.Fatalf("classify(%q).flagged() = %v, want %v", tc.re, got.flagged(), tc.flags)
			}
		})
	}
}

// TestOneHalfAloneIsNotFlagged says it in one place: the gate is the
// CONJUNCTION. A rule with only the unanchored verb group, or only the span,
// is weaker than #3842 and not this gate's question.
func TestOneHalfAloneIsNotFlagged(t *testing.T) {
	onlyVerb := classify(`(cat|less)\s+x`)
	if !onlyVerb.LeadingVerbAlternation || onlyVerb.UnboundedSpan || onlyVerb.flagged() {
		t.Fatalf("verb-only regex: got %+v, want verb=true span=false flagged=false", onlyVerb)
	}
	onlySpan := classify(`\b(cp|mv)\s+.*x`)
	if onlySpan.LeadingVerbAlternation || !onlySpan.UnboundedSpan || onlySpan.flagged() {
		t.Fatalf("span-only regex: got %+v, want verb=false span=true flagged=false", onlySpan)
	}
}

func TestSplitTopLevel(t *testing.T) {
	got := splitTopLevel(`cp|mv|(a|b)|[|]x|\|y`)
	want := []string{"cp", "mv", "(a|b)", "[|]x", `\|y`}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("splitTopLevel = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// The ratchet, against a synthetic corpus.
// ---------------------------------------------------------------------------

func writePack(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeBaseline(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "baseline.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runIn(t *testing.T, packs, baseline string) (int, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(packs, baseline, false, true, &out, &errw)
	return code, out.String() + errw.String()
}

const cleanPack = `
name: clean
rules:
  - id: rule-anchored
    match:
      command_regex: \b(cat|less)\s+.*\.config/thing/
    decision: BLOCK
    reason: r
  - id: rule-no-span
    match:
      command_regex: (cat|less)\s+[^;&|\n]*\.config/thing/
    decision: BLOCK
    reason: r
  - id: rule-no-regex
    match:
      command_prefix: [thing]
    decision: AUDIT
    reason: r
`

const flaggedPack = `
name: flagged
rules:
  - id: rule-flagged
    match:
      command_regex: (cat|less)\s+.*\.config/thing/
    decision: BLOCK
    reason: r
`

func TestCleanCorpus_Passes(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 0 {
		t.Fatalf("clean corpus should pass, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "2 command_regex examined, 0 baselined, 0 new, 0 stale") {
		t.Fatalf("expected the summary line with the denominator:\n%s", out)
	}
}

func TestNewFlag_FailsAndNamesIdFileRegex(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "b.yaml", flaggedPack)
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 1 {
		t.Fatalf("new flagged rule must fail, got exit %d\n%s", code, out)
	}
	for _, want := range []string{"NEW  rule-flagged", "b.yaml", `command_regex: (cat|less)\s+.*\.config/thing/`, "1 new, 0 stale"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in the report:\n%s", want, out)
		}
	}
}

func TestBaselinedFlag_Passes(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "b.yaml", flaggedPack)
	bl := writeBaseline(t, d, "# debt\nrule-flagged\n")
	code, out := runIn(t, d, bl)
	if code != 0 {
		t.Fatalf("baselined rule should pass, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "3 command_regex examined, 1 baselined, 0 new, 0 stale") {
		t.Fatalf("expected the summary line:\n%s", out)
	}
}

// The ratchet's second direction: a row whose rule no longer flags must be
// deleted, so the baseline can only shrink.
func TestStaleRow_Fails(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	bl := writeBaseline(t, d, "rule-flagged\n")
	code, out := runIn(t, d, bl)
	if code != 1 {
		t.Fatalf("stale baseline row must fail, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "STALE  rule-flagged") || !strings.Contains(out, "0 new, 1 stale") {
		t.Fatalf("expected a STALE report:\n%s", out)
	}
}

func TestEmptyCorpus_RefusesToPass(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", "name: none\nrules:\n  - id: r\n    match:\n      command_prefix: [x]\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 2 {
		t.Fatalf("0 examined must be exit 2, got %d\n%s", code, out)
	}
}

func TestDisabledPackIsSkipped(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "_old.yaml", flaggedPack)
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 0 {
		t.Fatalf("_-prefixed pack must not count, got exit %d\n%s", code, out)
	}
}

func TestOtherIdBearingSectionsAreExamined(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", "name: s\nstructural_rules:\n  - id: sr-flagged\n    match:\n      command_regex: (cat|less)\\s+.*x\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 1 || !strings.Contains(out, "NEW  sr-flagged") {
		t.Fatalf("structural_rules must be examined, got exit %d\n%s", code, out)
	}
}

func TestUnknownIdBearingSection_IsRefused(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", "name: f\nfuture_rules:\n  - id: fr\n    match:\n      command_regex: x\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 2 || !strings.Contains(out, "future_rules") {
		t.Fatalf("unknown id-bearing section must be refused and named, got exit %d\n%s", code, out)
	}
}

// Block-scalar values (`command_regex: |-`) are how the longest regexes are
// written; a line-oriented grep sees only the key. The parser must see the
// value.
func TestBlockScalarRegexIsExamined(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", "name: b\nrules:\n  - id: block-flagged\n    match:\n      command_regex: |-\n        (?i)(curl|wget)\\s+.*https?://\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 1 || !strings.Contains(out, "NEW  block-flagged") {
		t.Fatalf("block-scalar regex must be examined and flagged, got exit %d\n%s", code, out)
	}
}

func TestDuplicateBaselineRow_IsRefused(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "b.yaml", flaggedPack)
	bl := writeBaseline(t, d, "rule-flagged\nrule-flagged\n")
	code, out := runIn(t, d, bl)
	if code != 2 {
		t.Fatalf("duplicate baseline row must be refused, got exit %d\n%s", code, out)
	}
}

func TestWriteBaseline_RoundTrips(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "b.yaml", flaggedPack)
	bl := filepath.Join(d, "baseline.txt")
	var out, errw bytes.Buffer
	if code := run(d, bl, true, false, &out, &errw); code != 0 {
		t.Fatalf("write-baseline failed: exit %d\n%s%s", code, out.String(), errw.String())
	}
	got, err := loadBaseline(bl)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got["rule-flagged"] {
		t.Fatalf("baseline after write = %v, want {rule-flagged}", got)
	}
	if code, report := runIn(t, d, bl); code != 0 {
		t.Fatalf("freshly written baseline should pass, got exit %d\n%s", code, report)
	}
}

// ---------------------------------------------------------------------------
// The live corpus.
// ---------------------------------------------------------------------------

// TestLiveCorpusMatchesCheckedInBaseline is the corpus smoke test. Three
// things it pins: the denominator (a parser regression that examines 0 — or
// only the inline scalars — fails here, not in CI a week later), the flagged
// SET equals the baseline set, and therefore the COUNT equals the baseline
// length. The corpus held 1377 command_regex values on introduction
// (2026-09-15); the floor is deliberately well below that.
func TestLiveCorpusMatchesCheckedInBaseline(t *testing.T) {
	sites, err := collect("../../packs")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(sites) < 1000 {
		t.Fatalf("examined only %d command_regex values — expected >1000; the scan is broken, not the corpus clean", len(sites))
	}
	flagged := map[string]bool{}
	for _, s := range sites {
		if classify(s.Regex).flagged() {
			flagged[s.key()] = true
		}
	}
	if len(flagged) == 0 {
		t.Fatalf("0 of %d command_regex flagged — the predicate is broken, not the corpus clean", len(sites))
	}
	baseline, err := loadBaseline("baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	for k := range flagged {
		if !baseline[k] {
			t.Errorf("NEW flagged rule not in baseline.txt: %s", k)
		}
	}
	for k := range baseline {
		if !flagged[k] {
			t.Errorf("STALE baseline row — %s no longer flags, delete the line", k)
		}
	}
	if len(flagged) != len(baseline) {
		t.Errorf("flagged %d rule(s) but baseline.txt lists %d", len(flagged), len(baseline))
	}
	if code, out := runIn(t, "../../packs", "baseline.txt"); code != 0 {
		t.Fatalf("run() against the live corpus: exit %d\n%s", code, out)
	}
}
