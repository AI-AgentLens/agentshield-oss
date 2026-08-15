package analyzer_test

// Fitness function for the required-literal prescan (internal/regexlit).
//
// The prescan is a pure accelerator sitting in front of EVERY command_regex in
// the shipped corpus. Its failure mode is silent and one-directional: a wrongly
// derived literal makes a rule stop matching, and a rule that stops matching
// does not error, does not log, and does not fail any test that only asserts on
// the commands it currently blocks. It just quietly stops enforcing.
//
// So the gate is differential, not behavioural: for every shipped pattern that
// gets a prescan, the prescan's verdict must equal the raw regexp's verdict on
// every command in the corpus. Nothing about which rules SHOULD match — only
// that adding the accelerator changed no answer anywhere.
//
// Per CLAUDE.md "gates must be able to fail": TestRegexLitParityGateDetectsUnsound
// below plants a deliberately unsound literal and asserts this comparison
// catches it. Without that, a differential test that silently compared zero
// patterns would read as proof.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/regexlit"
	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// Floors keep the comparison from going vacuous. Measured 2026-08-09 at 811
// shipped patterns (767 with a prescan) over 1806+ corpus commands; the floors
// sit well under that so ordinary corpus churn does not trip them, while a
// collapsed loader (wrong path, changed YAML shape, renamed field) does.
const (
	regexLitPatternFloor  = 500
	regexLitPrescanFloor  = 400
	regexLitCorpusCmdFlor = 1000
)

type regexLitProbeRule struct {
	ID    string `yaml:"id"`
	Match struct {
		CommandRegex        string `yaml:"command_regex"`
		CommandRegexExclude string `yaml:"command_regex_exclude"`
	} `yaml:"match"`
}

type regexLitProbePack struct {
	Rules []regexLitProbeRule `yaml:"rules"`
}

// shippedCommandPatterns collects every command_regex / command_regex_exclude
// the product ships: embedded community packs plus, when present, the premium
// tree on disk. Premium is read from disk rather than an embed because only
// community shell packs are embedded; an OSS-only checkout has no premium
// directory and simply contributes nothing.
//
// Covering premium matters here specifically: TestPipelinePerfBudget loads
// community packs only, so a premium-only regression has no other gate.
func shippedCommandPatterns(t *testing.T) map[string]string {
	t.Helper()
	out := make(map[string]string) // pattern -> owning rule id (for diagnostics)

	collect := func(src string, b []byte) {
		var p regexLitProbePack
		if err := yaml.Unmarshal(b, &p); err != nil {
			// A pack whose top-level shape does not parse here is not this
			// test's business (the pack loader has its own validation), but
			// log it so a silent whole-pack drop is visible.
			t.Logf("regexlit parity: skipping unparseable %s: %v", src, err)
			return
		}
		for _, r := range p.Rules {
			for _, pat := range [...]string{r.Match.CommandRegex, r.Match.CommandRegexExclude} {
				if pat == "" {
					continue
				}
				if _, seen := out[pat]; !seen {
					out[pat] = r.ID
				}
			}
		}
	}

	for name, b := range packs.ShellFiles() {
		collect("community/"+name, b)
	}

	premiumGlob := filepath.Join("..", "..", "packs", "premium", "*.yaml")
	premiumFiles, _ := filepath.Glob(premiumGlob)
	for _, f := range premiumFiles {
		if strings.HasPrefix(filepath.Base(f), "_") {
			continue // disabled legacy pack
		}
		b, err := os.ReadFile(f) //nolint:gosec // fixed in-repo test path
		if err != nil {
			continue
		}
		collect(f, b)
	}
	if len(premiumFiles) == 0 {
		t.Log("regexlit parity: no premium packs on disk (OSS-only checkout) — community coverage only")
	}
	return out
}

// corpusInputs is the command corpus plus case-mutated forms. The case
// mutations exist because the prescan takes a different code path for
// case-folded patterns (containsFoldASCII) than for exact ones
// (strings.Contains), and only mixed-case input exercises it.
func corpusInputs(t *testing.T) []string {
	t.Helper()
	cases := testdata.AllTestCases()
	inputs := make([]string, 0, len(cases)*3)
	for _, tc := range cases {
		inputs = append(inputs,
			tc.Command,
			strings.ToUpper(tc.Command),
			strings.ToLower(tc.Command),
		)
	}
	return inputs
}

// firstDivergence reports the first input where the matcher's verdict differs
// from the reference regexp's, or ok=true when they agree everywhere.
//
// Both the gate and its negative control call this, so the control proves the
// gate's actual comparison detects unsoundness — not a lookalike written
// alongside it.
func firstDivergence(m *regexlit.Matcher, re *regexp.Regexp, inputs []string) (bad string, want, got bool, ok bool) {
	for _, in := range inputs {
		w, g := re.MatchString(in), m.MatchString(in)
		if w != g {
			return in, w, g, false
		}
	}
	return "", false, false, true
}

// TestRegexLitParityAgainstCorpus is the gate: prescan verdict == regexp
// verdict, for every shipped pattern over the whole corpus.
func TestRegexLitParityAgainstCorpus(t *testing.T) {
	t.Parallel()

	patterns := shippedCommandPatterns(t)
	inputs := corpusInputs(t)

	assertProbeNotVacuous(t, "regexlit parity: shipped patterns", len(patterns), regexLitPatternFloor)
	assertProbeNotVacuous(t, "regexlit parity: corpus inputs", len(inputs), regexLitCorpusCmdFlor)

	var withPrescan, compared int
	for pattern, ruleID := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue // pack loader rejects these separately
		}
		m := regexlit.NewFromRegexp(re)
		if !m.HasPrescan() {
			continue // no acceleration, nothing to diverge
		}
		withPrescan++
		compared += len(inputs)
		if bad, want, got, ok := firstDivergence(m, re, inputs); !ok {
			t.Fatalf("prescan changed a verdict — rule %s\n"+
				"  pattern:  %s\n"+
				"  literals: %q\n"+
				"  input:    %q\n"+
				"  regexp=%v prescan=%v\n"+
				"A prescan may only skip inputs that could not have matched. "+
				"A false skip silently disables this rule.",
				ruleID, pattern, m.Literals(), bad, want, got)
		}
	}

	assertProbeNotVacuous(t, "regexlit parity: patterns with a prescan", withPrescan, regexLitPrescanFloor)
	t.Logf("regexlit parity: %d/%d shipped patterns prescanned (%.1f%%), %d pattern x input verdicts compared",
		withPrescan, len(patterns), 100*float64(withPrescan)/float64(len(patterns)), compared)
}

// TestRegexLitParityGateDetectsUnsound is the negative control required by
// CLAUDE.md ("a new gate ships with a test that makes it fail").
//
// It builds a matcher whose prescan is genuinely unsound for the regexp it is
// paired with — the literals come from a narrow pattern, the reference regexp
// is a broader one — and asserts firstDivergence catches it. That is exactly
// the silent-disable failure mode the gate exists for, and it is reproduced
// through public API only: no test-only backdoor into regexlit that could
// itself drift away from the real construction path.
func TestRegexLitParityGateDetectsUnsound(t *testing.T) {
	t.Parallel()

	// Prescan derived from a pattern requiring "/etc/shadow"...
	narrow, err := regexlit.Compile(`rm\s+-rf\s+/etc/shadow`)
	if err != nil {
		t.Fatal(err)
	}
	if !narrow.HasPrescan() {
		t.Fatal("precondition: narrow pattern should yield a prescan")
	}
	// ...paired against a regexp that also matches inputs without it.
	broad := regexp.MustCompile(`rm\s+-rf\s+/`)

	inputs := []string{"rm -rf /", "rm -rf /etc/shadow", "ls"}
	bad, want, got, ok := firstDivergence(narrow, broad, inputs)
	if ok {
		t.Fatal("firstDivergence found no divergence between an unsound prescan " +
			"and its reference regexp — TestRegexLitParityAgainstCorpus cannot " +
			"detect a wrongly derived literal and therefore proves nothing")
	}
	if bad != "rm -rf /" || want != true || got != false {
		t.Errorf("unexpected divergence report: input=%q want=%v got=%v", bad, want, got)
	}

	// And confirm the corpus loader itself is not the vacuous part.
	if n := len(shippedCommandPatterns(t)); n < regexLitPatternFloor {
		t.Fatalf("shipped pattern loader returned %d patterns (floor %d)", n, regexLitPatternFloor)
	}
}
