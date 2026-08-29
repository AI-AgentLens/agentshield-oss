package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

func shadowRule() Rule {
	return Rule{
		ID:       "test-shadow-position-exclude",
		Taxonomy: "credential-exposure/password-db-access/system-shadow-read",
		Match: Match{
			CommandRegex:           `(/etc/shadow|/etc/master\.passwd)`,
			CommandPositionExclude: []string{analyzer.LabelPosLoopWordList},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

func fridaNameRule() Rule {
	return Rule{
		ID:       "test-frida-name-position-exclude",
		Taxonomy: "credential-exposure/process-credential/ptrace-process-attach",
		Match: Match{
			CommandRegex:           `(?:sudo\s+)?frida\b(?:\s+\S+)*?\s+(?:-n|--name)\s+\S+`,
			CommandPositionExclude: []string{analyzer.LabelPosSearchNeedle},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

func sitecustomizeRule() Rule {
	return Rule{
		ID:       "test-sitecustomize-position-exclude",
		Taxonomy: "persistence-evasion/shell-init/python-pth-persistence",
		Match: Match{
			CommandRegex:           `(echo|printf|tee|cat|cp|mv|install)\b.*\b(site|user)customize\.py`,
			CommandPositionExclude: []string{analyzer.LabelPosHeredocBody},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

// An unknown position label must fail policy load, not silently no-op. It
// needs this more than an intent label does: the exclusion only ever runs
// AFTER a match has fired, so a typo is invisible to every test that asserts
// the rule fires and shows up only as the false positive the rule opted out of.
func TestUnknownPositionLabelFailsLoad(t *testing.T) {
	r := shadowRule()
	r.Match.CommandPositionExclude = []string{"loop_word_list"}
	if _, err := NewEngineWithAnalyzers(&Policy{Rules: []Rule{r}}, 2); err == nil {
		t.Fatal("expected policy load to reject an unknown position label")
	}
	if _, err := NewEngineWithAnalyzers(&Policy{Rules: []Rule{shadowRule()}}, 2); err != nil {
		t.Fatalf("valid label must load: %v", err)
	}
}

// command_position_exclude has to be implemented on BOTH evaluation paths —
// the regex-only fallback (Engine.matchRule) and the analyzer pipeline
// (RegexAnalyzer.Analyze). #3232 and #3234 are the two times a match-field
// was wired to one path only and shipped as a latent trap; this is the test
// that would have caught either.
func TestPositionExcludeParityAcrossEvaluationPaths(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{shadowRule()}}
	testPositionExcludeParity(t, pol, []struct {
		name    string
		command string
		want    Decision
	}{
		{
			"inert loop word list — the #3376 FP",
			`for p in ".ssh/" "/etc/shadow"; do n=$(grep -c -- "$p" "$F"); echo "$n <= $p"; done`,
			DecisionAudit,
		},
		{"plain read", `cat /etc/shadow`, DecisionBlock},
		{"loop variable is read", `for p in /etc/shadow; do cat "$p"; done`, DecisionBlock},
		{
			"inert loop chained with a quote-spliced read",
			`for p in /etc/shadow; do echo "$p"; done; cat /etc/sha'dow'`,
			DecisionBlock,
		},
	})
}

// Same parity guard as above, for the search_needle label added in #3382 —
// wired through the exact same analyzer.PositionExcluded call, but worth its
// own case because a rule whose signal spans two tokens ("frida" then "-n")
// stresses the predicate differently than a single literal path does.
func TestPositionExcludeSearchNeedleParityAcrossEvaluationPaths(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{fridaNameRule()}}
	testPositionExcludeParity(t, pol, []struct {
		name    string
		command string
		want    Decision
	}{
		{
			"quoted multi-word needle — the #3382 FP",
			`grep -i "frida -n <process>" -r docs/`,
			DecisionAudit,
		},
		{"genuine attach", `frida -n chrome`, DecisionBlock},
		{
			"needle plus a genuine attach elsewhere",
			`grep -i "frida -n <process>" -r docs/ && frida -n chrome`,
			DecisionBlock,
		},
	})
}

// Same parity guard, for the heredoc_body label added in #3397 — a rule
// whose signal spans two co-required tokens (an executable word and a
// filename) rather than one contiguous region, which is the shape that made
// attribution worth stress-testing on its own (see position_test.go).
func TestPositionExcludeHeredocBodyParityAcrossEvaluationPaths(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{sitecustomizeRule()}}
	testPositionExcludeParity(t, pol, []struct {
		name    string
		command string
		want    Decision
	}{
		{
			"both trigger tokens co-located in heredoc body prose — the #3397 FP",
			"cat > \"$S/notes.md\" <<'EOF'\n- blocks cat/tee writes to sitecustomize.py\nEOF",
			DecisionAudit,
		},
		{"plain write", "cp backdoor.py sitecustomize.py", DecisionBlock},
		{
			"filename is the real write target, not body prose",
			"cat > sitecustomize.py <<'EOF'\nimport os\nEOF",
			DecisionBlock,
		},
	})
}

func testPositionExcludeParity(t *testing.T, pol *Policy, cases []struct {
	name    string
	command string
	want    Decision
}) {
	t.Helper()
	fallback, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pipeline, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range []struct {
				label  string
				engine *Engine
			}{{"fallback", fallback}, {"pipeline", pipeline}} {
				got := e.engine.Evaluate(tc.command, nil).Decision
				if got != tc.want {
					t.Errorf("%s engine: Evaluate(%q) = %s, want %s", e.label, tc.command, got, tc.want)
				}
			}
		})
	}
}

// A rule that does not opt in must be byte-for-byte unaffected — the whole
// mechanism is dead code for the other ~1,500 rules.
func TestPositionExcludeIsOptInAtRuleLevel(t *testing.T) {
	r := shadowRule()
	r.Match.CommandPositionExclude = nil
	engine, err := NewEngineWithAnalyzers(&Policy{Rules: []Rule{r}}, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	cmd := `for p in "/etc/shadow"; do echo "$p"; done`
	if got := engine.Evaluate(cmd, nil).Decision; got != DecisionBlock {
		t.Fatalf("rule without the opt-in must still fire: got %s", got)
	}
}
