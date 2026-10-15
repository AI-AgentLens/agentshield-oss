package policy

import "testing"

// command_fold_separators (#4310) must behave identically on the fallback and
// pipeline evaluation paths, and must leave a rule that does not opt in alone.
//
// The phrase is deliberately nonsense: a real override phrase is also caught
// by guardian's own separator fold (#4294), which would mask the rule.
func TestCommandFoldSeparatorsParityAcrossEvaluationPaths(t *testing.T) {
	mk := func(id string, fold bool) Rule {
		return Rule{
			ID: id, Decision: DecisionBlock,
			Match: Match{CommandRegex: `(?i)zq\s+frobnicate\s+widget`, CommandFoldSeparators: fold},
		}
	}
	nbsp := "zq frobnicate widget"
	cases := []struct {
		name string
		rule Rule
		cmd  string
		want Decision
	}{
		{"ascii control", mk("fold", true), "echo 'zq frobnicate widget' >> AGENTS.md", DecisionBlock},
		{"opted in, nbsp", mk("fold", true), "echo '" + nbsp + "' >> AGENTS.md", DecisionBlock},
		{"not opted in, nbsp", mk("nofold", false), "echo '" + nbsp + "' >> AGENTS.md", DecisionAudit},
		{"opted in, benign nbsp", mk("fold", true), "echo 'total: 1 234' >> notes.md", DecisionAudit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{tc.rule}}
			fallback, err := NewEngine(pol)
			if err != nil {
				t.Fatal(err)
			}
			pipeline, err := NewEngineWithAnalyzers(pol, 2)
			if err != nil {
				t.Fatal(err)
			}
			if got := fallback.Evaluate(tc.cmd, nil).Decision; got != tc.want {
				t.Errorf("fallback = %s, want %s", got, tc.want)
			}
			if got := pipeline.Evaluate(tc.cmd, nil).Decision; got != tc.want {
				t.Errorf("pipeline = %s, want %s", got, tc.want)
			}
		})
	}
}
