package policy

import "testing"

func ufwRule() Rule {
	return Rule{
		ID:       "test-ufw-disable-leading-word-boundary",
		Taxonomy: "destructive-ops/system-management/firewall-disable",
		Match: Match{
			// The shape the whole issue is about: a pattern whose first
			// element is \b. 263 of 1377 command_regex lines in packs/ open
			// this way.
			CommandRegex: `\bufw\b\s+(disable|reset)\b`,
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}
}

// TestEmittedSeparatorParityAcrossEvaluationPaths is the guard engine.go's
// emittedCommand comment promises.
//
// #3232 and #3234 are the two times a match-affecting transform was wired to
// one evaluation path only and shipped as a latent trap: the pipeline caught
// the bypass, the regex-only fallback did not, and disabling the pipeline
// silently reopened it. Every whole-command candidate added since has needed
// this test, and this one is no different — the fallback is what a
// pipeline-disabled deployment evaluates.
func TestEmittedSeparatorParityAcrossEvaluationPaths(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{ufwRule()}}
	fallback, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pipeline, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	cases := []struct {
		name    string
		command string
		want    Decision
		why     string
	}{
		{
			"control: the payload as plain text",
			`echo "ufw disable" | sh`,
			DecisionBlock,
			"the non-evaded form; if this ever stops blocking the rest of the table proves nothing",
		},
		{
			"the #3802 bypass: a newline escape against the leading \\b",
			`printf '\nufw disable\n' | sh`,
			DecisionBlock,
			"executes identically to the control",
		},
		{"tab escape", `printf '\tufw disable\n' | sh`, DecisionBlock, ""},
		{"echo -e", `echo -e '\nufw disable' | bash`, DecisionBlock, ""},
		{"hex spelling", `printf '\x0aufw disable' | sh`, DecisionBlock, ""},
		{"octal spelling", `printf '\012ufw disable' | sh`, DecisionBlock, ""},
		{
			"write-then-execute rather than a pipe",
			`printf '\nufw disable\n' > /tmp/x.sh; sh /tmp/x.sh`,
			DecisionBlock,
			"#3800's route to an executor, same evidence",
		},

		{
			"printed, never executed",
			`printf '\nufw disable\n'`,
			DecisionAudit,
			"the FP the executor gate exists for: documentation stays documentation",
		},
		{
			"written to notes, nothing executes it",
			`printf 'note: \nufw disable is blocked\n' >> notes.md`,
			DecisionAudit,
			"",
		},
		{
			"echo without -e piped to a shell",
			`echo '\nufw disable' | sh`,
			DecisionAudit,
			"bash prints the backslash literally, so `sh` receives no newline and \\nufw is not a command",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, e := range []struct {
				label  string
				engine *Engine
			}{{"regex-only fallback", fallback}, {"analyzer pipeline", pipeline}} {
				if got := e.engine.Evaluate(tc.command, nil).Decision; got != tc.want {
					t.Errorf("%s: Evaluate(%q) = %v, want %v %s",
						e.label, tc.command, got, tc.want, tc.why)
				}
			}
		})
	}
}
