package policy

import "testing"

// #4623: git's value-taking global options (`-C <dir>`, `-c k=v`) shift the
// subcommand one slot right in the parsed argv, so a structural rule keyed on
// `subcommand: commit` stopped reading `git -C /repo commit -n`. The stripped
// reading is a second evaluation that can raise the result and never lower it.
func TestEvaluateQuotedFlags_GitGlobalOptionsReadingOnlyRaises(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		Rule{
			ID: "custom-block-git-commit-n",
			Match: Match{Structural: &StructuralMatch{
				Executable: []string{"git"}, SubCommand: "commit", FlagsAny: []string{"n"},
			}},
			Decision: DecisionBlock, Reason: "hook skip",
		},
		Rule{ID: "custom-allow-git-status", Match: Match{CommandRegex: `^git\s+status\b`}, Decision: DecisionAllow, Reason: "read-only"},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	eval := func(cmd string, mode QuotedFlagsMode) EvalResult {
		return engine.EvaluateQuotedFlags(cmd, nil, nil, "", mode)
	}

	if r := eval(`git commit -n -m msg`, QuotedFlagsOff); r.Decision != DecisionBlock {
		t.Fatalf("control: plain form decided %v; want BLOCK", r.Decision)
	}
	for _, cmd := range []string{
		`git -C /tmp/repo commit -n -m msg`,
		`git -c user.name=x commit -n -m msg`,
		`git -C /a -c k=v commit -n -m msg`,
		`git --git-dir /a/.git commit -n -m msg`,
		`sudo git -C /a commit -n`,
		`cd /a && git -C /a commit -n`,
	} {
		if r := eval(cmd, QuotedFlagsOff); r.Decision == DecisionBlock {
			t.Fatalf("control: %q already BLOCKs as written (%v); the row shows no bypass", cmd, r.TriggeredRules)
		}
		if r := eval(cmd, QuotedFlagsStricter); r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-git-commit-n") {
			t.Errorf("%q decided %v rules=%v; want BLOCK by custom-block-git-commit-n", cmd, r.Decision, r.TriggeredRules)
		}
	}

	t.Run("no hook-skip flag stays unblocked", func(t *testing.T) {
		for _, cmd := range []string{
			`git -C /tmp/repo commit -m msg`,
			`git -c user.name=x commit -m msg`,
			`git -C /tmp/repo status`,
			// -C after the subcommand is commit's own --reuse-message
			`git commit -C HEAD -m msg`,
		} {
			if r := eval(cmd, QuotedFlagsStricter); r.Decision == DecisionBlock {
				t.Errorf("%q BLOCKed by %v", cmd, r.TriggeredRules)
			}
		}
	})

	t.Run("never lowers: the stripped reading's ALLOW is not taken", func(t *testing.T) {
		cmd := `git -C /tmp/repo status`
		if r := eval(`git status`, QuotedFlagsOff); r.Decision != DecisionAllow {
			t.Fatalf("control: stripped form decided %v; want ALLOW", r.Decision)
		}
		asWritten := eval(cmd, QuotedFlagsOff)
		r := eval(cmd, QuotedFlagsStricter)
		if r.Decision != asWritten.Decision || has(r.TriggeredRules, "custom-allow-git-status") {
			t.Errorf("%q: as written %v, with reading %v rules=%v; the reading must not lower", cmd, asWritten.Decision, r.Decision, r.TriggeredRules)
		}
	})
}
