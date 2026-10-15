package policy

import "testing"

// EvaluateQuotedFlags (#4289) on a synthetic policy, so the guarantee is
// pinned without the shipped packs: the bare reading of a quoted flag token
// can raise the decision, and can never lower it.
func TestEvaluateQuotedFlags_BareReadingOnlyRaises(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		Rule{ID: "custom-block-zzq-x", Match: Match{CommandRegex: `^zzq\s+-x\b`}, Decision: DecisionBlock, Reason: "bare -x"},
		Rule{ID: "custom-allow-zzq-y", Match: Match{CommandRegex: `^zzq\s+-y\b`}, Decision: DecisionAllow, Reason: "bare -y"},
		Rule{ID: "custom-block-zzq-quoted-y", Match: Match{CommandRegex: `^zzq\s+"-y"`}, Decision: DecisionBlock, Reason: "quoted -y"},
		Rule{ID: "custom-audit-zzq-z", Match: Match{CommandRegex: `^zzq\s+-z\b`}, Decision: DecisionAudit, Reason: "bare -z"},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	eval := func(cmd string, mode QuotedFlagsMode) EvalResult {
		return engine.EvaluateQuotedFlags(cmd, nil, nil, "", mode)
	}

	t.Run("raises: the bare twin's BLOCK is reached", func(t *testing.T) {
		cmd := `zzq "-x" a`
		if r := eval(`zzq -x a`, QuotedFlagsOff); r.Decision != DecisionBlock {
			t.Fatalf("control: bare form decided %v; want BLOCK", r.Decision)
		}
		if r := eval(cmd, QuotedFlagsOff); r.Decision == DecisionBlock {
			t.Fatalf("control: as written the quoted form already BLOCKs (%v); the row no longer shows the bypass", r.TriggeredRules)
		}
		for _, q := range []string{cmd, `zzq '-x' a`, `zzq "-"'x' a`} {
			r := eval(q, QuotedFlagsStricter)
			if r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzq-x") {
				t.Errorf("%q decided %v rules=%v; want BLOCK by custom-block-zzq-x", q, r.Decision, r.TriggeredRules)
			}
		}
	})

	t.Run("never lowers: a stricter as-written result stands", func(t *testing.T) {
		cmd := `zzq "-y" a`
		if r := eval(`zzq -y a`, QuotedFlagsOff); r.Decision != DecisionAllow {
			t.Fatalf("control: bare form decided %v; want ALLOW", r.Decision)
		}
		r := eval(cmd, QuotedFlagsStricter)
		if r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzq-quoted-y") || has(r.TriggeredRules, "custom-allow-zzq-y") {
			t.Errorf("%q decided %v rules=%v; want the as-written BLOCK, untouched", cmd, r.Decision, r.TriggeredRules)
		}
	})

	t.Run("a tie keeps the as-written record", func(t *testing.T) {
		// Default AUDIT as written, AUDIT by a rule bare: equal decision, so
		// the bare reading's rule is not added to the receipt.
		cmd := `zzq "-z" a`
		r := eval(cmd, QuotedFlagsStricter)
		if r.Decision != DecisionAudit || has(r.TriggeredRules, "custom-audit-zzq-z") {
			t.Errorf("%q decided %v rules=%v; want AUDIT without custom-audit-zzq-z", cmd, r.Decision, r.TriggeredRules)
		}
	})

	t.Run("production entry point uses the stricter mode", func(t *testing.T) {
		if r := engine.Evaluate(`zzq "-x" a`, nil); r.Decision != DecisionBlock {
			t.Errorf("Evaluate decided %v rules=%v; want BLOCK (EvaluateWithParsedCwd must run the bare reading)", r.Decision, r.TriggeredRules)
		}
	})

	t.Run("the regex-only fallback reads the bare form too", func(t *testing.T) {
		fallback, err := NewEngine(pol)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		if r := fallback.Evaluate(`zzq -x a`, nil); r.Decision != DecisionBlock {
			t.Fatalf("control: fallback on the bare form decided %v; want BLOCK", r.Decision)
		}
		if r := fallback.Evaluate(`zzq "-x" a`, nil); r.Decision != DecisionBlock {
			t.Errorf("fallback decided %v rules=%v; want BLOCK", r.Decision, r.TriggeredRules)
		}
		if r := fallback.Evaluate(`zzq "-y" a`, nil); r.Decision != DecisionBlock {
			t.Errorf("fallback lowered the as-written BLOCK to %v rules=%v", r.Decision, r.TriggeredRules)
		}
	})
}
