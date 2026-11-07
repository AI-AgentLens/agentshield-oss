package policy

import "testing"

// TestANSICAssignmentSplitParityAcrossEvaluationPaths is the guard for #4591.
// A value bound from $'...' holds the decoded bytes at runtime, so an
// unquoted read splits on a decoded tab or newline exactly as it does on a
// literal one. On each evaluation path, every $'...' spelling must decide the
// same as its plain twin.
//
// The first rule is anchored at the start of a statement, the shape of the
// rm-root rules the issue measured. A rule led by \b would already match
// main's dequoted form (`x=ufw<TAB>disable`), so it could not tell the fix
// from main. The second is an unanchored rule that needs the value in an
// argument position, which only the whole-command fold reaches.
//
// The regex-only fallback does not resolve an indirect executable for an
// anchored rule even for the plain twin (it AUDITs `x='ufw disable'; $x` on
// main as well), so there the twin rows prove only "no weaker than the plain
// spelling". The argument-position row is the fallback's non-vacuous case.
func TestANSICAssignmentSplitParityAcrossEvaluationPaths(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{
		{
			ID:       "test-ufw-disable-statement-start",
			Taxonomy: "destructive-ops/system-management/firewall-disable",
			Match:    Match{CommandRegex: `^(sudo\s+)?ufw\s+(disable|reset)\b`},
			Decision: DecisionBlock,
			Reason:   "test",
		},
		{
			ID:       "test-sudo-ufw-disable-anywhere",
			Taxonomy: "destructive-ops/system-management/firewall-disable",
			Match:    Match{CommandRegex: `\bsudo\s+-n\s+ufw\s+disable\b`},
			Decision: DecisionBlock,
			Reason:   "test",
		},
	}}
	fallback, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pipeline, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	paths := []struct {
		label  string
		engine *Engine
	}{{"regex-only fallback", fallback}, {"analyzer pipeline", pipeline}}

	plainExec := `x='ufw disable'; $x`
	plainArg := `x='ufw disable'; sudo -n $x`
	twins := []struct {
		name  string
		plain string
		ansic string
	}{
		{"the #4591 bypass: a tab escape", plainExec, `x=$'ufw\tdisable'; $x`},
		{"octal tab", plainExec, `x=$'ufw\011disable'; $x`},
		{"newline escape", plainExec, `x=$'ufw\ndisable'; $x`},
		{"hex-encoded letter", plainExec, `x=$'\x75fw disable'; $x`},
		{"argument position", plainArg, `x=$'ufw\tdisable'; sudo -n $x`},
	}
	for _, tc := range twins {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range paths {
				want := p.engine.Evaluate(tc.plain, nil).Decision
				if got := p.engine.Evaluate(tc.ansic, nil).Decision; got != want {
					t.Errorf("%s: Evaluate(%q) = %v, but its plain twin %q decides %v",
						p.label, tc.ansic, got, tc.plain, want)
				}
			}
		})
	}

	// The controls that keep the twin rows from being vacuous.
	controls := []struct {
		label   string
		engine  *Engine
		command string
	}{
		{"analyzer pipeline", pipeline, plainExec},
		{"analyzer pipeline", pipeline, "x='ufw\tdisable'; $x"},
		{"analyzer pipeline", pipeline, plainArg},
		{"regex-only fallback", fallback, plainArg},
	}
	for _, c := range controls {
		if got := c.engine.Evaluate(c.command, nil).Decision; got != DecisionBlock {
			t.Errorf("control %s: Evaluate(%q) = %v, want BLOCK", c.label, c.command, got)
		}
	}

	for _, cmd := range []string{
		`x=$'ufw\tdisable'; echo done`, // a binding alone runs nothing
		`echo $'ufw\tdisable'`,         // printed, not executed
	} {
		for _, p := range paths {
			if got := p.engine.Evaluate(cmd, nil).Decision; got != DecisionAudit {
				t.Errorf("%s: Evaluate(%q) = %v, want AUDIT", p.label, cmd, got)
			}
		}
	}
}
