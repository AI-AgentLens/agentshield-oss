package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// EvaluateZshReading (#4598) on a synthetic policy, so the guarantee is pinned
// without the shipped packs: the zsh reading of a command the bash parser
// rejects can raise the decision, never lower it, and at a tie the as-written
// record is kept.
func TestEvaluateZshReading_ReadingOnlyRaises(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		// Anchored at both ends: only the per-statement split sees it.
		Rule{ID: "custom-block-zzanch", Match: Match{CommandRegex: `^zzanch [a-z]+$`}, Decision: DecisionBlock, Reason: "anchored"},
		// An ALLOW only the zsh reading's text earns, and an AUDIT only the
		// text as written earns: the reading must never vouch for the
		// command.
		Rule{ID: "custom-allow-zzok", Match: Match{CommandRegex: `^: \$\{HOME\}; zzok$`}, Decision: DecisionAllow, Reason: "zzok"},
		Rule{ID: "custom-audit-zzflags", Match: Match{CommandRegex: `\$\{\(U\)HOME\}; zzok`}, Decision: DecisionAudit, Reason: "flags"},
		// Unanchored: both readings match it, and the anchored twin only the
		// zsh reading.
		Rule{ID: "custom-block-zzraw", Match: Match{CommandRegex: `zzraw [a-z]+`}, Decision: DecisionBlock, Reason: "raw"},
		Rule{ID: "custom-block-zzraw-anch", Match: Match{CommandRegex: `^zzraw [a-z]+$`}, Decision: DecisionBlock, Reason: "raw anchored"},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	eval := func(cmd string, mode ZshReadingMode) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateZshReading(cmd, n.Paths, n.Parsed, "", mode)
	}
	rules := func(r EvalResult) string { return strings.Join(r.TriggeredRules, ",") }

	t.Run("raises: the statement after a zsh-only one is a command of its own", func(t *testing.T) {
		for _, tc := range []struct{ control, cmd string }{
			{`: ${HOME}; zzanch a`, `: ${(U)HOME}; zzanch a`},
			{`{ zzanch a; }`, `{ zzanch a }`},
			{`{ zzanch a; }`, `() { zzanch a }`},
			{`zzanch a; : ${HOME}`, `zzanch a; : ${(U)HOME}`},
			{`echo x | cat; zzanch a`, `echo ${(L)x} | cat; zzanch a`},
		} {
			if r := eval(tc.control, ZshReadingOff); r.Decision != DecisionBlock {
				t.Fatalf("control %q decided %v; want BLOCK", tc.control, r.Decision)
			}
			if r := eval(tc.cmd, ZshReadingOff); r.Decision == DecisionBlock {
				t.Errorf("as written %q already BLOCKs (%v); the row no longer shows the bypass", tc.cmd, r.TriggeredRules)
				continue
			}
			r := eval(tc.cmd, ZshReadingStricter)
			if r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzanch") {
				t.Errorf("%q decided %v rules=%v; want BLOCK by custom-block-zzanch", tc.cmd, r.Decision, r.TriggeredRules)
			}
		}
	})

	t.Run("never lowers: an ALLOW only the zsh reading earns does not apply", func(t *testing.T) {
		cmd := `: ${(U)HOME}; zzok`
		if r := eval(cmd, ZshReadingOn); r.Decision != DecisionAllow {
			t.Fatalf("control: the zsh reading alone decided %v rules=%v; want ALLOW (the row must show a reading that would lower)", r.Decision, r.TriggeredRules)
		}
		off := eval(cmd, ZshReadingOff)
		if off.Decision != DecisionAudit || !has(off.TriggeredRules, "custom-audit-zzflags") {
			t.Fatalf("control: as written decided %v rules=%v; want AUDIT by custom-audit-zzflags", off.Decision, off.TriggeredRules)
		}
		r := eval(cmd, ZshReadingStricter)
		if r.Decision != off.Decision || rules(r) != rules(off) {
			t.Errorf("%q decided %v rules=%v; want the as-written record %v %v untouched", cmd, r.Decision, r.TriggeredRules, off.Decision, off.TriggeredRules)
		}
	})

	t.Run("tie: the as-written record and its attribution win", func(t *testing.T) {
		cmd := `: ${(U)HOME}; zzraw a`
		on := eval(cmd, ZshReadingOn)
		off := eval(cmd, ZshReadingOff)
		if on.Decision != DecisionBlock || !has(on.TriggeredRules, "custom-block-zzraw-anch") {
			t.Fatalf("control: the zsh reading decided %v rules=%v; want BLOCK naming custom-block-zzraw-anch", on.Decision, on.TriggeredRules)
		}
		if off.Decision != DecisionBlock || has(off.TriggeredRules, "custom-block-zzraw-anch") {
			t.Fatalf("control: as written decided %v rules=%v; want BLOCK without the anchored rule", off.Decision, off.TriggeredRules)
		}
		r := eval(cmd, ZshReadingStricter)
		if r.Decision != DecisionBlock || rules(r) != rules(off) {
			t.Errorf("%q decided %v rules=%v; at a tie want the as-written record %v", cmd, r.Decision, r.TriggeredRules, off.TriggeredRules)
		}
	})

	t.Run("no reading: a command the bash parser accepts decides exactly as before", func(t *testing.T) {
		for _, cmd := range []string{`: ${HOME}; zzanch a`, `zzok`, `{ zzanch a; }`, `echo '${(U)HOME}'; zzanch a`} {
			off, got := eval(cmd, ZshReadingOff), eval(cmd, ZshReadingStricter)
			if got.Decision != off.Decision || rules(got) != rules(off) {
				t.Errorf("%q decided %v %v; want exactly the as-written %v %v", cmd, got.Decision, got.TriggeredRules, off.Decision, off.TriggeredRules)
			}
		}
	})

	t.Run("no reading: the zsh parser rejects it too", func(t *testing.T) {
		cmd := `for i (1) zzanch a`
		off, got := eval(cmd, ZshReadingOff), eval(cmd, ZshReadingStricter)
		if got.Decision != off.Decision || rules(got) != rules(off) {
			t.Errorf("%q decided %v %v; want exactly the as-written %v %v (#4598 residual)", cmd, got.Decision, got.TriggeredRules, off.Decision, off.TriggeredRules)
		}
	})
}

// The production entry point runs the zsh reading: EvaluateWithParsedCwd and
// EvaluateZshReading(..., ZshReadingStricter) are the same evaluation.
func TestEvaluateWithParsedCwd_RunsTheZshReading(t *testing.T) {
	engine := shippedEngine(t)
	cmd := ": ${(U)HOME}; " + zshWitnessChmod
	n := normalize.NormalizeCommand(cmd, "")
	off := engine.EvaluateZshReading(cmd, n.Paths, n.Parsed, "", ZshReadingOff)
	if off.Decision == DecisionBlock {
		t.Fatalf("control: as written %q already BLOCKs (%v)", cmd, off.TriggeredRules)
	}
	want := engine.EvaluateZshReading(cmd, n.Paths, n.Parsed, "", ZshReadingStricter)
	got := engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "")
	if got.Decision != DecisionBlock || got.Decision != want.Decision || strings.Join(got.TriggeredRules, ",") != strings.Join(want.TriggeredRules, ",") {
		t.Errorf("entry point decided %v %v; ZshReadingStricter decided %v %v", got.Decision, got.TriggeredRules, want.Decision, want.TriggeredRules)
	}
}
