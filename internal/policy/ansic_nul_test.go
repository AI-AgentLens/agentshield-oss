package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// EvaluateANSICNUL (#4540) on a synthetic policy, so the guarantee is pinned
// without the shipped packs: the cut reading of a $'...' body with a byte-0
// escape can raise the decision, and can never lower it.
func TestEvaluateANSICNUL_CutReadingOnlyRaises(t *testing.T) {
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, "/zzp/secret/**")
	pol.Rules = append(pol.Rules,
		Rule{ID: "custom-block-zzq", Match: Match{CommandRegex: `^zzq\s`}, Decision: DecisionBlock, Reason: "zzq"},
		Rule{ID: "custom-block-zzt-tail", Match: Match{CommandRegex: `zzt-tail`}, Decision: DecisionBlock, Reason: "text after the NUL"},
		Rule{ID: "custom-allow-zzw", Match: Match{CommandRegex: `^zzw\b`}, Decision: DecisionAllow, Reason: "zzw"},
		Rule{ID: "custom-audit-zzv", Match: Match{CommandRegex: `^zzv\b`}, Decision: DecisionAudit, Reason: "zzv"},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	eval := func(cmd string, mode ANSICNULMode) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateANSICNUL(cmd, n.Paths, n.Parsed, "", mode)
	}

	t.Run("raises: the verb bash runs is reached", func(t *testing.T) {
		if r := eval(`zzq a`, ANSICNULOff); r.Decision != DecisionBlock {
			t.Fatalf("control: the plain verb decided %v; want BLOCK", r.Decision)
		}
		for _, cmd := range []string{
			`zz$'\0'q a`, `zz$'\00'q a`, `zz$'\000'q a`, `zz$'\400'q a`,
			`zz$'\x0'q a`, `zz$'\x00'q a`, `zz$'\u0'q a`, `zz$'\U00000000'q a`,
			`zz$'\c@'q a`, "zz$'\\c`'q a", `zz$'\c 'q a`,
			`$'zzq\0yy' a`, `$'zzq\x00'"" a`,
		} {
			if r := eval(cmd, ANSICNULOff); r.Decision == DecisionBlock {
				t.Errorf("control: as written %q already BLOCKs (%v); the row no longer shows the bypass", cmd, r.TriggeredRules)
				continue
			}
			r := eval(cmd, ANSICNULStricter)
			if r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzq") {
				t.Errorf("%q decided %v rules=%v; want BLOCK by custom-block-zzq", cmd, r.Decision, r.TriggeredRules)
			}
		}
	})

	t.Run("raises: a protected path is read from the cut reading's own argv", func(t *testing.T) {
		cmd := `cat /zzp/sec$'\0'ret/key`
		if r := eval(`cat /zzp/secret/key`, ANSICNULOff); r.Decision != DecisionBlock {
			t.Fatalf("control: the plain path decided %v; want BLOCK", r.Decision)
		}
		if r := eval(cmd, ANSICNULOff); r.Decision == DecisionBlock {
			t.Fatalf("control: as written %q already BLOCKs (%v)", cmd, r.TriggeredRules)
		}
		if r := eval(cmd, ANSICNULStricter); r.Decision != DecisionBlock {
			t.Errorf("%q decided %v rules=%v; want BLOCK (protected path)", cmd, r.Decision, r.TriggeredRules)
		}
	})

	t.Run("never lowers: text after the NUL that the as-written reading matched stands", func(t *testing.T) {
		// zsh keeps the NUL, so for its eval/trap/alias/source this text is
		// live; the cut reading alone would decide ALLOW here.
		cmd := `zzw $'x\0zzt-tail'`
		if r := eval(cmd, ANSICNULOn); r.Decision != DecisionAllow {
			t.Fatalf("control: the cut reading alone decided %v rules=%v; want ALLOW (the row must show a reading that would lower)", r.Decision, r.TriggeredRules)
		}
		off := eval(cmd, ANSICNULOff)
		r := eval(cmd, ANSICNULStricter)
		if r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzt-tail") {
			t.Errorf("%q decided %v rules=%v; want the as-written BLOCK by custom-block-zzt-tail", cmd, r.Decision, r.TriggeredRules)
		}
		if strings.Join(r.TriggeredRules, ",") != strings.Join(off.TriggeredRules, ",") {
			t.Errorf("%q rules=%v; want the as-written record %v untouched", cmd, r.TriggeredRules, off.TriggeredRules)
		}
	})

	t.Run("a tie keeps the as-written record", func(t *testing.T) {
		// Default AUDIT as written, AUDIT by a rule in the cut reading: equal
		// decision, so the cut reading's rule is not added to the receipt.
		cmd := `zz$'\0'v a`
		r := eval(cmd, ANSICNULStricter)
		if r.Decision != DecisionAudit || has(r.TriggeredRules, "custom-audit-zzv") {
			t.Errorf("%q decided %v rules=%v; want AUDIT without custom-audit-zzv", cmd, r.Decision, r.TriggeredRules)
		}
		if on := eval(cmd, ANSICNULOn); !has(on.TriggeredRules, "custom-audit-zzv") {
			t.Errorf("control: the cut reading alone did not name custom-audit-zzv (%v); the row proves nothing", on.TriggeredRules)
		}
	})

	t.Run("no byte-0 escape: one evaluation, byte-for-byte the as-written result", func(t *testing.T) {
		for _, cmd := range []string{`zzw $'x\x41'`, `zz$'\x01'q a`, `zz$'\x0b'q a`, `zz$'\\0'q a`, `zzq "$'\0'"`} {
			off, got := eval(cmd, ANSICNULOff), eval(cmd, ANSICNULStricter)
			if off.Decision != got.Decision || strings.Join(off.TriggeredRules, ",") != strings.Join(got.TriggeredRules, ",") {
				t.Errorf("%q: Stricter %v %v differs from Off %v %v", cmd, got.Decision, got.TriggeredRules, off.Decision, off.TriggeredRules)
			}
		}
	})

	t.Run("production entry point uses the stricter mode", func(t *testing.T) {
		if r := engine.Evaluate(`zz$'\0'q a`, nil); r.Decision != DecisionBlock {
			t.Errorf("Evaluate decided %v rules=%v; want BLOCK (EvaluateWithParsedCwd must run the cut reading)", r.Decision, r.TriggeredRules)
		}
	})

	t.Run("the regex-only fallback reads the cut form too", func(t *testing.T) {
		fallback, err := NewEngine(pol)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		if r := fallback.Evaluate(`$'zzq\0yy' a`, nil); r.Decision != DecisionBlock {
			t.Errorf("fallback decided %v rules=%v; want BLOCK", r.Decision, r.TriggeredRules)
		}
		if r := fallback.Evaluate(`zzw $'x\0zzt-tail'`, nil); r.Decision != DecisionBlock {
			t.Errorf("fallback lowered the as-written BLOCK to %v rules=%v", r.Decision, r.TriggeredRules)
		}
	})
}
