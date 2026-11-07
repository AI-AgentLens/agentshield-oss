package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// EvaluateStderrRedirect (#4610) on a synthetic policy, so the guarantee is
// pinned without the shipped packs: the stripped reading of a command whose
// stderr redirect or `|&` broke a rule's pipe adjacency can raise the
// decision, and can never lower it.
func TestEvaluateStderrRedirect_StrippedReadingOnlyRaises(t *testing.T) {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		// Written for pipe adjacency, the shape of the rules #4610 measured.
		Rule{ID: "custom-block-zzsrc-pipe", Match: Match{CommandRegex: `zzsrc\s+\S+\s*\|\s*zzsink\b`}, Decision: DecisionBlock, Reason: "zzsrc piped to zzsink"},
		// Anchored at both ends: only the per-statement retry sees it.
		Rule{ID: "custom-block-zzanch", Match: Match{CommandRegex: `^zzanch\s+\S+\s*\|\s*zzsink$`}, Decision: DecisionBlock, Reason: "anchored"},
		// An ALLOW that only the redirect-free text earns: the stripped
		// reading must never vouch for the command.
		Rule{ID: "custom-allow-zzok", Match: Match{CommandRegex: `^zzok [a-z]+$`}, Decision: DecisionAllow, Reason: "zzok"},
		Rule{ID: "custom-audit-zzredir", Match: Match{CommandRegex: `zzok \S+ 2>`}, Decision: DecisionAudit, Reason: "redirect"},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	eval := func(cmd string, mode StderrRedirectMode) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateStderrRedirect(cmd, n.Paths, n.Parsed, "", mode)
	}

	t.Run("raises: the adjacency the data flow keeps is matched", func(t *testing.T) {
		for _, tc := range []struct{ control, cmd, rule string }{
			{`zzsrc a | zzsink b`, `zzsrc a 2>/dev/null | zzsink b`, "custom-block-zzsrc-pipe"},
			{`zzsrc a | zzsink b`, `zzsrc a 2>&1 | zzsink b`, "custom-block-zzsrc-pipe"},
			{`zzsrc a | zzsink b`, `zzsrc a |& zzsink b`, "custom-block-zzsrc-pipe"},
			{`zzsrc a | zzsink b`, `zzsrc a >&2 | zzsink b`, "custom-block-zzsrc-pipe"},
			{`cd /tmp && zzanch a | zzsink`, `cd /tmp && zzanch a 2>/dev/null | zzsink`, "custom-block-zzanch"},
		} {
			if r := eval(tc.control, StderrRedirectOff); r.Decision != DecisionBlock {
				t.Fatalf("control %q decided %v; want BLOCK", tc.control, r.Decision)
			}
			if r := eval(tc.cmd, StderrRedirectOff); r.Decision == DecisionBlock {
				t.Errorf("as written %q already BLOCKs (%v); the row no longer shows the bypass", tc.cmd, r.TriggeredRules)
				continue
			}
			r := eval(tc.cmd, StderrRedirectStricter)
			if r.Decision != DecisionBlock || !has(r.TriggeredRules, tc.rule) {
				t.Errorf("%q decided %v rules=%v; want BLOCK by %s", tc.cmd, r.Decision, r.TriggeredRules, tc.rule)
			}
		}
	})

	t.Run("no reading: a redirect that moves stdout breaks the flow", func(t *testing.T) {
		for _, cmd := range []string{
			`zzsrc a >out.txt | zzsink b`,
			`zzsrc a &>/dev/null | zzsink b`,
			`echo "zzsrc a 2>/dev/null | zzsink b"`,
		} {
			if r := eval(cmd, StderrRedirectStricter); r.Decision == DecisionBlock {
				t.Errorf("%q decided BLOCK rules=%v; stdout does not reach the pipe (or it is quoted text), want no BLOCK", cmd, r.TriggeredRules)
			}
		}
	})

	t.Run("never lowers: an ALLOW only the stripped text earns does not apply", func(t *testing.T) {
		cmd := `zzok abc 2>/dev/null`
		if r := eval(cmd, StderrRedirectOn); r.Decision != DecisionAllow {
			t.Fatalf("control: the stripped reading alone decided %v rules=%v; want ALLOW (the row must show a reading that would lower)", r.Decision, r.TriggeredRules)
		}
		off := eval(cmd, StderrRedirectOff)
		if off.Decision != DecisionAudit {
			t.Fatalf("control: as written decided %v rules=%v; want AUDIT", off.Decision, off.TriggeredRules)
		}
		r := eval(cmd, StderrRedirectStricter)
		if r.Decision != DecisionAudit || strings.Join(r.TriggeredRules, ",") != strings.Join(off.TriggeredRules, ",") {
			t.Errorf("%q decided %v rules=%v; want the as-written AUDIT record %v untouched", cmd, r.Decision, r.TriggeredRules, off.TriggeredRules)
		}
	})
}

// The witness from #4610 on the shipped (embedded community) packs, through
// the single evaluation entry point every surface uses. The attack text is
// assembled at runtime: the hook reads test sources as commands.
func TestStderrRedirect_ShippedWitness_4610(t *testing.T) {
	engine := shippedEngine(t)
	eval := func(cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "")
	}
	src := "cat ~/.zsh_" + "history"
	sink := "grep -i pass" + "word"
	control := src + " | " + sink
	if r := eval(control); r.Decision != DecisionBlock || !has(r.TriggeredRules, "sec-block-history-grep-password") {
		t.Fatalf("control decided %v rules=%v; want BLOCK by sec-block-history-grep-password", r.Decision, r.TriggeredRules)
	}
	for _, cmd := range []string{
		src + " 2>/dev/null | " + sink,
		src + " 2>&1 | " + sink,
		src + " |& " + sink,
	} {
		if r := eval(cmd); r.Decision != DecisionBlock || !has(r.TriggeredRules, "sec-block-history-grep-password") {
			t.Errorf("%q decided %v rules=%v; want BLOCK by sec-block-history-grep-password", cmd, r.Decision, r.TriggeredRules)
		}
	}
	// A benign read with the same redirect stays as it was.
	if r := eval("cat README.md 2>/dev/null | grep -i install"); r.Decision == DecisionBlock {
		t.Errorf("benign control decided BLOCK rules=%v", r.TriggeredRules)
	}
}
