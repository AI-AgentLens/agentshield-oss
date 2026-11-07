package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// EvaluateHomeTilde (#4596) on a synthetic policy and a synthetic account, so
// the guarantee is pinned without the developer's login or the shipped packs:
// the expanded reading of `~<login>/` and `~+/` can raise the decision, and
// can never lower it.
func TestEvaluateHomeTilde_ExpandedReadingOnlyRaises(t *testing.T) {
	const home = "/zzhome/zzme"
	t.Setenv("HOME", home)
	restore := tildeAccountLookup
	tildeAccountLookup = func() (string, string) { return "zzme", home }
	t.Cleanup(func() { tildeAccountLookup = restore })

	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, "~/.zzcred/**", "~/.zzcredfile")
	pol.Rules = append(pol.Rules,
		Rule{ID: "custom-block-zzrule", Match: Match{CommandRegex: `cat\s+~/\.zzrule\b`}, Decision: DecisionBlock, Reason: "written against ~/"},
		Rule{ID: "custom-allow-cat", Match: Match{CommandRegex: `^cat [^;|&]+$`}, Decision: DecisionAllow, Reason: "read-only"},
		Rule{ID: "custom-allow-zzok", Match: Match{CommandRegex: `^zzok ~/x$`}, Decision: DecisionAllow, Reason: "only the expanded text"},
		Rule{ID: "custom-audit-zzok", Match: Match{CommandRegex: `^zzok ~zzme/x$`}, Decision: DecisionAudit, Reason: "as written"},
	)
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	eval := func(cmd, cwd string, mode HomeTildeMode) EvalResult {
		n := normalize.NormalizeCommand(cmd, cwd)
		return engine.EvaluateHomeTilde(cmd, n.Paths, n.Parsed, cwd, mode)
	}

	t.Run("raises: protected paths and ~/ rules see the expanded home", func(t *testing.T) {
		for _, tc := range []struct{ control, cmd, cwd string }{
			{`cat ~/.zzcredfile`, `cat ~zzme/.zzcredfile`, "/tmp"},
			{`cat ~/.zzcred/key`, `cat ~zzme/.zzcred/key`, "/tmp"},
			{`cat ~/.zzcredfile`, `cat ~+/.zzcredfile`, home},
			{`cat ~/.zzrule`, `cat ~zzme/.zzrule`, "/tmp"},
		} {
			if r := eval(tc.control, tc.cwd, HomeTildeOff); r.Decision != DecisionBlock {
				t.Fatalf("control %q decided %v rules=%v; want BLOCK", tc.control, r.Decision, r.TriggeredRules)
			}
			if r := eval(tc.cmd, tc.cwd, HomeTildeOff); r.Decision == DecisionBlock {
				t.Errorf("as written %q already BLOCKs (%v); the row no longer shows the bypass", tc.cmd, r.TriggeredRules)
				continue
			}
			if r := eval(tc.cmd, tc.cwd, HomeTildeStricter); r.Decision != DecisionBlock {
				t.Errorf("%q (cwd %s) decided %v rules=%v; want BLOCK", tc.cmd, tc.cwd, r.Decision, r.TriggeredRules)
			}
		}
	})

	t.Run("no reading: other logins, ~+ elsewhere, quoted text", func(t *testing.T) {
		for _, tc := range []struct{ cmd, cwd string }{
			{`cat ~other/.zzcredfile`, "/tmp"},
			{`cat ~+/.zzcredfile`, "/tmp"},
			{`cat "~zzme/.zzcredfile"`, "/tmp"},
		} {
			if r := eval(tc.cmd, tc.cwd, HomeTildeStricter); r.Decision == DecisionBlock {
				t.Errorf("%q (cwd %s) decided BLOCK rules=%v; want no BLOCK", tc.cmd, tc.cwd, r.TriggeredRules)
			}
		}
	})

	t.Run("never lowers: an ALLOW only the expanded text earns does not apply", func(t *testing.T) {
		cmd := `zzok ~zzme/x`
		if r := eval(cmd, "/tmp", HomeTildeOn); r.Decision != DecisionAllow {
			t.Fatalf("control: the expanded reading alone decided %v rules=%v; want ALLOW", r.Decision, r.TriggeredRules)
		}
		off := eval(cmd, "/tmp", HomeTildeOff)
		r := eval(cmd, "/tmp", HomeTildeStricter)
		if r.Decision != DecisionAudit || strings.Join(r.TriggeredRules, ",") != strings.Join(off.TriggeredRules, ",") {
			t.Errorf("%q decided %v rules=%v; want the as-written AUDIT record %v", cmd, r.Decision, r.TriggeredRules, off.TriggeredRules)
		}
	})

	t.Run("the single entry point carries it", func(t *testing.T) {
		n := normalize.NormalizeCommand(`cat ~zzme/.zzcredfile`, "/tmp")
		if r := engine.EvaluateWithParsedCwd(`cat ~zzme/.zzcredfile`, n.Paths, n.Parsed, "/tmp"); r.Decision != DecisionBlock {
			t.Errorf("EvaluateWithParsedCwd decided %v rules=%v; want BLOCK", r.Decision, r.TriggeredRules)
		}
	})
}
