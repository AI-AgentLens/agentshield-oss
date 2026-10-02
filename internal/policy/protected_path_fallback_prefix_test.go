package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// TestProtectedPathViaCommandSubstitution_ParseFailureOnLaterLine pins #4090.
// Bash executes a script line by line: it runs line 1, and only fails once it
// reaches a broken line further down. Before this fix, ANY syntax error sent
// the whole command to shellparse.fallbackParse, which extracts no
// substitutions at all — so a protected read inside "$(...)" on an earlier,
// otherwise-clean line silently escaped the built-in protected-path check
// even though the same read at top level (no wrapping "$(...)") was still
// caught by the naive fallback tokenizer. As in the sibling #4030 test, every
// path here is backed by no dedicated rule ("secrets/**"), so a BLOCK can
// only come from the built-in check actually extracting the path.
func TestProtectedPathViaCommandSubstitution_ParseFailureOnLaterLine(t *testing.T) {
	cwd := "/tmp/agentshield-protected-cmdsubst-prefix-test"
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"secrets/**"}
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	eval := func(cmd string) (Decision, []string, []string) {
		n := normalize.NormalizeCommand(cmd, cwd)
		r := engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, cwd)
		return r.Decision, r.TriggeredRules, n.Paths
	}

	blocking := []string{
		// Base case: no substitution involved, a stray ")" on line 2. Already
		// BLOCKed on main via the naive fallback tokenizer — kept as a control
		// that the fix doesn't change this path's decision.
		"cat secrets/token\n)",
		// The gap: the same read, one line up, wrapped in "$(...)".
		"echo \"$(cat secrets/token)\"\n)",
		// Line 2 fails to parse for a different reason (unterminated quote,
		// not a stray paren) — same recovery must apply regardless of why the
		// later line breaks.
		"cat secrets/token\necho 'oops",
		"echo \"$(cat secrets/token)\"\necho 'oops",
	}
	for _, cmd := range blocking {
		d, rules, paths := eval(cmd)
		exact := false // containsRule is a substring match; "protected-path-consumer" must not count
		for _, r := range rules {
			exact = exact || r == "protected-path"
		}
		if d != DecisionBlock || !exact {
			t.Errorf("%q: decided %s rules=%v, want BLOCK by protected-path (paths=%v)", cmd, d, rules, paths)
		}
	}

	// Controls: a clean prefix that reads nothing sensitive must not
	// manufacture a BLOCK just because recovery ran.
	benign := []string{
		"echo hi\n)",
		"echo \"$(echo hi)\"\n)",
		"echo hi\necho 'oops",
		// No clean prefix exists at all (line 1 alone is already unparseable)
		// — nothing to recover, must fall through exactly as before.
		"echo \"$(echo secrets/token\n)",
	}
	for _, cmd := range benign {
		if d, rules, paths := eval(cmd); d == DecisionBlock {
			t.Errorf("%q: decided BLOCK unexpectedly (rules=%v, paths=%v)", cmd, rules, paths)
		}
	}
}
