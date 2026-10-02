package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// TestProtectedPathViaCommandSubstitution pins #4030: the built-in
// protected-path check never saw a protected path read inside a command or
// process substitution when the outer command parsed to at least one AST
// segment — `echo $(cat <protected>)` decided the policy default
// (REQUIRE_APPROVAL) instead of BLOCK. Every path here has no dedicated rule
// of its own ("secrets/**", the same unbacked pattern #4020's sibling test
// uses), so a BLOCK can only come from the built-in protected-path check
// actually extracting the path — a key path like ~/.ssh would pass this test
// vacuously even with the gap wide open, because a dedicated rule backstops it.
// The attribution is asserted too, for the same reason: a BLOCK from some
// other rule would not show the path was seen.
func TestProtectedPathViaCommandSubstitution(t *testing.T) {
	cwd := "/tmp/agentshield-protected-cmdsubst-test"
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
		`echo $(cat secrets/token)`,
		"echo `cat secrets/token`",
		`x=$(cat secrets/token); echo $x`,
		// #4051 Codex pass 1, item 1: nested escaped backquotes.
		"echo `echo \\`cat secrets/token\\``",
		// Item 2: level 9 used to fall off an unreported depth cap.
		`echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo $(cat secrets/token)))))))))`,
		// Zero-segment bodies.
		`K=$(<secrets/token)`,
		`echo "$([[ -s secrets/token ]])"`,
		// Process substitution, both directions.
		`diff <(cat secrets/token) /dev/null`,
		`echo hi > >(cat secrets/token)`,
		// A substitution inside a here-string word still runs.
		`cat <<< "$(cat secrets/token)"`,
	}
	for _, cmd := range blocking {
		d, rules, paths := eval(cmd)
		exact := false // containsRule is a substring match; "protected-path-consumer" must not count
		for _, r := range rules {
			exact = exact || r == "protected-path"
		}
		if d != DecisionBlock || !exact {
			t.Errorf("%s: decided %s rules=%v, want BLOCK by protected-path (paths=%v)", cmd, d, rules, paths)
		}
	}

	// Controls: a substitution that does not read the path must not
	// manufacture a BLOCK. The last two are Codex pass 1 item 3's mechanism —
	// the body evaluated without the enclosing command's bindings — which
	// false-BLOCKed on the first version of this fix.
	benign := []string{
		`echo $(basename foo)`,
		`echo $(pwd)`,
		`echo $(echo secrets/token)`,
		`e=echo; echo "$($e cat secrets/token)"`,
		`IFS=; echo $(cat${IFS}secrets/token)`,
		// #4051 Opus pass 2, F1: a here-string's word is data on stdin, not a
		// file. Pass 1 BLOCKed these; main never did.
		`echo "$(cat <<< 'secrets/token')"`,
		`N=$(wc -l <<< "secrets/token")`,
		`echo "$(<<<'secrets/token')"`,
	}
	for _, cmd := range benign {
		if d, rules, paths := eval(cmd); d == DecisionBlock {
			t.Errorf("%s: decided BLOCK unexpectedly (rules=%v, paths=%v)", cmd, rules, paths)
		}
	}
}
