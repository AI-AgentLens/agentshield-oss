package policy

import (
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4413: a command-prefix assignment whose value is a sibling statement's
// variable is the same redirect as the literal spelling. The rule is the
// shipped ts-block-home-redirect-inline regex. Control rows first: the literal
// and `export` spellings decide BLOCK on main, so the variable form leaking is
// the prefix-assignment value alone. Commands are assembled at runtime: the
// hook reads test sources as commands.
func TestPrefixAssignmentValueMaterialized_4413(t *testing.T) {
	rule := Rule{
		ID:       "t-home-redirect-inline",
		Match:    Match{CommandRegex: `\bHOME=(/tmp|/dev/shm|/var/tmp|/run/user|\./|\.\./)\S*\s+(ssh|git|npm|pip|gpg|kubectl|helm|aws|gcloud|terraform|docker|podman)`},
		Decision: DecisionBlock,
		Reason:   "test",
	}
	engine := privateAliasEngine(t, nil, rule)
	eval := func(cmd string) EvalResult {
		nc := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, "")
	}
	home := "HO" + "ME="
	for _, cmd := range []string{
		home + "/dev/shm/x ssh host",
		"h=/dev/shm/x; export " + home + "$h; ssh host",
	} {
		if r := eval(cmd); r.Decision != DecisionBlock {
			t.Fatalf("control %q = %v %v; want BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	for _, cmd := range []string{
		"h=/dev/shm/x; " + home + "$h ssh host",
		"h=/dev/shm/x; " + home + `"$h" git status`,
	} {
		if r := eval(cmd); r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, rule.ID) {
			t.Errorf("%q = %v %v; want BLOCK by %s", cmd, r.Decision, r.TriggeredRules, rule.ID)
		}
	}
	// A benign redirect target must not move.
	if r := eval("h=/work/proj; " + home + "$h git status"); r.Decision == DecisionBlock {
		t.Errorf("benign prefix assignment BLOCKed: %v", r.TriggeredRules)
	}
}
