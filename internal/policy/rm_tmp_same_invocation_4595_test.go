package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4595, shipped (embedded community) packs: a temp operand in the SAME rm
// invocation no longer earns ts-allow-rm-tmp / ts-allow-rm-var-folders-tmp
// for a system operand beside it. The same-invocation sibling of
// TestOverrideCannotSilenceAnotherStatement, which appends the earner as a
// separate statement and so cannot see this shape.
//
// The mixed rows BLOCK: ts-struct-block-rm-system's args_none carves temp
// OPERANDS out of args_any instead of vetoing the whole invocation, so the
// system operand beside a temp one keeps its BLOCK.
func TestRmTempOperandCannotVouchForSameInvocation_4595(t *testing.T) {
	engine := shippedEngine(t)
	eval := func(cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "/tmp")
		return engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "/tmp")
	}
	if r := eval("rm -rf /etc/kai-marker"); r.Decision != DecisionBlock {
		t.Fatalf("control: the system operand alone decided %v rules=%v; want BLOCK", r.Decision, r.TriggeredRules)
	}
	for _, cmd := range []string{
		"rm -rf /tmp/kai-scratch /etc/kai-marker",
		"rm -rf /tmp/kai-scratch /usr/local/kai-marker",
		"rm -r -f /boot/kai-marker /tmp/kai-scratch",
		"rm -rf /var/folders/kai-scratch /etc/kai-marker",
		"declare x=$(rm -rf /tmp/kai-scratch /etc/nginx)",
	} {
		r := eval(cmd)
		if r.Decision != DecisionBlock || !has(r.TriggeredRules, "ts-struct-block-rm-system") {
			t.Errorf("%q decided %v rules=%v; a temp operand must not vouch for the system operand beside it (want BLOCK via ts-struct-block-rm-system)", cmd, r.Decision, r.TriggeredRules)
		}
		if has(r.TriggeredRules, "ts-allow-rm-tmp") || has(r.TriggeredRules, "ts-allow-rm-var-folders-tmp") {
			t.Errorf("%q still attributed to a temp-cleanup ALLOW: %v", cmd, r.TriggeredRules)
		}
	}
	// Controls: genuine temp cleanup keeps its ALLOW.
	for _, cmd := range []string{
		"rm -rf /tmp/kai-scratch",
		"rm -rf /tmp/kai-a /tmp/kai-b",
		"rm -rf /var/folders/kai-scratch",
	} {
		if r := eval(cmd); r.Decision != DecisionAllow {
			t.Errorf("control %q decided %v rules=%v; want ALLOW", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
