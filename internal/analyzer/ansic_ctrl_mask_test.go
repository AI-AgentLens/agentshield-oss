package analyzer_test

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestANSICControlMaskSplitsVerbs_4543: bash computes \cX as X & 0x1f, so
// \c* is a newline and \c) a tab. The decoder used XOR 0x40 and read them as
// the letters j and i, which joined the two words of a split command into one
// and kept the verb rule from firing. Each row decided AUDIT before the fix.
func TestANSICControlMaskSplitsVerbs_4543(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := ansicNULDecideWith(engine, policy.ANSICNULOff)
	rows := []struct{ name, cmd string }{
		{"newline-form", `eval $'true\c*rm -rf /'`},
		{"tab-form", `eval $'rm\c)-rf\c)/'`},
		{"control: newline escape", `eval $'true\nrm -rf /'`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := decide(r.cmd).Decision; got != policy.DecisionBlock {
				t.Errorf("%q decided %v, want BLOCK", r.cmd, got)
			}
		})
	}
}
