package hookentry

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// TestIsShellInvocation_PastTheChainBound_4778: a shell-form hook entry past
// the chain bound is not "agentshield hook", and is refused without being
// parsed. Without the check, ParseText's past-the-bound panic would escape
// into setup and the settings readers (#4823 Opus pass 1, M17: no test
// covered it). Control: the plain entry is still recognised.
func TestIsShellInvocation_PastTheChainBound_4778(t *testing.T) {
	if !isShellInvocation(BinaryName + " " + Subcommand) {
		t.Fatalf("control: %q not recognised", BinaryName+" "+Subcommand)
	}
	past := BinaryName + " " + Subcommand + strings.Repeat("|a", shellparse.MaxChainOperators+1)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("isShellInvocation panicked on an entry past the bound: %v", r)
		}
	}()
	if isShellInvocation(past) {
		t.Errorf("an entry past the chain bound was recognised as the hook")
	}
}
