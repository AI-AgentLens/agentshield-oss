package cli

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

// The MCP proxies' guard exempts a plain read in command text exactly as the
// shell hook's sp-block-config-touch does (#4337 review pass 2). internal/mcp
// keeps its own copy of the regex because it may not import the enterprise
// layer; this pins the copy to the original, so "one definition of read"
// survives an edit to either.
func TestPlainReadPattern_MatchesEnterprise(t *testing.T) {
	if got, want := mcp.PlainReadPattern(), enterprise.PlainReadPattern(); got != want {
		t.Fatalf("internal/mcp plainReadRe drifted from internal/enterprise:\n mcp:        %s\n enterprise: %s", got, want)
	}
}
