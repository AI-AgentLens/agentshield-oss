package mcp

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

func TestBareToolName(t *testing.T) {
	for in, want := range map[string]string{
		"mcp__fs__write_file":     "write_file",
		"mcp__my_srv__write_file": "write_file",
		"mcp__a__b__c":            "b__c",
	} {
		if got, ok := BareToolName(in); !ok || got != want {
			t.Errorf("%q: got %q,%v want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"write_file", "mcp__", "mcp__fs", "mcp__fs__", "mcp____x", "Write"} {
		if got, ok := BareToolName(in); ok {
			t.Errorf("%q: got %q, want no bare name", in, got)
		}
	}
}

func TestPreferBlockingBareResult(t *testing.T) {
	audit := MCPEvalResult{Decision: policy.DecisionAudit}
	allow := MCPEvalResult{Decision: policy.DecisionAllow}
	block := MCPEvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"bare-rule"}}
	wouldBlock := MCPEvalResult{Decision: policy.DecisionAudit, OriginalDecision: policy.DecisionBlock, TriggeredRules: []string{"bare-rule"}}
	wireBlock := MCPEvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"wire-rule"}}
	wireWouldBlock := MCPEvalResult{Decision: policy.DecisionAudit, OriginalDecision: policy.DecisionBlock, TriggeredRules: []string{"wire-rule"}}
	approval := MCPEvalResult{Decision: policy.DecisionRequireApproval, TriggeredRules: []string{"wire-rule"}}

	for _, c := range []struct {
		name       string
		wire, bare MCPEvalResult
		want       MCPEvalResult
	}{
		{"enforce: bare block replaces wire audit", audit, block, block},
		{"enforce: bare block replaces wire allow", allow, block, block},
		{"enforce: bare block replaces wire require-approval", approval, block, block},
		{"audit-only: bare would-block is recorded", audit, wouldBlock, wouldBlock},
		{"wire block is kept", wireBlock, block, wireBlock},
		{"wire would-block is kept", wireWouldBlock, wouldBlock, wireWouldBlock},
		{"bare audit never lowers wire require-approval", approval, audit, approval},
		{"bare allow never lowers wire audit", audit, allow, audit},
	} {
		if got := PreferBlockingBareResult(c.wire, c.bare); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}
