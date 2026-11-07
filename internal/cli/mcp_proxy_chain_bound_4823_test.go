package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

type nopWriteCloser4823 struct{ io.Writer }

func (nopWriteCloser4823) Close() error { return nil }

// TestMCPProxy_ConfigGuardPastTheChainBound_4823 is the stdio proxy as the
// CLI wires it, with the shell's self-protection matcher
// (enterprise.MatchSelfProtectCommand). On a managed host it BLOCKs an
// execute_command whose command is past the chain bound, as
// enterprise-chain-too-long, as the hook does there (Gary, 2026-11-04: past
// the chain bound every managed host BLOCKs). That holds in audit-only too,
// since self-protection is never lowered. #4823 Opus pass 1 found that the
// first cut read only the raw text there, which let 63 of the 66 spellings
// only a parsing reading finds through. The policy here blocks nothing, so
// the guard is the only thing that can. Controls: the same text under the
// bound, and the padded text on an unmanaged host, are not blocked.
func TestMCPProxy_ConfigGuardPastTheChainBound_4823(t *testing.T) {
	pad := strings.Repeat("|a", shellparse.MaxChainOperators+1)
	for _, c := range []struct {
		name    string
		cmd     string
		managed bool
		block   bool
	}{
		{"managed, past the bound", "ls -la" + pad, true, true},
		{"managed, under the bound (control)", "ls -la|a|a", true, false},
		{"unmanaged, past the bound (control)", "ls -la" + pad, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var audited []mcp.AuditEntry
			managed := c.managed
			proxy := mcp.NewProxy(mcp.ProxyConfig{
				Evaluator:           mcp.NewPolicyEvaluator(&mcp.MCPPolicy{Defaults: mcp.MCPDefaults{Decision: policy.DecisionAudit}}),
				OnAudit:             func(e mcp.AuditEntry) { audited = append(audited, e) },
				Stderr:              io.Discard,
				ManagedHost:         func() bool { return managed },
				Mode:                "audit-only",
				SchemaDriftCacheDir: t.TempDir(),
				SelfProtectCommand:  enterprise.MatchSelfProtectCommand,
			})
			req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]any{"name": "execute_command", "arguments": map[string]any{"command": c.cmd}}})
			server := &bytes.Buffer{}
			proxy.RunWithIO(bytes.NewReader(append(req, '\n')), &bytes.Buffer{}, strings.NewReader(""), nopWriteCloser4823{server})
			blocked := server.Len() == 0
			if blocked != c.block {
				t.Fatalf("blocked = %v, want %v (records %d)", blocked, c.block, len(audited))
			}
			if len(audited) != 1 {
				t.Fatalf("%d audit entries, want 1", len(audited))
			}
			reasons := strings.Join(audited[0].Reasons, " ")
			if c.block {
				if audited[0].Decision != "BLOCK" || !strings.Contains(reasons, enterprise.ChainTooLongRuleID) {
					t.Errorf("decision %s reasons %q, want BLOCK naming %s", audited[0].Decision, reasons, enterprise.ChainTooLongRuleID)
				}
				return
			}
			if strings.Contains(reasons, enterprise.ChainTooLongRuleID) {
				t.Errorf("a control names %s: %q", enterprise.ChainTooLongRuleID, reasons)
			}
		})
	}
}

// TestChainTooLongSentinel_HookAndProxiesAgree_4823: the hook's managed
// past-the-bound BLOCK and the MCP proxies' guard record one rule id
// (#4823 Opus pass 2, M6).
func TestChainTooLongSentinel_HookAndProxiesAgree_4823(t *testing.T) {
	if chainTooLongManagedRuleID != enterprise.ChainTooLongRuleID {
		t.Errorf("hook %q, proxies %q", chainTooLongManagedRuleID, enterprise.ChainTooLongRuleID)
	}
}
