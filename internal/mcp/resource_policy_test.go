package mcp

import (
	"os"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

func testResourcePolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedResources: []string{
			"secret://*",
		},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-postgres",
				Match:    ResourceMatch{Scheme: "postgres"},
				Decision: policy.DecisionBlock,
				Reason:   "Direct database access is blocked.",
			},
			{
				ID:       "block-ssh-file",
				Match:    ResourceMatch{URIRegex: `.ssh`},
				Decision: policy.DecisionBlock,
				Reason:   "SSH key resources are blocked.",
			},
		},
	}
}

func TestResourcePolicy_DefaultAudit(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("https://api.example.com/data")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for unmatched URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockedResourcePattern(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("secret://api-key-123")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for secret:// URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockByScheme(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("postgres://user:pass@prod-db:5432/mydb")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for postgres:// URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockByRegex(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("file:///home/user/.ssh/id_rsa")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for SSH key URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_ConfigGuardOnFileURI(t *testing.T) {
	home := os.Getenv("HOME")
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	})

	// file:// URI pointing to AgentShield config should be blocked by config guard
	result := evaluator.EvaluateResourceRead("file://" + home + "/.agentshield/policy.yaml")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for file:// to AgentShield config, got %s", result.Decision)
	}
}

func TestResourcePolicy_AllowSafeURI(t *testing.T) {
	evaluator := NewPolicyEvaluator(testResourcePolicy())
	result := evaluator.EvaluateResourceRead("https://docs.example.com/readme")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for safe URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_NilPolicy(t *testing.T) {
	evaluator := NewPolicyEvaluator(nil)
	result := evaluator.EvaluateResourceRead("https://example.com/data")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT default, got %s", result.Decision)
	}
}

func TestResourcePolicy_FileURItoSSHKey(t *testing.T) {
	home := os.Getenv("HOME")
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	})
	// file:// URI to SSH key should be blocked by config guard
	result := evaluator.EvaluateResourceRead("file://" + home + "/.ssh/config")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for file:// to SSH config, got %s", result.Decision)
	}
}

func TestResourcePolicy_FileURItoShellConfig(t *testing.T) {
	home := os.Getenv("HOME")
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	})
	result := evaluator.EvaluateResourceRead("file://" + home + "/.bashrc")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for file:// to .bashrc, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockedResourceExactMatch(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults:         MCPDefaults{Decision: policy.DecisionAudit},
		BlockedResources: []string{"secret://production-db-password"},
	})
	result := evaluator.EvaluateResourceRead("secret://production-db-password")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for exact blocked resource, got %s", result.Decision)
	}
}

func TestResourcePolicy_BlockedResourceNoFalsePositive(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults:         MCPDefaults{Decision: policy.DecisionAudit},
		BlockedResources: []string{"secret://production-db-password"},
	})
	result := evaluator.EvaluateResourceRead("secret://staging-db-password")
	if result.Decision == "BLOCK" {
		t.Errorf("expected AUDIT — different secret name, got BLOCK")
	}
}

func TestResourcePolicy_MultipleRulesMatchMostRestrictive(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		ResourceRules: []ResourceRule{
			{
				ID:       "audit-all-db",
				Match:    ResourceMatch{Scheme: "postgres"},
				Decision: policy.DecisionAudit,
				Reason:   "Database access audited.",
			},
			{
				ID:       "block-prod-db",
				Match:    ResourceMatch{URIRegex: "prod"},
				Decision: policy.DecisionBlock,
				Reason:   "Production database blocked.",
			},
		},
	})
	result := evaluator.EvaluateResourceRead("postgres://user@prod-db:5432/mydb")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK (most restrictive), got %s", result.Decision)
	}
}

func TestResourcePolicy_URIRegexMatch(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-internal",
				Match:    ResourceMatch{URIRegex: `internal\.corp\.com`},
				Decision: policy.DecisionBlock,
				Reason:   "Internal resources blocked.",
			},
		},
	})
	result := evaluator.EvaluateResourceRead("https://api.internal.corp.com/secrets")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for internal URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_SafeFileURI(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	})
	// file:// to a project file should be allowed
	result := evaluator.EvaluateResourceRead("file:///Users/dev/project/README.md")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for safe file:// URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_MysqlSchemeBlock(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-mysql",
				Match:    ResourceMatch{Scheme: "mysql"},
				Decision: policy.DecisionBlock,
				Reason:   "MySQL access blocked.",
			},
		},
	})
	result := evaluator.EvaluateResourceRead("mysql://root:password@prod:3306/db")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for mysql:// URI, got %s", result.Decision)
	}
}

func TestResourcePolicy_RedisSchemeBlock(t *testing.T) {
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-redis",
				Match:    ResourceMatch{Scheme: "redis"},
				Decision: policy.DecisionBlock,
				Reason:   "Redis access blocked.",
			},
		},
	})
	result := evaluator.EvaluateResourceRead("redis://default:password@prod-redis:6379/0")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for redis:// URI, got %s", result.Decision)
	}
}

// TestResourcePolicy_HTTPURIAudit validates that an HTTP/HTTPS resources/read URI is
// flagged with AUDIT by the mcp-response-integrity-resource-audit-http rule.
// This tests the behaviour codified in packs/community/mcp/mcp-response-integrity.yaml:resource_rules.
func TestResourcePolicy_HTTPURIAudit(t *testing.T) {
	rule := ResourceRule{
		ID:       "mcp-response-integrity-resource-audit-http",
		Match:    ResourceMatch{URIRegex: `^https?://`},
		Decision: policy.DecisionAudit,
		Reason:   "external HTTP/HTTPS resource",
	}
	evaluator := NewPolicyEvaluator(&MCPPolicy{
		Defaults:      MCPDefaults{Decision: policy.DecisionAllow},
		ResourceRules: []ResourceRule{rule},
	})

	tps := []string{
		"https://attacker.example.com/malicious-resource",
		"http://api.untrusted.org/data",
		"https://raw.githubusercontent.com/owner/repo/main/README.md",
	}
	for _, uri := range tps {
		result := evaluator.EvaluateResourceRead(uri)
		if result.Decision != "AUDIT" {
			t.Errorf("TP: expected AUDIT for %q, got %s", uri, result.Decision)
		}
		found := false
		for _, id := range result.TriggeredRules {
			if id == "mcp-response-integrity-resource-audit-http" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("TP: expected rule mcp-response-integrity-resource-audit-http in triggered rules for %q, got %v", uri, result.TriggeredRules)
		}
	}

	// TN: non-HTTP schemes — should not match the HTTP audit rule (default ALLOW in this test policy)
	tns := []string{
		"file:///workspace/project/README.md",
		"postgres://user@localhost:5432/mydb",
		"custom-scheme://internal/resource",
	}
	for _, uri := range tns {
		result := evaluator.EvaluateResourceRead(uri)
		// Should not be AUDIT from the HTTP rule (may be ALLOW from default)
		for _, id := range result.TriggeredRules {
			if id == "mcp-response-integrity-resource-audit-http" {
				t.Errorf("TN: non-HTTP URI %q should not trigger HTTP audit rule, but got rule %q", uri, id)
			}
		}
	}
}
