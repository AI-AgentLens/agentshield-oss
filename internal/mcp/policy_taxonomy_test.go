package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Issue #3111: MCPEvalResult.TaxonomyRef was only ever set by Go-implemented
// intercepts — a decision made by a YAML MCP rule carried no taxonomy at all,
// so the SaaS received an MCP block it could not resolve to a control. These
// tests pin the rule-derived refs and the merged accessor the audit wire uses.

func taxonomyMCPPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{
				ID:       "tax-mcp-block-ssh-key-read",
				Taxonomy: "credential-exposure/secret-material/ssh-private-key-read",
				Match: MCPMatch{
					ToolNameAny:           []string{"read_file"},
					ArgumentRegexPatterns: map[string]string{"path": `\.ssh/id_rsa`},
				},
				Decision: policy.DecisionBlock,
				Reason:   "SSH private key read via MCP filesystem tool",
			},
			{
				// Ties on severity with the rule above — both refs must survive.
				ID:       "tax-mcp-block-dotfile-read",
				Taxonomy: "reconnaissance/host-discovery/dotfile-enumeration",
				Match: MCPMatch{
					ToolNameAny:           []string{"read_file"},
					ArgumentRegexPatterns: map[string]string{"path": `/\.[a-z]+/`},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Dotfile directory read via MCP filesystem tool",
			},
			{
				// No taxonomy — contributes nothing, not an empty entry.
				ID: "tax-mcp-block-untagged",
				Match: MCPMatch{
					ToolNameAny:           []string{"read_file"},
					ArgumentRegexPatterns: map[string]string{"path": `id_rsa`},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Private key filename",
			},
		},
	}
}

func TestEvaluateToolCall_CarriesRuleTaxonomy(t *testing.T) {
	e := NewPolicyEvaluator(taxonomyMCPPolicy())
	result := e.EvaluateToolCall("read_file", map[string]interface{}{
		"path": "/home/dev/.ssh/id_rsa",
	})

	if result.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK", result.Decision)
	}

	refs := result.AllTaxonomyRefs()
	want := map[string]bool{
		"credential-exposure/secret-material/ssh-private-key-read": false,
		"reconnaissance/host-discovery/dotfile-enumeration":        false,
	}
	for _, r := range refs {
		if r == "" {
			t.Fatalf("AllTaxonomyRefs contains an empty placeholder: %v", refs)
		}
		if _, ok := want[r]; ok {
			want[r] = true
		}
	}
	for ref, found := range want {
		if !found {
			t.Errorf("AllTaxonomyRefs = %v; missing %q — an MCP rule that fired "+
				"contributed no taxonomy node, so its block can never resolve "+
				"to a compliance control", refs, ref)
		}
	}
}

// TestAllTaxonomyRefs_MergesInterceptAndRuleRefs pins the merge. A composite
// MCP decision can set the Go-intercept TaxonomyRef, the per-rule TaxonomyRefs,
// or both; a caller that reads only one field silently drops half the MCP
// decisions from the fusion chain.
func TestAllTaxonomyRefs_MergesInterceptAndRuleRefs(t *testing.T) {
	cases := []struct {
		name string
		in   MCPEvalResult
		want []string
	}{
		{
			name: "empty",
			in:   MCPEvalResult{},
			want: []string{},
		},
		{
			name: "go intercept only",
			in:   MCPEvalResult{TaxonomyRef: "a/b/c"},
			want: []string{"a/b/c"},
		},
		{
			name: "yaml rules only",
			in:   MCPEvalResult{TaxonomyRefs: []string{"a/b/c", "d/e/f"}},
			want: []string{"a/b/c", "d/e/f"},
		},
		{
			name: "both, intercept first and deduped",
			in: MCPEvalResult{
				TaxonomyRef:  "a/b/c",
				TaxonomyRefs: []string{"d/e/f", "a/b/c", ""},
			},
			want: []string{"a/b/c", "d/e/f"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.AllTaxonomyRefs()
			if got == nil {
				t.Fatal("AllTaxonomyRefs must never return nil — the wire needs [] not null")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("AllTaxonomyRefs() = %v; want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("AllTaxonomyRefs()[%d] = %q; want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestEvaluateToolCall_HigherSeverityResetsTaxonomy — when a rule outranks
// everything seen so far it replaces the triggered-rule set; the taxonomy refs
// must be replaced with it, or the payload would attribute a BLOCK to a
// taxonomy node that only an AUDIT rule named.
func TestEvaluateToolCall_HigherSeverityResetsTaxonomy(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules: []MCPRule{
			{
				ID:       "tax-mcp-audit-first",
				Taxonomy: "audit/only/node",
				Match:    MCPMatch{ToolNameAny: []string{"read_file"}},
				Decision: policy.DecisionAudit,
				Reason:   "audit",
			},
			{
				ID:       "tax-mcp-block-second",
				Taxonomy: "block/winning/node",
				Match: MCPMatch{
					ToolNameAny:           []string{"read_file"},
					ArgumentRegexPatterns: map[string]string{"path": `id_rsa`},
				},
				Decision: policy.DecisionBlock,
				Reason:   "block",
			},
		},
	}

	e := NewPolicyEvaluator(pol)
	result := e.EvaluateToolCall("read_file", map[string]interface{}{"path": "/home/dev/.ssh/id_rsa"})

	if result.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK", result.Decision)
	}
	refs := result.AllTaxonomyRefs()
	if len(refs) != 1 || refs[0] != "block/winning/node" {
		t.Errorf("AllTaxonomyRefs = %v; want only the winning BLOCK rule's node — "+
			"the losing AUDIT rule's taxonomy must go with its rule id", refs)
	}
}
