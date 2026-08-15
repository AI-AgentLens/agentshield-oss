package mcp

import (
	"testing"
)

// helper to build a chat-like MCP call arguments map
func chatArgs(extra map[string]interface{}) map[string]interface{} {
	args := map[string]interface{}{"model": "gpt-4", "messages": []interface{}{}}
	for k, v := range extra {
		args[k] = v
	}
	return args
}

// TestLLMInferencePack_ExtremeTemperature validates the mcp-llminf-audit-extreme-temperature
// ValueLimitRule from packs/premium/mcp/mcp-llm-inference.yaml. ValueLimitRule has no
// Tests field (silently ignored by YAML), so this is the only automated gate for that rule.
func TestLLMInferencePack_ExtremeTemperature(t *testing.T) {
	base := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks("../../packs/premium/mcp", base)
	if err != nil {
		t.Fatalf("failed to load premium MCP packs: %v", err)
	}

	e := NewPolicyEvaluator(merged)

	cases := []struct {
		name        string
		tool        string
		temperature float64
		wantFinding bool
		wantRuleID  string
	}{
		{
			name:        "temperature 2.0 — clearly extreme",
			tool:        "chat_completion",
			temperature: 2.0,
			wantFinding: true,
			wantRuleID:  "mcp-llminf-audit-extreme-temperature",
		},
		{
			name:        "temperature 1.9 — above threshold",
			tool:        "generate_text",
			temperature: 1.9,
			wantFinding: true,
			wantRuleID:  "mcp-llminf-audit-extreme-temperature",
		},
		{
			name:        "temperature 1.8 — at boundary (> 1.79 fires)",
			tool:        "chat_completion",
			temperature: 1.8,
			wantFinding: true,
			wantRuleID:  "mcp-llminf-audit-extreme-temperature",
		},
		{
			name:        "temperature 1.79 — exactly at max (NOT fired, condition is >)",
			tool:        "chat_completion",
			temperature: 1.79,
			wantFinding: false,
		},
		{
			name:        "temperature 1.5 — creative writing range",
			tool:        "chat_completion",
			temperature: 1.5,
			wantFinding: false,
		},
		{
			name:        "temperature 0.7 — normal",
			tool:        "chat_completion",
			temperature: 0.7,
			wantFinding: false,
		},
		{
			name:        "non-LLM tool name — not matched by tool_name_regex",
			tool:        "read_file",
			temperature: 2.0,
			wantFinding: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := e.CheckValueLimits(tc.tool, map[string]interface{}{
				"temperature": tc.temperature,
				"model":       "gpt-4",
			})

			if tc.wantFinding {
				if len(result.Findings) == 0 {
					t.Errorf("expected a finding for temperature=%.2f tool=%q, got none", tc.temperature, tc.tool)
					return
				}
				found := false
				for _, f := range result.Findings {
					if f.RuleID == tc.wantRuleID {
						found = true
					}
				}
				if !found {
					t.Errorf("expected finding with ruleID=%q, got findings: %+v", tc.wantRuleID, result.Findings)
				}
			} else {
				if len(result.Findings) > 0 {
					t.Errorf("expected no findings for temperature=%.2f tool=%q, got: %+v", tc.temperature, tc.tool, result.Findings)
				}
			}
		})
	}
}

// TestLLMInferencePack_ExtremeTopP validates mcp-llminf-audit-extreme-top-p (issue #1551).
func TestLLMInferencePack_ExtremeTopP(t *testing.T) {
	base := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks("../../packs/premium/mcp", base)
	if err != nil {
		t.Fatalf("failed to load premium MCP packs: %v", err)
	}
	e := NewPolicyEvaluator(merged)

	cases := []struct {
		name        string
		topP        float64
		wantFinding bool
	}{
		{"top_p 0.01 — near-zero", 0.01, true},
		{"top_p 0.03 — just below threshold", 0.03, true},
		{"top_p 0.04 — exactly at min (NOT fired, condition is < min)", 0.04, false},
		{"top_p 0.1 — factual tasks range", 0.1, false},
		{"top_p 0.9 — creative writing", 0.9, false},
		{"top_p 1.0 — standard default", 1.0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := e.CheckValueLimits("chat_completion", chatArgs(map[string]interface{}{"top_p": tc.topP}))
			gotFinding := false
			for _, f := range result.Findings {
				if f.RuleID == "mcp-llminf-audit-extreme-top-p" {
					gotFinding = true
				}
			}
			if tc.wantFinding && !gotFinding {
				t.Errorf("expected finding for top_p=%.3f, got none", tc.topP)
			}
			if !tc.wantFinding && gotFinding {
				t.Errorf("expected no finding for top_p=%.3f, got one", tc.topP)
			}
		})
	}
}

// TestLLMInferencePack_ExtremePenalties validates presence_penalty and frequency_penalty
// rules (issue #1551).
func TestLLMInferencePack_ExtremePenalties(t *testing.T) {
	base := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks("../../packs/premium/mcp", base)
	if err != nil {
		t.Fatalf("failed to load premium MCP packs: %v", err)
	}
	e := NewPolicyEvaluator(merged)

	cases := []struct {
		name       string
		argName    string
		val        float64
		wantRuleID string
		wantFire   bool
	}{
		// presence_penalty low
		{"presence_penalty -2.0 — extreme negative", "presence_penalty", -2.0, "mcp-llminf-audit-extreme-presence-penalty-low", true},
		{"presence_penalty -1.5 — extreme negative", "presence_penalty", -1.5, "mcp-llminf-audit-extreme-presence-penalty-low", true},
		{"presence_penalty -1.49 — at boundary (NOT fired)", "presence_penalty", -1.49, "mcp-llminf-audit-extreme-presence-penalty-low", false},
		{"presence_penalty -1.0 — normal range", "presence_penalty", -1.0, "mcp-llminf-audit-extreme-presence-penalty-low", false},
		{"presence_penalty 0.0 — default", "presence_penalty", 0.0, "mcp-llminf-audit-extreme-presence-penalty-low", false},
		// presence_penalty high
		{"presence_penalty 2.0 — extreme positive", "presence_penalty", 2.0, "mcp-llminf-audit-extreme-presence-penalty-high", true},
		{"presence_penalty 1.5 — extreme positive", "presence_penalty", 1.5, "mcp-llminf-audit-extreme-presence-penalty-high", true},
		{"presence_penalty 1.49 — at boundary (NOT fired)", "presence_penalty", 1.49, "mcp-llminf-audit-extreme-presence-penalty-high", false},
		{"presence_penalty 1.0 — normal range", "presence_penalty", 1.0, "mcp-llminf-audit-extreme-presence-penalty-high", false},
		// frequency_penalty low
		{"frequency_penalty -2.0 — extreme negative", "frequency_penalty", -2.0, "mcp-llminf-audit-extreme-frequency-penalty-low", true},
		{"frequency_penalty -1.5 — extreme negative", "frequency_penalty", -1.5, "mcp-llminf-audit-extreme-frequency-penalty-low", true},
		{"frequency_penalty -1.49 — at boundary (NOT fired)", "frequency_penalty", -1.49, "mcp-llminf-audit-extreme-frequency-penalty-low", false},
		{"frequency_penalty 0.0 — default", "frequency_penalty", 0.0, "mcp-llminf-audit-extreme-frequency-penalty-low", false},
		// frequency_penalty high
		{"frequency_penalty 2.0 — extreme positive", "frequency_penalty", 2.0, "mcp-llminf-audit-extreme-frequency-penalty-high", true},
		{"frequency_penalty 1.5 — extreme positive", "frequency_penalty", 1.5, "mcp-llminf-audit-extreme-frequency-penalty-high", true},
		{"frequency_penalty 1.49 — at boundary (NOT fired)", "frequency_penalty", 1.49, "mcp-llminf-audit-extreme-frequency-penalty-high", false},
		{"frequency_penalty 0.5 — creative writing", "frequency_penalty", 0.5, "mcp-llminf-audit-extreme-frequency-penalty-high", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := e.CheckValueLimits("chat_completion", chatArgs(map[string]interface{}{tc.argName: tc.val}))
			gotFinding := false
			for _, f := range result.Findings {
				if f.RuleID == tc.wantRuleID {
					gotFinding = true
				}
			}
			if tc.wantFire && !gotFinding {
				t.Errorf("expected rule %q to fire for %s=%.3f, got no finding", tc.wantRuleID, tc.argName, tc.val)
			}
			if !tc.wantFire && gotFinding {
				t.Errorf("expected rule %q NOT to fire for %s=%.3f, got a finding", tc.wantRuleID, tc.argName, tc.val)
			}
		})
	}
}

// TestVectorDBEnumeration validates the vector DB enumeration value limit rules
// (mcp-llminf-audit-vector-db-enum-*) in packs/premium/mcp/mcp-llm-inference.yaml.
// These rules detect unbounded result-limit parameters in vector search tool calls
// that enable systematic corpus enumeration (top_k/k/n_results/nResults/limit > 100).
func TestVectorDBEnumeration(t *testing.T) {
	base := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks("../../packs/premium/mcp", base)
	if err != nil {
		t.Fatalf("failed to load premium MCP packs: %v", err)
	}
	e := NewPolicyEvaluator(merged)

	cases := []struct {
		name        string
		tool        string
		argName     string
		argVal      float64
		wantFinding bool
		wantRuleID  string
	}{
		// top_k — the canonical RAG result-limit parameter
		{"top_k=5000 vector_search — clear corpus enumeration", "vector_search", "top_k", 5000, true, "mcp-llminf-audit-vector-db-enum-top-k"},
		{"top_k=100 semantic_search — just over threshold", "semantic_search", "top_k", 100, true, "mcp-llminf-audit-vector-db-enum-top-k"},
		{"top_k=99 rag_query — exactly at max (should NOT fire)", "rag_query", "top_k", 99, false, ""},
		{"top_k=10 vector_search — normal RAG retrieval", "vector_search", "top_k", 10, false, ""},

		// k — used by scikit-learn style APIs and many vector DBs
		{"k=200 embed_search — enumeration via k", "embed_search", "k", 200, true, "mcp-llminf-audit-vector-db-enum-k"},
		{"k=5 similarity_search — normal RAG retrieval", "similarity_search", "k", 5, false, ""},

		// n_results — Chroma / ChromaDB convention
		{"n_results=500 qdrant_search — corpus dump", "qdrant_search", "n_results", 500, true, "mcp-llminf-audit-vector-db-enum-n-results"},
		{"n_results=20 chroma_query — normal retrieval", "chroma_query", "n_results", 20, false, ""},

		// nResults — camelCase variant used in some JS/TS MCP SDKs
		{"nResults=1000 pinecone_query — full corpus", "pinecone_query", "nResults", 1000, true, "mcp-llminf-audit-vector-db-enum-n-results-camel"},
		{"nResults=15 weaviate_search — normal", "weaviate_search", "nResults", 15, false, ""},

		// limit — generic pagination param repurposed as result-limit
		{"limit=2000 milvus_search — full corpus", "milvus_search", "limit", 2000, true, "mcp-llminf-audit-vector-db-enum-limit"},
		{"limit=10 query_collection — normal", "query_collection", "limit", 10, false, ""},

		// non-matching tools — should NOT fire even with extreme values
		{"top_k=5000 read_file — not a vector search tool", "read_file", "top_k", 5000, false, ""},
		{"top_k=5000 chat_completion — LLM inference, not vector search", "chat_completion", "top_k", 5000, false, ""},
		{"limit=5000 list_files — filesystem tool, not vector search", "list_files", "limit", 5000, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := e.CheckValueLimits(tc.tool, map[string]interface{}{
				tc.argName: tc.argVal,
			})
			if tc.wantFinding {
				if len(result.Findings) == 0 {
					t.Fatalf("expected finding (rule %q) for %s=%v on tool %q, got none", tc.wantRuleID, tc.argName, tc.argVal, tc.tool)
				}
				gotRule := result.Findings[0].RuleID
				if tc.wantRuleID != "" && gotRule != tc.wantRuleID {
					t.Errorf("expected rule %q, got %q", tc.wantRuleID, gotRule)
				}
			} else {
				if len(result.Findings) != 0 {
					t.Fatalf("expected NO finding for %s=%v on tool %q, got: %+v", tc.argName, tc.argVal, tc.tool, result.Findings)
				}
			}
		})
	}
}
