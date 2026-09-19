package mcp

import (
	"io"
	"testing"
)

// #3617: the audit event's taxonomy for a Go-engine detection comes from the
// sentinel rule, so re-homing a detection in mcp-sentinel.yaml changes the
// receipt without a code change.

func TestSentinelTaxonomyRef_UsesSentinelWhenLoaded(t *testing.T) {
	ev := NewPolicyEvaluator(&MCPPolicy{Rules: []MCPRule{
		{ID: "test-sentinel", Engine: "mcp-response-meta-field-injection", Taxonomy: "test-kingdom/test-category/test-node", Decision: "BLOCK"},
		{ID: "no-taxonomy-sentinel", Engine: "mcp-response-non-text-content", Decision: "BLOCK"},
	}})
	h := &MessageHandler{Stderr: io.Discard, Evaluator: ev}

	if got := h.sentinelTaxonomyRef("mcp-response-meta-field-injection"); got != "test-kingdom/test-category/test-node" {
		t.Errorf("sentinel taxonomy not used: %q", got)
	}
	if got := h.sentinelTaxonomyRef("mcp-response-non-text-content"); got != genericResponsePoisoningTaxonomy {
		t.Errorf("sentinel without taxonomy must fall back to the generic node, got %q", got)
	}
	if got := h.sentinelTaxonomyRef("mcp-engine-that-does-not-exist"); got != genericResponsePoisoningTaxonomy {
		t.Errorf("unknown engine must fall back to the generic node, got %q", got)
	}
	none := &MessageHandler{Stderr: io.Discard}
	if got := none.sentinelTaxonomyRef("mcp-response-meta-field-injection"); got != genericResponsePoisoningTaxonomy {
		t.Errorf("no evaluator must fall back to the generic node, got %q", got)
	}
}

// TestFilterToolCallResponse_AuditTaxonomyFollowsSentinel drives a real
// detection end to end: with the meta-field sentinel re-homed in the loaded
// policy, the emitted AuditEntry carries the new node, not the literal the
// handler used to hardcode.
func TestFilterToolCallResponse_AuditTaxonomyFollowsSentinel(t *testing.T) {
	ev := NewPolicyEvaluator(&MCPPolicy{Rules: []MCPRule{
		{ID: "mcp-response-meta-field-injection-sentinel", Engine: "mcp-response-meta-field-injection", Taxonomy: "test-kingdom/test-category/meta-field-node", Decision: "BLOCK"},
	}})
	resp := buildToolCallResultWithMeta(t,
		[]ContentItem{{Type: "text", Text: "3 results found"}},
		map[string]string{"debug_info": metaInj2},
	)
	var audited []AuditEntry
	h := &MessageHandler{
		Stderr:    io.Discard,
		Evaluator: ev,
		OnAudit:   func(e AuditEntry) { audited = append(audited, e) },
	}
	if filtered := h.FilterToolCallResponse(resp); filtered == nil {
		t.Fatal("expected the meta-field injection to be replaced")
	}
	if len(audited) == 0 {
		t.Fatal("expected an audit entry")
	}
	if audited[0].TaxonomyRef != "test-kingdom/test-category/meta-field-node" {
		t.Fatalf("AuditEntry.TaxonomyRef = %q; want the sentinel's node — the receipt must follow the YAML", audited[0].TaxonomyRef)
	}
}
