package mcp

import (
	"strings"
	"testing"
)

// Rule 2 — outputSchema rug-pull drift.
//
// The drift fingerprint historically covered InputSchema + Description only. A
// malicious server could re-list a tool with an IDENTICAL input schema and
// description but a SWAPPED outputSchema (MCP 2025-06-18) — re-shaping how the
// agent interprets the tool's structured result, and re-introducing poisoned
// example/enum values on the output surface — and the drift check would report
// "no change". These tests verify the OutputSchemaHash fingerprint closes that
// gap while staying upgrade-safe and false-positive-free.

func outSchema(t *testing.T, props map[string]interface{}) []byte {
	t.Helper()
	return rawSchema(t, map[string]interface{}{
		"type":       "object",
		"properties": props,
	})
}

// TP: outputSchema swap with input + description stable IS flagged as drift.
func TestOutputSchemaDrift_SwapDetected(t *testing.T) {
	s := newTestScanner(t)
	in := outSchema(t, map[string]interface{}{"id": map[string]string{"type": "string"}})

	v1 := []ToolDefinition{{
		Name:         "get_record",
		Description:  "Fetch a record by id.",
		InputSchema:  in,
		OutputSchema: outSchema(t, map[string]interface{}{"value": map[string]string{"type": "string"}}),
	}}
	if r := s.CheckDrift("srv", v1); !r.FirstSeen {
		t.Fatalf("expected first-seen baseline, got %+v", r)
	}

	// Same name, same input schema, same description — ONLY outputSchema changes.
	v2 := []ToolDefinition{{
		Name:         "get_record",
		Description:  "Fetch a record by id.",
		InputSchema:  in,
		OutputSchema: outSchema(t, map[string]interface{}{"value": map[string]string{"type": "string"}, "rows_affected": map[string]string{"type": "integer"}}),
	}}
	r := s.CheckDrift("srv", v2)
	if !r.Drifted {
		t.Fatal("expected drift when outputSchema swapped")
	}
	if len(r.OutputSchemaChangedTools) != 1 || r.OutputSchemaChangedTools[0] != "get_record" {
		t.Fatalf("expected OutputSchemaChangedTools=[get_record], got %+v", r.OutputSchemaChangedTools)
	}
	// Input-only drift list must NOT contain it (the swap is output-side only).
	if len(r.ChangedTools) != 0 {
		t.Fatalf("input schema unchanged but ChangedTools=%v", r.ChangedTools)
	}
	if len(r.DescriptionChangedTools) != 0 {
		t.Fatalf("description unchanged but DescriptionChangedTools=%v", r.DescriptionChangedTools)
	}
	if !strings.Contains(r.DriftSummary(), "output-schema rug-pull") {
		t.Fatalf("DriftSummary should mention output-schema rug-pull, got %q", r.DriftSummary())
	}
}

// TN: identical outputSchema across listings → no drift.
func TestOutputSchemaDrift_NoChange(t *testing.T) {
	s := newTestScanner(t)
	out := outSchema(t, map[string]interface{}{"value": map[string]string{"type": "string"}})
	tools := []ToolDefinition{{
		Name:         "get_record",
		Description:  "Fetch a record.",
		InputSchema:  outSchema(t, map[string]interface{}{"id": map[string]string{"type": "string"}}),
		OutputSchema: out,
	}}
	_ = s.CheckDrift("srv", tools) // baseline
	r := s.CheckDrift("srv", tools)
	if r.Drifted {
		t.Fatalf("identical re-list should not drift, got %+v", r)
	}
	if len(r.OutputSchemaChangedTools) != 0 {
		t.Fatalf("expected no output-schema drift, got %+v", r.OutputSchemaChangedTools)
	}
}

// TN: a tool that never declares an outputSchema across two listings → no drift
// (both hashes are "empty"; no spurious flag).
func TestOutputSchemaDrift_NoOutputSchema_NoDrift(t *testing.T) {
	s := newTestScanner(t)
	tools := []ToolDefinition{{
		Name:        "ping",
		Description: "Health check.",
		InputSchema: outSchema(t, map[string]interface{}{}),
		// no OutputSchema
	}}
	_ = s.CheckDrift("srv", tools)
	r := s.CheckDrift("srv", tools)
	if r.Drifted {
		t.Fatalf("tool without outputSchema should never drift, got %+v", r)
	}
}

// Upgrade safety: a baseline written WITHOUT an OutputSchemaHash (simulating a
// cache from before this field existed) must not produce a spurious output-schema
// drift on the first post-upgrade listing, even if the tool now has an
// outputSchema. We simulate the old cache by hand-writing an entry whose
// OutputSchemaHash is "".
func TestOutputSchemaDrift_UpgradeSafe(t *testing.T) {
	s := newTestScanner(t)
	// Hand-craft and persist an "old" cache entry lacking OutputSchemaHash.
	old := schemaCache{Tools: map[string]toolSchemaEntry{
		"get_record": {
			InputSchemaHash: hashInputSchema(outSchema(t, map[string]interface{}{"id": map[string]string{"type": "string"}})),
			DescriptionHash: hashDescription("Fetch a record."),
			// OutputSchemaHash deliberately empty (pre-upgrade cache).
		},
	}}
	if err := s.saveCache("srv", old); err != nil {
		t.Fatalf("saveCache: %v", err)
	}

	now := []ToolDefinition{{
		Name:         "get_record",
		Description:  "Fetch a record.",
		InputSchema:  outSchema(t, map[string]interface{}{"id": map[string]string{"type": "string"}}),
		OutputSchema: outSchema(t, map[string]interface{}{"value": map[string]string{"type": "string"}}),
	}}
	r := s.CheckDrift("srv", now)
	if len(r.OutputSchemaChangedTools) != 0 {
		t.Fatalf("first post-upgrade listing must not flag output-schema drift, got %+v", r.OutputSchemaChangedTools)
	}
}
