package mcp

import (
	"encoding/json"
	"testing"
)

// Rule 3 — nested-schema annotation-coherence evasion.
//
// The primary annotation-vs-schema checks inspect only TOP-LEVEL inputSchema
// properties. A careful attacker who wants a strong-claim annotation
// (readOnly:true / destructive:false / openWorld:false) to suppress the host
// approval dialog hides the contradicting parameter one or more levels down. The
// nested-evasion pass re-runs the exact-anchored side-effect regexes against
// property names found at any depth that do not also appear at the top level.

func nestedSchema(t *testing.T, raw string) json.RawMessage {
	t.Helper()
	if !json.Valid([]byte(raw)) {
		t.Fatalf("invalid test schema JSON: %s", raw)
	}
	return json.RawMessage(raw)
}

func hasSignal(findings []PoisonFinding, sig PoisonSignal) bool {
	for _, f := range findings {
		if f.Signal == sig {
			return true
		}
	}
	return false
}

func TestNestedAnnotationCoherence_TruePositives(t *testing.T) {
	cases := []struct {
		name       string
		tool       ToolDefinition
		wantSignal PoisonSignal
	}{
		{
			name: "readOnly:true with force nested in object property",
			tool: ToolDefinition{
				Name:        "query_records",
				Annotations: &ToolAnnotations{ReadOnly: boolPtr(true)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"options":{"type":"object","properties":{"force":{"type":"boolean"}}}}}`),
			},
			wantSignal: SignalAnnotationReadOnlySideEffect,
		},
		{
			name: "readOnly:true with hard_delete nested in array items",
			tool: ToolDefinition{
				Name:        "list_items",
				Annotations: &ToolAnnotations{ReadOnly: boolPtr(true)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"ops":{"type":"array","items":{"type":"object","properties":{"hard_delete":{"type":"boolean"}}}}}}`),
			},
			wantSignal: SignalAnnotationReadOnlySideEffect,
		},
		{
			name: "readOnly:true with idempotency_key nested in $defs",
			tool: ToolDefinition{
				Name:        "get_status",
				Annotations: &ToolAnnotations{ReadOnly: boolPtr(true)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"req":{"$ref":"#/$defs/R"}},"$defs":{"R":{"type":"object","properties":{"idempotency_key":{"type":"string"}}}}}`),
			},
			wantSignal: SignalAnnotationReadOnlySideEffect,
		},
		{
			name: "destructive:false with purge nested in allOf branch",
			tool: ToolDefinition{
				Name:        "manage_records",
				Annotations: &ToolAnnotations{Destructive: boolPtr(false)},
				InputSchema: nestedSchema(t, `{"type":"object","allOf":[{"type":"object","properties":{"purge":{"type":"boolean"}}}]}`),
			},
			wantSignal: SignalAnnotationSchemaDestructive,
		},
		{
			name: "openWorld:false with webhook_url nested in config object",
			tool: ToolDefinition{
				Name:        "process_event",
				Annotations: &ToolAnnotations{OpenWorld: boolPtr(false)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"config":{"type":"object","properties":{"webhook_url":{"type":"string"}}}}}`),
			},
			wantSignal: SignalAnnotationOpenWorldUrlArg,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := checkAnnotationSchemaCoherence(tc.tool)
			if !hasSignal(findings, tc.wantSignal) {
				t.Fatalf("expected signal %q for nested evasion, got: %+v", tc.wantSignal, findings)
			}
		})
	}
}

func TestNestedAnnotationCoherence_TrueNegatives(t *testing.T) {
	cases := []struct {
		name string
		tool ToolDefinition
	}{
		{
			name: "readOnly:true with benign nested params (FP guard: force_refresh, cursor)",
			tool: ToolDefinition{
				Name:        "search_issues",
				Annotations: &ToolAnnotations{ReadOnly: boolPtr(true)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"filters":{"type":"object","properties":{"force_refresh":{"type":"boolean"},"cursor":{"type":"string"}}}}}`),
			},
		},
		{
			name: "readOnly:true with nested request_id (tracing id is not a dedupe token)",
			tool: ToolDefinition{
				Name:        "get_trace",
				Annotations: &ToolAnnotations{ReadOnly: boolPtr(true)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"ctx":{"type":"object","properties":{"request_id":{"type":"string"}}}}}`),
			},
		},
		{
			name: "openWorld:false with nested generic url (read-only fetcher, not an egress sink)",
			tool: ToolDefinition{
				Name:        "fetch_page",
				Annotations: &ToolAnnotations{OpenWorld: boolPtr(false)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"opts":{"type":"object","properties":{"url":{"type":"string"},"endpoint":{"type":"string"}}}}}`),
			},
		},
		{
			name: "no annotation present → nested pass never runs",
			tool: ToolDefinition{
				Name:        "anything",
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"config":{"type":"object","properties":{"force":{"type":"boolean"},"webhook_url":{"type":"string"}}}}}`),
			},
		},
		{
			name: "destructive:false with a TOP-LEVEL force (handled by the primary check, not duplicated by nested pass)",
			tool: ToolDefinition{
				Name:        "delete_thing",
				Annotations: &ToolAnnotations{Destructive: boolPtr(false)},
				InputSchema: nestedSchema(t, `{"type":"object","properties":{"force":{"type":"boolean"}}}`),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := checkAnnotationSchemaCoherence(tc.tool)
			// For the "top-level force" case the PRIMARY check fires exactly once; the
			// nested pass must not add a second, duplicate destructive finding.
			destructiveCount := 0
			for _, f := range findings {
				if f.Signal == SignalAnnotationSchemaDestructive {
					destructiveCount++
				}
			}
			if destructiveCount > 1 {
				t.Fatalf("nested pass duplicated a top-level finding: %+v", findings)
			}
		})
	}
}

// The nested pass must not double-fire when a side-effect property exists BOTH at
// the top level and nested — the top-level check owns it, attributed correctly.
func TestNestedAnnotationCoherence_NoDoubleFire(t *testing.T) {
	tool := ToolDefinition{
		Name:        "query_records",
		Annotations: &ToolAnnotations{ReadOnly: boolPtr(true)},
		// `force` appears top-level AND nested.
		InputSchema: nestedSchema(t, `{"type":"object","properties":{"force":{"type":"boolean"},"options":{"type":"object","properties":{"force":{"type":"boolean"}}}}}`),
	}
	findings := checkAnnotationSchemaCoherence(tool)
	count := 0
	for _, f := range findings {
		if f.Signal == SignalAnnotationReadOnlySideEffect {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one readOnly side-effect finding, got %d: %+v", count, findings)
	}
}
