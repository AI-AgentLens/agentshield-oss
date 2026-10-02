package cli

import (
	"encoding/json"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// #3995: notes reach the wire only when present. The audit-only contract
// golden (TestBuildAuditPayload_AuditOnlyContract) already pins the absent
// case byte-for-byte; this pins the present one.
func TestBuildAuditPayload_NotesPresentOnlyWhenSet(t *testing.T) {
	ev := &logger.AuditEvent{Command: "ls", Decision: "AUDIT", Mode: "enforce"}
	raw, err := buildAuditPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	// The wire payload is {"events":[{...}]}; unwrap the one event.
	unwrap := func(raw []byte) map[string]any {
		t.Helper()
		var body struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || len(body.Events) != 1 {
			t.Fatalf("payload shape: %s (%v)", raw, err)
		}
		return body.Events[0]
	}
	entry := unwrap(raw)
	if _, ok := entry["notes"]; ok {
		t.Fatalf("payload without notes must omit the key: %s", raw)
	}

	ev.Notes = auditNotes([]analyzer.Note{{Kind: analyzer.NoteExcused, Rule: "ts-block-x", Detail: "intent:is_doc_text"}})
	raw, err = buildAuditPayload(ev)
	if err != nil {
		t.Fatal(err)
	}
	entry = unwrap(raw)
	notes, ok := entry["notes"].([]any)
	if !ok || len(notes) != 1 {
		t.Fatalf("payload with notes: %s", raw)
	}
	n := notes[0].(map[string]any)
	if n["kind"] != "excused" || n["rule"] != "ts-block-x" || n["detail"] != "intent:is_doc_text" {
		t.Fatalf("note fields: %v", n)
	}
	if auditNotes(nil) != nil {
		t.Fatal("auditNotes(nil) must be nil so omitempty applies")
	}
}
