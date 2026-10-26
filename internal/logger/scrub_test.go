package logger

import (
	"encoding/json"
	"strings"
	"testing"
)

func fakeScrub(s string) string { return strings.ReplaceAll(s, "CUST-104233", "[LABEL:customer-records]") }

func TestRedacted_ScrubberCoversEveryAgentTextField(t *testing.T) {
	e := AuditEvent{
		Command: "echo CUST-104233",
		Args:    []string{"CUST-104233"},
		Reasons: []string{"data label CUST-104233"},
		Error:   "failed on CUST-104233",
		MCPArguments: map[string]interface{}{
			"a": "CUST-104233",
			"n": map[string]interface{}{"b": []interface{}{"x CUST-104233", 7}},
		},
	}.WithScrubber(fakeScrub)

	r := e.Redacted()
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "CUST-104233") {
		t.Fatalf("value survived Redacted(): %s", raw)
	}
	if strings.Count(string(raw), "[LABEL:customer-records]") != 6 {
		t.Fatalf("expected 6 placeholders: %s", raw)
	}
	// The caller's event is not modified.
	if e.Command != "echo CUST-104233" || e.Args[0] != "CUST-104233" || e.MCPArguments["a"] != "CUST-104233" {
		t.Fatal("Redacted mutated the original event")
	}
}

func TestRedacted_NoScrubberIsUnchanged(t *testing.T) {
	e := AuditEvent{Command: "echo CUST-104233", MCPArguments: map[string]interface{}{"a": "CUST-104233"}}
	r := e.Redacted()
	if r.Command != "echo CUST-104233" || r.MCPArguments["a"] != "CUST-104233" {
		t.Fatalf("no scrubber must leave label-shaped text alone: %+v", r)
	}
}

func TestScrubber_IsNeverSerialised(t *testing.T) {
	plain, _ := json.Marshal(AuditEvent{Command: "ls"})
	with, _ := json.Marshal(AuditEvent{Command: "ls"}.WithScrubber(fakeScrub))
	if string(plain) != string(with) {
		t.Fatalf("scrubber changed the wire shape:\n%s\n%s", plain, with)
	}
}
