package logger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// fakeScrub finds the customer-records label: a real engine's Spans, the
// scrubber the hook attaches (#4813).
var fakeScrub = mustLabelSpans(datalabel.DataLabelConfig{ID: "customer-records", Patterns: []datalabel.PatternConfig{{Regex: `CUST-[0-9]{6}`}}})

// mustLabelSpans compiles labels into a scrubber.
func mustLabelSpans(labels ...datalabel.DataLabelConfig) func(string) []datalabel.Span {
	e, err := datalabel.NewEngine(labels)
	if err != nil {
		panic(err)
	}
	return e.Spans
}

// codenameScrub finds the codename label, the keyword PHOENIX in that case.
var codenameScrub = mustLabelSpans(datalabel.DataLabelConfig{ID: "codename", Patterns: []datalabel.PatternConfig{{Keywords: []string{"PHOENIX"}, CaseSensitive: true}}})

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
		Notes: []Note{{Kind: "dynamic_name", Detail: `command name "CUST-104233" is computed`}},
	}.WithScrubber(fakeScrub)

	r := e.Redacted()
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "CUST-104233") {
		t.Fatalf("value survived Redacted(): %s", raw)
	}
	if strings.Count(string(raw), "[LABEL:customer-records]") != 7 {
		t.Fatalf("expected 7 placeholders: %s", raw)
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
