package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/redact"
)

// secretShaped is assembled at runtime: the hook reads test sources as commands.
func secretShaped() string { return "api_key=" + strings.Repeat("A1b2", 6) }

func TestAuditEntryRedacted_4463(t *testing.T) {
	label := "PHOENIX-" + "7731"
	eng, err := datalabel.NewEngine([]datalabel.DataLabelConfig{{ID: "codename", Patterns: []datalabel.PatternConfig{{Regex: `PHOENIX-[0-9]{4}`}}}})
	if err != nil {
		t.Fatal(err)
	}
	scrub := eng.Spans

	in := AuditEntry{
		ToolName: "send_message",
		Decision: "BLOCK",
		Arguments: map[string]interface{}{
			"body":   "status of " + label + " is green",
			"nested": map[string]interface{}{"items": []interface{}{"x " + label, 3.0}},
			"cfg":    secretShaped(),
		},
		Reasons: []string{"matched " + label + " in outbound argument"},
	}

	// Control: without Redacted the entry carries both values. Proves the
	// assertions below can fail.
	raw, _ := json.Marshal(in)
	if !strings.Contains(string(raw), label) || !strings.Contains(string(raw), secretShaped()) {
		t.Fatalf("control: raw entry should carry label and secret: %s", raw)
	}

	for name, fn := range map[string]func(string) []datalabel.Span{"with scrubber": scrub} {
		out, _ := json.Marshal(in.Redacted(fn))
		got := string(out)
		if strings.Contains(got, label) {
			t.Errorf("%s: label value survived: %s", name, got)
		}
		if !strings.Contains(got, "[LABEL:codename]") {
			t.Errorf("%s: placeholder missing: %s", name, got)
		}
		if strings.Contains(got, secretShaped()) {
			t.Errorf("%s: secret survived: %s", name, got)
		}
		if !strings.Contains(got, `"decision":"BLOCK"`) || !strings.Contains(got, `"tool_name":"send_message"`) {
			t.Errorf("%s: decision/tool altered: %s", name, got)
		}
	}

	// No data labels configured: secrets are still redacted.
	out, _ := json.Marshal(in.Redacted(nil))
	if strings.Contains(string(out), secretShaped()) {
		t.Errorf("nil scrubber: secret survived: %s", out)
	}

	// The input is not modified.
	if in.Arguments["cfg"] != secretShaped() || !strings.Contains(in.Reasons[0], label) {
		t.Errorf("Redacted modified its receiver")
	}
}

func TestAuditEntryRedacted_NilShapesKept_4463(t *testing.T) {
	out := AuditEntry{ToolName: "t", Decision: "ALLOW"}.Redacted(func(string) []datalabel.Span { return nil })
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "arguments") || strings.Contains(string(b), "reasons") {
		t.Errorf("empty fields must stay omitted: %s", b)
	}
}

// TestAuditEntryRedacted_LabelInsideSecret_4813: the proxies' entry had the
// hook's order (scrub, then redact), so a label value inside a secret left
// the secret's tail in the entry. Arguments at depth and reasons are now
// masked as the hook's record is. Control: main's order leaves the tail.
func TestAuditEntryRedacted_LabelInsideSecret_4813(t *testing.T) {
	eng, err := datalabel.NewEngine([]datalabel.DataLabelConfig{{ID: "customer-records", Patterns: []datalabel.PatternConfig{{Regex: `CUST-[0-9]{6}`}}}})
	if err != nil {
		t.Fatal(err)
	}
	tail := "zz9yy8xx7ww6vv5u"
	shape := "export TO" + "KEN=abcdefghijklmn" + "CUST-" + "104233" + tail
	in := AuditEntry{
		ToolName:  "run_command",
		Decision:  "BLOCK",
		Arguments: map[string]interface{}{"command": shape, "nested": map[string]interface{}{"list": []interface{}{shape}}},
		Reasons:   []string{"matched in " + shape},
	}
	got, _ := json.Marshal(in.Redacted(eng.Spans))
	for _, g := range []string{tail, "104233", "abcdefghijklmn"} {
		if strings.Contains(string(got), g) {
			t.Errorf("%q survived: %s", g, got)
		}
	}
	if !strings.Contains(string(got), `"decision":"BLOCK"`) || !strings.Contains(string(got), `"tool_name":"run_command"`) {
		t.Errorf("decision/tool altered: %s", got)
	}
	// Control: main's order, scrub then redact.
	if main := redact.Redact(eng.Scrub(shape)); !strings.Contains(main, tail) {
		t.Fatalf("control: main's order no longer leaves the tail (%q)", main)
	}
}
