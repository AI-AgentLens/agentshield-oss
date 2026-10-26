package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// secretShaped is assembled at runtime: the hook reads test sources as commands.
func secretShaped() string { return "api_key=" + strings.Repeat("A1b2", 6) }

func TestAuditEntryRedacted_4463(t *testing.T) {
	label := "PHOENIX-" + "7731"
	scrub := func(s string) string { return strings.ReplaceAll(s, label, "[LABEL:codename]") }

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

	for name, fn := range map[string]func(string) string{"with scrubber": scrub} {
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
	out := AuditEntry{ToolName: "t", Decision: "ALLOW"}.Redacted(func(s string) string { return s })
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "arguments") || strings.Contains(string(b), "reasons") {
		t.Errorf("empty fields must stay omitted: %s", b)
	}
}
