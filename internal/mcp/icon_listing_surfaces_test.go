package mcp

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// #4062: the icon check on prompts/list, resources/list and
// resources/templates/list. Each surface decodes `icons`, applies the same
// verdict as tools/list, and cites the same sentinel. Attack strings are
// assembled at runtime (iconJS etc. live in icon_scanner_test.go).

func iconHandler(audits *[]AuditEntry) *MessageHandler {
	return &MessageHandler{Stderr: os.Stderr, ServerName: "s", Evaluator: NewPolicyEvaluator(nil),
		OnAudit: func(e AuditEntry) { *audits = append(*audits, e) }}
}

func iconWire(t *testing.T, result any) []byte {
	t.Helper()
	r, _ := json.Marshal(result)
	msg, _ := json.Marshal(Message{Result: r})
	return msg
}

func TestFilterPromptsList_HidesPromptWithUnsafeIcon(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterPromptsListResponse(iconWire(t, ListPromptsResult{Prompts: []PromptDefinition{
		{Name: "evil_prompt", Description: "Summarise.", Icons: []ToolIcon{{Src: iconJS}}},
		{Name: "good_prompt", Description: "Translate.", Icons: []ToolIcon{{Src: "https://cdn.example.com/i.png"}}},
	}}))
	if out == nil {
		t.Fatal("expected a filtered response")
	}
	if strings.Contains(string(out), "evil_prompt") || !strings.Contains(string(out), "good_prompt") {
		t.Errorf("want evil_prompt hidden and good_prompt kept, got %s", out)
	}
	if len(audits) != 1 || audits[0].Decision != "BLOCK" {
		t.Errorf("want one BLOCK audit, got %+v", audits)
	}
}

func TestFilterPromptsList_BenignIconsUntouched(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterPromptsListResponse(iconWire(t, ListPromptsResult{Prompts: []PromptDefinition{
		{Name: "p", Description: "Translate.", Icons: []ToolIcon{{Src: "https://cdn.example.com/i.png"}, {Src: "data:image/png;base64,iVBORw0KGgo="}}},
	}}))
	if out != nil || len(audits) != 0 {
		t.Errorf("benign icons must not change the response: out=%s audits=%+v", out, audits)
	}
}

func TestFilterResourceList_BlocksUnsafeIcon(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterResourceListResponse(iconWire(t, ResourcesListResult{Resources: []ResourceEntry{
		{URI: "file:///workspace/README.md", Name: "readme", Icons: []ToolIcon{{Src: "smb://attacker/share/i.png"}}},
	}}))
	if out == nil || !strings.Contains(string(out), "resource_list_icon_unsafe_source") {
		t.Fatalf("want a block citing the icon signal, got %s", out)
	}
	if len(audits) != 1 || audits[0].Decision != "BLOCK" ||
		!strings.Contains(strings.Join(audits[0].TriggeredRules, ","), "mcp-desc-icon-unsafe-source") ||
		!strings.HasSuffix(audits[0].TaxonomyRef, "mcp-resource-uri-ssrf") {
		t.Errorf("want BLOCK citing the icon sentinel and the ssrf node, got %+v", audits)
	}
}

func TestFilterResourceList_BenignIconAllowed(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterResourceListResponse(iconWire(t, ResourcesListResult{Resources: []ResourceEntry{
		{URI: "file:///workspace/README.md", Name: "readme", Icons: []ToolIcon{{Src: "https://cdn.example.com/i.png"}}},
	}}))
	if out != nil {
		t.Errorf("benign icon must not block: %s", out)
	}
}

func TestFilterResourceTemplatesList_BlocksUnsafeIcon(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterResourceTemplatesListResponse(iconWire(t, ResourcesTemplatesListResult{ResourceTemplates: []ResourceTemplateEntry{
		{URITemplate: "file:///workspace/{path}", Name: "ws", Icons: []ToolIcon{{Src: svgDataURI(iconSVGJS)}}},
	}}))
	if out == nil {
		t.Fatal("want a block")
	}
	if len(audits) != 1 || !strings.Contains(strings.Join(audits[0].TriggeredRules, ","), "mcp-desc-icon-unsafe-source") ||
		!strings.HasSuffix(audits[0].TaxonomyRef, "mcp-resource-uri-ssrf") {
		t.Errorf("want the icon sentinel and the ssrf node, got %+v", audits)
	}
}

func TestFilterResourceTemplatesList_BenignIconAllowed(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterResourceTemplatesListResponse(iconWire(t, ResourcesTemplatesListResult{ResourceTemplates: []ResourceTemplateEntry{
		{URITemplate: "file:///workspace/{path}", Name: "ws", Icons: []ToolIcon{{Src: "https://cdn.example.com/i.png"}}},
	}}))
	if out != nil {
		t.Errorf("benign icon must not block: %s", out)
	}
}
