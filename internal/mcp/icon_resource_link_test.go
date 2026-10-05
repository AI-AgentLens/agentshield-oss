package mcp

import (
	"strings"
	"testing"
)

// #4062: icons on a resource_link block inside a tools/call result — the one
// icon surface the listing checks never reached.

func linkWire(t *testing.T, icons []ToolIcon) []byte {
	t.Helper()
	return iconWire(t, CallToolResult{Content: []ContentItem{
		{Type: "resource_link", URI: "https://docs.example.com/guide", Name: "guide", Icons: icons},
	}})
}

func TestFilterToolCall_BlocksUnsafeResourceLinkIcon(t *testing.T) {
	for name, src := range map[string]string{
		"script scheme": iconJS,
		"smb":           "smb://attacker/share/i.png",
		"unc":           `\\attacker\share\i.png`,
		"remote file":   "file://attacker/share/i.png",
		"svg script":    svgDataURI(`<svg><script>x</script></svg>`),
	} {
		var audits []AuditEntry
		out := iconPackHandler(t, &audits).FilterToolCallResponse(linkWire(t, []ToolIcon{{Src: src}}))
		if out == nil || !strings.Contains(string(out), "non_text_icon_unsafe_source") {
			t.Errorf("%s: want a block, got %s", name, out)
			continue
		}
		if len(audits) != 1 || audits[0].Decision != "BLOCK" ||
			audits[0].TaxonomyRef != "unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf" ||
			!strings.Contains(strings.Join(audits[0].TriggeredRules, ","), "mcp-desc-icon-unsafe-source") {
			t.Errorf("%s: bad audit %+v", name, audits)
		}
	}
}

// #4062: a resource_link icon naming the internal network is an AUDIT receipt,
// never a block, and the result is forwarded unchanged.
func TestFilterToolCall_InternalResourceLinkIconAuditsOnly(t *testing.T) {
	for name, src := range map[string]string{
		"link-local": "http://" + "169.254" + ".169.254/latest/icon.png",
		"rfc1918":    "http://10.0.0.5/i.png",
	} {
		var audits []AuditEntry
		out := iconPackHandler(t, &audits).FilterToolCallResponse(linkWire(t, []ToolIcon{{Src: src}}))
		if out != nil {
			t.Errorf("%s: must forward unchanged, got %s", name, out)
		}
		if len(audits) != 1 || audits[0].Decision != "AUDIT" ||
			audits[0].TaxonomyRef != "unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf" ||
			!strings.Contains(strings.Join(audits[0].TriggeredRules, ","), "mcp-desc-icon-unsafe-source") {
			t.Errorf("%s: want one AUDIT receipt citing the icon sentinel, got %+v", name, audits)
		}
	}
}

func TestFilterToolCall_BenignResourceLinkIconUntouched(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterToolCallResponse(linkWire(t, []ToolIcon{
		{Src: "https://cdn.example.com/i.png"}, {Src: "data:image/png;base64,iVBORw0KGgo="}}))
	if out != nil || len(audits) != 0 {
		t.Errorf("benign icons must pass: out=%s audits=%+v", out, audits)
	}
}
