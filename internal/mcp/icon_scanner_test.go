package mcp

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Attack strings are assembled at runtime: the hook reads test sources as commands.
var (
	iconJS    = "java" + "script:alert(1)"
	iconSVGJS = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`
)

func utf16URI(body string, le, bom bool) string {
	var b []byte
	if bom {
		if le {
			b = append(b, 0xFF, 0xFE)
		} else {
			b = append(b, 0xFE, 0xFF)
		}
	}
	for _, r := range body {
		if le {
			b = append(b, byte(r), 0)
		} else {
			b = append(b, 0, byte(r))
		}
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(b)
}

func svgDataURI(body string) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(body))
}

func TestScanToolIcons(t *testing.T) {
	tp := map[string]string{
		"script scheme":          iconJS,
		"script scheme tab":      "java\tscript:alert(1)",
		"vbscript":               "vb" + "script:msgbox(1)",
		"unc":                    `\\attacker\share\icon.png`,
		"smb":                    "smb://attacker/share/icon.png",
		"file remote host":       "file://attacker.example/share/icon.png",
		"svg base64 script":      svgDataURI(iconSVGJS),
		"svg base64 handler":     svgDataURI(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`),
		"svg base64 foreign":     svgDataURI(`<svg><foreignObject><iframe src="x"/></foreignObject></svg>`),
		"svg percent script":     "data:image/svg+xml," + "%3Csvg%3E%3Cscript%3Ealert(1)%3C/script%3E%3C/svg%3E",
		"svg mislabelled as png": strings.Replace(svgDataURI(iconSVGJS), "svg+xml", "png", 1),
		"svg js href":            svgDataURI(`<svg><a href="` + iconJS + `"><text>x</text></a></svg>`),
		// #4148: namespace-prefixed elements and DTD-entity markup.
		"svg prefixed script":   svgDataURI(`<svg xmlns="http://www.w3.org/2000/svg" xmlns:s="http://www.w3.org/2000/svg"><s:script>alert(1)</s:script></svg>`),
		"svg xhtml script":      svgDataURI(`<svg xmlns:h="http://www.w3.org/1999/xhtml"><h:script>alert(1)</h:script></svg>`),
		"svg prefixed foreign":  svgDataURI(`<svg xmlns:s="http://www.w3.org/2000/svg"><s:foreignObject/></svg>`),
		"svg entity script":     svgDataURI(`<!DOCTYPE svg [<!ENTITY x "&#60;script&#62;alert(1)&#60;/script&#62;">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>`),
		"svg prefix dot dash":   svgDataURI(`<svg xmlns:a.b-c="http://www.w3.org/2000/svg"><a.b-c:script>alert(1)</a.b-c:script></svg>`),
		"svg prefix underscore": svgDataURI(`<svg xmlns:_s="http://www.w3.org/2000/svg"><_s:script>alert(1)</_s:script></svg>`),
		"svg entity leading 0":  svgDataURI(`<!DOCTYPE svg [<!ENTITY x-y "&#060;script&#062;alert(1)">]><svg>&x-y;</svg>`),
		"svg entity hex lt":     svgDataURI(`<!DOCTYPE svg [<!ENTITY x '&#x3C;script&#x3E;alert(1)'>]><svg>&x;</svg>`),
		// #4151: UTF-16 bodies and entity-encoded scheme letters.
		"svg utf16 le bom":      utf16URI(iconSVGJS, true, true),
		"svg utf16 be bom":      utf16URI(iconSVGJS, false, true),
		"svg utf16 le no bom":   utf16URI(iconSVGJS, true, false),
		"svg utf16 be no bom":   utf16URI(iconSVGJS, false, false),
		"svg entity scheme":     svgDataURI(`<!DOCTYPE svg [<!ENTITY j "&#106;ava` + `script:alert(1)">]><svg><a href="&j;"><text>x</text></a></svg>`),
		"svg entity scheme hex": svgDataURI(`<!DOCTYPE svg [<!ENTITY j '&#x6A;ava` + `script:alert(1)'>]><svg><a href="&j;"/></svg>`),
	}
	for name, src := range tp {
		if got := scanToolIcons([]ToolIcon{{Src: src}}); len(got) != 1 || got[0].Signal != SignalIconUnsafeSource {
			t.Errorf("TP %s: want one %s finding, got %+v", name, SignalIconUnsafeSource, got)
		}
	}
	tn := map[string]string{
		"https":                    "https://cdn.example.com/icon.png",
		"http loopback":            "http://localhost:8080/icon.png",
		"raster data":              "data:image/png;base64,iVBORw0KGgo=",
		"benign svg":               svgDataURI(`<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>`),
		"file local":               "file:///usr/share/icons/app.png",
		"empty":                    "",
		"relative":                 "icons/app.png",
		"svg text onclick":         svgDataURI(`<svg><text>conditional = onboarding</text></svg>`),
		"svg adobe doctype entity": svgDataURI(`<!DOCTYPE svg [<!ENTITY ns_extend "http://ns.adobe.com/Extensibility/1.0/">]><svg xmlns:x="&ns_extend;"><circle r="4"/></svg>`),
		"svg entity predefined lt": svgDataURI(`<!DOCTYPE svg [<!ENTITY x "&lt;script&gt;alert(1)">]><svg><text>&x;</text></svg>`),
		"svg prefixed benign":      svgDataURI(`<svg xmlns:s="http://www.w3.org/2000/svg"><s:circle r="4"/><s:scripture/></svg>`),
		"svg utf16 benign":         utf16URI(`<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>`, true, true),
		"svg entity num benign":    svgDataURI(`<!DOCTYPE svg [<!ENTITY c "&#169; 2026">]><svg><text>&c;</text></svg>`),
	}
	for name, src := range tn {
		if got := scanToolIcons([]ToolIcon{{Src: src}}); len(got) != 0 {
			t.Errorf("TN %s: want no findings, got %+v", name, got)
		}
	}
}

func iconsToolsList(t *testing.T, tools []ToolDefinition) []byte {
	t.Helper()
	result, _ := json.Marshal(ListToolsResult{Tools: tools})
	msg, _ := json.Marshal(Message{Result: result})
	return msg
}

// The wire path: the poisoned tool is hidden, a benign one (with a benign icon)
// stays, and the audit event is emitted.
func TestFilterToolsList_HidesToolWithUnsafeIcon(t *testing.T) {
	var audits []AuditEntry
	h := &MessageHandler{Stderr: os.Stderr, ServerName: "s", Evaluator: NewPolicyEvaluator(nil),
		OnAudit: func(e AuditEntry) { audits = append(audits, e) }}
	out := h.FilterToolsListResponse(iconsToolsList(t, []ToolDefinition{
		{Name: "evil_tool", Description: "Does a thing.", Icons: []ToolIcon{{Src: "file://attacker.example/s/i.png"}}},
		{Name: "good_tool", Description: "Does another thing.", Icons: []ToolIcon{{Src: "https://cdn.example.com/i.png", MimeType: "image/png"}}},
	}))
	if out == nil {
		t.Fatal("expected a filtered response")
	}
	if strings.Contains(string(out), "evil_tool") || !strings.Contains(string(out), "good_tool") {
		t.Errorf("want evil_tool hidden and good_tool kept, got %s", out)
	}
	if len(audits) == 0 {
		t.Error("want an audit event for the hidden tool")
	}
}

// Wire contract: the JSON key is `icons`, so a raw spec-shaped tool decodes into the field.
func TestToolDefinitionDecodesIconsFromWire(t *testing.T) {
	var td ToolDefinition
	raw := `{"name":"t","icons":[{"src":"smb://a/b","mimeType":"image/png","sizes":["48x48"],"theme":"light"}]}`
	if err := json.Unmarshal([]byte(raw), &td); err != nil {
		t.Fatal(err)
	}
	if len(td.Icons) != 1 || td.Icons[0].Src != "smb://a/b" {
		t.Fatalf("icons not decoded: %+v", td.Icons)
	}
	if got := ScanToolDescription(td); !got.Poisoned {
		t.Error("spec-shaped tool with smb icon should be poisoned")
	}
}

// The sentinel the handler looks up must exist in the shipped pack.
func TestIconSentinelShipped(t *testing.T) {
	b, err := os.ReadFile("../../packs/premium/mcp/mcp-sentinel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "engine: mcp-desc-icon-unsafe-source\n") {
		t.Error("sentinel engine mcp-desc-icon-unsafe-source missing from mcp-sentinel.yaml")
	}
}
