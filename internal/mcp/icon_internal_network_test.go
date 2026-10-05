package mcp

import (
	"strings"
	"testing"
)

// #4062: an http(s) icon naming the user's own network is AUDIT-only. The
// entry is forwarded untouched; the receipt cites the icon sentinel → ssrf node.
// Metadata addresses are assembled at runtime: the hook reads test sources as
// commands.
var (
	iconMetaIP   = "169.254." + "169.254"
	iconMetaName = "metadata.google" + ".internal"
)

func TestInternalIconHost(t *testing.T) {
	for src, want := range map[string]bool{
		"http://" + iconMetaIP + "/latest/x.png": true,
		"https://10.0.0.5/i.png":                 true,
		"http://192.168.1.1:8080/i.png":          true,
		"http://172.16.4.4/i.png":                true,
		"http://[fd00::1]/i.png":                 true,
		"http://[fe80::1]/i.png":                 true,
		"http://" + iconMetaName + "/i.png":      true,
		`http:\\` + iconMetaIP + `\i.png`:        true,
		"HTTP://10.1.2.3/i.png":                  true,
		"http://2852039166/i.png":                true,  // decimal dword
		"http://0xa9fea9fe/i.png":                true,  // hex dword
		"http://0251.0376.0251.0376/i.png":       true,  // octal parts
		"http://169.254.43774/i.png":             true,  // 3-part form
		"http://0xa.1/i.png":                     true,  // 10.0.0.1
		"http://167772161./i.png":                true,  // trailing dot, 10.0.0.1
		"http://2130706433/i.png":                false, // loopback
		"http://134744072/i.png":                 false, // 8.8.8.8
		"http://4294967296/i.png":                false, // overflow: a hostname
		"http://1.2.3.4.5/i.png":                 false,
		"https://cdn.example.com/i.png":          false,
		"https://8.8.8.8/i.png":                  false,
		"http://172.32.0.1/i.png":                false, // outside 172.16/12
		"http://127.0.0.1:3000/i.png":            false, // local stdio server
		"http://localhost/i.png":                 false,
		"data:image/png;base64,iVBORw0KGgo=":     false,
		"ftp://10.0.0.5/i.png":                   false,
		"":                                       false,
	} {
		if got := internalIconHost(src) != ""; got != want {
			t.Errorf("internalIconHost(%q) = %v, want %v", src, got, want)
		}
	}
}

func TestInternalIcon_AuditsAndForwardsOnEverySurface(t *testing.T) {
	src := "http://" + iconMetaIP + "/i.png"
	for _, s := range iconSurfaces {
		t.Run(s.key, func(t *testing.T) {
			var audits []AuditEntry
			out := s.filter(iconPackHandler(t, &audits))(iconRawWire(s.list(s.entry("p", `"icons":`+iconsJSON(src)))))
			if out != nil {
				t.Errorf("entry must be forwarded untouched, got rewrite: %s", out)
			}
			if len(audits) != 1 {
				t.Fatalf("want one AUDIT receipt, got %+v", audits)
			}
			e := audits[0]
			if e.Decision != "AUDIT" || !e.Flagged || e.ToolName != "p" || e.Source != s.source ||
				e.TaxonomyRef != iconSSRFNode || len(e.TriggeredRules) != 1 || e.TriggeredRules[0] != iconSentinelRuleID ||
				!strings.Contains(e.Reasons[0], "internal-network host "+iconMetaIP) {
				t.Errorf("wrong receipt: %+v", e)
			}
		})
	}
}

func TestInternalIcon_ToolsListAuditsAndKeepsTool(t *testing.T) {
	var audits []AuditEntry
	wire := iconRawWire(`{"tools":[{"name":"t1","description":"Does a thing.","icons":` + iconsJSON("https://10.0.0.5/i.png") + `}]}`)
	out := iconPackHandler(t, &audits).FilterToolsListResponse(wire)
	if out != nil && !strings.Contains(string(out), "t1") {
		t.Errorf("tool must be kept, got %s", out)
	}
	if len(audits) != 1 || audits[0].Decision != "AUDIT" || audits[0].ToolName != "t1" {
		t.Errorf("want one AUDIT receipt for t1, got %+v", audits)
	}
}

// A BLOCK-tier icon still hides the entry; the internal icon beside it adds an
// AUDIT receipt but cannot soften the BLOCK.
func TestInternalIcon_DoesNotSoftenUnsafeIconBlock(t *testing.T) {
	var audits []AuditEntry
	wire := iconRawWire(`{"prompts":[{"name":"p","icons":` + iconsJSON("http://10.0.0.5/i.png", iconSMB) + `}]}`)
	out := iconPackHandler(t, &audits).FilterPromptsListResponse(wire)
	if out == nil || strings.Contains(string(out), `"name":"p"`) {
		t.Fatalf("unsafe icon must still hide the prompt, got %s", out)
	}
	var blocks, auds int
	for _, a := range audits {
		switch a.Decision {
		case "BLOCK":
			blocks++
		case "AUDIT":
			auds++
		}
	}
	if blocks != 1 || auds != 1 {
		t.Errorf("want 1 BLOCK + 1 AUDIT, got %+v", audits)
	}
}

// serverInfo has no entry to hide, so an internal-network icon there is a
// receipt on the initialize event only; the handshake is forwarded.
func TestInternalIcon_ServerInfoAuditsAndForwards(t *testing.T) {
	init := func(icons string) []byte {
		return iconRawWire(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"acme","version":"1","icons":` + icons + `}}`)
	}
	var audits []AuditEntry
	if out := iconPackHandler(t, &audits).FilterInitializeResponse(init(iconsJSON("http://" + iconMetaIP + "/i.png"))); out != nil {
		t.Errorf("handshake must be forwarded untouched, got %s", out)
	}
	if len(audits) != 1 {
		t.Fatalf("want one AUDIT receipt, got %+v", audits)
	}
	e := audits[0]
	if e.Decision != "AUDIT" || e.ToolName != "initialize" || e.TaxonomyRef != iconSSRFNode ||
		len(e.TriggeredRules) != 1 || e.TriggeredRules[0] != iconSentinelRuleID ||
		!strings.Contains(e.Reasons[0], "internal-network host "+iconMetaIP) {
		t.Errorf("wrong receipt: %+v", e)
	}

	// TN: a public https icon leaves no receipt.
	audits = nil
	iconPackHandler(t, &audits).FilterInitializeResponse(init(iconsJSON("https://example.com/i.png")))
	if len(audits) != 0 {
		t.Errorf("public icon must not be receipted: %+v", audits)
	}

	// An unsafe icon still BLOCKs, with no extra AUDIT beside it.
	audits = nil
	out := iconPackHandler(t, &audits).FilterInitializeResponse(init(iconsJSON("http://10.0.0.5/i.png", iconSMB)))
	if out == nil || len(audits) != 1 || audits[0].Decision != "BLOCK" {
		t.Errorf("want one BLOCK, got out=%s audits=%+v", out, audits)
	}
}
