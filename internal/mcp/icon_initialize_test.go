package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// #4062: serverInfo.icons on the initialize handshake — same verdict and
// sentinel as the listing surfaces.

func initWire(t *testing.T, icons []ToolIcon) []byte {
	t.Helper()
	return iconWire(t, InitializeResult{ProtocolVersion: MinAcceptedProtocolVersion,
		ServerInfo: &ServerInfo{Name: "acme-db", Version: "1.0", Icons: icons}})
}

func TestFilterInitialize_BlocksUnsafeServerIcon(t *testing.T) {
	for name, src := range map[string]string{
		"script scheme": iconJS,
		"smb":           "smb://attacker/share/i.png",
		"unc":           `\\attacker\share\i.png`,
		"svg script":    svgDataURI(`<svg><script>x</script></svg>`),
	} {
		var audits []AuditEntry
		out := iconHandler(&audits).FilterInitializeResponse(initWire(t, []ToolIcon{{Src: src}}))
		if out == nil || !strings.Contains(string(out), "icon") {
			t.Errorf("%s: want a block, got %s", name, out)
		}
		if len(audits) != 1 || audits[0].Decision != "BLOCK" ||
			audits[0].TaxonomyRef != "unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf" ||
			len(audits[0].TriggeredRules) != 1 || audits[0].TriggeredRules[0] != "mcp-desc-icon-unsafe-source" {
			t.Errorf("%s: bad audit %+v", name, audits)
		}
	}
}

func TestFilterInitialize_BenignServerIconUntouched(t *testing.T) {
	var audits []AuditEntry
	out := iconHandler(&audits).FilterInitializeResponse(initWire(t, []ToolIcon{
		{Src: "https://cdn.example.com/i.png"}, {Src: "data:image/png;base64,iVBORw0KGgo="}}))
	if out != nil || len(audits) != 0 {
		t.Errorf("benign icons must pass: out=%s audits=%+v", out, audits)
	}
}

func TestServerInfoIconsDecode(t *testing.T) {
	var r InitializeResult
	if err := json.Unmarshal([]byte(`{"protocolVersion":"2025-11-25","serverInfo":{"name":"x","icons":[{"src":"https://a/b.png"}]}}`), &r); err != nil || len(r.ServerInfo.Icons) != 1 {
		t.Fatalf("icons not decoded: %v %+v", err, r)
	}
}

// The icon BLOCK must not be masked by an earlier AUDIT return (trust keyword,
// old protocolVersion): ordering is pinned here.
func TestFilterInitialize_IconBlockNotMaskedByAudit(t *testing.T) {
	for name, r := range map[string]InitializeResult{
		"trust keyword": {ProtocolVersion: MinAcceptedProtocolVersion, ServerInfo: &ServerInfo{Name: "internal-db", Icons: []ToolIcon{{Src: iconJS}}}},
		"old protocol":  {ProtocolVersion: "2024-11-05", ServerInfo: &ServerInfo{Name: "acme-db", Icons: []ToolIcon{{Src: iconJS}}}},
	} {
		var audits []AuditEntry
		out := iconHandler(&audits).FilterInitializeResponse(iconWire(t, r))
		if out == nil || len(audits) != 1 || audits[0].Decision != "BLOCK" || audits[0].TriggeredRules[0] != "mcp-desc-icon-unsafe-source" {
			t.Errorf("%s: want icon BLOCK, got out=%s audits=%+v", name, out, audits)
		}
	}
}

// With the sentinel loaded, initialize cites the same id as the listing surfaces.
func TestFilterInitialize_IconCitesSentinelWhenLoaded(t *testing.T) {
	var audits []AuditEntry
	h := iconHandler(&audits)
	h.Evaluator.SentinelRules = map[string]*MCPRule{"mcp-desc-icon-unsafe-source": {ID: "mcp-desc-icon-unsafe-source-sentinel"}}
	if out := h.FilterInitializeResponse(initWire(t, []ToolIcon{{Src: iconJS}})); out == nil {
		t.Fatal("want a block")
	}
	if len(audits) != 1 || audits[0].TriggeredRules[0] != "mcp-desc-icon-unsafe-source-sentinel" {
		t.Errorf("want sentinel id, got %+v", audits)
	}
}
