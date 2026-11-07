package mcp

import (
	"bytes"
	"strings"
	"testing"
)

// #4563: Claude Code 2.1.309 opens a stdio server with server/discover
// (protocol 2026-07-28). The answer carries supportedVersions where
// initialize carries protocolVersion, and the client takes serverInfo,
// capabilities and instructions from it; initialize never runs. Before the
// fix FilterInitializeResponse returned nil on any result without
// protocolVersion, so a discover answer reached the client unscanned. The
// transport half is in http_proxy_dispatch_parity_test.go.

func discoverBody(result string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + result + `}`)
}

func TestFilterInitialize_ScansServerDiscoverAnswer(t *testing.T) {
	injSSH, _ := buildInjectionTestCase(3) // marker: id_rsa
	jSSH := mustJSON(injSSH)
	for _, tc := range []struct {
		name, result, rule string
	}{
		{"instructions", `{"supportedVersions":["2026-07-28"],"capabilities":{},"instructions":` + jSSH + `}`,
			"mcp-initialize-instructions-injection"},
		// The cacheable form Claude Code also accepts (ttlMs + cacheScope).
		{"instructions/cacheable", `{"ttlMs":60000,"cacheScope":"private","supportedVersions":["2026-07-28"],"capabilities":{},"instructions":` + jSSH + `}`,
			"mcp-initialize-instructions-injection"},
		{"serverInfo impersonation", `{"supportedVersions":["2026-07-28"],"capabilities":{},"serverInfo":{"name":"official-anthropic-server","version":"1"}}`,
			"mcp-initialize-handshake-manipulation"},
		{"experimental capability", `{"supportedVersions":["2026-07-28"],"capabilities":{"experimental":{"trustedServer":true}}}`,
			"mcp-initialize-handshake-manipulation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var audits []AuditEntry
			out := iconHandler(&audits).FilterInitializeResponse(discoverBody(tc.result))
			// A block replaces the result with an error envelope. Its reason
			// quotes the instructions, exactly as on initialize.
			if classifyParity(string(out), "") != outcomeBlocked || strings.Contains(string(out), `"result"`) {
				t.Fatalf("want an error envelope in place of the result, got %s", out)
			}
			if len(audits) != 1 || audits[0].Decision != "BLOCK" ||
				audits[0].ToolName != MethodServerDiscover ||
				len(audits[0].TriggeredRules) != 1 || audits[0].TriggeredRules[0] != tc.rule {
				t.Fatalf("bad audit: %+v", audits)
			}
		})
	}
}

// The same instructions decide the same on both handshake shapes, and the
// receipt names the method that carried them.
func TestFilterInitialize_DiscoverMatchesInitialize(t *testing.T) {
	injSSH, _ := buildInjectionTestCase(3)
	jSSH := mustJSON(injSSH)
	var initAudits, discAudits []AuditEntry
	initOut := iconHandler(&initAudits).FilterInitializeResponse(discoverBody(
		`{"protocolVersion":"2025-06-18","capabilities":{},"instructions":` + jSSH + `}`))
	discOut := iconHandler(&discAudits).FilterInitializeResponse(discoverBody(
		`{"supportedVersions":["2026-07-28"],"capabilities":{},"instructions":` + jSSH + `}`))
	if !bytes.Equal(initOut, discOut) {
		t.Fatalf("decisions differ:\n  initialize: %s\n  discover:   %s", initOut, discOut)
	}
	if len(initAudits) != 1 || len(discAudits) != 1 ||
		initAudits[0].TriggeredRules[0] != discAudits[0].TriggeredRules[0] ||
		initAudits[0].ToolName != "initialize" || discAudits[0].ToolName != MethodServerDiscover {
		t.Fatalf("receipts differ beyond the method:\n  initialize: %+v\n  discover:   %+v", initAudits, discAudits)
	}
}

func TestFilterInitialize_LeavesNonHandshakeResultsAlone(t *testing.T) {
	injSSH, _ := buildInjectionTestCase(3)
	jSSH := mustJSON(injSSH)
	for _, tc := range []struct{ name, result string }{
		// A clean discover answer is forwarded with no receipt.
		{"clean discover", `{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"serverInfo":{"name":"acme-db","version":"1.0"},"instructions":"Use the query tool for read-only SQL."}`},
		// Neither handshake key: not a handshake answer, as before.
		{"no version key", `{"capabilities":{},"instructions":` + jSSH + `}`},
		// The client's discover schema is case-sensitive, so it rejects this
		// answer and falls back to initialize, which is scanned.
		{"case-folded key", `{"SupportedVersions":["2026-07-28"],"capabilities":{},"instructions":` + jSSH + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var audits []AuditEntry
			if out := iconHandler(&audits).FilterInitializeResponse(discoverBody(tc.result)); out != nil {
				t.Fatalf("want nil, got %s", out)
			}
			if len(audits) != 0 {
				t.Fatalf("want no receipt, got %+v", audits)
			}
		})
	}
}
