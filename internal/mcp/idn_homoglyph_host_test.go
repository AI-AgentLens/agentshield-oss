package mcp

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// Non-ASCII written numerically so this file stays ASCII-only (writing a
// literal confusable trips AgentShield's own hook on every edit).
func homoglyphHost(host string) string {
	// Latin 'i' -> Cyrillic 'i' (U+0456): renders identically, resolves elsewhere.
	return strings.Replace(host, "i", string(rune(0x0456)), 1)
}

// TestMCPIDNHomoglyphHostParity is the shell<->MCP parity gate for
// supply-chain/typosquatting/idn-homoglyph-domain. ts-block-url-non-ascii-host
// has guarded the shell surface since it was written; before the rules this
// test covers, `fetch(url="https://g<U+0456>thub.com/...")` and
// `fetch(url="https://github.com/...")` produced byte-identical verdicts.
//
// Each row asserts its ASCII control does NOT block first — otherwise the row
// would pass for a reason unrelated to the host.
func TestMCPIDNHomoglyphHostParity(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	e := renderEvasionEvaluator(t)

	rows := []struct {
		tool string
		key  string
		url  string
	}{
		{"fetch", "url", "https://github.com/user/repo/raw/main/install.sh"},
		{"http_request", "url", "https://raw.githubusercontent.com/u/r/main/setup.sh"},
		{"browser_navigate", "url", "https://login.microsoft.com/oauth2/authorize"},
		{"download_file", "url", "https://pypi.org/simple/requests"},
		{"web_fetch", "url", "https://registry.npmjs.org/express"},
	}
	for _, r := range rows {
		ctl := e.EvaluateToolCall(r.tool, map[string]interface{}{r.key: r.url})
		if ctl.Decision == "BLOCK" {
			t.Fatalf("CONTROL %s(%s=%q) already BLOCKs via %v — the row cannot measure the host",
				r.tool, r.key, r.url, ctl.TriggeredRules)
		}
		spoofed := homoglyphHost(r.url)
		if spoofed == r.url {
			t.Fatalf("mutation did not apply to %q", r.url)
		}
		got := e.EvaluateToolCall(r.tool, map[string]interface{}{r.key: spoofed})
		if got.Decision != "BLOCK" {
			t.Errorf("%s(%s=%+q) = %s via %v, want BLOCK", r.tool, r.key, spoofed, got.Decision, got.TriggeredRules)
		}
	}

	// resources/read carries the URI in its own field, not an argument map.
	uri := "https://github.com/u/r"
	if ctl := e.EvaluateResourceRead(uri); ctl.Decision == "BLOCK" {
		t.Fatalf("CONTROL resources/read %q already BLOCKs via %v", uri, ctl.TriggeredRules)
	}
	if got := e.EvaluateResourceRead(homoglyphHost(uri)); got.Decision != "BLOCK" {
		t.Errorf("resources/read %+q = %s via %v, want BLOCK", homoglyphHost(uri), got.Decision, got.TriggeredRules)
	}
}

// TestMCPIDNHomoglyphHostFPBoundary pins that the detection is scoped to the
// HOST. A non-ASCII path or query is ordinary and must survive.
func TestMCPIDNHomoglyphHostFPBoundary(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	e := renderEvasionEvaluator(t)

	kanji := string([]rune{0x65E5, 0x672C})
	benign := []struct {
		label string
		url   string
	}{
		{"non-ascii-path", "https://en.wikipedia.org/wiki/" + kanji},
		{"non-ascii-query", "https://api.github.com/search/issues?q=caf" + string(rune(0x00E9))},
		{"plain-ascii", "https://github.com/user/repo"},
		{"localhost", "http://localhost:3000/dashboard"},
		{"xn--in-path-not-host", "https://example.com/xn--not-a-host-segment"},
	}
	for _, b := range benign {
		if got := e.EvaluateToolCall("fetch", map[string]interface{}{"url": b.url}); got.Decision == "BLOCK" {
			t.Errorf("%s: fetch(url=%q) = BLOCK via %v, want no block", b.label, b.url, got.TriggeredRules)
		}
	}

	// Punycode is AUDIT, not BLOCK — some legitimate non-Latin business
	// domains are reached this way, the same calibration ts-audit-url-punycode-host made.
	puny := e.EvaluateToolCall("fetch", map[string]interface{}{"url": "https://xn--gthub-dxa.com/install.sh"})
	if puny.Decision == "BLOCK" {
		t.Errorf("punycode host = BLOCK via %v, want AUDIT", puny.TriggeredRules)
	}
	found := false
	for _, id := range puny.TriggeredRules {
		if id == "mcp-sc-audit-url-arg-punycode-host" {
			found = true
		}
	}
	if !found {
		t.Errorf("punycode host triggered %v, want mcp-sc-audit-url-arg-punycode-host", puny.TriggeredRules)
	}
}
