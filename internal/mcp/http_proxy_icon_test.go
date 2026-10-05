package mcp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// #4062 / #3989: icon verdicts reach the HTTP Streamable proxy through the
// shared response dispatch. The handler tests exercise the filters directly;
// these drive the real relay, over JSON and over SSE.

func iconUpstream(result string, sse bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		payload := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, result)
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
}

func relayIconResult(t *testing.T, method, result string, sse bool) (string, []AuditEntry) {
	t.Helper()
	up := iconUpstream(result, sse)
	defer up.Close()
	var audited []AuditEntry
	var mu sync.Mutex
	hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{}}`, method)
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(req))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	mu.Lock()
	defer mu.Unlock()
	return string(body), append([]AuditEntry(nil), audited...)
}

func hasIconRule(audits []AuditEntry, decision string) bool {
	for _, a := range audits {
		if a.Decision != decision {
			continue
		}
		for _, id := range a.TriggeredRules {
			if strings.Contains(id, "icon") {
				return true
			}
		}
	}
	return false
}

func TestHTTPProxy_UnsafeIconBlockedOnEveryListingSurface(t *testing.T) {
	bad := fmt.Sprintf(`[{"src":%q}]`, iconJS)
	surfaces := map[string][2]string{
		"initialize": {"initialize", `{"protocolVersion":"2025-11-25","serverInfo":{"name":"acme-db","version":"1","icons":` + bad + `}}`},
		"tools":      {"tools/list", `{"tools":[{"name":"t","description":"d","inputSchema":{"type":"object"},"icons":` + bad + `}]}`},
		"prompts":    {"prompts/list", `{"prompts":[{"name":"p","icons":` + bad + `}]}`},
		"resources":  {"resources/list", `{"resources":[{"uri":"file:///a","name":"r","icons":` + bad + `}]}`},
		"templates":  {"resources/templates/list", `{"resourceTemplates":[{"uriTemplate":"x://{a}","name":"r","icons":` + bad + `}]}`},
	}
	for name, s := range surfaces {
		for _, sse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sse=%v", name, sse), func(t *testing.T) {
				body, audits := relayIconResult(t, s[0], s[1], sse)
				if strings.Contains(body, `"icons"`) {
					t.Errorf("icon carrier reached the client: %s", body)
				}
				if !hasIconRule(audits, "BLOCK") {
					t.Errorf("no icon BLOCK receipt: %+v", audits)
				}
			})
		}
	}
}

func TestHTTPProxy_BenignIconForwardedUntouched(t *testing.T) {
	res := `{"protocolVersion":"2025-11-25","serverInfo":{"name":"acme-db","version":"1","icons":[{"src":"https://cdn.example.com/i.png"}]}}`
	for _, sse := range []bool{false, true} {
		body, audits := relayIconResult(t, "initialize", res, sse)
		if !strings.Contains(body, "cdn.example.com/i.png") || hasIconRule(audits, "BLOCK") || hasIconRule(audits, "AUDIT") {
			t.Errorf("sse=%v benign icon altered or flagged: body=%s audits=%+v", sse, body, audits)
		}
	}
}

func TestHTTPProxy_InternalNetworkIconForwardedWithAuditReceipt(t *testing.T) {
	host := "169.254." + "169.254"
	res := `{"protocolVersion":"2025-11-25","serverInfo":{"name":"acme-db","version":"1","icons":[{"src":"http://` + host + `/i.png"}]}}`
	for _, sse := range []bool{false, true} {
		body, audits := relayIconResult(t, "initialize", res, sse)
		if !strings.Contains(body, host) {
			t.Errorf("sse=%v receipt-only path must forward unchanged: %s", sse, body)
		}
		if !hasIconRule(audits, "AUDIT") {
			t.Errorf("sse=%v want internal-network AUDIT receipt: %+v", sse, audits)
		}
	}
}
