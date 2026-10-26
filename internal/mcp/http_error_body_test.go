package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// driveStatusBody posts one tools/call through the HTTP proxy to an upstream
// that answers with the given status and body, and returns what the client
// received plus the audits recorded after the upstream was reached (#4408).
func driveStatusBody(t *testing.T, status int, ctype, body string) (int, string, []AuditEntry) {
	t.Helper()
	var mu sync.Mutex
	var audits []AuditEntry
	pre := -1
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		pre = len(audits)
		mu.Unlock()
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()
	hp := NewHTTPProxy(HTTPProxyConfig{
		UpstreamURL:         upstream.URL,
		Evaluator:           NewPolicyEvaluator(parityPolicy()),
		OnAudit:             func(e AuditEntry) { mu.Lock(); audits = append(audits, e); mu.Unlock() },
		Stderr:              io.Discard,
		SchemaDriftCacheDir: t.TempDir(),
	})
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	mu.Lock()
	defer mu.Unlock()
	var after []AuditEntry
	if pre >= 0 {
		after = append(after, audits[pre:]...)
	}
	return resp.StatusCode, string(raw), after
}

func TestNon2xxTextBodyIsScanned_4408(t *testing.T) {
	msg, _ := buildInjectionTestCase(2)

	t.Run("poisoned 500 text body is replaced and receipted", func(t *testing.T) {
		status, got, audits := driveStatusBody(t, 500, "text/plain", "Internal error: "+msg)
		if status != 500 {
			t.Errorf("status = %d, want 500 kept", status)
		}
		if strings.Contains(got, "attacker.com") || !strings.Contains(got, "HTTP 500") {
			t.Errorf("body not sanitized: %q", got)
		}
		if len(audits) != 1 || audits[0].Source != "mcp-proxy-error-scan" || len(audits[0].TriggeredRules) == 0 {
			t.Fatalf("want one error-scan receipt, got %+v", audits)
		}
	})
	t.Run("same text under HTTP 200 is not this channel", func(t *testing.T) {
		_, got, _ := driveStatusBody(t, 200, "text/plain", "Internal error: "+msg)
		if !strings.Contains(got, "attacker.com") {
			t.Errorf("2xx body must be left to the existing screens, got %q", got)
		}
	})
	t.Run("clean HTML error page stays receipt-free and byte-identical", func(t *testing.T) {
		page := "<html><body>upstream down</body></html>"
		status, got, audits := driveStatusBody(t, 502, "text/html", page)
		if status != 502 || got != page || len(audits) != 0 {
			t.Errorf("status=%d body=%q audits=%+v", status, got, audits)
		}
	})
	t.Run("clean text 404 stays receipt-free", func(t *testing.T) {
		_, got, audits := driveStatusBody(t, 404, "text/plain", "Session not found")
		if got != "Session not found" || len(audits) != 0 {
			t.Errorf("body=%q audits=%+v", got, audits)
		}
	})
}
