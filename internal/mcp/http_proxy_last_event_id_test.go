package mcp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// #4180: a reconnecting client's Last-Event-ID must reach the upstream, or the
// server cannot resume the stream and the events sent while the client was
// disconnected are lost.
func TestHTTPProxy_LastEventIDForwarded_4180(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var mu sync.Mutex
			var saw string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				mu.Lock()
				saw = r.Header.Get("Last-Event-ID")
				mu.Unlock()
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("id: 43\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"resumed\"}}\n\n"))
			}))
			defer upstream.Close()

			var audited []AuditEntry
			var amu sync.Mutex
			hp := newTestHTTPProxy(t, upstream.URL, testHTTPProxyPolicy(), &audited, &amu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()

			var body io.Reader
			if method == http.MethodPost {
				body = bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}`))
			}
			req, _ := http.NewRequest(method, ts.URL, body)
			req.Header.Set("Accept", "text/event-stream")
			if method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Last-Event-ID", "evt-42")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			mu.Lock()
			defer mu.Unlock()
			if saw != "evt-42" {
				t.Errorf("upstream saw Last-Event-ID %q, want %q", saw, "evt-42")
			}
			if !bytes.Contains(got, []byte("resumed")) {
				t.Errorf("resumed event not relayed: %.200s", got)
			}
		})
	}
}
