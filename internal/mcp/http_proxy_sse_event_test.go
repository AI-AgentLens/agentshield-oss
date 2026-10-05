package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// An SSE client joins an event's data fields with "\n" and accepts "data:"
// with no space (#4070). The proxy must scan the event as the client reads it.
// The control row is the single-line form the scanner already suppressed.
func TestHTTPProxy_SSEEventReassembly(t *testing.T) {
	const nonce = "evt4070marker"
	msg := string(suppressedNotification(nonce)) // "data: {json}\n"
	body := strings.TrimSuffix(strings.TrimPrefix(msg, "data: "), "\n")
	cut := strings.Index(body, `"method"`)
	if cut < 0 {
		t.Fatalf("fixture shape changed: %s", body)
	}
	cases := []struct {
		name, stream string
	}{
		{"control single line", "data: " + body + "\n\n"},
		{"no space after colon", "data:" + body + "\n\n"},
		{"split over two data lines", "data: " + body[:cut] + "\ndata: " + body[cut:] + "\n\n"},
		{"split, no space, with event field", "event: message\ndata:" + body[:cut] + "\ndata:" + body[cut:] + "\n\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte(tc.stream))
			}))
			defer upstream.Close()
			var audited []AuditEntry
			var mu sync.Mutex
			hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()

			_, raw := postToolsList(t, ts.URL, "identity")
			if strings.Contains(string(raw), nonce) {
				t.Errorf("suppressed payload reached the client: %q", raw)
			}
		})
	}

	t.Run("benign multi-line event is forwarded intact", func(t *testing.T) {
		stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n"
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(stream))
		}))
		defer upstream.Close()
		var audited []AuditEntry
		var mu sync.Mutex
		hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
		ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
		defer ts.Close()
		_, raw := postToolsList(t, ts.URL, "identity")
		if string(raw) != stream {
			t.Errorf("got %q, want %q", raw, stream)
		}
	})
}
