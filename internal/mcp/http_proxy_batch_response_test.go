package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// #4070 (batch row): a JSON-RPC batch array on the response side. The scanners
// all reject a non-object, so a poisoned member rode out unscanned. Each member
// is a message of its own and is scanned as one.

func batchBody(t *testing.T) []byte {
	t.Helper()
	benign := json.RawMessage(`{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"72F and sunny"}]}}`)
	return []byte("[" + string(benign) + "," + string(bomToolsListBody(t)) + "]")
}

func batchUpstream(t *testing.T, sse bool, body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: " + string(body) + "\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func TestHTTPProxy_BatchResponseMembersAreScanned_4070(t *testing.T) {
	for _, tc := range []struct {
		name string
		sse  bool
		body func(*testing.T) []byte
		bad  bool
	}{
		{"json-batch-poisoned", false, batchBody, true},
		{"sse-batch-poisoned", true, batchBody, true},
		{"json-batch-benign-control", false, func(*testing.T) []byte {
			return []byte(`[{"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"ok"}]}}]`)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := batchUpstream(t, tc.sse, tc.body(t))
			defer up.Close()
			var audited []AuditEntry
			var mu sync.Mutex
			hp := newTestHTTPProxy(t, up.URL, testHTTPProxyPolicy(), &audited, &mu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()
			_, got, err := postJSON(ts.URL, `{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}`)
			if err != nil {
				t.Fatal(err)
			}
			if tc.bad {
				if strings.Contains(got, "poisoned_tool") {
					t.Errorf("poisoned batch member reached the client: %.200s", got)
				}
				if !strings.Contains(got, "72F and sunny") {
					t.Errorf("benign member dropped with the poisoned one: %.200s", got)
				}
			} else if !strings.Contains(got, `"text":"ok"`) {
				t.Errorf("benign batch altered: %.200s", got)
			}
		})
	}
}
