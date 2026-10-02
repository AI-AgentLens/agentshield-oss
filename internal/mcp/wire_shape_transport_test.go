package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// These tests pin #4081 at the TRANSPORT, not at FilterErrorResponse. The
// unit tests in error_scanner_test.go call the filter directly, which is only
// the HTTP relay's path; stdio goes ParseMessage → DispatchServerResponse, and
// the Opus adversarial pass on #4101 measured that reverting parser.go alone
// (re-strictening ParseMessage) left the whole ./internal/mcp suite green while
// the issue's own witness went back to "forwarded raw, 0 audit events".

// floatCodeErrorLine is the #4081 witness: a JSON-RPC error whose code is
// spelled as a float — valid JSON the TypeScript SDK accepts — carrying an
// injection the error scanner catches. Written by hand because json.Marshal
// would round-trip the float back to an integer literal.
func floatCodeErrorLine(t testing.TB) (line, poisoned string) {
	t.Helper()
	poisoned, _ = buildInjectionTestCase(2)
	return `{"jsonrpc":"2.0","id":1,"error":{"code":-32603.0,"message":` + mustJSON(poisoned) + `}}`, poisoned
}

// assertSanitizedErrorReplacement checks that raw is NOT the original line,
// that it is a JSON-RPC error whose message was replaced, and that the error
// code survived the float spelling (finding 3 of the Opus pass: -32603.0 used
// to come back as code 0).
func assertSanitizedErrorReplacement(t *testing.T, transport, raw, original, poisoned string) {
	t.Helper()
	if raw == "" {
		t.Fatalf("%s: message was dropped, expected a sanitized replacement", transport)
	}
	if raw == original {
		t.Fatalf("%s: float-spelled error.code forwarded the poisoned error raw — the #4081 fail-open", transport)
	}
	var msg Message
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		t.Fatalf("%s: replacement is not a JSON-RPC message: %v\n%s", transport, err, raw)
	}
	if msg.Error == nil {
		t.Fatalf("%s: replacement is not an error response: %s", transport, raw)
	}
	if msg.Error.Message == poisoned || !strings.Contains(msg.Error.Message, "AgentShield") {
		t.Errorf("%s: error message was not sanitized: %q", transport, msg.Error.Message)
	}
	if msg.Error.Code != -32603 {
		t.Errorf("%s: sanitized replacement lost the error code: got %d, want -32603", transport, msg.Error.Code)
	}
}

func hasErrorScanAudit(entries []AuditEntry) bool {
	for _, e := range entries {
		if e.Source == "mcp-proxy-error-scan" && e.ToolName == "error-response" {
			return true
		}
	}
	return false
}

// TestProxy_FloatErrorCodeScannedOnStdio drives the #4081 witness server→client
// through the real stdio proxy and asserts the sanitized replacement AND the
// audit event. Under a strict ParseMessage this line is forwarded byte-for-byte
// with no audit at all.
func TestProxy_FloatErrorCodeScannedOnStdio(t *testing.T) {
	line, poisoned := floatCodeErrorLine(t)

	var mu sync.Mutex
	var audited []AuditEntry
	proxy := NewProxy(ProxyConfig{
		Evaluator: NewPolicyEvaluator(testProxyPolicy()),
		OnAudit: func(e AuditEntry) {
			mu.Lock()
			defer mu.Unlock()
			audited = append(audited, e)
		},
		Stderr: io.Discard,
	})
	clientOut := &bytes.Buffer{}
	serverBuf := &bytes.Buffer{}
	proxy.RunWithIO(strings.NewReader(""), clientOut, strings.NewReader(line+"\n"), newNopWriteCloser(serverBuf))

	assertSanitizedErrorReplacement(t, "stdio", strings.TrimSpace(clientOut.String()), line, poisoned)

	mu.Lock()
	defer mu.Unlock()
	if !hasErrorScanAudit(audited) {
		t.Errorf("no error-scan audit event on stdio — audits: %+v", audited)
	}
}

// TestProxy_TypeErrorRequestStillClassifiedOnStdio is the client→server half.
// A tools/call for a blocked tool must still be classified as KindToolCall —
// and blocked — when an unrelated envelope field carries a value the Go type
// cannot hold. Two mutations the Opus pass found surviving the full suite both
// forward these to the server: a strict ParseMessage (parse error → fail open)
// and a lenient one that returns KindUnknown whenever the strict decode fails.
func TestProxy_TypeErrorRequestStillClassifiedOnStdio(t *testing.T) {
	const call = `"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"ls"}}`
	rows := []struct{ name, line string }{
		{"control_clean_envelope", `{"jsonrpc":"2.0","id":1,` + call + `}`},
		{"jsonrpc_is_a_number", `{"jsonrpc":2,"id":1,` + call + `}`},
		{"extra_error_with_fractional_code", `{"jsonrpc":"2.0","id":1,` + call + `,"error":{"code":1.5}}`},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			var mu sync.Mutex
			var audited []AuditEntry
			proxy := NewProxy(ProxyConfig{
				Evaluator: NewPolicyEvaluator(testProxyPolicy()),
				OnAudit: func(e AuditEntry) {
					mu.Lock()
					defer mu.Unlock()
					audited = append(audited, e)
				},
				Stderr: io.Discard,
			})
			clientOut := &bytes.Buffer{}
			serverBuf := &bytes.Buffer{}
			proxy.RunWithIO(strings.NewReader(r.line+"\n"), clientOut, strings.NewReader(""), newNopWriteCloser(serverBuf))

			if serverBuf.Len() > 0 {
				t.Fatalf("blocked tool call reached the server: %s", serverBuf.String())
			}
			if !strings.Contains(clientOut.String(), "AgentShield") {
				t.Fatalf("client did not receive a block response, got: %q", clientOut.String())
			}
			mu.Lock()
			defer mu.Unlock()
			blocked := false
			for _, e := range audited {
				if e.Decision == "BLOCK" {
					blocked = true
				}
			}
			if !blocked {
				t.Errorf("no BLOCK audit event — audits: %+v", audited)
			}
		})
	}
}

// TestHTTPProxy_FloatErrorCodeSanitizedWithCodePreserved covers the two HTTP
// relay paths, plain JSON (relayJSON) and SSE (relaySSE), with the same
// witness and the same assertions, including the preserved -32603.
func TestHTTPProxy_FloatErrorCodeSanitizedWithCodePreserved(t *testing.T) {
	line, poisoned := floatCodeErrorLine(t)

	for _, sse := range []bool{false, true} {
		sse := sse
		name := "relayJSON"
		if sse {
			name = "relaySSE"
		}
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if sse {
					// Flush like a real SSE server so the upstream response is
					// chunked. An unflushed short body gets a Content-Length,
					// which relaySSE copies onto the client response (pre-existing,
					// http_proxy.go). A replacement longer than the original then
					// fails net/http's write with ErrContentLength and the client
					// gets only the `event:` line; a shorter one arrives whole and
					// is followed by an unexpected EOF. Keeping the error code makes
					// this witness's replacement longer, so unflushed it would drop.
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(http.StatusOK)
					_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", line)
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(line))
			}))
			defer upstream.Close()

			var mu sync.Mutex
			var audited []AuditEntry
			hp := newTestHTTPProxy(upstream.URL, testHTTPProxyPolicy(), &audited, &mu)
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()

			req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			raw := strings.TrimSpace(string(body))
			if sse {
				raw = ""
				for _, l := range strings.Split(string(body), "\n") {
					if strings.HasPrefix(l, "data: ") {
						raw = strings.TrimPrefix(l, "data: ")
					}
				}
			}
			assertSanitizedErrorReplacement(t, name, raw, line, poisoned)

			mu.Lock()
			defer mu.Unlock()
			if !hasErrorScanAudit(audited) {
				t.Errorf("%s: no error-scan audit event — audits: %+v", name, audited)
			}
		})
	}
}
