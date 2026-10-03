package mcp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The #4158 depth BLOCK meets #4154's content codings. The depth screen must
// run on every form a client might read, which means on decoded plaintext:
// decodeAttempt.complete() is json.Valid, which rejects nesting past the
// decoder limit, so without a screen on the decoded attempt a deep gzip body
// is "not a message", the raw compressed bytes are scanned (no brackets to
// count) and relayed with an AUDIT receipt — the TypeScript SDK then
// inflates and parses it. Shapes and helpers come from json_depth_proxy_test.go.

// deepToolsList is the fixture's poisoned tools/list with a field nested
// extra levels deep spliced into result. With the envelope and result already
// open, jsonMaxNestingDepth-1 crosses the decoder limit; one level less is
// the deepest legal message, the positive control.
func deepToolsList(t *testing.T, inner *httptest.Server, extra int) []byte {
	t.Helper()
	resp, err := http.Post(inner.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out = bytes.TrimSpace(out)
	if !bytes.HasSuffix(out, []byte("}}")) {
		t.Fatalf("unexpected fixture shape: %q", out)
	}
	return append(append(out[:len(out)-2], nestedField(extra)...), "}}"...)
}

func TestHTTPProxy_DeepJSONUnderContentEncodingIsBlocked(t *testing.T) {
	inner := fakeUpstreamMCP()
	defer inner.Close()
	deep := deepToolsList(t, inner, jsonMaxNestingDepth-1)
	legal := deepToolsList(t, inner, jsonMaxNestingDepth-2)

	encodings := []struct {
		name, transform string
		ce              string
	}{
		{"gzip", "gzip", "gzip"},
		{"x-gzip", "gzip", "x-gzip"},
		{"deflate-zlib", "deflate-zlib", "deflate"},
		{"deflate-raw", "deflate-raw", "deflate"},
		{"gzip-multi-member-deep-first", "gzip-multi-member", "gzip"},
	}
	for _, sse := range []bool{false, true} {
		for _, enc := range encodings {
			for _, body := range []struct {
				name    string
				plain   []byte
				blocked bool
			}{{"depth-exceeded", deep, true}, {"deepest-legal-control", legal, false}} {
				path := "json"
				if sse {
					path = "sse"
				}
				t.Run(path+"/"+enc.name+"/"+body.name, func(t *testing.T) {
					plain := body.plain
					if sse {
						plain = []byte(sseEvent(string(plain)))
					}
					wire := encodedBody(t, enc.transform, plain)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if sse {
							w.Header().Set("Content-Type", "text/event-stream")
						} else {
							w.Header().Set("Content-Type", "application/json")
						}
						w.Header().Set("Content-Encoding", enc.ce)
						_, _ = w.Write(wire)
					}))
					defer upstream.Close()
					var audited []AuditEntry
					var mu sync.Mutex
					hp := newEncodingTestProxy(t, upstream.URL, &audited, &mu)
					ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
					defer ts.Close()

					resp, raw := postToolsList(t, ts.URL, "gzip, deflate")
					if resp.StatusCode != http.StatusOK {
						t.Fatalf("status %d", resp.StatusCode)
					}
					if ce := resp.Header.Get("Content-Encoding"); ce != "" {
						t.Errorf("client Content-Encoding = %q; the proxy must answer in plaintext", ce)
					}
					if bytes.Contains(raw, []byte("poisoned_tool")) || bytes.Contains(raw, []byte("[[[[")) {
						t.Errorf("payload content reached the client: %.120q", raw)
					}
					mu.Lock()
					audits := append([]AuditEntry(nil), audited...)
					mu.Unlock()

					if !body.blocked {
						// The deepest legal nesting is an ordinary message: decoded,
						// filtered, relayed as identity with the one poisoning BLOCK.
						if !bytes.Contains(raw, []byte("get_weather")) {
							t.Errorf("control not relayed: %.120q", raw)
						}
						if len(audits) != 1 || audits[0].Decision != "BLOCK" || countRule(audits, depthRuleID) != 0 {
							t.Errorf("control audits = %s", auditSummary(audits))
						}
						return
					}

					// Past the limit: the depth BLOCK, in whatever form the body
					// was decoded, and the parse-error reply in the payload's place.
					assertDepthBlockAudit(t, audits)
					if sse {
						if !strings.Contains(string(raw), "-32700") {
							t.Errorf("SSE relay did not carry the parse-error event: %.200q", raw)
						}
						lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
						for _, l := range lines {
							if strings.HasPrefix(l, "data: ") {
								assertParseErrorReply(t, strings.TrimPrefix(l, "data: "))
							}
						}
					} else {
						assertParseErrorReply(t, string(raw))
					}
				})
			}
		}
	}
}
