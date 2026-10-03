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
	"sync/atomic"
	"testing"
)

// Black-box tests for #4158: a JSON-RPC message nested past encoding/json's
// 10000-level limit used to be forwarded by both proxies, in both directions,
// unparsed and unaudited — a tools/call for a tool in BlockedTools included.
//
// This file deliberately uses only API that exists on main (NewProxy /
// RunWithIO, NewHTTPProxy / handleMCP, AuditEntry, the taxonomy constant), so
// the same file compiles and runs unchanged on a main checkout. The
// main-vs-branch matrix in the PR body comes from doing exactly that: the
// depth-10001 rows fail on main and pass here, the depth-0 and depth-9990 rows
// pass on both, which is what "unchanged from main" means.

const (
	depthRuleID    = "mcp-json-depth-exceeded"
	failOpenRuleID = "mcp-extract-fail-open"
)

// nestedField returns `,"x":[[[...]]]` nested depth deep, or "" for depth 0.
// With the two containers already open around it (the envelope and params,
// or the envelope and result) it crosses the decoder limit at depth 9999.
func nestedField(depth int) string {
	if depth == 0 {
		return ""
	}
	return `,"x":` + strings.Repeat("[", depth) + strings.Repeat("]", depth)
}

// depthToolCall builds a tools/call for tool. The blocked tool carries the
// exec-shaped argument its name implies; the benign read-verb tool carries a
// read-shaped one, so the argument-coherence scanner (which blocks a
// read-verb tool invoked with an exec-shaped argument, on main and here
// alike) stays out of the matrix.
func depthToolCall(tool string, depth int) string {
	args := `{"location":"NYC"}`
	if tool == "execute_command" {
		args = `{"command":"ls"}`
	}
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool +
		`","arguments":` + args + nestedField(depth) + `}}`
}

func depthResponse(depth int) string {
	return `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]` + nestedField(depth) + `}}`
}

// auditSink collects audit entries from the proxy goroutines.
type auditSink struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (s *auditSink) fn(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

func (s *auditSink) all() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEntry(nil), s.entries...)
}

func countRule(entries []AuditEntry, id string) int {
	n := 0
	for _, e := range entries {
		for _, r := range e.TriggeredRules {
			if r == id {
				n++
			}
		}
	}
	return n
}

func auditSummary(entries []AuditEntry) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, e.Decision+strings.Join(e.TriggeredRules, "+"))
	}
	return fmt.Sprintf("%d[%s]", len(entries), strings.Join(parts, ","))
}

// runStdio drives one client line and one server line through the stdio proxy.
func runStdio(t *testing.T, clientLine, serverLine string) (clientOut, serverOut string, audits []AuditEntry) {
	t.Helper()
	sink := &auditSink{}
	p := NewProxy(ProxyConfig{
		Evaluator:           NewPolicyEvaluator(testProxyPolicy()),
		OnAudit:             sink.fn,
		Stderr:              io.Discard,
		SchemaDriftCacheDir: t.TempDir(),
	})
	cBuf, sBuf := &bytes.Buffer{}, &bytes.Buffer{}
	p.RunWithIO(strings.NewReader(clientLine), cBuf, strings.NewReader(serverLine), newNopWriteCloser(sBuf))
	return cBuf.String(), sBuf.String(), sink.all()
}

// assertParseErrorReply checks the reply is the JSON-RPC parse error the
// spec prescribes when the id cannot be read: code -32700 and `"id": null`
// spelled out, not omitted.
func assertParseErrorReply(t *testing.T, got string) {
	t.Helper()
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(got)), &m); err != nil {
		t.Fatalf("reply is not a JSON-RPC message: %v\n%q", err, got)
	}
	if string(m.ID) != "null" {
		t.Errorf("reply id = %q, want the literal null the spec requires for a parse error", string(m.ID))
	}
	if m.Error == nil || m.Error.Code != -32700 {
		t.Fatalf("reply error = %+v, want code -32700", m.Error)
	}
	if !strings.Contains(m.Error.Message, "AgentShield") {
		t.Errorf("reply message %q does not name AgentShield", m.Error.Message)
	}
}

// assertDepthBlockAudit checks exactly one BLOCK receipt carrying the depth
// rule and the parse-fail-open taxonomy node was written.
func assertDepthBlockAudit(t *testing.T, audits []AuditEntry) {
	t.Helper()
	if len(audits) != 1 {
		t.Fatalf("want exactly 1 audit entry, got %s", auditSummary(audits))
	}
	e := audits[0]
	if e.Decision != "BLOCK" || !e.Flagged {
		t.Errorf("Decision=%q Flagged=%v, want a flagged BLOCK", e.Decision, e.Flagged)
	}
	if countRule(audits, depthRuleID) != 1 {
		t.Errorf("TriggeredRules = %v, want %s", e.TriggeredRules, depthRuleID)
	}
	if e.TaxonomyRef != securityMediatorParseFailOpenTaxonomyRef {
		t.Errorf("TaxonomyRef = %q, want %q", e.TaxonomyRef, securityMediatorParseFailOpenTaxonomyRef)
	}
	if len(e.Reasons) == 0 {
		t.Error("want a Reasons line saying what was refused")
	}
}

// assertFailOpenReceipt checks exactly one AUDIT receipt carrying the
// existing fail-open rule was written, and no BLOCK.
func assertFailOpenReceipt(t *testing.T, audits []AuditEntry) {
	t.Helper()
	if len(audits) != 1 {
		t.Fatalf("want exactly 1 audit entry, got %s", auditSummary(audits))
	}
	e := audits[0]
	if e.Decision != "AUDIT" || !e.Flagged {
		t.Errorf("Decision=%q Flagged=%v, want a flagged AUDIT", e.Decision, e.Flagged)
	}
	if countRule(audits, failOpenRuleID) != 1 {
		t.Errorf("TriggeredRules = %v, want %s", e.TriggeredRules, failOpenRuleID)
	}
	if e.TaxonomyRef != securityMediatorParseFailOpenTaxonomyRef {
		t.Errorf("TaxonomyRef = %q, want %q", e.TaxonomyRef, securityMediatorParseFailOpenTaxonomyRef)
	}
}

// depthMatrix is the client→server matrix shared by the stdio and HTTP tests.
// wantAudits pins the audit shape main produces for the parseable rows,
// measured on main @ 16bce6b0: one BLOCK (blocked-tool) for the BlockedTools
// call, and one bare AUDIT entry for an allowed call under the AUDIT default.
var depthMatrix = []struct {
	name       string
	tool       string
	depth      int
	wantBlock  bool // the message must not reach the server
	wantDepth  bool // the block is the depth rule, with a -32700 null-id reply
	wantAudits int
}{
	{"blocked tool depth 0", "execute_command", 0, true, false, 1},
	{"blocked tool depth 9990", "execute_command", 9990, true, false, 1},
	{"blocked tool depth 10001", "execute_command", 10001, true, true, 1},
	{"benign tool depth 0", "get_weather", 0, false, false, 1},
	{"benign tool depth 9990", "get_weather", 9990, false, false, 1},
	{"benign tool depth 10001", "get_weather", 10001, true, true, 1},
}

func TestProxy_ClientToServer_JSONDepth(t *testing.T) {
	for _, tc := range depthMatrix {
		t.Run(tc.name, func(t *testing.T) {
			line := depthToolCall(tc.tool, tc.depth)
			clientOut, serverOut, audits := runStdio(t, line+"\n", "")
			reached := strings.Contains(serverOut, line)
			t.Logf("MATRIX stdio c2s %s: reached_server=%v client_reply=%v audits=%s",
				tc.name, reached, strings.TrimSpace(clientOut) != "", auditSummary(audits))

			if tc.wantBlock {
				if reached {
					t.Fatalf("message reached the server")
				}
				if !strings.Contains(clientOut, "AgentShield") {
					t.Fatalf("client got no block reply: %q", clientOut)
				}
			} else {
				if !reached {
					t.Fatalf("allowed call was not forwarded; client=%q audits=%s", clientOut, auditSummary(audits))
				}
				if strings.TrimSpace(clientOut) != "" {
					t.Fatalf("client must receive nothing for a forwarded call, got %q", clientOut)
				}
			}
			if tc.wantDepth {
				assertParseErrorReply(t, clientOut)
				assertDepthBlockAudit(t, audits)
				return
			}
			if len(audits) != tc.wantAudits {
				t.Errorf("audit shape changed from main: want %d entries, got %s", tc.wantAudits, auditSummary(audits))
			}
			if countRule(audits, depthRuleID)+countRule(audits, failOpenRuleID) != 0 {
				t.Errorf("a parseable message must leave neither receipt, got %s", auditSummary(audits))
			}
		})
	}
}

func TestProxy_ServerToClient_JSONDepth(t *testing.T) {
	t.Run("poisoned response depth 10001 is not forwarded", func(t *testing.T) {
		line := depthResponse(10001)
		clientOut, _, audits := runStdio(t, "", line+"\n")
		t.Logf("MATRIX stdio s2c depth 10001: reached_client=%v audits=%s", strings.Contains(clientOut, line), auditSummary(audits))
		if strings.Contains(clientOut, line) {
			t.Fatalf("poisoned response reached the client")
		}
		assertParseErrorReply(t, clientOut)
		assertDepthBlockAudit(t, audits)
	})
	t.Run("benign response depth 9990 is relayed unchanged", func(t *testing.T) {
		line := depthResponse(9990)
		clientOut, _, audits := runStdio(t, "", line+"\n")
		t.Logf("MATRIX stdio s2c depth 9990: reached_client=%v audits=%s", strings.TrimSpace(clientOut) == line, auditSummary(audits))
		if strings.TrimSpace(clientOut) != line {
			t.Fatalf("response changed in transit:\n got %q", clientOut)
		}
		if len(audits) != 0 {
			t.Errorf("a clean response must leave no receipt, got %s", auditSummary(audits))
		}
	})
}

func TestProxy_NonDepthParseFailure_FailOpenWithReceipt(t *testing.T) {
	truncated := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command"`

	t.Run("client-to-server truncated JSON is forwarded with one receipt", func(t *testing.T) {
		clientOut, serverOut, audits := runStdio(t, truncated+"\n", "")
		if strings.TrimSpace(serverOut) != truncated {
			t.Fatalf("truncated message must still be forwarded (fail open), server got %q", serverOut)
		}
		if strings.TrimSpace(clientOut) != "" {
			t.Fatalf("client must receive nothing, got %q", clientOut)
		}
		assertFailOpenReceipt(t, audits)
	})
	t.Run("server-to-client truncated JSON is forwarded with one receipt", func(t *testing.T) {
		clientOut, _, audits := runStdio(t, "", truncated+"\n")
		if strings.TrimSpace(clientOut) != truncated {
			t.Fatalf("truncated response must still be forwarded (fail open), client got %q", clientOut)
		}
		assertFailOpenReceipt(t, audits)
	})
	t.Run("batch truncated JSON is forwarded with one receipt", func(t *testing.T) {
		batch := `[` + depthToolCall("execute_command", 0) // no closing bracket
		clientOut, serverOut, audits := runStdio(t, batch+"\n", "")
		if strings.TrimSpace(serverOut) != batch {
			t.Fatalf("truncated batch must still be forwarded (fail open), server got %q", serverOut)
		}
		if strings.TrimSpace(clientOut) != "" {
			t.Fatalf("client must receive nothing, got %q", clientOut)
		}
		assertFailOpenReceipt(t, audits)
	})
	t.Run("batch depth 10001 is blocked", func(t *testing.T) {
		batch := `[` + depthToolCall("execute_command", 10001) + `]`
		clientOut, serverOut, audits := runStdio(t, batch+"\n", "")
		if strings.Contains(serverOut, "execute_command") {
			t.Fatalf("deep batch reached the server")
		}
		assertParseErrorReply(t, clientOut)
		assertDepthBlockAudit(t, audits)
	})
	t.Run("whitespace-only line leaves no receipt", func(t *testing.T) {
		_, _, audits := runStdio(t, " \r\n", " \r\n")
		if len(audits) != 0 {
			t.Errorf("blank lines are not messages, got %s", auditSummary(audits))
		}
	})
}

// countingUpstream is an upstream MCP server that counts hits and answers
// every POST with reply under the given Content-Type and status.
type countingUpstream struct {
	*httptest.Server
	hits atomic.Int32
}

func newCountingUpstream(contentType string, status int, reply string) *countingUpstream {
	u := &countingUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		_, _ = io.ReadAll(r.Body)
		u.hits.Add(1)
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		if reply != "" {
			_, _ = io.WriteString(w, reply)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	return u
}

func newDepthHTTPProxy(t *testing.T, upstreamURL string) (*httptest.Server, *auditSink) {
	t.Helper()
	sink := &auditSink{}
	hp := NewHTTPProxy(HTTPProxyConfig{
		UpstreamURL:         upstreamURL,
		Evaluator:           NewPolicyEvaluator(testHTTPProxyPolicy()),
		OnAudit:             sink.fn,
		Stderr:              io.Discard,
		SchemaDriftCacheDir: t.TempDir(),
	})
	ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
	t.Cleanup(ts.Close)
	return ts, sink
}

const httpOKReply = `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`

func TestHTTPProxy_Request_JSONDepth(t *testing.T) {
	for _, tc := range depthMatrix {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newCountingUpstream("application/json", http.StatusOK, httpOKReply)
			defer upstream.Close()
			ts, sink := newDepthHTTPProxy(t, upstream.URL)

			resp, body, err := postJSON(ts.URL, depthToolCall(tc.tool, tc.depth))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			audits := sink.all()
			reached := upstream.hits.Load() > 0
			t.Logf("MATRIX http request %s: reached_server=%v status=%d audits=%s", tc.name, reached, resp.StatusCode, auditSummary(audits))

			if tc.wantBlock {
				if reached {
					t.Fatalf("message reached the upstream server")
				}
				if !strings.Contains(body, "AgentShield") {
					t.Fatalf("client got no block reply: %q", body)
				}
			} else {
				if !reached {
					t.Fatalf("allowed call was not forwarded; body=%q audits=%s", body, auditSummary(audits))
				}
				if body != httpOKReply {
					t.Fatalf("upstream reply changed in transit: %q", body)
				}
			}
			if tc.wantDepth {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status = %d, want 200 (JSON-RPC errors travel as 200)", resp.StatusCode)
				}
				assertParseErrorReply(t, body)
				assertDepthBlockAudit(t, audits)
				return
			}
			if len(audits) != tc.wantAudits {
				t.Errorf("audit shape changed from main: want %d entries, got %s", tc.wantAudits, auditSummary(audits))
			}
			if countRule(audits, depthRuleID)+countRule(audits, failOpenRuleID) != 0 {
				t.Errorf("a parseable message must leave neither receipt, got %s", auditSummary(audits))
			}
		})
	}
}

const pingRequest = `{"jsonrpc":"2.0","id":1,"method":"ping"}`

func TestHTTPProxy_ResponseJSON_JSONDepth(t *testing.T) {
	t.Run("poisoned response depth 10001 is not relayed", func(t *testing.T) {
		poisoned := depthResponse(10001)
		upstream := newCountingUpstream("application/json", http.StatusOK, poisoned)
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		resp, body, err := postJSON(ts.URL, pingRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		audits := sink.all()
		t.Logf("MATRIX http json response depth 10001: reached_client=%v status=%d audits=%s", body == poisoned, resp.StatusCode, auditSummary(audits))
		if body == poisoned {
			t.Fatalf("poisoned response reached the client")
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertParseErrorReply(t, body)
		assertDepthBlockAudit(t, audits)
	})
	t.Run("benign response depth 9990 is relayed unchanged", func(t *testing.T) {
		benign := depthResponse(9990)
		upstream := newCountingUpstream("application/json", http.StatusOK, benign)
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		_, body, err := postJSON(ts.URL, pingRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		audits := sink.all()
		t.Logf("MATRIX http json response depth 9990: reached_client=%v audits=%s", body == benign, auditSummary(audits))
		if body != benign {
			t.Fatalf("response changed in transit")
		}
		if len(audits) != 0 {
			t.Errorf("a clean response must leave no receipt, got %s", auditSummary(audits))
		}
	})
}

func sseEvent(data string) string {
	return "event: message\ndata: " + data + "\n\n"
}

func TestHTTPProxy_ResponseSSE_JSONDepth(t *testing.T) {
	t.Run("poisoned event depth 10001 is replaced", func(t *testing.T) {
		poisoned := depthResponse(10001)
		upstream := newCountingUpstream("text/event-stream", http.StatusOK, sseEvent(poisoned))
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		_, body, err := postJSON(ts.URL, pingRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		audits := sink.all()
		t.Logf("MATRIX http sse response depth 10001: reached_client=%v audits=%s", strings.Contains(body, poisoned), auditSummary(audits))
		if strings.Contains(body, poisoned) {
			t.Fatalf("poisoned event reached the client")
		}
		var replaced string
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "data: ") {
				replaced = strings.TrimPrefix(l, "data: ")
			}
		}
		if replaced == "" {
			t.Fatalf("no data line in the relayed stream:\n%q", body)
		}
		assertParseErrorReply(t, replaced)
		assertDepthBlockAudit(t, audits)
	})
	t.Run("benign event depth 9990 is relayed unchanged", func(t *testing.T) {
		benign := depthResponse(9990)
		upstream := newCountingUpstream("text/event-stream", http.StatusOK, sseEvent(benign))
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		_, body, err := postJSON(ts.URL, pingRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		audits := sink.all()
		t.Logf("MATRIX http sse response depth 9990: reached_client=%v audits=%s", strings.Contains(body, "data: "+benign+"\n"), auditSummary(audits))
		if !strings.Contains(body, "data: "+benign+"\n") {
			t.Fatalf("event changed in transit:\n%q", body)
		}
		if len(audits) != 0 {
			t.Errorf("a clean event must leave no receipt, got %s", auditSummary(audits))
		}
	})
}

func TestHTTPProxy_NonDepthParseFailure_FailOpenWithReceipt(t *testing.T) {
	truncatedRequest := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command"`
	truncatedResponse := `{"jsonrpc":"2.0","id":1,"result":`

	t.Run("request truncated JSON is forwarded with one receipt", func(t *testing.T) {
		// The upstream answers 400 with no body, as a real server does to a
		// request it cannot parse; an empty body is not a message and leaves
		// no receipt of its own.
		upstream := newCountingUpstream("", http.StatusBadRequest, "")
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		resp, _, err := postJSON(ts.URL, truncatedRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if upstream.hits.Load() != 1 {
			t.Fatalf("truncated request must still be forwarded (fail open), upstream hits = %d", upstream.hits.Load())
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("upstream status not relayed: %d", resp.StatusCode)
		}
		assertFailOpenReceipt(t, sink.all())
	})
	t.Run("JSON response truncated is relayed with one receipt", func(t *testing.T) {
		upstream := newCountingUpstream("application/json", http.StatusOK, truncatedResponse)
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		_, body, err := postJSON(ts.URL, pingRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if body != truncatedResponse {
			t.Fatalf("truncated response must still be relayed (fail open), got %q", body)
		}
		assertFailOpenReceipt(t, sink.all())
	})
	t.Run("SSE event truncated is relayed with one receipt", func(t *testing.T) {
		upstream := newCountingUpstream("text/event-stream", http.StatusOK, sseEvent(truncatedResponse))
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)

		_, body, err := postJSON(ts.URL, pingRequest)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !strings.Contains(body, "data: "+truncatedResponse+"\n") {
			t.Fatalf("truncated event must still be relayed (fail open), got %q", body)
		}
		assertFailOpenReceipt(t, sink.all())
	})
	t.Run("transport frames that are not messages leave no receipt", func(t *testing.T) {
		cases := []struct {
			name        string
			contentType string
			status      int
			reply       string
		}{
			{"202 Accepted with no body", "", http.StatusAccepted, ""},
			{"HTML error page", "text/html", http.StatusBadGateway, "<html><body>upstream down</body></html>"},
			{"legacy SSE endpoint event", "text/event-stream", http.StatusOK, "event: endpoint\ndata: /messages/?session_id=abc\n\n"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				upstream := newCountingUpstream(tc.contentType, tc.status, tc.reply)
				defer upstream.Close()
				ts, sink := newDepthHTTPProxy(t, upstream.URL)

				_, body, err := postJSON(ts.URL, pingRequest)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				if body != tc.reply {
					t.Fatalf("frame changed in transit: got %q want %q", body, tc.reply)
				}
				if audits := sink.all(); len(audits) != 0 {
					t.Errorf("not a message, must leave no receipt, got %s", auditSummary(audits))
				}
			})
		}
	})
}

// ---- Round 2 (Opus pass 1 on #4161) ----

const bom = "\xEF\xBB\xBF"

// TestHTTPProxy_Response_BOMRun_JSONDepth: a run of UTF-8 BOMs in front of
// a message defeats Go's decoder, and on Node 25 undici's Response.json()
// (the TypeScript SDK's JSON path) accepts two of them. The depth BLOCK
// must not depend on any shape gate, and the fail-open receipt must survive
// however many BOMs the payload carries. Both HTTP relays.
func TestHTTPProxy_Response_BOMRun_JSONDepth(t *testing.T) {
	for _, n := range []int{2, 3} {
		prefix := strings.Repeat(bom, n)
		deep := prefix + depthResponse(10001)
		shallow := prefix + depthResponse(0)

		t.Run(fmt.Sprintf("JSON %d BOMs + depth 10001 is blocked", n), func(t *testing.T) {
			upstream := newCountingUpstream("application/json", http.StatusOK, deep)
			defer upstream.Close()
			ts, sink := newDepthHTTPProxy(t, upstream.URL)
			_, body, err := postJSON(ts.URL, pingRequest)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			audits := sink.all()
			t.Logf("MATRIX http json response %d BOMs depth 10001: reached_client=%v audits=%s", n, body == deep, auditSummary(audits))
			if body == deep {
				t.Fatalf("BOM-prefixed deep response reached the client")
			}
			assertParseErrorReply(t, body)
			assertDepthBlockAudit(t, audits)
		})
		t.Run(fmt.Sprintf("JSON %d BOMs + shallow message is relayed with one receipt", n), func(t *testing.T) {
			upstream := newCountingUpstream("application/json", http.StatusOK, shallow)
			defer upstream.Close()
			ts, sink := newDepthHTTPProxy(t, upstream.URL)
			_, body, err := postJSON(ts.URL, pingRequest)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			audits := sink.all()
			t.Logf("MATRIX http json response %d BOMs shallow: relayed=%v audits=%s", n, body == shallow, auditSummary(audits))
			if body != shallow {
				t.Fatalf("BOM-prefixed message must be relayed as-is (fail open), got %q", body)
			}
			assertFailOpenReceipt(t, audits)
		})
		t.Run(fmt.Sprintf("SSE %d BOMs + depth 10001 is replaced", n), func(t *testing.T) {
			upstream := newCountingUpstream("text/event-stream", http.StatusOK, sseEvent(deep))
			defer upstream.Close()
			ts, sink := newDepthHTTPProxy(t, upstream.URL)
			_, body, err := postJSON(ts.URL, pingRequest)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			audits := sink.all()
			t.Logf("MATRIX http sse response %d BOMs depth 10001: reached_client=%v audits=%s", n, strings.Contains(body, deep), auditSummary(audits))
			if strings.Contains(body, deep) {
				t.Fatalf("BOM-prefixed deep event reached the client")
			}
			var replaced string
			for _, l := range strings.Split(body, "\n") {
				if strings.HasPrefix(l, "data: ") {
					replaced = strings.TrimPrefix(l, "data: ")
				}
			}
			assertParseErrorReply(t, replaced)
			assertDepthBlockAudit(t, audits)
		})
		t.Run(fmt.Sprintf("SSE %d BOMs + shallow message is relayed with one receipt", n), func(t *testing.T) {
			upstream := newCountingUpstream("text/event-stream", http.StatusOK, sseEvent(shallow))
			defer upstream.Close()
			ts, sink := newDepthHTTPProxy(t, upstream.URL)
			_, body, err := postJSON(ts.URL, pingRequest)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			audits := sink.all()
			t.Logf("MATRIX http sse response %d BOMs shallow: relayed=%v audits=%s", n, strings.Contains(body, "data: "+shallow+"\n"), auditSummary(audits))
			if !strings.Contains(body, "data: "+shallow+"\n") {
				t.Fatalf("BOM-prefixed event must be relayed as-is (fail open), got %q", body)
			}
			assertFailOpenReceipt(t, audits)
		})
	}
}

// strayStdoutServer is the reviewer's realistic stray-stdout server: a
// 5-line startup banner, then one debug print per request alongside the
// real response, for 50 requests. 105 lines, 55 of them not messages.
func strayStdoutServer() (output string, lines int, stray int) {
	var b strings.Builder
	banner := []string{
		"Starting weather MCP server v1.2.0",
		"Loading config from ./config.json",
		"Connected to cache",
		"[INFO] 3 tools registered",
		"Server running on stdio",
	}
	for _, l := range banner {
		b.WriteString(l + "\n")
	}
	for i := 1; i <= 50; i++ {
		fmt.Fprintf(&b, "DEBUG handling tools/call get_weather id=%d\n", i)
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"sunny"}]}}`+"\n", i)
	}
	return b.String(), len(banner) + 100, len(banner) + 50
}

// TestProxy_ServerToClient_StrayStdoutLeavesNoReceipt: a stdio server that
// logs to stdout must not leave one AUDIT per log line. Neither host can act
// on a line that does not open `{` or `[`, so nothing the receipt exists to
// record is lost. The depth BLOCK stays unconditional.
func TestProxy_ServerToClient_StrayStdoutLeavesNoReceipt(t *testing.T) {
	t.Run("banner and debug lines leave no receipt and are relayed", func(t *testing.T) {
		out, lines, stray := strayStdoutServer()
		clientOut, _, audits := runStdio(t, "", out)
		t.Logf("NOISE lines=%d stray=%d audits=%s", lines, stray, auditSummary(audits))
		if len(audits) != 0 {
			t.Fatalf("stray stdout lines must leave no receipt, got %s", auditSummary(audits))
		}
		if clientOut != out {
			t.Fatalf("stray lines must still be relayed byte-for-byte (fail open)")
		}
	})
	t.Run("a truncated JSON line still leaves exactly one receipt", func(t *testing.T) {
		out, _, _ := strayStdoutServer()
		truncated := `{"jsonrpc":"2.0","id":51,"result":`
		_, _, audits := runStdio(t, "", out+truncated+"\n")
		assertFailOpenReceipt(t, audits)
	})
	t.Run("a log-shaped line nested past the limit is still blocked", func(t *testing.T) {
		line := "DEBUG payload=" + strings.Repeat("[", 10001) + strings.Repeat("]", 10001)
		clientOut, _, audits := runStdio(t, "", line+"\n")
		if strings.Contains(clientOut, line) {
			t.Fatalf("deep line reached the client")
		}
		assertParseErrorReply(t, clientOut)
		assertDepthBlockAudit(t, audits)
	})
}

// TestHTTPProxy_RequestBatch_JSONDepth is the row the mutation pass found
// missing (M20): the HTTP handlePost batch branch has its own parse call
// and its own screen.
func TestHTTPProxy_RequestBatch_JSONDepth(t *testing.T) {
	t.Run("batch depth 10001 is blocked", func(t *testing.T) {
		upstream := newCountingUpstream("application/json", http.StatusOK, "["+httpOKReply+"]")
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)
		batch := `[` + pingRequest + `,` + depthToolCall("get_weather", 10001) + `]`
		resp, body, err := postJSON(ts.URL, batch)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		audits := sink.all()
		t.Logf("MATRIX http batch depth 10001: reached_server=%v status=%d audits=%s", upstream.hits.Load() > 0, resp.StatusCode, auditSummary(audits))
		if upstream.hits.Load() != 0 {
			t.Fatalf("deep batch reached the upstream server")
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertParseErrorReply(t, body)
		assertDepthBlockAudit(t, audits)
	})
	t.Run("batch depth 9990 is forwarded as on main", func(t *testing.T) {
		upstream := newCountingUpstream("application/json", http.StatusOK, "["+httpOKReply+"]")
		defer upstream.Close()
		ts, sink := newDepthHTTPProxy(t, upstream.URL)
		batch := `[` + pingRequest + `,` + depthToolCall("get_weather", 9990) + `]`
		_, body, err := postJSON(ts.URL, batch)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		audits := sink.all()
		t.Logf("MATRIX http batch depth 9990: reached_server=%v audits=%s", upstream.hits.Load() > 0, auditSummary(audits))
		if upstream.hits.Load() != 1 {
			t.Fatalf("batch at depth 9990 must be forwarded, upstream hits = %d", upstream.hits.Load())
		}
		if body != "["+httpOKReply+"]" {
			t.Fatalf("upstream reply changed in transit: %q", body)
		}
		if countRule(audits, depthRuleID)+countRule(audits, failOpenRuleID) != 0 {
			t.Errorf("a parseable batch must leave neither receipt, got %s", auditSummary(audits))
		}
		if len(audits) != 1 || audits[0].Decision != "AUDIT" {
			t.Errorf("audit shape changed from main (one bare AUDIT for the allowed call): %s", auditSummary(audits))
		}
	})
}

// TestHTTPProxy_BlockedResponseKeepsUpstreamHeaders pins the choice the
// mutation pass found untested (M30): when the proxy replaces a
// server-to-client response, the upstream's headers travel with the
// replacement — Mcp-Session-Id above all, since dropping it would end the
// client's session over one refused message — except the three that
// described the body being replaced.
func TestHTTPProxy_BlockedResponseKeepsUpstreamHeaders(t *testing.T) {
	deep := depthResponse(10001)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Mcp-Session-Id", "sess-4161")
		w.Header().Set("X-Upstream-Custom", "kept")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Encoding", "identity")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, deep)
	}))
	defer upstream.Close()
	ts, sink := newDepthHTTPProxy(t, upstream.URL)

	resp, body, err := postJSON(ts.URL, pingRequest)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	assertParseErrorReply(t, body)
	assertDepthBlockAudit(t, sink.all())

	if got := resp.Header.Get("Mcp-Session-Id"); got != "sess-4161" {
		t.Errorf("Mcp-Session-Id = %q, want sess-4161 — a blocked response must not end the session", got)
	}
	if got := resp.Header.Get("X-Upstream-Custom"); got != "kept" {
		t.Errorf("X-Upstream-Custom = %q, want kept", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (describes the replacement, not the upstream body)", got)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want absent (described the replaced body)", got)
	}
	if got := resp.Header.Get("Content-Length"); got != fmt.Sprint(len(body)) {
		t.Errorf("Content-Length = %q, want %d (the replacement's length)", got, len(body))
	}
}
