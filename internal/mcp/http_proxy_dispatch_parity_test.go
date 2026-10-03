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

// This file pins the #3989 fix: relayJSON and relaySSE used to carry their
// own hand-rolled, duplicate copy of the response-filter list, separate from
// handler.go's responseFilterChain()/DispatchServerResponse that the stdio
// proxy uses. Three scanners (error, task-get, task-list) were entirely
// absent from both HTTP-side lists until they were added by hand — the exact
// "wiring a match field to one path only" trap this repo has hit repeatedly
// (#3232/#3234).
//
// The test is ONE fixture table driven through all three transports — stdio
// (RunWithIO), HTTP plain JSON (relayJSON) and HTTP SSE (relaySSE, decoded)
// — asserting the same outcome per row. The first cut of this file had a
// separate test per transport and asserted only that a substring was
// absent, which is satisfied by dropping the event entirely and says nothing
// about the other transport; Codex pass 1 on #4053 listed five mutations it
// would not catch, and the null-id regression it did not catch (finding 1)
// was real. Every confirmed finding from that pass is a row here.

// parityOutcome is what a transport did with a server→client message.
type parityOutcome int

const (
	outcomeForwarded parityOutcome = iota // byte-identical to the upstream body
	outcomeRewritten                      // changed, and still a JSON-RPC success/notification shape
	outcomeBlocked                        // replaced by a JSON-RPC error envelope
)

func (o parityOutcome) String() string {
	switch o {
	case outcomeForwarded:
		return "forwarded"
	case outcomeRewritten:
		return "rewritten"
	case outcomeBlocked:
		return "blocked"
	}
	return fmt.Sprintf("outcome(%d)", int(o))
}

// parityRow is one server→client message and the outcome every transport
// must produce for it.
type parityRow struct {
	name string
	// body is the upstream response body (one JSON-RPC message, or garbage).
	body string
	want parityOutcome
	// absent must not appear in what the client receives; present must.
	absent, present []string
	// rules are audit rule ids that must have fired (any order); empty means
	// no audit entry at all is expected.
	rules []string
}

type parityResult struct {
	got     string
	outcome parityOutcome
	audits  []AuditEntry
}

func classifyParity(got, body string) parityOutcome {
	if got == body {
		return outcomeForwarded
	}
	var msg Message
	if err := json.Unmarshal([]byte(got), &msg); err == nil && msg.Error != nil && msg.Result == nil {
		return outcomeBlocked
	}
	return outcomeRewritten
}

func parityPolicy() *MCPPolicy { return testHTTPProxyPolicy() }

// driveStdio pushes body through the stdio proxy's server→client direction.
func driveStdio(t *testing.T, body string) parityResult {
	t.Helper()
	var mu sync.Mutex
	var audits []AuditEntry
	p := NewProxy(ProxyConfig{
		Evaluator:           NewPolicyEvaluator(parityPolicy()),
		OnAudit:             func(e AuditEntry) { mu.Lock(); audits = append(audits, e); mu.Unlock() },
		Stderr:              io.Discard,
		SchemaDriftCacheDir: t.TempDir(),
	})
	clientOut := &bytes.Buffer{}
	p.RunWithIO(strings.NewReader(""), clientOut, strings.NewReader(body+"\n"), newNopWriteCloser(&bytes.Buffer{}))
	got := strings.TrimSuffix(clientOut.String(), "\n")
	return parityResult{got: got, outcome: classifyParity(got, body), audits: audits}
}

// sseFraming is what the fake SSE upstream wraps every event in; the relay
// must forward these lines untouched around a rewritten data line.
const sseFraming = "event: message\nid: 7\nretry: 1000\n"

// driveHTTP posts one client request through handleMCP to a fake upstream
// that answers with body, as plain JSON or as one SSE event (flushed, so the
// upstream response is chunked the way a real streaming server's is). For
// SSE the returned got is the decoded data line; the framing lines are
// asserted here because they are transport plumbing, not a per-row outcome.
func driveHTTP(t *testing.T, body string, sse bool) parityResult {
	t.Helper()
	var mu sync.Mutex
	var audits []AuditEntry
	// The client→server tools/call that triggers the round trip leaves its
	// own audit entry (default AUDIT decision). Only entries recorded after
	// the upstream was reached belong to the response scan under test.
	preUpstream := -1
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		preUpstream = len(audits)
		mu.Unlock()
		if !sse {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "%sdata: %s\n\n", sseFraming, body)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
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

	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{}}}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, raw)
	}
	got := string(raw)
	if sse {
		if !strings.HasPrefix(got, sseFraming) {
			t.Errorf("SSE relay lost or reordered event/id/retry framing:\n%q", got)
		}
		if !strings.HasSuffix(got, "\n\n") {
			t.Errorf("SSE relay lost the blank event separator:\n%q", got)
		}
		var dataLines []string
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, "data: ") {
				dataLines = append(dataLines, strings.TrimPrefix(l, "data: "))
			}
		}
		if len(dataLines) != 1 {
			t.Fatalf("SSE relay emitted %d data lines for one event (want exactly 1):\n%q", len(dataLines), got)
		}
		got = dataLines[0]
	}
	mu.Lock()
	defer mu.Unlock()
	if preUpstream < 0 {
		t.Fatalf("upstream was never reached; response scan did not run")
	}
	return parityResult{got: got, outcome: classifyParity(got, body), audits: audits[preUpstream:]}
}

func auditRuleIDs(audits []AuditEntry) []string {
	var out []string
	for _, a := range audits {
		out = append(out, a.TriggeredRules...)
	}
	return out
}

func checkParityRow(t *testing.T, transport string, row parityRow, res parityResult) {
	t.Helper()
	if res.outcome != row.want {
		t.Errorf("%s: outcome %s, want %s\n  got: %s", transport, res.outcome, row.want, res.got)
	}
	for _, s := range row.absent {
		if strings.Contains(res.got, s) {
			t.Errorf("%s: %q reached the client:\n  got: %s", transport, s, res.got)
		}
	}
	for _, s := range row.present {
		if !strings.Contains(res.got, s) {
			t.Errorf("%s: %q did not survive:\n  got: %s", transport, s, res.got)
		}
	}
	fired := auditRuleIDs(res.audits)
	for _, want := range row.rules {
		found := false
		for _, f := range fired {
			if f == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: audit rule %q did not fire (fired: %v)", transport, want, fired)
		}
	}
	if len(row.rules) == 0 && len(res.audits) != 0 {
		t.Errorf("%s: unexpected audit entries on a clean row: %v", transport, fired)
	}
}

func parityRows() []parityRow {
	// Injection prose is assembled at runtime (error_scanner_test.go) so this
	// file does not itself trip the content scanners guarding the repo.
	injIgnore, _ := buildInjectionTestCase(2) // marker: attacker.com
	injSSH, _ := buildInjectionTestCase(3)    // marker: id_rsa
	injKube, _ := buildInjectionTestCase(7)   // marker: kube/config
	jIgnore, jSSH, jKube := mustJSON(injIgnore), mustJSON(injSSH), mustJSON(injKube)
	const mIgnore, mSSH, mKube = "attacker.com", "id_rsa", "kube/config"

	poisonedTool := `{"name":"safe_tool","description":` + jSSH + `}`
	poisonedText := `{"type":"text","text":` + jIgnore + `}`
	embeddedSampling := `{"summarize":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":` + jSSH + `}}],"maxTokens":200}}}`

	const (
		ruleErr      = "mcp-error-message-injection"
		ruleTask     = "mcp-task-status-error-injection"
		ruleToolDesc = "tool-description-poisoning"
		ruleToolResp = "tool-response-poisoning"
		ruleMeta     = "mcp-response-meta-field-injection"
	)

	return []parityRow{
		// --- error.message injection, across every id shape (finding 1) ---
		{name: "error/int-id", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":` + jIgnore + `}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, present: []string{`"code":-32603`}, rules: []string{ruleErr}},
		{name: "error/null-id", body: `{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":` + jIgnore + `}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, present: []string{`"code":-32603`}, rules: []string{ruleErr}},
		{name: "error/missing-id", body: `{"jsonrpc":"2.0","error":{"code":-32603,"message":` + jIgnore + `}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, present: []string{`"code":-32603`}, rules: []string{ruleErr}},

		// --- SEP-1686 task status error fields ---
		{name: "tasks/get/error", body: `{"jsonrpc":"2.0","id":1,"result":{"taskId":"786512e2","status":"failed","keepAlive":30000,"error":` + jKube + `}}`,
			want: outcomeRewritten, absent: []string{mKube}, present: []string{"786512e2", `"keepAlive":30000`}, rules: []string{ruleTask}},
		{name: "tasks/list/error", body: `{"jsonrpc":"2.0","id":1,"result":{"tasks":[{"taskId":"t-1","status":"working"},{"taskId":"t-2","status":"failed","error":` + jKube + `}]}}`,
			want: outcomeRewritten, absent: []string{mKube}, present: []string{"t-1", "t-2"}, rules: []string{ruleTask}},
		// Both discriminators at once: the chain must COMPOSE and sanitize
		// both error surfaces, not stop at the first rewrite (finding 2).
		{name: "tasks/get+list/composite", body: `{"jsonrpc":"2.0","id":1,"result":{"taskId":"t-0","status":"failed","error":` + jIgnore + `,"tasks":[{"taskId":"t-1","status":"failed","error":` + jKube + `}]}}`,
			want: outcomeRewritten, absent: []string{mIgnore, mKube}, present: []string{"t-0", "t-1"}, rules: []string{ruleTask}},

		// --- malformed envelopes the typed dispatch must not narrow on (finding 3) ---
		{name: "error+result.tools/poisoned-tool", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boring"},"result":{"tools":[` + poisonedTool + `]}}`,
			want: outcomeRewritten, absent: []string{mSSH}, rules: []string{ruleToolDesc}},
		{name: "tools[]+Content/poisoned-text", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"Content":[` + poisonedText + `]}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleToolResp}},

		// --- result-level _meta beside a typed discriminator (Opus pass 2, finding 1) ---
		// Six scanners scan `_meta` themselves; the typed route to any other
		// scanner used to skip it, so a valid tools/list with a poisoned
		// `_meta` forwarded on every transport. The dispatcher now scans it
		// once for every result shape. The two-key tasks/get route shares
		// that code path with the single-key ones; initialize stands in for
		// completion, tasks/list and input_required, which do too.
		{name: "tools/list+_meta/valid-tool", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"ok","inputSchema":{"type":"object"}}],"_meta":{"note":` + jIgnore + `}}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleMeta}},
		{name: "initialize+_meta", body: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"s","version":"1"},"_meta":{"note":` + jIgnore + `}}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleMeta}},
		{name: "tasks/get+_meta", body: `{"jsonrpc":"2.0","id":1,"result":{"taskId":"t-1","status":"working","_meta":{"note":` + jIgnore + `}}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleMeta}},

		// --- fold-only discriminators are ambiguous, not typed (findings 2 and 3) ---
		// `Tools` / `TASKS` match a discriminator only under case folding; the
		// first cut folded them INTO the typed route, which skipped the chain
		// the zero-discriminator envelope used to get. And `ſtructuredContent`
		// (U+017F) is a key encoding/json decodes into StructuredContent while
		// strings.ToLower leaves it alone, so an exact-or-ToLower discriminator
		// saw only `tools` and forwarded the tool-call poison.
		{name: "Tools[]+_meta/fold-only", body: `{"jsonrpc":"2.0","id":1,"result":{"Tools":[],"_meta":{"note":` + jIgnore + `}}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleMeta}},
		{name: "TASKS[]+_meta/fold-only", body: `{"jsonrpc":"2.0","id":1,"result":{"TASKS":[],"_meta":{"note":` + jIgnore + `}}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleMeta}},
		{name: "tools[]+ſtructuredContent/unicode-fold", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"ſtructuredContent":{"x":` + jIgnore + `}}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{"mcp-structured-content-injection"}},

		// --- documented residual: a sanitizing rewrite pre-empts a later BLOCK (#4165) ---
		// `Tools` is fold-only, so this envelope is ambiguous and runs the
		// COMPOSING chain. FilterToolsListResponse hides tool `t` (its `_meta`
		// is poisoned) and re-marshals ListToolsResult, which drops `content`;
		// FilterToolCallResponse never sees the poisoned text, so the BLOCK it
		// would have raised never happens and the `content` injection is
		// neither blocked nor audited. On main's stdio the same body took the
		// typed tools/call route and the whole message was BLOCKed as
		// tool-response-poisoning. What reaches the client is the rewrite
		// with `nextCursor` intact, a key no scanner reads on any tree. Gary
		// accepted this as a residual on 2026-10-02 (#4053, Opus pass 3). This
		// row PINS today's behaviour so that closing #4165 has to flip it
		// deliberately: want becomes outcomeBlocked, mKube moves to absent,
		// and ruleToolResp fires.
		{name: "residual/Tools+content+nextCursor/rewrite-pre-empts-block", body: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + jIgnore + `}],"nextCursor":` + jKube + `,"Tools":[{"name":"t","description":"ok","inputSchema":{"type":"object"},"_meta":{"n":` + jSSH + `}}]}}`,
			want: outcomeRewritten, absent: []string{mIgnore, mSSH}, present: []string{`"tools":null`, mKube}, rules: []string{ruleToolDesc}},

		// --- the single-discriminator hot path, poisoned ---
		{name: "tools/list/poisoned-tool", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[` + poisonedTool + `,{"name":"ok_tool","description":"fine"}]}}`,
			want: outcomeRewritten, absent: []string{mSSH}, present: []string{"ok_tool"}, rules: []string{ruleToolDesc}},
		{name: "tools/call/poisoned-text", body: `{"jsonrpc":"2.0","id":1,"result":{"content":[` + poisonedText + `]}}`,
			want: outcomeBlocked, absent: []string{mIgnore}, rules: []string{ruleToolResp}},
		{name: "input_required/embedded-sampling", body: `{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":` + embeddedSampling + `}}`,
			want: outcomeBlocked, absent: []string{mSSH}, rules: []string{"sampling-content-scan"}},

		// --- clean messages of every discriminated shape pass through byte-identical ---
		{name: "clean/error", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params: path must be a string"}}`, want: outcomeForwarded},
		{name: "clean/tools/list", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"safe_tool","description":"does nothing bad"}]}}`, want: outcomeForwarded},
		{name: "clean/tools/call", body: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`, want: outcomeForwarded},
		{name: "clean/tasks/get", body: `{"jsonrpc":"2.0","id":1,"result":{"taskId":"t-1","status":"completed","keepAlive":1000}}`, want: outcomeForwarded},
		{name: "clean/tasks/list", body: `{"jsonrpc":"2.0","id":1,"result":{"tasks":[{"taskId":"t-1","status":"completed"}]}}`, want: outcomeForwarded},
		{name: "clean/input_required", body: `{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required","inputRequests":{}}}`, want: outcomeForwarded},
		// Unparseable: no envelope to rewrite, forwarded verbatim (the fail
		// open documented on ParseMessage's other callers) — and must not
		// crash the proxy on either transport.
		{name: "unparseable/forwarded", body: `not-json-at-all but still contains ` + injSSH, want: outcomeForwarded},
	}
}

// TestResponseDispatch_TransportParity drives every row through stdio, HTTP
// JSON and HTTP SSE and requires the same outcome, the same absent/present
// strings and the same audit rules on each. A row that passes on one
// transport and fails on another is the #3989 defect class by definition.
func TestResponseDispatch_TransportParity(t *testing.T) {
	for _, row := range parityRows() {
		t.Run(row.name, func(t *testing.T) {
			stdio := driveStdio(t, row.body)
			httpJSON := driveHTTP(t, row.body, false)
			httpSSE := driveHTTP(t, row.body, true)

			checkParityRow(t, "stdio", row, stdio)
			checkParityRow(t, "http-json", row, httpJSON)
			checkParityRow(t, "http-sse", row, httpSSE)

			// Beyond each transport meeting the row's expectation, the three
			// must agree with each other byte for byte: the shared dispatch
			// is the whole point, and a divergence here is a second list
			// growing back.
			if stdio.got != httpJSON.got || stdio.got != httpSSE.got {
				t.Errorf("transports diverged on the same body:\n  stdio:     %s\n  http-json: %s\n  http-sse:  %s", stdio.got, httpJSON.got, httpSSE.got)
			}
		})
	}
}

// TestResponseDispatch_ParityRowsHaveControls guards the table itself: a
// table with no clean rows would pass a proxy that blocks everything, and a
// table with no poisoned rows would pass one that scans nothing.
func TestResponseDispatch_ParityRowsHaveControls(t *testing.T) {
	var clean, poisoned int
	for _, row := range parityRows() {
		if row.want == outcomeForwarded {
			clean++
		} else {
			poisoned++
		}
	}
	if clean < 3 || poisoned < 3 {
		t.Fatalf("parity table needs both controls: clean=%d poisoned=%d", clean, poisoned)
	}
}
