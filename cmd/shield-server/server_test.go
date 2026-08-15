package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// sharedServer is built once for the whole package: engine construction
// compiles every embedded pack (~seconds), and every test only needs a
// read-only view. HOME points at a throwaway dir because config.Load mkdirs
// ~/.agentshield as a side effect and the audit logger writes there.
var sharedServer *Server

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "shield-server-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = os.Setenv("HOME", dir)

	sharedServer, err = NewServer(Options{Version: "test"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewServer: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	sharedServer.Close()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func postEval(t *testing.T, ts *httptest.Server, req evaluateRequest) (int, evaluateResponse) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(ts.URL+"/v1/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/evaluate: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out evaluateResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return resp.StatusCode, out
}

// Attack-shaped strings are assembled by concatenation, not written as
// literals: this repo dogfoods AgentShield, and quoted attack text in file
// content can trip the very rules under test (see the fixture-indirection
// note in CLAUDE.md).
func destructiveCommand() string { return "rm -rf " + "/" }
func credentialPath() string     { return "/home/user/" + ".vault-token" }

func TestEvaluateShellBlocksDestructive(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, resp := postEval(t, ts, evaluateRequest{Command: destructiveCommand(), SessionID: "tp-shell"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "BLOCK" {
		t.Fatalf("decision = %q, want BLOCK (rules: %v)", resp.Decision, resp.Rules)
	}
	if len(resp.Rules) == 0 {
		t.Error("BLOCK carried no triggered rules")
	}
	// The fusion contract: a runtime decision must carry taxonomy refs or it
	// can never become a control-mapped attestation record (#3111).
	if len(resp.Taxonomy) == 0 {
		t.Error("BLOCK carried no taxonomy refs — attestation chain would be broken")
	}
	if resp.SessionID != "tp-shell" {
		t.Errorf("session_id = %q, want echo of request value", resp.SessionID)
	}
	if resp.Mode == "" {
		t.Error("mode missing from response")
	}
}

func TestEvaluateShellAllowsBenign(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, resp := postEval(t, ts, evaluateRequest{Command: "ls -la"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW (rules: %v, reasons: %v)", resp.Decision, resp.Rules, resp.Reasons)
	}
}

func TestEvaluateMCPBlocksCredentialRead(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, resp := postEval(t, ts, evaluateRequest{
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": credentialPath()},
		SessionID: "tp-mcp",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "BLOCK" {
		t.Fatalf("decision = %q, want BLOCK (rules: %v)", resp.Decision, resp.Rules)
	}
}

func TestEvaluateMCPBenignNotBlocked(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, resp := postEval(t, ts, evaluateRequest{
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": "/workspace/project/README.md"},
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision == "BLOCK" {
		t.Fatalf("benign read_file was BLOCKed (rules: %v, reasons: %v)", resp.Rules, resp.Reasons)
	}
}

func TestEvaluateRejectsMalformedRequests(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	// Both surfaces at once — ambiguous, must refuse rather than guess.
	code, _ := postEval(t, ts, evaluateRequest{Command: "ls", ToolName: "read_file"})
	if code != http.StatusBadRequest {
		t.Errorf("command+tool_name: status = %d, want 400", code)
	}

	// Neither surface.
	code, _ = postEval(t, ts, evaluateRequest{SessionID: "empty"})
	if code != http.StatusBadRequest {
		t.Errorf("empty request: status = %d, want 400", code)
	}

	// Wrong method.
	resp, err := http.Get(ts.URL + "/v1/evaluate")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", resp.StatusCode)
	}

	// Invalid JSON.
	r2, err := http.Post(ts.URL+"/v1/evaluate", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid JSON: status = %d, want 400", r2.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var h healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Status != "ok" || h.Version != "test" || h.Mode == "" {
		t.Errorf("unexpected health payload: %+v", h)
	}
}

// requireAuth is engine-independent, so auth is tested on a bare Server —
// no need to pay for a second pipeline build.
func TestRequireAuth(t *testing.T) {
	s := &Server{token: "sekrit-token"}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(s.requireAuth(inner))
	defer ts.Close()

	get := func(auth string) int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := get(""); code != http.StatusUnauthorized {
		t.Errorf("no header: %d, want 401", code)
	}
	if code := get("Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d, want 401", code)
	}
	if code := get("sekrit-token"); code != http.StatusUnauthorized {
		t.Errorf("missing Bearer prefix: %d, want 401", code)
	}
	if code := get("Bearer sekrit-token"); code != http.StatusNoContent {
		t.Errorf("valid token: %d, want 204", code)
	}

	// Empty token means loopback-only operation (enforced at startup) and no
	// auth gate at all — not "empty bearer accepted".
	open := &Server{}
	ts2 := httptest.NewServer(open.requireAuth(inner))
	defer ts2.Close()
	resp, err := http.Get(ts2.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("tokenless server: %d, want 204", resp.StatusCode)
	}
}

func TestSessionHistoryIsPerSession(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	benign := func(session string) evaluateRequest {
		return evaluateRequest{
			ToolName:  "read_file",
			Arguments: map[string]interface{}{"path": "/workspace/project/README.md"},
			SessionID: session,
		}
	}
	for i := 0; i < 2; i++ {
		if code, _ := postEval(t, ts, benign("hist-a")); code != http.StatusOK {
			t.Fatalf("call %d: status %d", i, code)
		}
	}
	if code, _ := postEval(t, ts, benign("hist-b")); code != http.StatusOK {
		t.Fatal("hist-b call failed")
	}

	if got := len(sharedServer.sessions.get("hist-a").History()); got != 2 {
		t.Errorf("hist-a history = %d calls, want 2", got)
	}
	if got := len(sharedServer.sessions.get("hist-b").History()); got != 1 {
		t.Errorf("hist-b history = %d calls, want 1", got)
	}
}

func TestSessionStoreBoundsMemory(t *testing.T) {
	store := newSessionStore()
	for i := 0; i < maxSessions+50; i++ {
		store.get(fmt.Sprintf("s-%d", i))
	}
	if got := store.count(); got > maxSessions {
		t.Errorf("session store grew to %d, cap is %d", got, maxSessions)
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8383": true,
		"localhost:8383": true,
		"[::1]:8383":     true,
		"0.0.0.0:8383":   false,
		":8383":          false, // all interfaces
		"10.0.0.5:8383":  false,
		"not-an-addr":    false,
	}
	for addr, want := range cases {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
