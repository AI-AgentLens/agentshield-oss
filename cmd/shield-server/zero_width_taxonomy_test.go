package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// #4560 at the agentless surface: /v1/evaluate and the server's own audit log
// carry the approved node for a built-in unicode-zero-width BLOCK, as the
// local hook does.
func TestEvaluateShellZeroWidthBlockCarriesInvisibleUnicodeNode(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := NewServer(Options{Version: "test", LogPath: logPath, Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Assembled from the code point, never a literal invisible character.
	cmd := "echo hel" + string(rune(0x200B)) + "lo"
	code, resp := postEval(t, ts, evaluateRequest{Command: cmd, SessionID: "zw-4560"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision != "BLOCK" {
		t.Fatalf("decision = %q, want BLOCK (rules=%v)", resp.Decision, resp.Rules)
	}
	found := false
	for _, r := range resp.Rules {
		found = found || r == "unicode-zero-width"
	}
	if !found {
		t.Fatalf("rules = %v, want unicode-zero-width", resp.Rules)
	}
	want := []string{"unauthorized-execution/agentic-attacks/invisible-unicode-prompt-injection"}
	if !reflect.DeepEqual(resp.Taxonomy, want) {
		t.Errorf("response taxonomy = %v, want exactly %v", resp.Taxonomy, want)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read server audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var ev logger.AuditEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if ev.Decision != "BLOCK" || !reflect.DeepEqual(ev.TaxonomyRefs, want) {
		t.Errorf("logged event = {decision:%s taxonomy:%v}, want {BLOCK %v}", ev.Decision, ev.TaxonomyRefs, want)
	}
}
