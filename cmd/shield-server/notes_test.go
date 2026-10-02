package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// #3995: the agentless service is a second production event source. Its
// /v1/evaluate response and its own audit log carry the same notes the local
// hook writes, omitted when there are none.
func TestEvaluateShellCarriesNotes(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, resp := postEval(t, ts, evaluateRequest{Command: "ls -la"})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(resp.Notes) != 0 {
		t.Fatalf("benign command carried notes: %v", resp.Notes)
	}

	// A doc-text mention of a blocked pattern: excused or downgraded, and
	// either way the response names the rule in a note.
	cmd := `git commit -m "docs: explain why ` + "ufw " + "disable" + ` is blocked"`
	code, resp = postEval(t, ts, evaluateRequest{Command: cmd})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Decision == "BLOCK" {
		t.Fatalf("doc text must not BLOCK: %v", resp.Rules)
	}
	found := false
	for _, n := range resp.Notes {
		if n.Rule == "ts-block-ufw-disable" && (n.Kind == "excused" || n.Kind == "downgraded") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no excused/downgraded note for ts-block-ufw-disable in response: notes=%v", resp.Notes)
	}
	if got := auditNotes(resp.Notes); len(got) != len(resp.Notes) || got[0].Rule != resp.Notes[0].Rule {
		t.Fatalf("auditNotes did not carry the notes to the audit event: %v", got)
	}
	if auditNotes(nil) != nil {
		t.Fatal("auditNotes(nil) must be nil so the event omits the key")
	}
}

// Opus review mutation (f): the server's own audit log must carry the notes,
// not just the response. A server with a private log path, one noted
// evaluation, one line on disk with the note.
func TestServerAuditLogCarriesNotes(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := NewServer(Options{Version: "test", LogPath: logPath})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	cmd := `git commit -m "docs: explain why ` + "ufw " + "disable" + ` is blocked"`
	if code, resp := postEval(t, ts, evaluateRequest{Command: cmd}); code != http.StatusOK || len(resp.Notes) == 0 {
		t.Fatalf("status=%d notes=%v; want 200 with a note", code, resp.Notes)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read server audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var ev logger.AuditEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(ev.Notes) == 0 || ev.Notes[0].Rule != "ts-block-ufw-disable" {
		t.Fatalf("logged event notes = %+v; the response carried the note and logAudit dropped it", ev.Notes)
	}
}
