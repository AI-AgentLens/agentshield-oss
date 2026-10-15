package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// Exercise the HTTP-to-disk seam: attribution must survive evaluation and
// stay separate from a harness conversation ID that the gateway cannot know.
func TestServerAuditPreservesGatewayIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := NewServer(Options{Version: "test", LogPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	identity := &logger.IdentityContext{TenantID: "lab", UserID: "gary", DeviceID: "client-a",
		IdentitySource: "wireguard-enrollment", HarnessSource: "inferred-user-agent"}
	code, _ := postEval(t, ts, evaluateRequest{Command: "ls -la", Principal: "gary",
		AgentID: "claude-code", RequestID: "request-a", ToolCallID: "tool-a", Identity: identity})
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event logger.AuditEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	if event.AgentID != "claude-code" || event.Principal != "gary" || event.RequestID != "request-a" ||
		event.ToolCallID != "tool-a" || event.SessionID != "" || event.Identity == nil || *event.Identity != *identity {
		t.Fatalf("attribution lost or conflated: %+v", event)
	}
	if result := logger.VerifyChain(path); result.State != logger.ChainStateVerified {
		t.Fatalf("identity event not integrity protected: %+v", result)
	}
	// Attribution is part of the chained evidence, not an unhashed sidecar.
	tampered := bytes.ReplaceAll(raw, []byte(`"user_id":"gary"`), []byte(`"user_id":"other"`))
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if result := logger.VerifyChain(path); result.State != logger.ChainStateBroken {
		t.Fatalf("identity tampering escaped verification: %+v", result)
	}
}
