package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4645 at the agentless surface: a customer protected path in the server's
// shell policy blocks the agent's file tools and the shell alike, both with
// the protected-path node, as the local hook does.
func TestEvaluateCustomerProtectedPath4645(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("defaults:\n  protected_paths:\n    - \"/etc/acme/secrets/**\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Options{Version: "test", PolicyPath: policyFile, LogPath: filepath.Join(dir, "audit.jsonl"), Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	secret := "/etc/acme/" + "secrets/db.env"
	want := []string{policy.ProtectedPathNode}
	for _, req := range []evaluateRequest{
		{ToolName: "Read", Arguments: map[string]interface{}{"file_path": secret}},
		{ToolName: "Edit", Arguments: map[string]interface{}{"file_path": secret, "old_string": "a", "new_string": "b"}},
		{ToolName: "read_file", Arguments: map[string]interface{}{"path": secret}},
		{Command: "c" + "at " + secret},
	} {
		code, resp := postEval(t, ts, req)
		if code != http.StatusOK || resp.Decision != "BLOCK" || !contains(resp.Rules, policy.ProtectedPathRuleID) {
			t.Errorf("%s%s: status %d %s %v; want BLOCK by protected-path", req.ToolName, req.Command, code, resp.Decision, resp.Rules)
			continue
		}
		if !reflect.DeepEqual(resp.Taxonomy, want) {
			t.Errorf("%s%s: taxonomy %v, want %v", req.ToolName, req.Command, resp.Taxonomy, want)
		}
	}
	// Near miss.
	if _, resp := postEval(t, ts, evaluateRequest{ToolName: "Read", Arguments: map[string]interface{}{"file_path": "/etc/acme/" + "secrets-howto.md"}}); resp.Decision == "BLOCK" {
		t.Errorf("near miss blocked: %v", resp.Rules)
	}

	// Control: a server whose policy names no customer path decides the
	// same Read as before #4645.
	shared := httptest.NewServer(sharedServer.Handler())
	defer shared.Close()
	if _, resp := postEval(t, shared, evaluateRequest{ToolName: "Read", Arguments: map[string]interface{}{"file_path": secret}}); resp.Decision == "BLOCK" || contains(resp.Rules, policy.ProtectedPathRuleID) {
		t.Errorf("no customer path: %s %v, want no protected-path BLOCK", resp.Decision, resp.Rules)
	}
}

// #4653: a relative customer pattern reaches a tool call through the
// request's cwd, as it reaches a command; a request without one is unchanged.
func TestEvaluateRelativeProtectedPathUsesRequestCwd4653(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("defaults:\n  protected_paths:\n    - \"secrets/**\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Options{Version: "test", PolicyPath: policyFile, LogPath: filepath.Join(dir, "audit.jsonl"), Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const repo = "/work/repo"
	key := repo + "/secrets/k" + ".pem"
	for _, req := range []evaluateRequest{
		{ToolName: "Read", Arguments: map[string]interface{}{"file_path": key}, Cwd: repo},
		{ToolName: "Grep", Arguments: map[string]interface{}{"pattern": "x", "path": "secrets"}, Cwd: repo},
		{Command: "c" + "at " + key, Cwd: repo},
	} {
		if _, resp := postEval(t, ts, req); resp.Decision != "BLOCK" || !contains(resp.Rules, policy.ProtectedPathRuleID) || !reflect.DeepEqual(resp.Taxonomy, []string{policy.ProtectedPathNode}) {
			t.Errorf("%s%s with cwd: %s %v %v; want BLOCK protected-path [%s]", req.ToolName, req.Command, resp.Decision, resp.Rules, resp.Taxonomy, policy.ProtectedPathNode)
		}
	}
	for _, cwd := range []string{"", "/elsewhere", "relative"} {
		req := evaluateRequest{ToolName: "Read", Arguments: map[string]interface{}{"file_path": key}, Cwd: cwd}
		if _, resp := postEval(t, ts, req); resp.Decision == "BLOCK" {
			t.Errorf("Read with cwd %q: %v; want no BLOCK", cwd, resp.Rules)
		}
	}
}

// relativePatternServer is a server whose policy protects secrets/**.
func relativePatternServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("defaults:\n  protected_paths:\n    - \"secrets/**\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Options{Version: "test", PolicyPath: policyFile, LogPath: filepath.Join(dir, "audit.jsonl"), Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// #4653, the thin clients: a tool call now carries the payload's cwd, so the
// server can resolve a relative pattern for it. Both clients, one contract.
func TestRemoteHookToolCallSendsCwd4653(t *testing.T) {
	ts := relativePatternServer(t)
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}
	read := func(path string) map[string]interface{} {
		return map[string]interface{}{
			"hook_event_name": "PreToolUse", "tool_name": "Read", "session_id": "it-4653", "cwd": "/repo",
			"tool_input": map[string]interface{}{"file_path": path},
		}
	}
	key := "/repo/secrets/k" + ".pem"
	if code, stderr := runHookClient(t, env, read(key)); code != 2 || !strings.Contains(stderr, policy.ProtectedPathRuleID) {
		t.Errorf("python client, file under the payload cwd: exit %d (stderr %s), want 2 by protected-path", code, stderr)
	}
	if code, stderr := runHookClient(t, env, read("/elsewhere/secrets/k"+".pem")); code != 0 {
		t.Errorf("python client, file outside the payload cwd: exit %d (stderr %s), want 0", code, stderr)
	}
	t.Run("pwsh", func(t *testing.T) {
		code, stdout, stderr := runPwshClient(t, env, copilotCompatPayload("Read", map[string]interface{}{"file_path": key}, "it-4653-ps"))
		assertDeny(t, "pwsh client, file under the payload cwd", code, stdout, stderr)
		code, stdout, stderr = runPwshClient(t, env, copilotCompatPayload("Read", map[string]interface{}{"file_path": "/elsewhere/secrets/k" + ".pem"}, "it-4653-ps2"))
		assertAllow(t, "pwsh client, file outside the payload cwd", code, stdout, stderr)
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
