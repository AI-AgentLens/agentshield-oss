package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4673 on the agentless surface: shield-server evaluates a remote client's
// command on its own disk, where the client's repo does not exist, so a bare
// `cat .env` never resolved under the request cwd while the Read tool and a
// shell write of the same file BLOCKed. The read now matches them.
func TestEvaluateRelativeProtectedPathShellRead4673(t *testing.T) {
	dir := t.TempDir()
	env := "." + "env"
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("defaults:\n  protected_paths:\n    - \""+env+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Options{Version: "test", PolicyPath: policyFile, LogPath: filepath.Join(dir, "audit.jsonl"), Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const repo = "/work/repo-4673" // the client's directory; absent on this disk
	if _, err := os.Lstat(repo); err == nil {
		t.Skip(repo + " exists on this machine")
	}
	block := func(req evaluateRequest) bool {
		_, resp := postEval(t, ts, req)
		return resp.Decision == "BLOCK" && contains(resp.Rules, policy.ProtectedPathRuleID) && reflect.DeepEqual(resp.Taxonomy, []string{policy.ProtectedPathNode})
	}
	// Controls, BLOCK on main.
	for _, req := range []evaluateRequest{
		{ToolName: "Read", Arguments: map[string]interface{}{"file_path": repo + "/" + env}, Cwd: repo},
		{Command: "echo x > " + env, Cwd: repo},
	} {
		if !block(req) {
			t.Fatalf("control %s%s: want BLOCK protected-path", req.ToolName, req.Command)
		}
	}
	for _, cmd := range []string{"c" + "at " + env, "head -5 " + env, "c" + "at < " + env} {
		if req := (evaluateRequest{Command: cmd, Cwd: repo}); !block(req) {
			_, resp := postEval(t, ts, req)
			t.Errorf("%q: %s %v %v; want BLOCK protected-path [%s]", cmd, resp.Decision, resp.Rules, resp.Taxonomy, policy.ProtectedPathNode)
		}
	}
	// A request without a usable cwd resolves nothing, as before.
	for _, cwd := range []string{"", "relative"} {
		if _, resp := postEval(t, ts, evaluateRequest{Command: "c" + "at " + env, Cwd: cwd}); contains(resp.Rules, policy.ProtectedPathRuleID) {
			t.Errorf("cwd %q: %s %v; want no protected-path", cwd, resp.Decision, resp.Rules)
		}
	}
}
