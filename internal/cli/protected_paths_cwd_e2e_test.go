package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4653 through the real hook entry point. A customer pack protects
// `secrets/**` and `.env`, patterns relative to the directory the agent works
// in. The payload's cwd is a scratch repo; the hook process runs in this
// package's directory, so a pass here cannot come from the process's own cwd
// (#4452: the payload cwd is used deliberately).

const ppRelPack = `name: Acme Relative
description: Paths relative to the project
version: 1.0.0
author: Acme Security
defaults:
  protected_paths:
  - secrets/**
  - .env
rules: []
`

// ppRelHome is an enforce-mode HOME with the relative-pattern pack.
func ppRelHome(t *testing.T, managedFailClosed bool) string {
	t.Helper()
	home := proxyHome(t, "mode: enforce\n")
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(filepath.Join(dir, "packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packs", "co-acme-rel.yaml"), []byte(ppRelPack), 0o600); err != nil {
		t.Fatal(err)
	}
	if managedFailClosed {
		if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(`{"managed": true, "fail_closed": true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// ppRepo is a scratch project directory spelled without symlinks.
func ppRepo(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ppShortRepo is ppRepo under /tmp with a short name. The proxies' content
// scanner reads a long random temp-dir segment as a high-entropy secret and
// blocks the call before policy, which would hide what these tests measure.
func ppShortRepo(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pp4653-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func ppPayloadIn(cwd, tool string, input map[string]interface{}) string {
	m := map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "pp-4653", "tool_input": input}
	if cwd != "" {
		m["cwd"] = cwd
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func ppKey(repo string) string { return filepath.Join(repo, "secrets", "k"+".pem") }

func TestHook_RelativeProtectedPath_FileToolsUnderPayloadCwd_4653(t *testing.T) {
	wd, _ := os.Getwd()
	repo := ppRepo(t)
	if strings.HasPrefix(wd, repo) || strings.HasPrefix(repo, wd) {
		t.Fatalf("the test must run the hook outside the repo: hook dir %s, repo %s", wd, repo)
	}
	rows := []struct {
		name  string
		tool  string
		input func(repo string) map[string]interface{}
	}{
		{"Read", "Read", func(r string) map[string]interface{} { return map[string]interface{}{"file_path": ppKey(r)} }},
		{"Write", "Write", func(r string) map[string]interface{} {
			return map[string]interface{}{"file_path": filepath.Join(r, "secrets", "new.key"), "content": "x"}
		}},
		{"Edit", "Edit", func(r string) map[string]interface{} {
			return map[string]interface{}{"file_path": ppKey(r), "old_string": "a", "new_string": "b"}
		}},
		{"NotebookEdit", "NotebookEdit", func(r string) map[string]interface{} {
			return map[string]interface{}{"notebook_path": filepath.Join(r, "secrets", "n.ipynb"), "new_source": "x"}
		}},
		{"Grep on secrets", "Grep", func(string) map[string]interface{} {
			return map[string]interface{}{"pattern": "password", "path": "secrets"}
		}},
		{"Read .env", "Read", func(r string) map[string]interface{} {
			return map[string]interface{}{"file_path": filepath.Join(r, "."+"env")}
		}},
		{"shell cat (parity)", "Bash", func(string) map[string]interface{} {
			return map[string]interface{}{"command": "c" + "at secrets/k" + ".pem"}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := ppRun(t, ppRelHome(t, false), ppPayloadIn(repo, row.tool, row.input(repo)))
			if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(policy.ProtectedPathRuleID) || !got.taxonomyIs(policy.ProtectedPathNode) {
				t.Fatalf("cwd = repo: exit %d %v %v %v; want exit 2, BLOCK protected-path, [%s] (stderr %q)", got.code, got.decision, got.rules, got.taxonomy, policy.ProtectedPathNode, got.stderr)
			}
			// Control: the same files, with the payload naming another
			// directory, are outside the relative patterns' reach. Grep and
			// the shell name `secrets` relative to the payload cwd, so they
			// look in the other directory and stay protected there too.
			other := ppRepo(t)
			if row.tool == "Grep" || row.tool == "Bash" {
				return
			}
			ctl := ppRun(t, ppRelHome(t, false), ppPayloadIn(other, row.tool, row.input(repo)))
			if ctl.hasRule(policy.ProtectedPathRuleID) {
				t.Errorf("cwd = another dir: %v %v; the relative pattern reached outside the working dir", ctl.decision, ctl.rules)
			}
		})
	}
}

// A payload with no cwd falls back to the hook's own directory, as the shell
// path does.
func TestHook_RelativeProtectedPath_NoPayloadCwdUsesHookDir_4653(t *testing.T) {
	repo := ppRepo(t)
	home := ppRelHome(t, false)
	inv := invokeAgentshieldIn(t, home, repo, []string{"agentshield", "hook"}, stdinPipe, ppPayloadIn("", "Read", map[string]interface{}{"file_path": ppKey(repo)}))
	rec := lastHookRecord(t, home)
	if inv.code != 2 || rec["decision"] != "BLOCK" {
		t.Errorf("no payload cwd, hook in the repo: exit %d %v %v; want exit 2 BLOCK", inv.code, rec["decision"], rec["triggered_rules"])
	}
}

// #4654 item 3, M23: on a managed fail_closed host, a shell pack the tool path
// cannot read degrades its ruleset, so the tool call BLOCKs, as the shell
// path refuses a command. The control (no broken pack) is not blocked.
func TestHook_BrokenShellPackFailsClosedOnToolCalls_4654(t *testing.T) {
	payload := ppPayloadIn("/tmp", "Read", map[string]interface{}{"file_path": "/tmp/readme.md"})
	ctlHome := ppRelHome(t, true)
	ctl := ppRun(t, ctlHome, payload)
	if ctl.code != 0 || ctl.decision == "BLOCK" {
		t.Fatalf("control, intact packs: exit %d %v %v; want no BLOCK", ctl.code, ctl.decision, ctl.rules)
	}
	home := ppRelHome(t, true)
	if err := os.WriteFile(filepath.Join(home, ".agentshield", "packs", "broken.yaml"), []byte("defaults:\n  protected_paths: [/a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ppRun(t, home, payload)
	if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(failClosedRuleID) {
		t.Errorf("broken shell pack, fail_closed: exit %d %v %v; want exit 2, BLOCK by %s (stderr %q)", got.code, got.decision, got.rules, failClosedRuleID, got.stderr)
	}
	if !strings.Contains(got.stderr, "broken.yaml") {
		t.Errorf("stderr does not name the broken pack: %q", got.stderr)
	}
}

// The stdio proxy resolves against its own directory, which the spawned
// server inherits.
func TestMCPProxy_RelativeProtectedPath_ProcessDir_4653(t *testing.T) {
	repo := ppShortRepo(t)
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, ppKey(repo))
	run := func(dir string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := proxyHelperCmd(ctx, ppRelHome(t, false), "mcp-proxy", "--", os.Args[0], "-test.run=^TestHelperFakeMCPServer$")
		cmd.Env = append(cmd.Env, "AGENTSHIELD_FAKE_MCP_SERVER=1")
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(req + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("mcp-proxy: %v", err)
		}
		return string(out)
	}
	if out := run(repo); strings.Contains(out, `"served"`) || !strings.Contains(out, "protected path denied: secrets/**") {
		t.Errorf("proxy in the repo: want a protected-path block on secrets/**, got: %s", out)
	}
	if out := run(ppShortRepo(t)); !strings.Contains(out, `"served"`) {
		t.Errorf("proxy in another dir: not served: %s", out)
	}
}

// The HTTP proxy has no working directory (its upstream is remote), so a
// relative pattern does not reach an absolute argument there. Pinned, so
// giving it one is a deliberate change.
func TestMCPHTTPProxy_RelativeProtectedPath_NoWorkDir_4653(t *testing.T) {
	repo := ppShortRepo(t)
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, ppKey(repo))
	if out, reached := runHTTPProxyOnce(t, ppRelHome(t, false), req); !reached {
		t.Errorf("HTTP proxy: the read did not reach the upstream (did it gain a working dir?): %s", out)
	}
}

// mcp-eval predicts the hook's tool path from its own directory.
func TestMCPEval_RelativeProtectedPath_ProcessDir_4653(t *testing.T) {
	repo := ppRepo(t)
	args, _ := json.Marshal(map[string]string{"file_path": ppKey(repo)})
	argv := []string{"agentshield", "mcp-eval", "--tool", "Read", "--json", string(args)}
	if got := invokeAgentshieldIn(t, ppRelHome(t, false), repo, argv, stdinDevNull, ""); got.code != 2 {
		t.Errorf("mcp-eval in the repo: exit %d, want 2\n%s%s", got.code, got.stdout, got.stderr)
	}
	if got := invokeAgentshieldIn(t, ppRelHome(t, false), ppRepo(t), argv, stdinDevNull, ""); got.code != 0 {
		t.Errorf("mcp-eval in another dir: exit %d, want 0\n%s", got.code, got.stdout)
	}
}
