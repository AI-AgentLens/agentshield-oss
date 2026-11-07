package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4645, through the real hook entry point (a child process running
// Execute(), Claude Code PreToolUse payloads on stdin, a scratch HOME in
// enforce mode). A customer pack adds /etc/acme/secrets/** to protected_paths.
// On main the shell BLOCKed `cat` of a file there with no taxonomy, and the
// agent's own Read of the same file was AUDIT with no rule.

// ppPack is the customer pack of the issue's repro.
const ppPack = `name: Acme Custom
description: Acme's own protected paths
version: 1.0.0
author: Acme Security
defaults:
  protected_paths:
  - /etc/acme/secrets/**
rules: []
`

// Paths are assembled, not written as literals: this repo dogfoods AgentShield.
func ppSecret() string   { return "/etc/acme/" + "secrets/db.env" }
func ppNearMiss() string { return "/etc/acme/" + "secrets-howto.md" }
func ppCat(p string) string {
	return "c" + "at " + p
}

// ppHome is a scratch HOME in enforce mode, with the customer pack when
// withPack, and a managed.json (managed, not fail_closed) when managed.
func ppHome(t *testing.T, withPack, managed bool) string {
	t.Helper()
	home := proxyHome(t, "mode: enforce\n")
	dir := filepath.Join(home, ".agentshield")
	if withPack {
		if err := os.MkdirAll(filepath.Join(dir, "packs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "packs", "co-acme.yaml"), []byte(ppPack), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if managed {
		if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(`{"managed": true}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func ppPayload(tool string, input map[string]interface{}) string {
	b, _ := json.Marshal(map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": tool, "session_id": "pp-4645", "cwd": "/tmp", "tool_input": input})
	return string(b)
}

// ppVerdict is what a harness and an auditor see of one hook run.
type ppVerdict struct {
	code     int
	decision interface{}
	rules    interface{}
	taxonomy interface{}
	stderr   string
}

func ppRun(t *testing.T, home, payload string) ppVerdict {
	t.Helper()
	inv := invokeAgentshield(t, home, []string{"agentshield", "hook"}, stdinPipe, payload)
	rec := lastHookRecord(t, home)
	return ppVerdict{inv.code, rec["decision"], rec["triggered_rules"], rec["taxonomy"], inv.stderr}
}

func (v ppVerdict) hasRule(id string) bool {
	list, _ := v.rules.([]interface{})
	for _, r := range list {
		if r == id {
			return true
		}
	}
	return false
}

func (v ppVerdict) taxonomyIs(want ...string) bool {
	list, _ := v.taxonomy.([]interface{})
	if len(list) != len(want) {
		return false
	}
	for i := range want {
		if list[i] != want[i] {
			return false
		}
	}
	return true
}

func TestHook_CustomerProtectedPath_FileToolsAndShellBlockWithTaxonomy_4645(t *testing.T) {
	f := ppSecret()
	rows := []struct {
		name  string
		tool  string
		input map[string]interface{}
	}{
		{"Read", "Read", map[string]interface{}{"file_path": f}},
		{"Write", "Write", map[string]interface{}{"file_path": f, "content": "x"}},
		{"Edit", "Edit", map[string]interface{}{"file_path": f, "old_string": "a", "new_string": "b"}},
		{"MultiEdit", "MultiEdit", map[string]interface{}{"file_path": f, "edits": []interface{}{map[string]interface{}{"old_string": "a", "new_string": "b"}}}},
		{"NotebookEdit", "NotebookEdit", map[string]interface{}{"notebook_path": "/etc/acme/" + "secrets/n.ipynb", "new_source": "x"}},
		{"Grep on the directory", "Grep", map[string]interface{}{"pattern": "password", "path": "/etc/acme/" + "secrets"}},
		{"MCP server read_file", "mcp__fs__read_file", map[string]interface{}{"path": f}},
		{"shell cat", "Bash", map[string]interface{}{"command": ppCat(f)}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			payload := ppPayload(row.tool, row.input)
			got := ppRun(t, ppHome(t, true, false), payload)
			if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(policy.ProtectedPathRuleID) {
				t.Fatalf("with the pack: exit %d, %v %v; want exit 2, BLOCK by protected-path (stderr %q)", got.code, got.decision, got.rules, got.stderr)
			}
			if !got.taxonomyIs(policy.ProtectedPathNode) {
				t.Errorf("taxonomy %v, want [%s]", got.taxonomy, policy.ProtectedPathNode)
			}
			// Control: the pack is what blocks. Without it no protected-path
			// rule fires (main's behaviour for every row).
			base := ppRun(t, ppHome(t, false, false), payload)
			if base.hasRule(policy.ProtectedPathRuleID) {
				t.Errorf("without the pack: %v %v; the protected-path rule fired anyway", base.decision, base.rules)
			}
			if row.tool == "Read" && (base.code != 0 || base.decision != "AUDIT") {
				t.Errorf("without the pack, Read: exit %d %v; want the issue's AUDIT, exit 0", base.code, base.decision)
			}
		})
	}
}

// Copilot CLI's own file tools reach the same check: native view and edit
// (toolName/toolArgs) and the Claude-compatible Read with `path`.
func TestHook_CustomerProtectedPath_CopilotFileTools_4645(t *testing.T) {
	for _, c := range []struct {
		name, payload string
	}{
		{"native view", copilotNativePayload(t, "pp-v", "view", map[string]interface{}{"path": ppSecret()})},
		{"native edit", copilotNativePayload(t, "pp-e", "edit", map[string]interface{}{"path": ppSecret(), "old_str": "a", "new_str": "b"})},
		{"compat Read", copilotCompatPayload(t, "pp-r", "Read", map[string]interface{}{"path": ppSecret()})},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runHookChild(t, ppHome(t, true, false), c.payload, "AGENTSHIELD_AGENT_ID=copilot-cli")
			requireCopilotDeny(t, c.name, code, stdout, stderr, "Rule: "+policy.ProtectedPathRuleID)
			if code, _, stderr := runHookChild(t, ppHome(t, false, false), c.payload, "AGENTSHIELD_AGENT_ID=copilot-cli"); code == 2 || strings.Contains(stderr, policy.ProtectedPathRuleID) {
				t.Errorf("without the pack: exit %d, stderr %q; want no protected-path BLOCK", code, stderr)
			}
		})
	}
}

// A sibling sharing the prefix is not under the protected directory.
func TestHook_CustomerProtectedPath_NearMissNotBlocked_4645(t *testing.T) {
	home := ppHome(t, true, false)
	for _, payload := range []string{
		ppPayload("Read", map[string]interface{}{"file_path": ppNearMiss()}),
		ppPayload("Write", map[string]interface{}{"file_path": ppNearMiss(), "content": "how to rotate the secrets"}),
		ppPayload("Bash", map[string]interface{}{"command": ppCat(ppNearMiss())}),
		// A file that mentions the path is not the path.
		ppPayload("Write", map[string]interface{}{"file_path": "/tmp/notes.md", "content": "rotate " + ppSecret()}),
	} {
		got := ppRun(t, home, payload)
		if got.code != 0 || got.decision == "BLOCK" || got.hasRule(policy.ProtectedPathRuleID) {
			t.Errorf("%s: exit %d %v %v; want no BLOCK", payload, got.code, got.decision, got.rules)
		}
	}
}

// Adding the customer pack changes nothing for the built-in sensitive paths:
// the same payloads decide byte for byte as without it, on the tool path and
// on the shell.
func TestHook_CustomerProtectedPath_BuiltInPathsUnchanged_4645(t *testing.T) {
	with, without := ppHome(t, true, false), ppHome(t, false, false)
	rel := func(home, p string) string { return filepath.Join(home, p) }
	for _, c := range []struct {
		name  string
		build func(home string) string
	}{
		{"Read aws credentials", func(h string) string {
			return ppPayload("Read", map[string]interface{}{"file_path": rel(h, ".aws/"+"credentials")})
		}},
		{"Read ssh key", func(h string) string {
			return ppPayload("Read", map[string]interface{}{"file_path": rel(h, ".ssh/"+"id_rsa")})
		}},
		{"Read npmrc", func(h string) string {
			return ppPayload("Read", map[string]interface{}{"file_path": rel(h, ".np"+"mrc")})
		}},
		{"Write kube config", func(h string) string {
			return ppPayload("Write", map[string]interface{}{"file_path": rel(h, ".kube/"+"config"), "content": "x"})
		}},
		{"shell cat aws credentials", func(h string) string {
			return ppPayload("Bash", map[string]interface{}{"command": ppCat(rel(h, ".aws/"+"credentials"))})
		}},
		{"Read /etc/hosts", func(string) string {
			return ppPayload("Read", map[string]interface{}{"file_path": "/etc/" + "hosts"})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := ppRun(t, with, c.build(with))
			b := ppRun(t, without, c.build(without))
			a.stderr, b.stderr = "", ""
			if !reflect.DeepEqual(a, b) {
				t.Errorf("with the pack %+v\n  without it %+v", a, b)
			}
			// The shipped patterns are in both homes' shell policy; on the
			// tool path they keep main's MCP-rule decisions and never reach
			// the protected-path check.
			if !strings.HasPrefix(c.name, "shell") && a.hasRule(policy.ProtectedPathRuleID) {
				t.Errorf("tool call decided by protected-path on a shipped pattern: %v %v", a.decision, a.rules)
			}
		})
	}
}

// AgentShield's own config directory on a managed host keeps main's behaviour
// and taxonomy: its node is Gary's open call (#4431 item 2). The harness write
// guard still decides a Write (enterprise-self-protect, security-tool-tampering),
// a Read is unchanged, and a shell write decided by the managed protected path
// still records no taxonomy.
func TestHook_CustomerProtectedPath_ManagedConfigDirUnchanged_4645(t *testing.T) {
	with, without := ppHome(t, true, true), ppHome(t, false, true)
	cfg := func(h string) string { return filepath.Join(h, "."+"agent"+"shield", "policy.yaml") }
	for _, c := range []struct {
		name  string
		build func(home string) string
		check func(t *testing.T, v ppVerdict)
	}{
		{"Write the policy", func(h string) string {
			return ppPayload("Write", map[string]interface{}{"file_path": cfg(h), "content": "rules: []"})
		}, func(t *testing.T, v ppVerdict) {
			if v.code != 2 || !v.hasRule("enterprise-self-protect") || !v.taxonomyIs("persistence-evasion/defense-evasion/security-tool-tampering") {
				t.Errorf("exit %d %v %v; want exit 2, enterprise-self-protect, security-tool-tampering", v.code, v.rules, v.taxonomy)
			}
		}},
		{"Read the policy", func(h string) string {
			return ppPayload("Read", map[string]interface{}{"file_path": cfg(h)})
		}, func(t *testing.T, v ppVerdict) {
			if v.hasRule(policy.ProtectedPathRuleID) {
				t.Errorf("Read decided by protected-path: %v", v.rules)
			}
		}},
		{"shell write through a variable", func(h string) string {
			return ppPayload("Bash", map[string]interface{}{"command": "D=$HOME/." + "agent" + "shield; c" + "p /tmp/s.json $D/watchdog-state.json"})
		}, func(t *testing.T, v ppVerdict) {
			// Decided by the managed protected path alone, so the record is
			// exactly main's: that rule, and no taxonomy.
			if v.code != 2 || v.decision != "BLOCK" || !v.hasRule("protected-path-via-substitution") || v.taxonomy != nil {
				t.Errorf("exit %d %v %v taxonomy %v; want exit 2, BLOCK by protected-path-via-substitution, no taxonomy", v.code, v.decision, v.rules, v.taxonomy)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := ppRun(t, with, c.build(with))
			b := ppRun(t, without, c.build(without))
			c.check(t, a)
			a.stderr, b.stderr = "", ""
			if !reflect.DeepEqual(a, b) {
				t.Errorf("with the pack %+v\n  without it %+v", a, b)
			}
		})
	}
}

// A customer pack the tool path cannot read is said out loud, and the call is
// still evaluated (fail-safe) where fail_closed is off.
func TestHook_CustomerProtectedPath_BrokenPackIsReported_4645(t *testing.T) {
	home := ppHome(t, false, false)
	if err := os.MkdirAll(filepath.Join(home, ".agentshield", "packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".agentshield", "packs", "broken.yaml"), []byte("defaults:\n  protected_paths: [/a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ppRun(t, home, ppPayload("Read", map[string]interface{}{"file_path": "/tmp/readme.md"}))
	if got.code != 0 || !strings.Contains(got.stderr, "broken.yaml") {
		t.Errorf("exit %d, stderr %q; want exit 0 and a warning naming broken.yaml", got.code, got.stderr)
	}
}

// ppToolsCall is an MCP tools/call reading the customer's protected file.
func ppToolsCall() string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, ppSecret())
}

// The stdio MCP proxy applies the same customer paths, read at startup.
func TestMCPProxy_CustomerProtectedPath_4645(t *testing.T) {
	home := ppHome(t, true, false)
	resp := runStdioProxy(t, home, ppToolsCall())
	if strings.Contains(resp, `"served"`) || !strings.Contains(resp, `"error"`) {
		t.Fatalf("with the pack: the read reached the server: %s", resp)
	}
	ev := lastProxyAudit(t, home, "read_file")
	rules, _ := ev["triggered_rules"].([]interface{})
	if ev["decision"] != "BLOCK" || len(rules) == 0 || rules[0] != policy.ProtectedPathRuleID {
		t.Errorf("record %v rules %v; want BLOCK by protected-path", ev["decision"], ev["triggered_rules"])
	}
	// The proxies' audit line carries one taxonomy_ref, filled from scanner
	// findings only: no YAML rule's taxonomy reaches it (pre-existing, the
	// shipped read_file BLOCKs record none either). The evaluator's verdict
	// carries the node (TestProtectedPathArgument_BlocksFileTools4645); if the
	// line ever carries a ref, it must be that node.
	if ref, ok := ev["taxonomy_ref"]; ok && ref != policy.ProtectedPathNode {
		t.Errorf("taxonomy_ref %v, want %s", ref, policy.ProtectedPathNode)
	}
	// Control: without the pack the same call is served, as on main.
	if resp := runStdioProxy(t, ppHome(t, false, false), ppToolsCall()); !strings.Contains(resp, `"served"`) {
		t.Errorf("without the pack: not served: %s", resp)
	}
}

// runHTTPProxyOnce posts one request through `agentshield mcp-http-proxy` and
// reports whether it reached the upstream.
func runHTTPProxyOnce(t *testing.T, home, request string) (string, bool) {
	t.Helper()
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"tools/call"`) {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"served"}]}}`))
	}))
	defer upstream.Close()
	port := freePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := proxyHelperCmd(ctx, home, "mcp-http-proxy", "--upstream", upstream.URL, "--port", fmt.Sprint(port))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		resp, err = http.Post(url, "application/json", strings.NewReader(request))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("mcp-http-proxy never answered: %v\nstderr:\n%s", err, stderr.String())
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return string(out), hits.Load() > 0
}

// The HTTP MCP proxy applies the same customer paths.
func TestMCPHTTPProxy_CustomerProtectedPath_4645(t *testing.T) {
	if out, reached := runHTTPProxyOnce(t, ppHome(t, true, false), ppToolsCall()); reached {
		t.Errorf("with the pack: the read reached the upstream: %s", out)
	}
	if out, reached := runHTTPProxyOnce(t, ppHome(t, false, false), ppToolsCall()); !reached {
		t.Errorf("without the pack: the read did not reach the upstream: %s", out)
	}
}

// mcp-eval predicts the hook's tool path, so it applies the same paths.
func TestMCPEval_CustomerProtectedPath_4645(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"file_path": ppSecret()})
	argv := []string{"agentshield", "mcp-eval", "--tool", "Read", "--json", string(args), "--format", "json"}
	got := invokeAgentshield(t, ppHome(t, true, false), argv, stdinDevNull, "")
	var r mcp.MCPEvalResult
	if err := json.Unmarshal([]byte(got.stdout), &r); err != nil {
		t.Fatalf("mcp-eval output: %v\n%s\nstderr: %s", err, got.stdout, got.stderr)
	}
	if got.code != 2 || r.Decision != policy.DecisionBlock || !reflect.DeepEqual(r.AllTaxonomyRefs(), []string{policy.ProtectedPathNode}) {
		t.Errorf("with the pack: exit %d %s %v %v; want exit 2, BLOCK, [%s]", got.code, r.Decision, r.TriggeredRules, r.AllTaxonomyRefs(), policy.ProtectedPathNode)
	}
	if base := invokeAgentshield(t, ppHome(t, false, false), argv, stdinDevNull, ""); base.code != 0 {
		t.Errorf("without the pack: exit %d, want 0\n%s", base.code, base.stdout)
	}
}
