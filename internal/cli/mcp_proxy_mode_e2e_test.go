package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// End-to-end tests for #4337 on the real `agentshield mcp-proxy` and
// `agentshield mcp-http-proxy` commands: the mode comes from the files a
// machine holds, through config.Load, exactly as in production. They use only
// symbols that exist on origin/main, so they also run there, where the
// audit-only rows fail (the proxies ignored the mode) and the enforce and
// self-protection rows pass.

// sshKeyRead is blocked by the embedded community MCP packs.
const sshKeyRead = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/.ssh/id_rsa"}}}`

// TestHelperFakeMCPServer is a stdio MCP server for the proxy tests: it
// answers every request with a text result reading "served". With
// AGENTSHIELD_FAKE_MCP_WRITE=1 it also carries out a write_file whose path is
// absolute, as a real filesystem server would, so a test can show what a
// forwarded write does to the machine.
func TestHelperFakeMCPServer(t *testing.T) {
	if os.Getenv("AGENTSHIELD_FAKE_MCP_SERVER") != "1" {
		return
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 10<<20)
	for sc.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					Path    string `json:"path"`
					Content string `json:"content"`
				} `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		if os.Getenv("AGENTSHIELD_FAKE_MCP_WRITE") == "1" && req.Params.Name == "write_file" && filepath.IsAbs(req.Params.Arguments.Path) {
			_ = os.WriteFile(req.Params.Arguments.Path, []byte(req.Params.Arguments.Content), 0o600)
		}
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"served"}]}}`+"\n", req.ID)
	}
	os.Exit(0)
}

// TestHelperProxyProcess runs `agentshield <AGENTSHIELD_PROXY_ARGS>`.
func TestHelperProxyProcess(t *testing.T) {
	if os.Getenv("AGENTSHIELD_PROXY_HELPER") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("AGENTSHIELD_PROXY_ARGS")), &args); err != nil {
		os.Exit(3)
	}
	rootCmd.SetArgs(args)
	if err := rootCmd.Execute(); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

func proxyHelperCmd(ctx context.Context, home string, args ...string) *exec.Cmd {
	enc, _ := json.Marshal(args)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProxyProcess$")
	cmd.Env = append(os.Environ(), "AGENTSHIELD_PROXY_HELPER=1", "AGENTSHIELD_PROXY_ARGS="+string(enc), "HOME="+home)
	return cmd
}

// proxyHome is a HOME holding agentshield.yaml with the given content ("" for none).
func proxyHome(t *testing.T, agentshieldYAML string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if agentshieldYAML != "" {
		if err := os.WriteFile(filepath.Join(dir, "agentshield.yaml"), []byte(agentshieldYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// runStdioProxy sends one request line through `agentshield mcp-proxy` to the
// fake server and returns the response line the client received.
func runStdioProxy(t *testing.T, home, request string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := proxyHelperCmd(ctx, home, "mcp-proxy", "--", os.Args[0], "-test.run=^TestHelperFakeMCPServer$")
	cmd.Env = append(cmd.Env, "AGENTSHIELD_FAKE_MCP_SERVER=1")
	cmd.Stdin = strings.NewReader(request + "\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("mcp-proxy: %v\nstderr:\n%s", err, stderr.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.Contains(line, `"jsonrpc"`) {
			return line
		}
	}
	t.Fatalf("no JSON-RPC response from mcp-proxy; stdout:\n%s\nstderr:\n%s", out, stderr.String())
	return ""
}

func lastProxyAudit(t *testing.T, home, tool string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".agentshield", "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var ev map[string]interface{}
		if json.Unmarshal([]byte(lines[i]), &ev) == nil && ev["tool_name"] == tool {
			return ev
		}
	}
	t.Fatalf("no audit record for %s:\n%s", tool, data)
	return nil
}

func TestMCPProxy_ModeFromConfig_EndToEnd(t *testing.T) {
	cases := []struct {
		name          string
		yaml          string
		wantForwarded bool
	}{
		{"no config: enforce", "", false},
		{"mode: enforce", "mode: enforce\n", false},
		{"mode: audit-only", "mode: audit-only\n", true},
		{"new-install default", "default_mode: audit-only\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := proxyHome(t, tc.yaml)
			resp := runStdioProxy(t, home, sshKeyRead)
			forwarded := strings.Contains(resp, `"served"`)
			if forwarded != tc.wantForwarded {
				t.Fatalf("forwarded = %v; want %v. response: %s", forwarded, tc.wantForwarded, resp)
			}
			ev := lastProxyAudit(t, home, "read_file")
			if tc.wantForwarded {
				if ev["decision"] != "AUDIT" || ev["original_decision"] != "BLOCK" || ev["mode"] != "audit-only" {
					t.Errorf("record = decision %v, original_decision %v, mode %v; want AUDIT, BLOCK, audit-only", ev["decision"], ev["original_decision"], ev["mode"])
				}
			} else if ev["decision"] != "BLOCK" || ev["original_decision"] != nil {
				t.Errorf("record = decision %v, original_decision %v; want BLOCK and none", ev["decision"], ev["original_decision"])
			}
		})
	}
}

// Self-protection holds in audit-only: a tool call writing AgentShield's own
// policy is blocked whatever the mode. Passes on main too.
func TestMCPProxy_AuditOnlyStillBlocksConfigWrites_EndToEnd(t *testing.T) {
	for _, yaml := range []string{"mode: audit-only\n", "default_mode: audit-only\n", ""} {
		home := proxyHome(t, yaml)
		target := filepath.Join(home, ".agentshield", "policy.yaml")
		req := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":%q,"content":"rules: []"}}}`, target)
		resp := runStdioProxy(t, home, req)
		if strings.Contains(resp, `"served"`) || !strings.Contains(resp, `"error"`) {
			t.Errorf("agentshield.yaml %q: a write to %s reached the server: %s", yaml, target, resp)
		}
	}
}

// freePort returns a loopback port nothing is listening on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestMCPHTTPProxy_ModeFromConfig_EndToEnd(t *testing.T) {
	cases := []struct {
		name         string
		yaml         string
		wantUpstream bool
	}{
		{"no config: enforce", "", false},
		{"mode: audit-only", "mode: audit-only\n", true},
		{"new-install default", "default_mode: audit-only\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), `"tools/call"`) {
					hits.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"served"}]}}`))
			}))
			defer upstream.Close()

			home := proxyHome(t, tc.yaml)
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
				resp, err = http.Post(url, "application/json", strings.NewReader(sshKeyRead))
				if err == nil {
					break
				}
			}
			if err != nil {
				t.Fatalf("mcp-http-proxy never answered: %v\nstderr:\n%s", err, stderr.String())
			}
			out, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if got := hits.Load() > 0; got != tc.wantUpstream {
				t.Fatalf("upstream reached = %v; want %v. response: %s", got, tc.wantUpstream, out)
			}
		})
	}
}
