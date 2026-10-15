package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #4337 review B1: on an audit-only host both MCP proxies forwarded writes to
// AgentShield's own configuration when the path was spelled any way but the
// one the config guard's text match accepted. Main blocked every row below
// (premium self-protection rules, blocked_tools). Each spelling runs, in
// audit-only mode, on a managed fail_closed host, a plain managed host and an
// unmanaged host (local mode and new-install default), through the real
// `mcp-proxy` and `mcp-http-proxy` commands. Controls on every host prove the
// host is in audit-only (a benign execute_command is forwarded) and that the
// guard did not grow into paths that merely mention the word.
//
// Uses only symbols that exist before the fix, so it ran against the head the
// review saw; every self-protection row failed there.

const orgAuditOnlyPolicy = `version: "0.1"
enforcement_mode: "audit-only"
defaults:
  decision: "AUDIT"
rules: []
`

type spHost struct {
	name    string
	managed bool
	files   map[string]string // under ~/.agentshield
}

func spHosts() []spHost {
	return []spHost{
		{"managed fail_closed, org audit-only", true, map[string]string{"managed.json": `{"managed": true, "fail_closed": true}`, "policy.yaml": orgAuditOnlyPolicy}},
		{"plain managed, org audit-only", true, map[string]string{"managed.json": `{"managed": true}`, "policy.yaml": orgAuditOnlyPolicy}},
		{"unmanaged, mode: audit-only", false, map[string]string{"agentshield.yaml": "mode: audit-only\n"}},
		{"unmanaged, new-install default", false, map[string]string{"agentshield.yaml": "default_mode: audit-only\n"}},
	}
}

type spCall struct {
	id      string
	label   string
	tool    string
	args    map[string]interface{}
	blocked bool // want: blocked (self-protection) or forwarded (control)
	// managedOnly: blocked on a managed host only, by the shell's
	// self-protection rules over command text, as the shell hook does.
	managedOnly bool
	// sameAs, when set, is the file this row's path names on SOME volumes
	// (a Unicode case variant on APFS, the macOS /private alias). The row
	// must block wherever its path is that file on this machine; where it
	// is another file, no outcome is required here (the guard's unit tests
	// pin that it is not blocked by the guard).
	sameAs string
}

func spCalls(home string) []spCall {
	unenroll := `{"managed": false}`
	return []spCall{
		{"sp-upper", "upper-case directory", "write_file", map[string]interface{}{"path": home + "/.AGENTSHIELD/managed.json", "content": unenroll}, false, false, filepath.Join(home, ".agentshield/managed.json")},
		{"sp-firmlink", "/System/Volumes/Data firmlink", "write_file", map[string]interface{}{"path": "/System/Volumes/Data" + home + "/.agentshield/managed.json", "content": unenroll}, false, false, filepath.Join(home, ".agentshield/managed.json")},
		{"sp-relative", "relative path", "write_file", map[string]interface{}{"path": ".agentshield/policy.yaml", "content": "rules: []"}, true, false, ""},
		{"sp-delete", "relative delete", "delete_file", map[string]interface{}{"path": ".agentshield/managed.json"}, true, false, ""},
		{"sp-dollar-home", "literal $HOME", "write_file", map[string]interface{}{"path": "$HOME/.agentshield/managed.json", "content": unenroll}, true, false, ""},
		{"sp-brace-home", "literal ${HOME}", "write_file", map[string]interface{}{"path": "${HOME}/.agentshield/policy.yaml", "content": "rules: []"}, true, false, ""},
		{"sp-file-uri", "file:// URI", "write_file", map[string]interface{}{"path": "file://" + home + "/.agentshield/managed.json", "content": unenroll}, true, false, ""},
		{"sp-command", "command text", "execute_command", map[string]interface{}{"command": "rm -rf ~/" + ".agentshield"}, true, false, ""},
		{"sp-hook-upper", "upper-case hook file", "write_file", map[string]interface{}{"path": home + "/.CLAUDE/settings.json", "content": "{}"}, false, false, filepath.Join(home, ".claude/settings.json")},

		// Review pass 2: hook-file spellings that name the same file on APFS
		// or relative to a HOME cwd. Main blocks each through the community
		// rules mcp-sec-block-gemini-credentials-read (**/.gemini/**) and
		// mcp-sec-block-codex-cli-credentials-read (**/.codex/**).
		{"sp2-gemini-longs", "Gemini hook file, APFS long-s case fold", "write_file", map[string]interface{}{"path": home + "/.gemini/ſettings.json", "content": "{}"}, false, false, filepath.Join(home, ".gemini/settings.json")},
		{"sp2-codex-longs", "Codex hook file, APFS long-s case fold", "write_file", map[string]interface{}{"path": home + "/.codex/hookſ.json", "content": "{}"}, false, false, filepath.Join(home, ".codex/hooks.json")},
		{"sp2-codex-kelvin", "Codex hook file, APFS Kelvin-sign case fold", "write_file", map[string]interface{}{"path": home + "/.codex/hooKs.json", "content": "{}"}, false, false, filepath.Join(home, ".codex/hooks.json")},
		{"sp2-gemini-rel", "Gemini hook file, relative", "write_file", map[string]interface{}{"path": ".gemini/settings.json", "content": "{}"}, true, false, ""},
		{"sp2-codex-rel", "Codex hook file, relative", "write_file", map[string]interface{}{"path": ".codex/hooks.json", "content": "{}"}, true, false, ""},
		{"sp2-gemini-alias", "Gemini hook file, /tmp-/private symlink alias of HOME", "write_file", map[string]interface{}{"path": aliasOf(home) + "/.gemini/settings.json", "content": "{}"}, false, false, filepath.Join(home, ".gemini/settings.json")},
		// Not a regression (main forwards it too), kept as a gap row for the
		// "case" claim: the config dir itself under the APFS long-s fold.
		{"sp2-cfg-longs", "config dir, APFS long-s case fold", "write_file", map[string]interface{}{"path": home + "/.agentſhield/managed.json", "content": unenroll}, false, false, filepath.Join(home, ".agentshield/managed.json")},

		{"ok-exec", "control: benign execute_command", "execute_command", map[string]interface{}{"command": "ls -la"}, false, false, ""},
		{"ok-notes", "control: agentshield-notes directory", "write_file", map[string]interface{}{"path": home + "/projects/agentshield-notes/readme.md", "content": "notes"}, false, false, ""},
		{"ok-dotnotes", "control: .agentshield-notes directory", "write_file", map[string]interface{}{"path": home + "/projects/.agentshield-notes/readme.md", "content": "notes"}, false, false, ""},
		{"ok-prose", "control: prose naming the path", "write_file", map[string]interface{}{"path": home + "/projects/docs/setup.md", "content": "Edit ~/.agentshield/policy.yaml to tune the rules."}, false, false, ""},

		{"mo-disable", "managed only: setup --disable in command text", "execute_command", map[string]interface{}{"command": "agentshield setup cursor " + "--disable"}, false, true, ""},
		{"mo-binary", "managed only: binary replacement in command text", "execute_command", map[string]interface{}{"command": "cp /tmp/x /opt/homebrew/bin/agent" + "shield"}, false, true, ""},
	}
}

// aliasOf names home through the macOS /private symlinks (/tmp and /var are
// symlinks to /private/tmp and /private/var): the same directory, spelled
// differently (review pass 2).
func aliasOf(home string) string {
	if strings.HasPrefix(home, "/private/") {
		return strings.TrimPrefix(home, "/private")
	}
	return "/private" + home
}

func (c spCall) request() string {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": c.id, "method": "tools/call",
		"params": map[string]interface{}{"name": c.tool, "arguments": c.args},
	})
	return string(b)
}

func newSPHome(t *testing.T, h spHost) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".agentshield")
	for _, d := range []string{dir, filepath.Join(home, "projects", "agentshield-notes"), filepath.Join(home, "projects", ".agentshield-notes"), filepath.Join(home, "projects", "docs"), filepath.Join(home, ".claude"), filepath.Join(home, ".gemini"), filepath.Join(home, ".codex")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Review pass 2: hook files a forwarded write would overwrite.
	for _, f := range []string{filepath.Join(home, ".gemini", "settings.json"), filepath.Join(home, ".codex", "hooks.json")} {
		if err := os.WriteFile(f, []byte(`{"hooks":"agentshield hook"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range h.files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// responsesByID decodes JSON-RPC response lines and keys them by string id.
func responsesByID(lines []string) map[string]string {
	out := map[string]string{}
	for _, line := range lines {
		var r struct {
			ID string `json:"id"`
		}
		if json.Unmarshal([]byte(line), &r) == nil && r.ID != "" {
			out[r.ID] = line
		}
	}
	return out
}

// sameFileE2E reports whether a and b name the same file on this machine:
// both exist and are the same file, or neither exists and they are the same
// name in the same directory.
func sameFileE2E(a, b string) bool {
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	if err1 == nil && err2 == nil {
		return os.SameFile(fa, fb)
	}
	if err1 == nil || err2 == nil || filepath.Base(a) != filepath.Base(b) {
		return false
	}
	da, err1 := os.Stat(filepath.Dir(a))
	db, err2 := os.Stat(filepath.Dir(b))
	return err1 == nil && err2 == nil && os.SameFile(da, db)
}

func checkSPResponses(t *testing.T, proxy string, managed bool, calls []spCall, got map[string]string) {
	t.Helper()
	for _, c := range calls {
		resp, ok := got[c.id]
		if !ok {
			t.Errorf("%s %s: no response", proxy, c.label)
			continue
		}
		forwarded := strings.Contains(resp, `"served"`)
		block := c.blocked || (c.managedOnly && managed)
		if c.sameAs != "" {
			p, _ := c.args["path"].(string)
			if !sameFileE2E(p, c.sameAs) {
				t.Logf("%s %s: not the same file as %s on this volume; no outcome required", proxy, c.label, c.sameAs)
				continue
			}
			block = true
		}
		if block && forwarded {
			t.Errorf("%s %s: FORWARDED to the server; self-protection must block in audit-only", proxy, c.label)
		}
		if !block && !forwarded {
			t.Errorf("%s %s: blocked; want forwarded (%s)", proxy, c.label, resp)
		}
	}
}

func TestMCPProxy_AuditOnlySelfProtectionSpellings_EndToEnd(t *testing.T) {
	for _, h := range spHosts() {
		t.Run(h.name, func(t *testing.T) {
			home := newSPHome(t, h)
			managedBefore, _ := os.ReadFile(filepath.Join(home, ".agentshield", "managed.json"))
			calls := spCalls(home)
			var reqs []string
			for _, c := range calls {
				reqs = append(reqs, c.request())
			}

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := proxyHelperCmd(ctx, home, "mcp-proxy", "--", os.Args[0], "-test.run=^TestHelperFakeMCPServer$")
			cmd.Env = append(cmd.Env, "AGENTSHIELD_FAKE_MCP_SERVER=1", "AGENTSHIELD_FAKE_MCP_WRITE=1")
			cmd.Dir = home // a stdio server inherits the proxy's working directory; the fake server writes absolute paths only
			cmd.Stdin = strings.NewReader(strings.Join(reqs, "\n") + "\n")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("mcp-proxy: %v\n%s", err, stderr.String())
			}
			checkSPResponses(t, "mcp-proxy", h.managed, calls, responsesByID(strings.Split(strings.TrimSpace(string(out)), "\n")))

			if managedBefore != nil {
				after, _ := os.ReadFile(filepath.Join(home, ".agentshield", "managed.json"))
				if !bytes.Equal(after, managedBefore) {
					t.Errorf("managed.json changed through the proxy: %q -> %q", managedBefore, after)
				}
			}
			for _, f := range []string{filepath.Join(home, ".gemini", "settings.json"), filepath.Join(home, ".codex", "hooks.json")} {
				if after, _ := os.ReadFile(f); string(after) != `{"hooks":"agentshield hook"}` {
					t.Errorf("hook file %s changed through the proxy: now %q", f, after)
				}
			}
		})
	}
}

func TestMCPHTTPProxy_AuditOnlySelfProtectionSpellings_EndToEnd(t *testing.T) {
	for _, h := range spHosts() {
		t.Run(h.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					ID string `json:"id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%q,"result":{"content":[{"type":"text","text":"served"}]}}`, req.ID)
			}))
			defer upstream.Close()

			home := newSPHome(t, h)
			calls := spCalls(home)
			port := freePort(t)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := proxyHelperCmd(ctx, home, "mcp-http-proxy", "--upstream", upstream.URL, "--port", fmt.Sprint(port))
			cmd.Dir = home
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

			url := fmt.Sprintf("http://127.0.0.1:%d/", port)
			got := map[string]string{}
			for i, c := range calls {
				var resp *http.Response
				var err error
				deadline := time.Now().Add(30 * time.Second)
				for {
					resp, err = http.Post(url, "application/json", strings.NewReader(c.request()))
					if err == nil || i > 0 || time.Now().After(deadline) {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				if err != nil {
					t.Fatalf("mcp-http-proxy: %v\n%s", err, stderr.String())
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				got[c.id] = string(body)
			}
			checkSPResponses(t, "mcp-http-proxy", h.managed, calls, got)
		})
	}
}
