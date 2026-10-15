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

// #4352: on a managed fail_closed host, a write to managed.json spelled with
// the long s (U+017F, which APFS folds to s) un-enrolled the host through both
// proxies, in every mode, on main. Same for the other spellings of the
// config directory the guard did not read: an NFD-spelled HOME (APFS treats
// NFC and NFD as one name), HOME reached through a symlink, and a file: URI
// with one slash. The config guard runs in every mode, so the fix is there;
// these rows run it in enforce and in audit-only, through both proxies.
//
// A row whose spelling names managed.json only on some volumes (long s, NFD)
// must block wherever it does on this machine; the symlink and file:/ rows
// name it everywhere.

var n4352 int

func new4352Home(t *testing.T, policyYAML string) (home, nfdHome, alias string) {
	t.Helper()
	// A short, low-entropy HOME: a long random temp path trips the
	// high-entropy content scanner, which would BLOCK every row in enforce
	// mode for a reason that has nothing to do with #4352.
	n4352++
	base := fmt.Sprintf("/tmp/as4352-%d-%d", os.Getpid(), n4352)
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	home = filepath.Join(base, "josé")     // NFC
	nfdHome = filepath.Join(base, "josé") // NFD
	dir := filepath.Join(home, ".agentshield")
	for _, d := range []string{dir, filepath.Join(home, "projects", "app")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"managed.json": `{"managed": true, "fail_closed": true}`}
	if policyYAML != "" {
		files["policy.yaml"] = policyYAML
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alias = filepath.Join(base+"-alias", "home")
	if err := os.MkdirAll(base+"-alias", 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base + "-alias") })
	if err := os.Symlink(home, alias); err != nil {
		t.Fatal(err)
	}
	return home, nfdHome, alias
}

type call4352 struct {
	id, label, path string
	always          bool // names managed.json on every volume
	control         bool // must be forwarded
}

func calls4352(home, nfdHome, alias string) []call4352 {
	cfg := "/.agent" + "shield/managed.json"
	return []call4352{
		{"x-longs", "long s in the directory name", home + "/.agentſhield/managed.json", false, false},
		{"x-nfd", "NFD-spelled HOME", nfdHome + cfg, false, false},
		{"x-alias", "HOME through a symlink", alias + cfg, true, false},
		{"x-file1", "file: URI with one slash", "file:" + home + cfg, true, false},
		// Relative: a long random temp path trips the high-entropy scanner.
		{"x-ok", "control: a project file", "projects/app/README.md", false, true},
	}
}

func (c call4352) request() string {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": c.id, "method": "tools/call",
		"params": map[string]interface{}{"name": "write_file", "arguments": map[string]interface{}{"path": c.path, "content": `{"managed": false}`}},
	})
	return string(b)
}

func check4352(t *testing.T, proxy, home string, calls []call4352, got map[string]string) {
	t.Helper()
	real := filepath.Join(home, ".agentshield", "managed.json")
	for _, c := range calls {
		resp, ok := got[c.id]
		if !ok {
			t.Errorf("%s %s: no response", proxy, c.label)
			continue
		}
		forwarded := strings.Contains(resp, `"served"`)
		switch {
		case c.control:
			if !forwarded {
				t.Errorf("%s %s: blocked; want forwarded (%s)", proxy, c.label, resp)
			}
		case c.always || sameFileE2E(c.path, real):
			if forwarded {
				t.Errorf("%s %s: FORWARDED a write to managed.json (#4352)", proxy, c.label)
			} else if strings.Contains(resp, "high_entropy") {
				t.Errorf("%s %s: blocked by the high-entropy scanner, which proves nothing about #4352: %s", proxy, c.label, resp)
			}
		default:
			t.Logf("%s %s: not managed.json on this volume; no outcome required", proxy, c.label)
		}
	}
}

var hosts4352 = []struct{ name, policy string }{
	{"managed fail_closed, enforce", ""},
	{"managed fail_closed, org audit-only", orgAuditOnlyPolicy},
}

func TestMCPProxy_ConfigGuard4352_EndToEnd(t *testing.T) {
	for _, h := range hosts4352 {
		t.Run(h.name, func(t *testing.T) {
			home, nfdHome, alias := new4352Home(t, h.policy)
			before, _ := os.ReadFile(filepath.Join(home, ".agentshield", "managed.json"))
			calls := calls4352(home, nfdHome, alias)
			var reqs []string
			for _, c := range calls {
				reqs = append(reqs, c.request())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cmd := proxyHelperCmd(ctx, home, "mcp-proxy", "--", os.Args[0], "-test.run=^TestHelperFakeMCPServer$")
			cmd.Env = append(cmd.Env, "AGENTSHIELD_FAKE_MCP_SERVER=1", "AGENTSHIELD_FAKE_MCP_WRITE=1")
			cmd.Dir = home
			cmd.Stdin = strings.NewReader(strings.Join(reqs, "\n") + "\n")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("mcp-proxy: %v\n%s", err, stderr.String())
			}
			check4352(t, "mcp-proxy", home, calls, responsesByID(strings.Split(strings.TrimSpace(string(out)), "\n")))
			if after, _ := os.ReadFile(filepath.Join(home, ".agentshield", "managed.json")); !bytes.Equal(after, before) {
				t.Errorf("managed.json changed through the proxy: %q -> %q (#4352)", before, after)
			}
		})
	}
}

func TestMCPHTTPProxy_ConfigGuard4352_EndToEnd(t *testing.T) {
	for _, h := range hosts4352 {
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

			home, nfdHome, alias := new4352Home(t, h.policy)
			calls := calls4352(home, nfdHome, alias)
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
			check4352(t, "mcp-http-proxy", home, calls, got)
		})
	}
}
