//go:build unix

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4478: six more reads on the hook's synchronous path were plain
// os.ReadFile (managed.json, agentshield.yaml, policy.yaml, a disk pack,
// mcp-policy.yaml, an MCP disk pack). A FIFO at any of them blocked open(2)
// with no writer, so the harness got no verdict (Codex and Gemini time a
// hook out at 10 s; Copilot fails open). They now read through
// safefile.ReadFile, and each site keeps the failure branch it already had
// for an unreadable file. The #4474 class, applied to the decision-feeding
// reads. This drives the real hook entry point, the contract a harness sees.

func fifoHookPayload(t *testing.T, tool string, input map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       tool,
		"session_id":      "fifo-4478",
		"tool_input":      input,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHook_FIFOAtConfigRead_GivesAVerdict(t *testing.T) {
	// Assembled at runtime: the hook reads test sources.
	shell := fifoHookPayload(t, "Bash", map[string]any{"command": destructiveCommand})
	mcpRead := fifoHookPayload(t, "Read", map[string]any{"file_path": os.Getenv("HOME") + "/.ss" + "h/id_rsa"})

	cases := []struct {
		name    string
		rel     string // FIFO path under ~/.agentshield; "" = none (control)
		payload *string
		want    int // exit code: 2 BLOCK; policy.yaml is failSafeDecision (AUDIT) when unmanaged, as for a corrupt file
		// noMode writes agentshield.yaml without a `mode:` key, so mode
		// resolution falls through to policy.yaml's enforcement_mode
		// (config.loadPolicyEnforcementMode). With `mode: enforce` that read
		// is never reached, and reverting it to os.ReadFile passed this test.
		noMode bool
	}{
		{"control shell", "", &shell, 2, false},
		{"managed.json", "managed.json", &shell, 2, false},
		{"agentshield.yaml", "agentshield.yaml", &shell, 2, false},
		{"policy.yaml", "policy.yaml", &shell, 0, false},
		{"policy.yaml, no mode: key", "policy.yaml", &shell, 0, true},
		{"disk pack", "packs/x.yaml", &shell, 2, false},
		{"control mcp", "", &mcpRead, 2, false},
		{"managed.json (mcp)", "managed.json", &mcpRead, 2, false},
		{"policy.yaml, no mode: key (mcp)", "policy.yaml", &mcpRead, 2, true},
		{"mcp-policy.yaml", "mcp-policy.yaml", &mcpRead, 2, false},
		{"mcp disk pack", "mcp-packs/x.yaml", &mcpRead, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.payload == &mcpRead {
				// The harness-Read BLOCK comes from a premium rule; the OSS
				// tree decides AUDIT, so want=2 cannot hold there.
				ossbuild.SkipPremiumSized(t)
			}
			home := t.TempDir()
			dir := filepath.Join(home, ".agentshield")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.rel != "agentshield.yaml" {
				cfg := "mode: enforce\n"
				if tc.noMode {
					cfg = "# no mode: key, so resolution reads policy.yaml (#4478)\n"
				}
				if err := os.WriteFile(filepath.Join(dir, "agentshield.yaml"), []byte(cfg), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.rel != "" {
				p := filepath.Join(dir, tc.rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					t.Skipf("mkfifo: %v", err)
				}
				releaseFIFOAtCleanup(t, p)
			}
			start := time.Now()
			code, stderr, timedOut := runHookWithDeadline(t, home, *tc.payload, 10*time.Second)
			if timedOut {
				t.Fatalf("hook gave no verdict in 10 s with a FIFO at %q", tc.rel)
			}
			t.Logf("exit %d in %v", code, time.Since(start).Round(time.Millisecond))
			if code != tc.want {
				t.Fatalf("exit code = %d, want %d. stderr:\n%s", code, tc.want, stderr)
			}
		})
	}
}
