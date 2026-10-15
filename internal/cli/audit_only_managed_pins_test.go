package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// Pins for #4337: on a managed host, fail_closed and self-protection block in
// audit-only mode, and the new-install default does not apply. They pass on
// origin/main too; they exist so a later change that routes these paths
// through the mode downgrade fails here. Each HOME also runs a control, an
// ordinary BLOCK (rm -rf /), which proves the mode the row claims is the mode
// the hook resolved: a row whose mode silently fell back to enforce would
// pass the protection checks vacuously.

const policyOrgAuditOnly = `version: "0.1"
enforcement_mode: "audit-only"
defaults:
  decision: "AUDIT"
rules: []
`

const bashSelfProtectPayload = `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"pin-4337","tool_input":{"command":"rm -rf ~/.agentshield"}}`

func TestHook_AuditOnly_ManagedProtectionsStillBlock(t *testing.T) {
	modes := []struct {
		name       string
		policy     string // policy.yaml
		yaml       string // agentshield.yaml
		failClosed bool   // managed.json: fail_closed true, or {"managed": true} alone
	}{
		{"organisation push audit-only", policyOrgAuditOnly, "", true},
		{"local mode: audit-only", failSafePolicyGood, "mode: audit-only\n", true},
		{"plain managed, organisation push audit-only", policyOrgAuditOnly, "", false},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			newHome := func(t *testing.T) (string, string) {
				home, configDir := newFailSafeHome(t, true, m.policy)
				if !m.failClosed {
					if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(`{"managed": true}`), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if m.yaml != "" {
					if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte(m.yaml), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return home, configDir
			}

			t.Run("control: an ordinary BLOCK is downgraded", func(t *testing.T) {
				home, _ := newHome(t)
				if code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive); code != 0 {
					t.Fatalf("exit %d; want 0 — this HOME is not in audit-only, so the rows below prove nothing. stderr:\n%s", code, stderr)
				}
			})
			t.Run("fail_closed: corrupt MCP policy", func(t *testing.T) {
				if !m.failClosed {
					t.Skip("fail_closed is off on a plain managed host")
				}
				home, configDir := newHome(t)
				writeCorruptMCPPolicy(t, configDir)
				if code, stderr := runHookInChildProcess(t, home, mcpReadPayload); code != 2 {
					t.Fatalf("exit %d; want 2 — fail_closed must block in audit-only. stderr:\n%s", code, stderr)
				}
			})
			t.Run("self-protection: shell", func(t *testing.T) {
				home, _ := newHome(t)
				if code, stderr := runHookInChildProcess(t, home, bashSelfProtectPayload); code != 2 {
					t.Fatalf("exit %d; want 2 — managed self-protection must block in audit-only. stderr:\n%s", code, stderr)
				}
			})
			t.Run("self-protection: harness Write to the config", func(t *testing.T) {
				home, _ := newHome(t)
				payload := claudeToolPayload(t, "pin-w", "Write", map[string]interface{}{"file_path": asConfigFile(home, "policy.yaml"), "content": "rules: []\n"})
				if code, stderr := runHookInChildProcess(t, home, payload); code != 2 {
					t.Fatalf("exit %d; want 2 — managed tool-write protection must block in audit-only. stderr:\n%s", code, stderr)
				}
			})
		})
	}
}

// A machine set up first (new-install default) and enrolled second is
// governed by its organisation: with no organisation mode it enforces. Both a
// fail_closed host and a plain managed host ({"managed": true} alone), so a
// check on FailClosed instead of Managed fails here (#4337 review).
func TestHook_ManagedHostIgnoresNewInstallDefault(t *testing.T) {
	for _, managedJSON := range []string{`{"managed": true, "fail_closed": true}`, `{"managed": true}`} {
		t.Run(managedJSON, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			for name, body := range map[string]string{"managed.json": managedJSON, "agentshield.yaml": "default_mode: audit-only\n"} {
				if err := os.WriteFile(filepath.Join(configDir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive); code != 2 {
				t.Fatalf("exit %d; want 2 — a managed host must not take the new-install default. stderr:\n%s", code, stderr)
			}
		})
	}
}
