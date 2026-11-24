package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// TestPowerShellLane_AuditOnlyKeepsSelfProtectionTwins (#4833, Opus pass 1
// finding 1): in audit-only mode, setup's default for a new install, a
// self-protection rule's BLOCK on Claude Code's PowerShell tool is kept, as
// its bash twin's is on the Bash tool. Before, the lane's keep accepted only
// protected-path hits; a pack rule's BLOCK has none, so each of these came
// out AUDIT[was BLOCK] and the keep's rule-id test was never asked.
//
// The control is a PowerShell BLOCK that is not self-protection
// (ps-block-remove-drive-root): it is still downgraded, so the keep accepts
// by rule, not every BLOCK.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).
func TestPowerShellLane_AuditOnlyKeepsSelfProtectionTwins(t *testing.T) {
	as := ".agent" + "shield"
	settings := ".claude/" + "settings.json"
	managed := `C:\Program Files\ClaudeCode\managed-` + "settings.json"
	rows := []struct {
		name, ps, rule, bash string
		premium              bool
	}{
		{"agent settings", `Set-Content ~\.claude\settings.json '{}'`, "ps-block-agent-settings-write", "echo '{}' > ~/" + settings, false},
		{"audit log", `Remove-Item ~\` + as + `\audit.jsonl`, "ps-block-agentshield-log-tamper", "r" + "m ~/" + as + "/audit.jsonl", false},
		{"config dir", `Remove-Item -Recurse -Force $HOME\` + as, "ps-block-agentshield-dir-delete", "r" + "m -rf ~/" + as, false},
		{"claude managed settings", `Set-Content -Path "` + managed + `" -Value '{}'`, "ps-block-claude-managed-settings-write", `echo x > "` + managed + `"`, true},
	}
	auditOnlyHome := func(t *testing.T, premium bool) (string, string) {
		t.Helper()
		home, configDir := newFailSafeHome(t, false, "")
		if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte("mode: audit-only\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if premium {
			installTreePremiumPacks(t, configDir)
		}
		return home, configDir
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if r.premium && !ossbuild.PremiumPacksPresent() {
				t.Skip("premium rule; the community-only tree has no premium packs")
			}
			home, configDir := auditOnlyHome(t, r.premium)
			code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(r.bash), nil))
			if code != 2 {
				t.Fatalf("control: the bash twin %q exits %d in audit-only mode, want 2 (kept). stderr:\n%s", r.bash, code, stderr)
			}
			if err := os.Remove(filepath.Join(configDir, "audit.jsonl")); err != nil {
				t.Fatal(err)
			}
			code, _, stderr = runHookChild(t, home, psCall(t, r.ps))
			if code != 2 {
				t.Fatalf("%q exits %d in audit-only mode, want 2: %s is a self-protection rule, so its BLOCK is kept. stderr:\n%s", r.ps, code, r.rule, stderr)
			}
			if e := oneEvent(t, configDir); e.Decision != "BLOCK" || !containsStr(e.TriggeredRules, r.rule) {
				t.Errorf("event decision=%q rules=%v, want BLOCK by %s", e.Decision, e.TriggeredRules, r.rule)
			}
		})
	}
	t.Run("control: not self-protection, downgraded", func(t *testing.T) {
		home, configDir := auditOnlyHome(t, false)
		code, _, stderr := runHookChild(t, home, psCall(t, `Remove-Item -Recurse -Force C:\`))
		if code != 0 {
			t.Fatalf("exit %d, want 0: ps-block-remove-drive-root is not self-protection, so audit-only mode downgrades it. stderr:\n%s", code, stderr)
		}
		if e := oneEvent(t, configDir); e.Decision != "AUDIT" || !containsStr(e.TriggeredRules, "ps-block-remove-drive-root") {
			t.Errorf("event decision=%q rules=%v, want AUDIT[was BLOCK] by ps-block-remove-drive-root", e.Decision, e.TriggeredRules)
		}
	})
}
