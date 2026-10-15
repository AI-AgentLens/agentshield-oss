package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/config"
)

// TestApplyNewInstallDefault_HomeStates is the table over HOME states for
// #4337: only a machine with no AgentShield state gets the audit-only
// default; every kind of prior state keeps the machine where it was. The
// end-to-end tests in setup_new_install_e2e_test.go run the real setup and
// hook for a subset of these rows.
func TestApplyNewInstallDefault_HomeStates(t *testing.T) {
	hook := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`
	wrapped := `{"mcpServers":{"fs":{"command":"/opt/homebrew/bin/agentshield","args":["mcp-proxy","--","npx","server"]}}}`
	cases := []struct {
		name    string
		files   map[string]string // path under HOME → content; a trailing "/" makes a directory
		wantNew bool
	}{
		{"nothing at all", nil, true},
		{"empty ~/.agentshield (any config.Load creates it)", map[string]string{".agentshield/": ""}, true},
		{"agent configs that do not mention agentshield", map[string]string{
			".claude/settings.json":        `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"lint-hook"}]}]}}`,
			".cursor/mcp.json":             `{"mcpServers":{"fs":{"command":"npx"}}}`,
			".gemini/settings.json":        `{}`,
			".codex/hooks.json":            `{}`,
			".cursor/hooks.json":           `{}`,
			".copilot/hooks/x.json":        `{}`,
			".openclaw/hooks/other/":       "",
			".codeium/windsurf/hooks.json": `{}`,
		}, true},

		{"agentshield.yaml", map[string]string{".agentshield/agentshield.yaml": "mode: enforce\n"}, false},
		{"agentshield.yaml without a mode", map[string]string{".agentshield/agentshield.yaml": "# nothing\n"}, false},
		{"audit.jsonl", map[string]string{".agentshield/audit.jsonl": ""}, false},
		{"policy.yaml", map[string]string{".agentshield/policy.yaml": "rules: []\n"}, false},
		{"managed.json", map[string]string{".agentshield/managed.json": `{"managed":true}`}, false},
		{"credentials.json (login before setup)", map[string]string{".agentshield/credentials.json": "{}"}, false},
		{"mcp-policy.yaml", map[string]string{".agentshield/mcp-policy.yaml": "defaults: {}\n"}, false},
		{"packs/ only, as the OSS brew formula's post_install leaves it", map[string]string{".agentshield/packs/terminal-safety.yaml": "rules: []\n", ".agentshield/packs/mcp/mcp-safety.yaml": "rules: []\n"}, true},
		{"empty packs/ directory", map[string]string{".agentshield/packs/": ""}, true},
		{"packs/ and an audit log", map[string]string{".agentshield/packs/a.yaml": "x", ".agentshield/audit.jsonl": ""}, false},
		{"packs/ and agentshield.yaml", map[string]string{".agentshield/packs/a.yaml": "x", ".agentshield/agentshield.yaml": "# x\n"}, false},
		{"packs/ and a Claude Code hook", map[string]string{".agentshield/packs/a.yaml": "x", ".claude/settings.json": hook}, false},
		{"packs as a file, not a directory", map[string]string{".agentshield/packs": "x"}, false},
		{"mcp-packs/ directory (setup mcp)", map[string]string{".agentshield/mcp-packs/": ""}, false},
		{"an unknown file", map[string]string{".agentshield/.DS_Store": "x"}, false},

		{"Claude Code hook", map[string]string{".claude/settings.json": hook}, false},
		{"Claude Code hook in settings.local.json", map[string]string{".claude/settings.local.json": hook}, false},
		{"Cursor hook", map[string]string{".cursor/hooks.json": `{"hooks":{"beforeShellExecution":[{"command":"agentshield hook"}]}}`}, false},
		{"Windsurf hook", map[string]string{".codeium/windsurf/hooks.json": `{"hooks":{"pre_run_command":[{"command":"agentshield hook"}]}}`}, false},
		{"Gemini CLI hook", map[string]string{".gemini/settings.json": `{"hooks":{"BeforeTool":[{"hooks":[{"command":"/usr/local/bin/agentshield hook"}]}]}}`}, false},
		{"Codex hook", map[string]string{".codex/hooks.json": `{"hooks":{"PreToolUse":[{"hooks":[{"command":"/usr/local/bin/agentshield hook"}]}]}}`}, false},
		{"Copilot CLI hook file", map[string]string{".copilot/hooks/agentshield.json": `{"version":1}`}, false},
		{"OpenClaw hook dir", map[string]string{".openclaw/hooks/agentshield/": ""}, false},
		{"Cursor MCP servers wrapped by setup mcp", map[string]string{".cursor/mcp.json": wrapped}, false},
		{"Claude Desktop MCP servers wrapped by setup mcp", map[string]string{"Library/Application Support/Claude/claude_desktop_config.json": wrapped}, false},
		{"a mention in any case", map[string]string{".claude/settings.json": `{"permissions":{"allow":["Bash(AgentShield scan)"]}}`}, false},
		{"~/.agentshield is a file, not a directory", map[string]string{".agentshield": "x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("COPILOT_HOME", "")
			writeHomeFiles(t, home, tc.files)
			before, _ := os.ReadFile(filepath.Join(home, ".agentshield", "agentshield.yaml"))

			written, evidence, err := applyNewInstallDefault(home)
			if err != nil && tc.wantNew {
				t.Fatal(err)
			}
			if written != tc.wantNew {
				t.Fatalf("written = %v (evidence %q); want %v", written, evidence, tc.wantNew)
			}
			if !tc.wantNew && evidence == "" {
				t.Errorf("an existing install must name its evidence")
			}

			cfg, err := config.Load("", "", "")
			if tc.name == "~/.agentshield is a file, not a directory" {
				// config.Load cannot run here; the point of the row is that
				// setup did not treat the machine as new.
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNew {
				if cfg.Mode != config.ModeAuditOnly || cfg.ModeSource != config.ModeSourceInstallDefault {
					t.Errorf("new install resolves to (%q, %q); want audit-only from the new-install default", cfg.Mode, cfg.ModeSource)
				}
				return
			}
			after, _ := os.ReadFile(filepath.Join(home, ".agentshield", "agentshield.yaml"))
			if string(after) != string(before) {
				t.Errorf("agentshield.yaml changed on an existing install:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if strings.Contains(string(after), "default_mode") {
				t.Errorf("an existing install got the new-install default:\n%s", after)
			}
		})
	}
}

// A ~/.agentshield that cannot be listed cannot prove the machine is new.
func TestApplyNewInstallDefault_UnreadableConfigDirIsExisting(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root POSIX user for permission bits to bite")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	written, evidence, _ := applyNewInstallDefault(home)
	if written || !strings.Contains(evidence, "unreadable") {
		t.Fatalf("written=%v evidence=%q; want not written, evidence naming the unreadable directory", written, evidence)
	}
}

// An agent config that cannot be read, or cannot even be stat'ed, cannot
// prove the machine is new.
func TestApplyNewInstallDefault_UnreadableAgentConfigIsExisting(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root POSIX user for permission bits to bite")
	}
	for _, tc := range []struct {
		name  string
		chmod string // path under HOME to make inaccessible
	}{
		{"file unreadable", ".claude/settings.json"},
		{"parent directory untraversable", ".claude"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("COPILOT_HOME", "")
			writeHomeFiles(t, home, map[string]string{".claude/settings.json": "{}"})
			p := filepath.Join(home, tc.chmod)
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, info.Mode().Perm()) })

			written, evidence, _ := applyNewInstallDefault(home)
			if written || !strings.Contains(evidence, "unreadable") {
				t.Fatalf("written=%v evidence=%q; want not written, evidence naming the unreadable path", written, evidence)
			}
		})
	}
}

// COPILOT_HOME moves the Copilot hook file; the check follows it.
func TestApplyNewInstallDefault_FollowsCopilotHome(t *testing.T) {
	home := t.TempDir()
	copilot := t.TempDir()
	t.Setenv("COPILOT_HOME", copilot)
	writeHomeFiles(t, copilot, map[string]string{"hooks/agentshield.json": `{"version":1}`})

	if written, evidence, _ := applyNewInstallDefault(home); written {
		t.Fatalf("a Copilot hook under COPILOT_HOME was missed (evidence %q)", evidence)
	}
}

// The mode line setup, status and scan print.
func TestModeSummary(t *testing.T) {
	cases := []struct {
		cfg  *config.Config
		want []string
	}{
		{&config.Config{Mode: config.ModeAuditOnly, ModeSource: config.ModeSourceInstallDefault}, []string{"audit-only", "new-install default", "`mode: enforce`"}},
		{&config.Config{Mode: config.ModeAuditOnly, ModeSource: config.ModeSourceConfigFile}, []string{"audit-only", "`mode: enforce`"}},
		{&config.Config{Mode: config.ModeAuditOnly, ModeSource: config.ModeSourcePolicyFile}, []string{"audit-only", "organisation"}},
		{&config.Config{Mode: config.ModeEnforce, ModeSource: config.ModeSourceBuiltIn}, []string{"enforce", "built-in default", "BLOCK rules block"}},
		{nil, []string{"unknown"}},
	}
	for _, tc := range cases {
		got := modeSummary(tc.cfg)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("modeSummary(%+v) = %q; want it to contain %q", tc.cfg, got, w)
			}
		}
	}
}

func writeHomeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
