package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end tests for #4337: new installs start in audit-only, existing
// installs keep enforcing. Each one runs the real `agentshield setup` command
// tree in a child process (so the setup pre-run wiring is what a user hits),
// then sends `rm -rf /` through the real hook in another child process and
// asserts on the exit code, which is the only contract a harness sees.
//
// These use only symbols that exist on origin/main, so they also run there:
// the new-install tests fail on main (it writes nothing and enforces), the
// existing-install tests pass on main and here (they pin "no downgrade").

// TestHelperSetupProcess is the re-exec target: it runs the agentshield
// command tree with the space-separated arguments in AGENTSHIELD_SETUP_ARGS.
// It is a no-op unless invoked by runSetupInChildProcess.
func TestHelperSetupProcess(t *testing.T) {
	if os.Getenv("AGENTSHIELD_SETUP_HELPER") != "1" {
		return
	}
	rootCmd.SetArgs(strings.Fields(os.Getenv("AGENTSHIELD_SETUP_ARGS")))
	if err := rootCmd.Execute(); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

// newSetupHome points HOME at a fresh directory and puts a stand-in
// `agentshield` on PATH so setup finds a binary. COPILOT_HOME is cleared so the
// Copilot hook path resolves under HOME, not under the developer's real one.
func newSetupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COPILOT_HOME", "")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "agentshield"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return home
}

// runSetupInChildProcess runs `agentshield <args>` with HOME set and returns
// its combined output. A non-zero exit fails the test.
func runSetupInChildProcess(t *testing.T, home string, args ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSetupProcess$")
	cmd.Env = append(os.Environ(),
		"AGENTSHIELD_SETUP_HELPER=1",
		"AGENTSHIELD_SETUP_ARGS="+strings.Join(args, " "),
		"HOME="+home,
		"COPILOT_HOME=",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agentshield %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func readConfigFile(t *testing.T, home string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".agentshield", "agentshield.yaml"))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data), true
}

// lastAuditEvent returns the last line of ~/.agentshield/audit.jsonl, decoded.
func lastAuditEvent(t *testing.T, home string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".agentshield", "audit.jsonl"))
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var ev map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("decoding last audit line %q: %v", lines[len(lines)-1], err)
	}
	return ev
}

// A machine with no AgentShield state: setup records the new-install default,
// says so in one line with the line that turns enforcement on, and the hook
// it installed records `rm -rf /` as a would-be block instead of blocking it.
func TestSetup_NewInstall_StartsInAuditOnly(t *testing.T) {
	home := newSetupHome(t)

	out := runSetupInChildProcess(t, home, "setup", "claude-code")

	cfgFile, ok := readConfigFile(t, home)
	if !ok || !strings.Contains(cfgFile, "\ndefault_mode: audit-only\n") {
		t.Fatalf("setup on a new machine must write default_mode: audit-only to agentshield.yaml; got (exists=%v):\n%s\nsetup output:\n%s", ok, cfgFile, out)
	}
	if !strings.Contains(out, "starts in audit-only mode") || !strings.Contains(out, "`mode: enforce`") {
		t.Errorf("setup must say the machine starts in audit-only and give the line that turns enforcement on:\n%s", out)
	}
	if strings.Contains(out, "rm -rf /") {
		t.Errorf("in audit-only mode setup must not suggest testing by asking the agent to run rm -rf /:\n%s", out)
	}
	settings, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil || !strings.Contains(string(settings), "agentshield") {
		t.Fatalf("setup claude-code did not install the hook (err %v):\n%s", err, settings)
	}

	code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)
	if code != 0 {
		t.Fatalf("hook exit %d; want 0 — a new install is audit-only, so rm -rf / is recorded, not blocked. stderr:\n%s", code, stderr)
	}
	ev := lastAuditEvent(t, home)
	if ev["decision"] != "AUDIT" || ev["original_decision"] != "BLOCK" || ev["mode"] != "audit-only" {
		t.Errorf("audit record = decision %v, original_decision %v, mode %v; want AUDIT, BLOCK, audit-only", ev["decision"], ev["original_decision"], ev["mode"])
	}
}

// The OSS Homebrew formula's post_install copies the community packs into
// ~/.agentshield/packs before the user runs setup. Those packs alone do not
// make the machine an existing install (#4337: counting them made every OSS
// brew install enforce, found by the README walkthrough).
func TestSetup_NewInstall_BrewPacksOnlyStillNew(t *testing.T) {
	home := newSetupHome(t)
	for _, rel := range []string{".agentshield/packs/terminal-safety.yaml", ".agentshield/packs/mcp/mcp-safety.yaml"} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("rules: []\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := runSetupInChildProcess(t, home, "setup", "claude-code")
	if cfgFile, _ := readConfigFile(t, home); !strings.Contains(cfgFile, "default_mode: audit-only") {
		t.Fatalf("brew-installed packs made the machine look existing; want the new-install default.\nsetup output:\n%s", out)
	}
	if code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive); code != 0 {
		t.Fatalf("hook exit %d; want 0 (audit-only). stderr:\n%s", code, stderr)
	}
}

// Re-running setup on a new install keeps it in audit-only and does not
// announce it a second time.
func TestSetup_NewInstall_ReRunIsIdempotent(t *testing.T) {
	home := newSetupHome(t)
	runSetupInChildProcess(t, home, "setup", "claude-code")
	first, _ := readConfigFile(t, home)

	out := runSetupInChildProcess(t, home, "setup", "claude-code")
	second, _ := readConfigFile(t, home)
	if first == "" || second != first {
		t.Fatalf("re-running setup changed agentshield.yaml:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if strings.Contains(out, "New install") {
		t.Errorf("a re-run must not announce a new install:\n%s", out)
	}
	if !strings.Contains(out, "audit-only (new-install default)") {
		t.Errorf("setup status must still report the audit-only mode and where it came from:\n%s", out)
	}
}

// `setup` with no target configures every detected agent. The default is
// written once and announced once, however many agents are configured.
func TestSetup_AutoSetup_AnnouncesOnce(t *testing.T) {
	home := newSetupHome(t)
	for _, d := range []string{".claude", ".gemini"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	out := runSetupInChildProcess(t, home, "setup")
	if n := strings.Count(out, "New install"); n != 1 {
		t.Errorf("new-install notice printed %d times; want 1:\n%s", n, out)
	}
	if cfgFile, _ := readConfigFile(t, home); !strings.Contains(cfgFile, "default_mode: audit-only") {
		t.Errorf("auto setup did not write the new-install default:\n%s", cfgFile)
	}
}

// --disable installs nothing, so it never writes the default.
func TestSetup_Disable_WritesNoDefault(t *testing.T) {
	home := newSetupHome(t)
	runSetupInChildProcess(t, home, "setup", "claude-code", "--disable")
	if cfgFile, ok := readConfigFile(t, home); ok {
		t.Errorf("setup --disable wrote agentshield.yaml:\n%s", cfgFile)
	}
}

// The control: a machine that already has AgentShield state keeps enforcing
// after an upgrade and a re-run of setup. Each row is one kind of prior state.
// These pass on origin/main too; they pin that #4337 downgrades no existing
// install.
func TestSetup_ExistingInstall_ReRunStillBlocks(t *testing.T) {
	agentShieldHook := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/local/bin/agentshield hook"}]}]}}`
	cases := []struct {
		name  string
		files map[string]string // path under HOME → content; a trailing "/" makes a directory
	}{
		{"audit log from earlier runs", map[string]string{".agentshield/audit.jsonl": "{}\n"}},
		{"agentshield.yaml without a mode", map[string]string{".agentshield/agentshield.yaml": "# settings\n"}},
		{"policy.yaml", map[string]string{".agentshield/policy.yaml": failSafePolicyGood}},
		{"managed.json", map[string]string{".agentshield/managed.json": `{"managed": true}`}},
		{"packs from brew post_install, plus an audit log", map[string]string{".agentshield/packs/terminal-safety.yaml": "rules: []\n", ".agentshield/audit.jsonl": "{}\n"}},
		{"a file this check has never heard of", map[string]string{".agentshield/.DS_Store": "x"}},
		{"hook installed, config dir empty", map[string]string{".agentshield/": "", ".claude/settings.json": agentShieldHook}},
		{"hook installed, no config dir", map[string]string{".claude/settings.json": agentShieldHook}},
		{"Cursor hook installed", map[string]string{".cursor/hooks.json": `{"hooks":{"beforeShellExecution":[{"command":"agentshield hook"}]}}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := newSetupHome(t)
			for rel, body := range tc.files {
				p := filepath.Join(home, rel)
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
			before, existed := readConfigFile(t, home)

			out := runSetupInChildProcess(t, home, "setup", "claude-code")

			after, exists := readConfigFile(t, home)
			if exists != existed || after != before {
				t.Fatalf("setup changed agentshield.yaml on an existing install:\nbefore (exists=%v):\n%s\nafter (exists=%v):\n%s", existed, before, exists, after)
			}
			if strings.Contains(out, "New install") {
				t.Errorf("an existing install was announced as new:\n%s", out)
			}
			code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)
			if code != 2 {
				t.Fatalf("hook exit %d; want 2 — an existing install must still BLOCK rm -rf / after re-running setup. stderr:\n%s", code, stderr)
			}
		})
	}
}
