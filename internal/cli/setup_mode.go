package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/spf13/cobra"
)

// New installs start in audit-only mode (#4337, Gary 2026-10-13): `setup` on a
// machine with no prior AgentShield state writes the new-install default to
// ~/.agentshield/agentshield.yaml. Every other machine keeps the mode it has,
// which for an existing install is the built-in enforce default.
//
// The default is `default_mode:`, not `mode:`. A `mode:` line outranks the
// organisation's policy.yaml, so writing one here would pin a machine that is
// set up first and enrolled second (the order the docs give) to audit-only
// whatever its organisation decides. `default_mode:` sits below that push and
// is ignored on a managed host (config.Load), so enrolling hands the decision
// to the organisation, as before #4337.

// newInstallConfig is the agentshield.yaml `setup` writes on a new install.
const newInstallConfig = `# AgentShield settings, written by ` + "`agentshield setup`" + ` on a new install (#4337).
#
# This machine starts in audit-only mode: AgentShield records what enforce mode
# would block and lets it run. Every decision is recorded in
# ~/.agentshield/audit.jsonl; a would-be block is recorded as AUDIT with
# original_decision: BLOCK.
#
# To turn on enforcement, add this line. A mode: line here wins over everything
# except the --mode flag.
#
#   mode: enforce
#
# default_mode applies only when nothing else sets the mode: no mode: line, no
# --mode flag and no organisation policy. A managed host ignores it.
default_mode: audit-only
`

// enableEnforcementHint is the one line that turns enforcement on.
const enableEnforcementHint = "set `mode: enforce` in ~/.agentshield/agentshield.yaml"

// harnessConfigPaths are the files `setup` writes AgentShield's hook or MCP
// proxy into. One that mentions agentshield means a hook may already be
// installed, so the machine enforces today even if ~/.agentshield is empty
// (setup on main leaves the directory empty until the first hook call).
func harnessConfigPaths(home string) []string {
	return []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(home, ".cursor", "hooks.json"),
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".codeium", "windsurf", "hooks.json"),
		filepath.Join(home, ".gemini", "settings.json"),
		filepath.Join(home, ".codex", "hooks.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		copilotHookFilePath(),
		filepath.Join(home, ".openclaw", "hooks", "agentshield"),
	}
}

// priorInstallEvidence returns the first sign that AgentShield has been on
// this machine before, or "" when there is none (#4337).
//
// A machine is new only when ~/.agentshield holds nothing but a packs/
// directory AND no harness config file setup writes to mentions agentshield.
// "Anything else at all in ~/.agentshield" is deliberately broader than a list
// of known files: the set of files AgentShield and its enterprise sync write
// grows, and a file this check did not know about must count as prior state,
// not be ignored. A path that cannot be read cannot prove the machine is new,
// so it counts too. Every doubt resolves to "existing", which keeps today's
// behaviour.
//
// packs/ is the one exception, because the OSS Homebrew formula's
// post_install copies the community packs into ~/.agentshield/packs before the
// user ever runs setup (and `setup --install` writes it too). Counting it made
// every OSS brew install look existing, so the new-install default never
// applied to the audience it was decided for (#4337, found by the README
// walkthrough). Pack files alone enforce nothing: with no hook, no audit log
// and no config, the machine has never blocked anything.
func priorInstallEvidence(home string) string {
	configDir := filepath.Join(home, config.DefaultConfigDir)
	entries, err := os.ReadDir(configDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return configDir + " is unreadable: " + err.Error()
	}
	for _, e := range entries {
		if e.Name() == "packs" && e.IsDir() {
			continue
		}
		return filepath.Join(configDir, e.Name()) + " exists"
	}
	for _, p := range harnessConfigPaths(home) {
		info, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return p + " is unreadable: " + err.Error()
		}
		// The Copilot hook file and the OpenClaw hook directory are
		// AgentShield's own by name: their existence is the evidence.
		if info.IsDir() || strings.Contains(strings.ToLower(filepath.Base(p)), "agentshield") {
			return p + " exists"
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return p + " is unreadable: " + err.Error()
		}
		if bytes.Contains(bytes.ToLower(data), []byte("agentshield")) {
			return p + " mentions agentshield"
		}
	}
	return ""
}

// applyNewInstallDefault writes the new-install default when the machine has
// no prior AgentShield state. written reports whether it did; evidence names
// the prior state when it did not. The file is created exclusively, so an
// existing agentshield.yaml is never rewritten.
func applyNewInstallDefault(home string) (written bool, evidence string, err error) {
	if ev := priorInstallEvidence(home); ev != "" {
		return false, ev, nil
	}
	dir := filepath.Join(home, config.DefaultConfigDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, "", err
	}
	path := filepath.Join(dir, config.DefaultConfigFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, path + " exists", nil
		}
		return false, "", err
	}
	if _, err := f.WriteString(newInstallConfig); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return false, "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return false, "", err
	}
	return true, "", nil
}

// setupPreRun runs before every `agentshield setup` command and applies the
// new-install default (#4337). A --disable run installs nothing, so it never
// writes the default. Neither do the Claude Code managed-settings runs
// (#4292): --managed writes nothing at all, and --write-managed usually runs
// under sudo, where the default would land root-owned in the user's
// ~/.agentshield. A failure to write it is reported and setup continues: the
// machine then runs in enforce mode, today's behaviour.
func setupPreRun(cmd *cobra.Command, _ []string) error {
	for _, name := range []string{"disable", "managed", "write-managed"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Value.String() == "true" {
			return nil
		}
	}
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}
	written, _, err := applyNewInstallDefault(home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠  Could not write the new-install default (%v); this machine runs in enforce mode.\n", err)
		return nil
	}
	if written {
		fmt.Println("ℹ  New install: AgentShield starts in audit-only mode. It records what enforce mode would block, and lets it run.")
		fmt.Printf("   To turn on enforcement, %s\n", enableEnforcementHint)
		fmt.Println()
	}
	return nil
}

// printTestHint tells the user how to watch AgentShield decide. Setup used to
// say "ask the agent to run rm -rf /", which in audit-only mode would run it,
// so in audit-only it points at `agentshield check`, which never executes
// anything (#4337).
func printTestHint(agent string) {
	cfg, _ := config.Load("", "", "")
	if cfg == nil || cfg.Mode == config.ModeAuditOnly {
		fmt.Println("See how AgentShield decides, without running anything:")
		fmt.Println(`  agentshield check --shell "cat ~/.ssh/id_ed25519"`)
		fmt.Printf("In audit-only mode %s's actions run and are recorded. Do not test AgentShield\n", agent)
		fmt.Println("by asking the agent to run a dangerous command.")
		return
	}
	fmt.Printf("AgentShield is active. Test it by asking %s to run:\n", agent)
	fmt.Println("  rm -rf /")
	fmt.Println("  cat ~/.ssh/id_ed25519")
}

// modeSummary is the one-line mode report for `setup`, `status` and `scan`:
// the mode, where it came from, and in audit-only how to turn enforcement on.
func modeSummary(cfg *config.Config) string {
	if cfg == nil {
		return "unknown (configuration could not be loaded)"
	}
	if cfg.Mode != config.ModeAuditOnly {
		return fmt.Sprintf("enforce (%s): BLOCK rules block", cfg.ModeSource)
	}
	switch cfg.ModeSource {
	case config.ModeSourcePolicyFile:
		return "audit-only (set by your organisation's policy.yaml enforcement_mode): would-be blocks are recorded, not enforced"
	case config.ModeSourceFlag:
		return "audit-only (--mode flag): would-be blocks are recorded, not enforced"
	default:
		return fmt.Sprintf("audit-only (%s): would-be blocks are recorded, not enforced; to turn on enforcement, %s", cfg.ModeSource, enableEnforcementHint)
	}
}
