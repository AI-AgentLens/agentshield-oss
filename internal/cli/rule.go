package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// agentshield rule manages the user's local rule preferences in
// ~/.agentshield/policy.yaml. The first surface is `disable` / `allow` for
// false-positive triage — when a rule fires on a command the user trusts,
// the BLOCK output suggests the disable command and this is what runs it.
//
// Managed mode (~/.agentshield/managed.json: managed: true) refuses these
// mutations so an enterprise admin's policy can't be subverted by the user
// or by prompt injection asking the agent to "just disable that rule."

var ruleCmd = &cobra.Command{
	Use:   "rule",
	Short: "Manage local rule preferences (disable, allow, list)",
	Long: `Manage local rule preferences in ~/.agentshield/policy.yaml.

Examples:
  agentshield rule disable cred-block-ssh-key-read
  agentshield rule allow   cred-block-ssh-key-read
  agentshield rule list`,
}

var ruleDisableCmd = &cobra.Command{
	Use:   "disable <rule-id>",
	Short: "Disable a rule by ID (writes to ~/.agentshield/policy.yaml)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return ruleMutate(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], ruleOpDisable)
	},
}

var ruleAllowCmd = &cobra.Command{
	Use:   "allow <rule-id>",
	Short: "Re-enable a previously disabled rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return ruleMutate(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], ruleOpAllow)
	},
}

var ruleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List rules currently disabled in the user policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		return ruleList(cmd.OutOrStdout())
	},
}

func init() {
	ruleCmd.AddCommand(ruleDisableCmd)
	ruleCmd.AddCommand(ruleAllowCmd)
	ruleCmd.AddCommand(ruleListCmd)
	rootCmd.AddCommand(ruleCmd)
}

type ruleOp int

const (
	ruleOpDisable ruleOp = iota
	ruleOpAllow
)

func ruleMutate(stdout, stderr io.Writer, ruleID string, op ruleOp) error {
	if ruleID == "" {
		return fmt.Errorf("rule ID is required")
	}

	configDir, err := resolveConfigDir()
	if err != nil {
		return err
	}

	if locked, why := managedLockReason(configDir); locked {
		return fmt.Errorf("refusing to modify policy in managed mode (%s): only the admin's policy applies; local disables are ignored", why)
	}

	policyFile := filepath.Join(configDir, "policy.yaml")
	pol, hadComments, err := loadPolicyForEdit(policyFile)
	if err != nil {
		return err
	}

	switch op {
	case ruleOpDisable:
		if pol.IsRuleDisabled(ruleID) {
			_, _ = fmt.Fprintf(stdout, "rule %q is already disabled\n", ruleID)
			return nil
		}
		pol.DisableRules = append(pol.DisableRules, ruleID)
	case ruleOpAllow:
		next := pol.DisableRules[:0]
		removed := false
		for _, id := range pol.DisableRules {
			if id == ruleID {
				removed = true
				continue
			}
			next = append(next, id)
		}
		pol.DisableRules = next
		if !removed {
			_, _ = fmt.Fprintf(stdout, "rule %q was not disabled\n", ruleID)
			return nil
		}
	}

	if hadComments {
		_, _ = fmt.Fprintln(stderr, "note: comments in policy.yaml will be lost on rewrite. Edit by hand to preserve them.")
	}

	if err := savePolicyAtomically(policyFile, pol); err != nil {
		return err
	}

	switch op {
	case ruleOpDisable:
		_, _ = fmt.Fprintf(stdout, "disabled rule %q\n", ruleID)
	case ruleOpAllow:
		_, _ = fmt.Fprintf(stdout, "re-enabled rule %q\n", ruleID)
	}
	return nil
}

func ruleList(stdout io.Writer) error {
	configDir, err := resolveConfigDir()
	if err != nil {
		return err
	}
	policyFile := filepath.Join(configDir, "policy.yaml")
	pol, _, err := loadPolicyForEdit(policyFile)
	if err != nil {
		return err
	}

	if len(pol.DisableRules) == 0 {
		_, _ = fmt.Fprintln(stdout, "no rules disabled")
		return nil
	}
	for _, id := range pol.DisableRules {
		_, _ = fmt.Fprintln(stdout, id)
	}
	return nil
}

// resolveConfigDir returns ~/.agentshield (or the path config.Load reports).
func resolveConfigDir() (string, error) {
	if cfg, _ := config.Load(policyPath, logPath, mode); cfg != nil && cfg.ConfigDir != "" {
		return cfg.ConfigDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, config.DefaultConfigDir), nil
}

// managedLockReason reports whether the local config has managed mode set.
// Returns (true, reason) when locked.
func managedLockReason(configDir string) (bool, string) {
	mc := config.LoadManaged(configDir)
	if mc != nil && mc.Managed {
		return true, "managed.json marks this install as managed"
	}
	return false, ""
}

// loadPolicyForEdit reads the user's policy.yaml. Missing file is fine — we
// return a fresh struct. Returns hadComments=true if the file contained any
// `# ...` lines, so the caller can warn the user before a write would lose
// them.
func loadPolicyForEdit(path string) (*policy.Policy, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &policy.Policy{Version: "0.1"}, false, nil
		}
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}

	var pol policy.Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if pol.Version == "" {
		pol.Version = "0.1"
	}

	return &pol, hasYAMLComments(data), nil
}

// hasYAMLComments — naive but cheap: a line that, after leading whitespace,
// starts with `#`. Misses inline comments (`key: val # foo`) but those are
// preserved differently anyway and the warning is purely informational.
func hasYAMLComments(data []byte) bool {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		trimmed := bytes.TrimLeft(line, " \t")
		if len(trimmed) > 0 && trimmed[0] == '#' {
			return true
		}
	}
	return false
}

// savePolicyAtomically writes a Policy to path via tmp + rename so a crash
// mid-write doesn't leave a half-written file.
func savePolicyAtomically(path string, pol *policy.Policy) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	out, err := yaml.Marshal(pol)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*.yaml")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath) // no-op if Rename succeeded
	}()

	// Drop a header so a curious user opening this file sees what generated it.
	header := []byte("# AgentShield local policy\n# Edit by hand to add custom rules; `agentshield rule disable/allow` updates `disable_rules:`.\n\n")
	if _, err := tmp.Write(header); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// suggestRemediation builds the self-help text appended to a BLOCK message.
// It tells the user three things in three lines:
//   1. how to allow this rule once they confirm it's a false positive,
//   2. how to debug what fired (link to `check --shell`),
//   3. that bypassing without thinking is a bad idea.
func suggestRemediation(triggeredRules []string, command string) string {
	if len(triggeredRules) == 0 {
		return ""
	}
	// The first rule is what got the user blocked. Surface it in the disable
	// command so they don't have to copy-paste from the rule list themselves.
	first := triggeredRules[0]

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("To allow this in your local environment (after confirming it's safe):\n")
	fmt.Fprintf(&sb, "    agentshield rule disable %s\n", first)
	sb.WriteString("To see why this triggered:\n")
	if command != "" {
		fmt.Fprintf(&sb, "    agentshield check --shell %q\n", command)
	} else {
		sb.WriteString("    agentshield check --shell \"<the command>\"\n")
	}
	sb.WriteString("Disabling rules in managed mode is not allowed.\n")
	return sb.String()
}
