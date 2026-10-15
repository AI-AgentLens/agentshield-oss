package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	policyPath string
	logPath    string
	mode       string
)

var rootCmd = &cobra.Command{
	Use:   "agentshield",
	Short: "AgentShield - Security gateway for AI agents",
	Long: `AgentShield is a local-first security gateway that sits between AI agents
and high-risk tools (terminal, repo/PR automation), enforcing deterministic
policies to prevent prompt-injection-driven damage, data exfiltration,
and destructive actions.`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&policyPath, "policy", "", "Path to policy YAML file (default: ~/.agentshield/policy.yaml)")
	rootCmd.PersistentFlags().StringVar(&logPath, "log", "", "Path to audit log file (default: ~/.agentshield/audit.jsonl)")
	// Enforcement mode — issue #1952. Default "enforce" preserves the historical
	// behavior for every existing user. "audit-only" downgrades BLOCK and
	// REQUIRE_APPROVAL decisions to AUDIT and records the original decision on
	// the audit log entry. Typical use: org-wide rollout dogfooding before
	// flipping to enforce. Can also be set via the `mode:` field in
	// ~/.agentshield/agentshield.yaml — the flag wins when provided.
	rootCmd.PersistentFlags().StringVar(&mode, "mode", "", "Enforcement mode: enforce (default) or audit-only")
}

func Execute() error {
	// A bare `agentshield` carrying a hook payload on stdin runs as
	// `agentshield hook` (#4292). Every other invocation is untouched.
	//
	// This backstop must outlive every exec-form hook entry setup has ever
	// written. Claude Code 2.1.138 and earlier drop "args" and run the entry's
	// program bare; without this branch that prints help and exits 0, which
	// Claude Code reads as allow, so every migrated install on those versions
	// would fail open with no evaluation and no audit record (#4292, #4314).
	if len(os.Args) == 1 {
		if in, ok := bareHookInput(os.Stdin); ok {
			hookStdin = in
			rootCmd.SetArgs([]string{hookCmd.Name()})
		}
	}
	return rootCmd.Execute()
}
