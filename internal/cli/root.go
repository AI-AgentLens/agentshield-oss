package cli

import (
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
	rootCmd.PersistentFlags().StringVar(&mode, "mode", "policy-only", "Execution mode: policy-only or guardian")
}

func Execute() error {
	return rootCmd.Execute()
}
