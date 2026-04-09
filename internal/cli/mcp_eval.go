package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

var mcpEvalCmd = &cobra.Command{
	Use:   "mcp-eval --tool <tool_name> [--arg key=value]...",
	Short: "Evaluate an MCP tool call against deployed policy",
	Long: `Evaluate a simulated MCP tool call against the deployed MCP policy packs.
Returns the decision (BLOCK/AUDIT/ALLOW), triggered rules, and reasons.

This is the MCP equivalent of "agentshield run" for shell commands — use it
to validate MCP rules without needing a running MCP server.

Examples:
  agentshield mcp-eval --tool read_file --arg path=/home/user/.ssh/id_rsa
  agentshield mcp-eval --tool write_file --arg path=/etc/resolv.conf --arg content="nameserver 8.8.8.8"
  agentshield mcp-eval --tool http_request --arg url=https://evil.com/exfil
  agentshield mcp-eval --tool read_file --arg path=/workspace/project/README.md
  agentshield mcp-eval --tool execute_command --arg command="ls -la"

Exit codes:
  0 — ALLOW or AUDIT
  2 — BLOCK`,
	RunE: mcpEvalRun,
}

var (
	mcpEvalTool string
	mcpEvalArgs []string
	mcpEvalJSON string
)

func init() {
	mcpEvalCmd.Flags().StringVar(&mcpEvalTool, "tool", "", "MCP tool name (e.g., read_file, write_file)")
	mcpEvalCmd.Flags().StringArrayVar(&mcpEvalArgs, "arg", nil, "Tool argument as key=value (repeatable)")
	mcpEvalCmd.Flags().StringVar(&mcpEvalJSON, "json", "", "Tool arguments as JSON object (alternative to --arg)")
	_ = mcpEvalCmd.MarkFlagRequired("tool")
	rootCmd.AddCommand(mcpEvalCmd)
}

func mcpEvalRun(cmd *cobra.Command, args []string) error {
	// Parse arguments.
	arguments, err := parseMCPEvalArgs()
	if err != nil {
		return err
	}

	// Load deployed MCP policy packs.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	packsDir := filepath.Join(home, ".agentshield", "packs", "mcp")
	basePolicy := &mcp.MCPPolicy{
		Defaults: mcp.MCPDefaults{Decision: policy.DecisionAudit},
	}

	mcpPolicy, packNames, err := mcp.LoadMCPPacks(packsDir, basePolicy)
	if err != nil {
		return fmt.Errorf("failed to load MCP packs from %s: %w", packsDir, err)
	}

	if len(packNames) > 0 && verbose {
		names := make([]string, len(packNames))
		for i, p := range packNames {
			names[i] = p.Name
		}
		fmt.Fprintf(os.Stderr, "Loaded %d MCP packs: %s\n", len(packNames), strings.Join(names, ", "))
	}

	// Evaluate.
	evaluator := mcp.NewPolicyEvaluator(mcpPolicy)
	result := evaluator.EvaluateToolCall(mcpEvalTool, arguments)

	// Output.
	printMCPEvalResult(result)

	if result.Decision == policy.DecisionBlock {
		os.Exit(2)
	}

	return nil
}

// parseMCPEvalArgs builds the arguments map from --arg and --json flags.
func parseMCPEvalArgs() (map[string]interface{}, error) {
	arguments := map[string]interface{}{}

	// --json takes precedence if provided.
	if mcpEvalJSON != "" {
		if err := json.Unmarshal([]byte(mcpEvalJSON), &arguments); err != nil {
			return nil, fmt.Errorf("invalid --json: %w", err)
		}
		return arguments, nil
	}

	// Parse --arg key=value pairs.
	for _, kv := range mcpEvalArgs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --arg %q: expected key=value", kv)
		}
		arguments[parts[0]] = parts[1]
	}

	return arguments, nil
}

// printMCPEvalResult formats and prints the evaluation result.
func printMCPEvalResult(result mcp.MCPEvalResult) {
	switch result.Decision {
	case policy.DecisionBlock:
		fmt.Printf("BLOCK\n")
	case policy.DecisionAudit:
		fmt.Printf("AUDIT\n")
	case policy.DecisionAllow:
		fmt.Printf("ALLOW\n")
	default:
		fmt.Printf("%s\n", result.Decision)
	}

	if len(result.TriggeredRules) > 0 {
		fmt.Printf("  Rules: %s\n", strings.Join(result.TriggeredRules, ", "))
	}
	for _, reason := range result.Reasons {
		fmt.Printf("  Reason: %s\n", reason)
	}
}
