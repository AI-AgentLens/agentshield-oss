package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/config"
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

The decision is enforce mode's unless --mode audit-only is passed; mcp-eval
does not read the mode configured in agentshield.yaml or policy.yaml. Under
--mode audit-only a call enforce mode would block reports AUDIT, with the
original decision in "original_decision" (--format json) and on the
"Original decision:" line, and its rules kept.

Exit codes:
  0 — ALLOW or AUDIT (including a BLOCK downgraded by --mode audit-only)
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

	// Evaluate in enforce mode and apply --mode once, to the final verdict
	// (#4356). Before, nothing applied --mode, so `mcp-eval --mode
	// audit-only` printed BLOCK for any rule. An evaluator built in audit-only
	// mode is not the fix either: it downgrades its own BLOCK, the
	// value_limits pass then runs on the AUDIT, and a value-limit BLOCK gets
	// through undowngraded, which is what shield-server did.
	evaluator := assembly.MCPEvaluator(loaded.Policy, "")
	result := mcpEvalVerdict(evaluator, mcpEvalTool, arguments, mcpEvalMode(mode))

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

// mcpEvalMode is the mode mcp-eval simulates: the --mode flag, normalised as
// config.Load normalises it, so an unrecognised value enforces. The warning for
// one is config.Load's own, printed when loadDeployedMCPPolicy resolves the
// config directory. Without the flag it is enforce: mcp-eval does not read the
// configured mode (agentshield.yaml, policy.yaml), so a flagless run reports
// what enforce mode decides, as it always has (#4324 row 6).
func mcpEvalMode(flag string) string {
	m, _ := config.NormalizeMode(flag)
	return m
}

// mcpEvalVerdict is mcp-eval's verdict for one tool call. evaluator must be in
// enforce mode: the verdict is computed as enforce mode computes it, from the
// rule matcher and then the value_limits pass, and mode is applied once at the
// end, so in audit-only mode a BLOCK from either source is reported as AUDIT
// with original_decision BLOCK and its rules and taxonomy kept (#4356). A
// self-protection BLOCK stays BLOCK in audit-only mode, as on the proxies
// (#4337 review B1, PolicyEvaluator.ApplyModeKeepingSelfProtection).
//
// value_limits rules are a separate check (numeric threshold on an argument)
// from the YAML rule matcher — the real MCP proxy (handler.go HandleToolCall)
// runs both and merges them, so mcp-eval must too or it silently
// mis-simulates every value_limits rule in the corpus (issue #3169): the CLI
// would report AUDIT/ALLOW for a call a live MCP session actually BLOCKs. Only
// consulted when not already BLOCKed, mirroring handler.go's
// `if result.Decision != "BLOCK"` gate.
func mcpEvalVerdict(evaluator *mcp.PolicyEvaluator, tool string, arguments map[string]interface{}, mode string) mcp.MCPEvalResult {
	result := evaluator.EvaluateToolCall(tool, arguments)
	result, _ = evaluator.ApplyValueLimits(result, tool, arguments)
	return evaluator.ApplyModeKeepingSelfProtection(result, mode, tool, arguments)
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
	if result.OriginalDecision != "" {
		fmt.Printf("  Original decision: %s (audit-only mode; enforce mode would %s)\n",
			result.OriginalDecision, strings.ToLower(strings.ReplaceAll(string(result.OriginalDecision), "_", " ")))
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
