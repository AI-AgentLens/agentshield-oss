package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/logger"
	"github.com/security-researcher-ca/agentshield/internal/normalize"
	"github.com/security-researcher-ca/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

// hookInput represents the JSON structure sent by IDE hooks.
// Windsurf sends:    {"agent_action_name": "pre_run_command", "tool_info": {"command_line": "..."}}
// Cursor sends:      {"command": "...", "cwd": "..."}
// Claude Code sends: {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "..."}}
type hookInput struct {
	// Windsurf fields
	AgentActionName string   `json:"agent_action_name"`
	TrajectoryID    string   `json:"trajectory_id"`
	ExecutionID     string   `json:"execution_id"`
	Timestamp       string   `json:"timestamp"`
	ToolInfo        toolInfo `json:"tool_info"`

	// Cursor fields
	Command string `json:"command"`
	Cwd     string `json:"cwd"`

	// Claude Code fields
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     claudeToolInput `json:"tool_input"`
}

type toolInfo struct {
	CommandLine string `json:"command_line"`
	Cwd         string `json:"cwd"`
	FilePath    string `json:"file_path"`
}

type claudeToolInput struct {
	Command string `json:"command"`
}

// cursorHookOutput is the JSON response Cursor expects from hook scripts.
type cursorHookOutput struct {
	Continue     bool   `json:"continue"`
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "IDE Hook handler for Windsurf, Cursor, and Claude Code integration",
	Long: `Reads an IDE hook JSON payload from stdin, evaluates the command
against AgentShield policy, and responds in the correct format.

Auto-detects the IDE based on the JSON input structure:
  Claude Code — uses exit code 2 to block Bash tool calls
  Windsurf    — uses exit code 2 to block actions
  Cursor      — returns JSON with permission: deny/allow

Setup:
  agentshield setup claude-code
  agentshield setup windsurf
  agentshield setup cursor`,
	RunE: hookCommand,
}

func init() {
	rootCmd.AddCommand(hookCmd)
}

func hookCommand(cmd *cobra.Command, args []string) error {
	// Check bypass — allow everything when disabled
	if os.Getenv("AGENTSHIELD_BYPASS") == "1" {
		// Still need to consume stdin and respond correctly for Cursor format
		data, _ := io.ReadAll(os.Stdin)
		var input hookInput
		if err := json.Unmarshal(data, &input); err == nil && input.Command != "" {
			outputCursorAllow()
		}
		return nil
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	var input hookInput
	if err := json.Unmarshal(data, &input); err != nil {
		// If we can't parse the input, allow the action (fail open)
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: could not parse hook input: %v\n", err)
		return nil
	}

	// Auto-detect IDE format based on input fields.
	// Claude Code sends {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {...}}.
	// Cursor sends      {"command": "..."} at the top level.
	// Windsurf sends    {"agent_action_name": "pre_run_command", "tool_info": {...}}.
	if input.HookEventName != "" {
		return handleClaudeCodeHook(input)
	}

	if input.Command != "" {
		return handleCursorHook(input)
	}

	switch input.AgentActionName {
	case "pre_run_command":
		return handleWindsurfHook(input)
	default:
		// Unsupported hook events pass through
		return nil
	}
}

// evaluateCommand is the shared policy evaluation logic for all IDE hooks.
func evaluateCommand(cmdStr, cwd, source string) (*policy.EvalResult, *logger.AuditEvent, error) {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return nil, nil, fmt.Errorf("config load failed: %w", err)
	}

	auditLogger, err := logger.New(cfg.LogPath)
	if err != nil {
		return nil, nil, fmt.Errorf("logger init failed: %w", err)
	}
	defer func() {
		_ = auditLogger.Close()
	}()

	cmdArgs := strings.Fields(cmdStr)
	normalized := normalize.Normalize(cmdArgs, cwd)

	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("policy load failed: %w", err)
	}

	packsPath := filepath.Join(cfg.ConfigDir, "packs")
	pol, _, err = policy.LoadPacks(packsPath, pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: packs load failed: %v\n", err)
	}

	engine, err := policy.NewEngineWithAnalyzers(pol, cfg.Analyzer.MaxParseDepth)
	if err != nil {
		return nil, nil, fmt.Errorf("engine init failed: %w", err)
	}

	evalResult := engine.Evaluate(cmdStr, normalized.Paths)

	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Command:        cmdStr,
		Args:           cmdArgs,
		Cwd:            cwd,
		Decision:       string(evalResult.Decision),
		TriggeredRules: evalResult.TriggeredRules,
		Reasons:        evalResult.Reasons,
		Mode:           cfg.Mode,
		Source:         source,
	}

	if evalResult.Decision == policy.DecisionBlock || evalResult.Decision == policy.DecisionAudit {
		event.Flagged = true
	}
	if err := auditLogger.Log(event); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
	}

	return &evalResult, &event, nil
}

// handleWindsurfHook processes Windsurf Cascade Hooks (pre_run_command).
// Block = exit code 2, message on stderr.
func handleWindsurfHook(input hookInput) error {
	cmdStr := input.ToolInfo.CommandLine
	if cmdStr == "" {
		return nil
	}

	evalResult, _, err := evaluateCommand(cmdStr, input.ToolInfo.Cwd, "windsurf-hook")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %v\n", err)
		return nil // fail open
	}

	if evalResult.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛑 BLOCKED by AgentShield\n")
		fmt.Fprintf(os.Stderr, "%s\n", evalResult.Explanation)
		os.Exit(2)
	}

	return nil
}

// handleCursorHook processes Cursor hooks (beforeShellExecution).
// Block = JSON output with permission: "deny".
func handleCursorHook(input hookInput) error {
	cmdStr := input.Command
	if cmdStr == "" {
		outputCursorAllow()
		return nil
	}

	evalResult, _, err := evaluateCommand(cmdStr, input.Cwd, "cursor-hook")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %v\n", err)
		outputCursorAllow() // fail open
		return nil
	}

	if evalResult.Decision == policy.DecisionBlock {
		output := cursorHookOutput{
			Continue:     true,
			Permission:   "deny",
			UserMessage:  "🛑 BLOCKED by AgentShield: " + strings.Join(evalResult.Reasons, "; "),
			AgentMessage: evalResult.Explanation,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return nil
	}

	outputCursorAllow()
	return nil
}

func outputCursorAllow() {
	output := cursorHookOutput{
		Continue:   true,
		Permission: "allow",
	}
	data, _ := json.Marshal(output)
	fmt.Println(string(data))
}

// handleClaudeCodeHook processes Claude Code PreToolUse hooks.
// Only Bash tool calls are evaluated; other tools pass through.
// Block → print reason to stdout + exit 2. Allow/Audit → exit 0.
func handleClaudeCodeHook(input hookInput) error {
	if input.ToolName != "Bash" {
		return nil
	}

	cmdStr := input.ToolInput.Command
	if cmdStr == "" {
		return nil
	}

	evalResult, _, err := evaluateCommand(cmdStr, "", "claude-code-hook")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %v\n", err)
		return nil // fail open
	}

	if evalResult.Decision == policy.DecisionBlock {
		fmt.Printf("🛑 BLOCKED by AgentShield\n%s\n", evalResult.Explanation)
		os.Exit(2)
	}

	return nil
}
