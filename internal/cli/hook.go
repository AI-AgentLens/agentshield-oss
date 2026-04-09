package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

// hookInput represents the JSON structure sent by IDE hooks.
// Windsurf sends:    {"agent_action_name": "pre_run_command", "tool_info": {"command_line": "..."}}
// Cursor sends:      {"command": "...", "cwd": "..."}
// Claude Code sends: {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "..."}}
// Gemini CLI sends:  {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {"command": "..."}}
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

	// Claude Code fields + Gemini CLI fields (both use hook_event_name/tool_name/tool_input)
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
	DirPath string `json:"dir_path,omitempty"` // Gemini CLI also sends dir_path
}

// rawHookInput is used for a second-pass parse to capture tool_input as raw JSON
// (needed for MCP tool calls where arguments are arbitrary key-value pairs).
type rawHookInput struct {
	ToolInput json.RawMessage `json:"tool_input"`
}

// cursorHookOutput is the JSON response Cursor expects from hook scripts.
type cursorHookOutput struct {
	Continue     bool   `json:"continue"`
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// geminiHookOutput is the JSON response Gemini CLI expects from hook scripts.
type geminiHookOutput struct {
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	SystemMessage string `json:"systemMessage,omitempty"`
}

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "IDE Hook handler for Windsurf, Cursor, Claude Code, and Gemini CLI",
	Long: `Reads an IDE hook JSON payload from stdin, evaluates the command
against AgentShield policy, and responds in the correct format.

Auto-detects the IDE based on the JSON input structure:
  Claude Code — uses exit code 2 to block Bash tool calls
  Gemini CLI  — returns JSON with decision: allow/deny
  Windsurf    — uses exit code 2 to block actions
  Cursor      — returns JSON with permission: deny/allow

Setup:
  agentshield setup claude-code
  agentshield setup gemini-cli
  agentshield setup windsurf
  agentshield setup cursor`,
	RunE: hookCommand,
}

func init() {
	rootCmd.AddCommand(hookCmd)
}

func hookCommand(cmd *cobra.Command, args []string) error {
	// Opportunistic heartbeat — keep agent online while IDE is active
	go sendOpportunisticHeartbeat()

	// Check bypass — allow everything when disabled (unless managed mode overrides)
	if os.Getenv("AGENTSHIELD_BYPASS") == "1" {
		managedCfg := enterprise.LoadManagedConfig()
		if managedCfg == nil || !managedCfg.Managed {
			// Non-managed mode: honor the bypass
			data, _ := io.ReadAll(os.Stdin)
			var input hookInput
			if err := json.Unmarshal(data, &input); err == nil && input.Command != "" {
				outputCursorAllow()
			}
			return nil
		}
		// Managed mode: ignore bypass, continue with evaluation
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: AGENTSHIELD_BYPASS detected in managed mode — ignoring bypass\n")
	}

	// Check pause — allow shell commands when paused (unless managed mode)
	if IsPaused() {
		managedCfg := enterprise.LoadManagedConfig()
		if managedCfg == nil || !managedCfg.Managed {
			return nil // paused = allow everything
		}
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

	// Also capture raw tool_input for MCP argument parsing
	var raw rawHookInput
	_ = json.Unmarshal(data, &raw)

	// Auto-detect IDE format based on input fields.
	// Claude Code sends {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {...}}.
	// Gemini CLI sends  {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {...}}.
	// Cursor sends      {"command": "..."} at the top level.
	// Windsurf sends    {"agent_action_name": "pre_run_command", "tool_info": {...}}.
	if input.HookEventName == "BeforeTool" {
		return handleGeminiCLIHook(input)
	}
	if input.HookEventName != "" {
		return handleClaudeCodeHook(input, raw.ToolInput)
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

	// Run enterprise middleware chain (pre-eval)
	ctx := &enterprise.EvalContext{Command: cmdStr, Cwd: cwd, Source: source}
	chain := buildMiddlewareChain()
	if len(chain) > 0 {
		// Run pre-eval middleware (SelfProtect, BypassGuard)
		enterprise.RunChain(ctx, chain)
		if ctx.Blocked {
			blockedResult := policy.EvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{"enterprise-self-protect"},
				Reasons:        []string{ctx.BlockMsg},
				Explanation:    ctx.BlockMsg,
			}
			event := logger.AuditEvent{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				Command:        cmdStr,
				Args:           strings.Fields(cmdStr),
				Cwd:            cwd,
				Decision:       "BLOCK",
				Flagged:        true,
				TriggeredRules: blockedResult.TriggeredRules,
				Reasons:        blockedResult.Reasons,
				Mode:           "managed",
				Source:         source,
			}
			return &blockedResult, &event, nil
		}
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		// Check fail_closed
		if managedCfg := enterprise.LoadManagedConfig(); managedCfg != nil && managedCfg.FailClosed {
			blockedResult := policy.EvalResult{
				Decision:    policy.DecisionBlock,
				Reasons:     []string{"AgentShield: config load error — blocking (fail_closed enabled)"},
				Explanation: "AgentShield: config load error — blocking (fail_closed enabled)",
			}
			return &blockedResult, nil, nil
		}
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
		// Check fail_closed
		if cfg.Managed != nil && cfg.Managed.FailClosed {
			blockedResult := policy.EvalResult{
				Decision:    policy.DecisionBlock,
				Reasons:     []string{"AgentShield: policy load error — blocking (fail_closed enabled)"},
				Explanation: "AgentShield: policy load error — blocking (fail_closed enabled)",
			}
			return &blockedResult, nil, nil
		}
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

	evalResult := engine.EvaluateWithParsed(cmdStr, normalized.Paths, normalized.Parsed)

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

	// Send to SaaS (fire-and-forget)
	sendRemoteAudit(&event)

	return &evalResult, &event, nil
}

// buildMiddlewareChain assembles the middleware chain based on enterprise config.
// Returns an empty chain in non-managed mode (zero overhead).
func buildMiddlewareChain() []enterprise.EvalMiddleware {
	managedCfg := enterprise.LoadManagedConfig()
	if managedCfg == nil || !managedCfg.Managed {
		return nil
	}

	var chain []enterprise.EvalMiddleware
	chain = append(chain, enterprise.BypassGuard(managedCfg))
	chain = append(chain, enterprise.SelfProtect())
	return chain
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
func handleClaudeCodeHook(input hookInput, rawToolInput json.RawMessage) error {
	// Shell commands (Bash tool) → evaluate through the analyzer pipeline
	if input.ToolName == "Bash" {
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
			fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED this command\n")
			if len(evalResult.TriggeredRules) > 0 {
				fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(evalResult.TriggeredRules, ", "))
			}
			for _, reason := range evalResult.Reasons {
				fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
			}
			os.Exit(2)
		}
		return nil
	}

	// MCP tool calls → evaluate through MCP policy
	return handleClaudeCodeMCPCall(input.ToolName, rawToolInput)
}

// handleClaudeCodeMCPCall evaluates an MCP tool call against MCP policy packs.
func handleClaudeCodeMCPCall(toolName string, rawToolInput json.RawMessage) error {
	// Parse tool_input as map for MCP evaluation
	var arguments map[string]interface{}
	if len(rawToolInput) > 0 {
		_ = json.Unmarshal(rawToolInput, &arguments)
	}

	// Load MCP packs with an empty base policy (LoadMCPPacks requires non-nil base).
	// MCP pack YAMLs live in packs/mcp/ and mcp-packs/.
	home, _ := os.UserHomeDir()
	packsDir := filepath.Join(home, ".agentshield", "packs", "mcp")
	basePolicy := &mcp.MCPPolicy{
		Defaults: mcp.MCPDefaults{Decision: policy.DecisionAudit},
	}
	mcpPolicy, packInfos, err := mcp.LoadMCPPacks(packsDir, basePolicy)
	if err != nil || mcpPolicy == nil {
		// No MCP policy loaded — allow (fail open)
		return nil
	}
	// Fall back to embedded packs if none installed on disk
	if len(packInfos) == 0 {
		mcpPolicy, _, _ = mcp.LoadEmbeddedMCPPacks(mcpPolicy)
	}

	evaluator := mcp.NewPolicyEvaluator(mcpPolicy)
	result := evaluator.EvaluateToolCall(toolName, arguments)

	// Audit log
	auditMCPCall(toolName, arguments, result)

	if result.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED MCP tool call: %s\n", toolName)
		if len(result.TriggeredRules) > 0 {
			fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(result.TriggeredRules, ", "))
		}
		for _, reason := range result.Reasons {
			fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
		}
		os.Exit(2)
	}

	if result.Decision == policy.DecisionAudit {
		fmt.Fprintf(os.Stderr, "[AgentShield] AUDIT MCP tool: %s\n", toolName)
		if len(result.TriggeredRules) > 0 {
			fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(result.TriggeredRules, ", "))
		}
	}

	return nil
}

// auditMCPCall writes an audit log entry for an MCP tool call evaluation.
func auditMCPCall(toolName string, arguments map[string]interface{}, result mcp.MCPEvalResult) {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentshield", "audit.jsonl")
	auditLogger, err := logger.New(logPath)
	if err != nil {
		return
	}
	defer func() { _ = auditLogger.Close() }()

	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ToolName:       toolName,
		MCPArguments:   arguments,
		Decision:       string(result.Decision),
		Flagged:        result.Decision == policy.DecisionBlock,
		TriggeredRules: result.TriggeredRules,
		Reasons:        result.Reasons,
		Source:         "claude-code-mcp-hook",
	}
	_ = auditLogger.Log(event)

	// Send to SaaS
	sendRemoteAudit(&event)
}

// handleGeminiCLIHook processes Gemini CLI BeforeTool hooks.
// Only run_shell_command tool calls are evaluated; other tools pass through.
// Responds with JSON {"decision": "allow"} or {"decision": "deny", "reason": "..."} on stdout.
func handleGeminiCLIHook(input hookInput) error {
	if input.ToolName != "run_shell_command" {
		outputGeminiAllow()
		return nil
	}

	cmdStr := input.ToolInput.Command
	if cmdStr == "" {
		outputGeminiAllow()
		return nil
	}

	cwd := input.ToolInput.DirPath
	evalResult, _, err := evaluateCommand(cmdStr, cwd, "gemini-cli-hook")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %v\n", err)
		outputGeminiAllow() // fail open
		return nil
	}

	if evalResult.Decision == policy.DecisionBlock {
		output := geminiHookOutput{
			Decision:      "deny",
			Reason:        "BLOCKED by AgentShield: " + strings.Join(evalResult.Reasons, "; "),
			SystemMessage: evalResult.Explanation,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return nil
	}

	outputGeminiAllow()
	return nil
}

func outputGeminiAllow() {
	output := geminiHookOutput{Decision: "allow"}
	data, _ := json.Marshal(output)
	fmt.Println(string(data))
}
