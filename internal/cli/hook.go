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
	"github.com/AI-AgentLens/agentshield/internal/execenv"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/policy/remediation"
	"github.com/spf13/cobra"
)

// hookInput represents the JSON structure sent by IDE hooks.
// Windsurf sends:    {"agent_action_name": "pre_run_command", "tool_info": {"command_line": "..."}}
// Cursor sends:      {"command": "...", "cwd": "..."}
// Claude Code sends: {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "..."}}
// Codex CLI sends:   {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "..."},
//
//	"turn_id": "...", "model": "..."} — payload is a superset of Claude Code's,
//	so handleClaudeCodeHook evaluates it unchanged; turn_id is used for source labeling.
//
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

	// Codex-only fields (Claude Code omits these). Used to tag the audit source
	// when the same handler processes a Codex PreToolUse payload.
	TurnID string `json:"turn_id"`

	// SessionID is the harness's own session identifier. Claude Code sends it
	// on every hook payload (alongside transcript_path); Codex's PreToolUse
	// payload is a superset of Claude Code's, so it lands here too. Recorded
	// verbatim on the audit event so the SaaS can group a session's events
	// into one attestation. Issue #3111.
	SessionID string `json:"session_id"`
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
	Short: "IDE Hook handler for Claude Code, Codex CLI, Gemini CLI, Windsurf, and Cursor",
	Long: `Reads an IDE hook JSON payload from stdin, evaluates the command
against AgentShield policy, and responds in the correct format.

Auto-detects the IDE based on the JSON input structure:
  Claude Code — uses exit code 2 to block Bash tool calls
  Codex CLI   — same PreToolUse payload as Claude Code; exit 2 blocks
  Gemini CLI  — returns JSON with decision: allow/deny
  Windsurf    — uses exit code 2 to block actions
  Cursor      — returns JSON with permission: deny/allow

Setup:
  agentshield setup claude-code
  agentshield setup codex
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
	// Codex CLI sends   the same shape plus turn_id/model — handled by handleClaudeCodeHook,
	//                   which labels the audit source as "codex-hook" when turn_id is present.
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
// sessionID is the harness's own session identifier (see sessionIDFor); pass
// "" when the harness doesn't provide one.
func evaluateCommand(cmdStr, cwd, source, sessionID string) (*policy.EvalResult, *logger.AuditEvent, error) {
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
				SessionID:      sessionID,
				Principal:      osPrincipal(),
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
	normalized := normalize.NormalizeCommand(cmdStr, cwd)

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

	// Layer 1: embedded community shell packs (always available, no disk dep).
	pol, embeddedInfos, _ := policy.LoadEmbeddedShellPacks(pol)

	// Layer 2: disk-installed packs (premium from SaaS, user custom).
	packsPath := filepath.Join(cfg.ConfigDir, "packs")
	pol, diskInfos, err := policy.LoadPacks(packsPath, pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: packs load failed: %v\n", err)
	}

	// Issue #2188: a pack that fails to parse is dropped with RuleCount 0. For a
	// security gateway a silently degraded ruleset is the worst outcome — surface
	// it loudly. In managed fail-closed mode, refuse to evaluate against a
	// known-degraded ruleset, consistent with the policy-load fail-closed path
	// above.
	failedPacks := append(policy.FailedPacks(embeddedInfos), policy.FailedPacks(diskInfos)...)
	for _, fp := range failedPacks {
		fmt.Fprintf(os.Stderr, "[AgentShield] CRITICAL: pack %q failed to parse — its rules are NOT loaded, enforcement degraded: %v\n", fp.Path, fp.LoadError)
	}
	if len(failedPacks) > 0 && cfg.Managed != nil && cfg.Managed.FailClosed {
		blockedResult := policy.EvalResult{
			Decision:    policy.DecisionBlock,
			Reasons:     []string{"AgentShield: a policy pack failed to parse — blocking (fail_closed enabled)"},
			Explanation: "AgentShield: a policy pack failed to parse — blocking (fail_closed enabled)",
		}
		return &blockedResult, nil, nil
	}

	engine, err := policy.NewEngineWithAnalyzers(pol, cfg.Analyzer.MaxParseDepth)
	if err != nil {
		return nil, nil, fmt.Errorf("engine init failed: %w", err)
	}
	// Issue #1952: audit-only mode downgrades happen inside the engine, so
	// every caller (shell hook, MCP hook, agentshield check, scan) gets the
	// same behavior without duplicating the downgrade logic at each call site.
	engine.SetMode(cfg.Mode)
	// Issue #3291: detect CI/CD execution context so context-scoped rules
	// (match.context.ci) can tighten posture when the agent is attacker-facing.
	// Detected here, at the live evaluation site, from the process environment
	// the runner set — the hook binary runs inside the CI runner, so its own
	// environment is the ground truth.
	engine.SetExecContext(execenv.Detect(os.Getenv))

	evalResult := engine.EvaluateWithParsedCwd(cmdStr, normalized.Paths, normalized.Parsed, cwd)

	event := logger.AuditEvent{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Command:          cmdStr,
		Args:             cmdArgs,
		Cwd:              cwd,
		Decision:         string(evalResult.Decision),
		TriggeredRules:   evalResult.TriggeredRules,
		Reasons:          evalResult.Reasons,
		TaxonomyRefs:     evalResult.TaxonomyRefs,
		Mode:             cfg.Mode,
		OriginalDecision: string(evalResult.OriginalDecision),
		Source:           source,
		SessionID:        sessionID,
		Principal:        osPrincipal(),
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

	evalResult, _, err := evaluateCommand(cmdStr, input.ToolInfo.Cwd, "windsurf-hook", sessionIDFor(input))
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

	evalResult, _, err := evaluateCommand(cmdStr, input.Cwd, "cursor-hook", sessionIDFor(input))
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

// handleClaudeCodeHook processes Claude Code and Codex CLI PreToolUse hooks.
// Both agents emit the same payload shape ({hook_event_name, tool_name,
// tool_input}); Codex adds turn_id which we use only for audit-log labeling.
// Only Bash tool calls are evaluated; other tools pass through.
// Block → print reason to stderr + exit 2. Allow/Audit → exit 0.
func handleClaudeCodeHook(input hookInput, rawToolInput json.RawMessage) error {
	// turn_id is a Codex-only field. Use it to label the audit source so the
	// dashboard can distinguish Codex from Claude Code traffic.
	source := "claude-code-hook"
	if input.TurnID != "" {
		source = "codex-hook"
	}

	// Shell commands (Bash tool) → evaluate through the analyzer pipeline
	if input.ToolName == "Bash" {
		cmdStr := input.ToolInput.Command
		if cmdStr == "" {
			return nil
		}
		evalResult, _, err := evaluateCommand(cmdStr, "", source, sessionIDFor(input))
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
			fmt.Fprint(os.Stderr, remediation.SuggestForShell(evalResult.TriggeredRules, cmdStr))
			os.Exit(2)
		}
		return nil
	}

	// MCP tool calls → evaluate through MCP policy
	return handleClaudeCodeMCPCall(input.ToolName, rawToolInput, source, sessionIDFor(input))
}

// handleClaudeCodeMCPCall evaluates an MCP tool call against MCP policy packs.
// source identifies the calling agent ("claude-code-hook" or "codex-hook"); it
// is recorded on the audit event and forwarded to SaaS telemetry. sessionID is
// the harness session identifier, carried onto the same audit event so shell
// and MCP evaluations from one session correlate (issue #3111).
func handleClaudeCodeMCPCall(toolName string, rawToolInput json.RawMessage, source, sessionID string) error {
	// Parse tool_input as map for MCP evaluation
	var arguments map[string]interface{}
	if len(rawToolInput) > 0 {
		_ = json.Unmarshal(rawToolInput, &arguments)
	}

	loaded := loadDeployedMCPPolicy("")
	for _, w := range loaded.Warnings {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %s\n", w)
	}

	// Issue #1952: load the AgentShield config so we can apply audit-only
	// mode to MCP tool calls too. The mode resolution lives in config.Load —
	// don't re-implement it here.
	cfg, _ := config.Load(policyPath, logPath, mode)
	modeForAudit := ""
	if cfg != nil {
		modeForAudit = cfg.Mode
	}

	evaluator := mcp.NewPolicyEvaluator(loaded.Policy)
	evaluator.SetMode(modeForAudit)
	result := evaluator.EvaluateToolCall(toolName, arguments)

	// Audit log
	auditMCPCall(toolName, arguments, result, source, modeForAudit, sessionID)

	if result.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED MCP tool call: %s\n", toolName)
		if len(result.TriggeredRules) > 0 {
			fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(result.TriggeredRules, ", "))
		}
		for _, reason := range result.Reasons {
			fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
		}
		fmt.Fprint(os.Stderr, remediation.SuggestForMCP(result.TriggeredRules))
		os.Exit(2)
	}

	// Real AUDIT (by policy) still surfaces to the developer's terminal so
	// audit-by-design rules retain their existing observability. But in
	// audit-only mode (issue #1952), a downgraded BLOCK/REQUIRE_APPROVAL has
	// OriginalDecision set — and printing the rule name there would
	// contradict the "silent rollout" assumption documented for ops. So we
	// suppress the stderr line exactly when the AUDIT came from a downgrade.
	if result.Decision == policy.DecisionAudit && result.OriginalDecision == "" {
		fmt.Fprintf(os.Stderr, "[AgentShield] AUDIT MCP tool: %s\n", toolName)
		if len(result.TriggeredRules) > 0 {
			fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(result.TriggeredRules, ", "))
		}
	}

	return nil
}

// auditMCPCall writes an audit log entry for an MCP tool call evaluation.
// hookSource is the originating shell-hook source ("claude-code-hook" or
// "codex-hook"); we suffix "-mcp" for the audit Source field so log readers can
// tell shell evaluations apart from MCP tool-call evaluations.
// enforcementMode is the AgentShield mode at decision time ("enforce" /
// "audit-only") — recorded so the SaaS can segment telemetry by rollout
// cohort. Issue #1952.
// sessionID is the harness session identifier (issue #3111).
func auditMCPCall(toolName string, arguments map[string]interface{}, result mcp.MCPEvalResult, hookSource, enforcementMode, sessionID string) {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentshield", "audit.jsonl")
	auditLogger, err := logger.New(logPath)
	if err != nil {
		return
	}
	defer func() { _ = auditLogger.Close() }()

	source := "claude-code-mcp-hook"
	if hookSource == "codex-hook" {
		source = "codex-mcp-hook"
	}

	cwd, _ := os.Getwd()

	event := logger.AuditEvent{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		ToolName:     toolName,
		MCPArguments: arguments,
		Cwd:          cwd,
		Decision:     string(result.Decision),
		// Flagged: mirror the shell-side semantics (hook.go above) — both
		// BLOCK and AUDIT events warrant the "look at this" signal in the
		// audit log. Previously MCP marked only BLOCK, which made AUDIT
		// events on MCP invisible to "flagged" filters. Issue #1952 deep-dive.
		Flagged:        result.Decision == policy.DecisionBlock || result.Decision == policy.DecisionAudit,
		TriggeredRules: result.TriggeredRules,
		Reasons:        result.Reasons,
		// Issue #3111: AllTaxonomyRefs merges the Go-intercept ref with the
		// per-rule refs — reading only one of the two silently drops half the
		// MCP decisions from the fusion chain.
		TaxonomyRefs:     result.AllTaxonomyRefs(),
		Mode:             enforcementMode,
		OriginalDecision: string(result.OriginalDecision),
		Source:           source,
		SessionID:        sessionID,
		Principal:        osPrincipal(),
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
	evalResult, _, err := evaluateCommand(cmdStr, cwd, "gemini-cli-hook", sessionIDFor(input))
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
