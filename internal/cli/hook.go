package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
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
//
// GitHub Copilot CLI sends one of two dialects, chosen by the event-name casing
// in its hook config (captured live from 1.0.93, #4251):
//
//	"PreToolUse" (Claude-compatible): the Claude Code shape plus "timestamp" (an
//	  ISO string); tools are mapped to Claude names, but argument names are not
//	  (Read carries "path"). Edits through apply_patch put the raw patch TEXT in
//	  tool_input.
//	"preToolUse" (native): {"sessionId", "timestamp": <int ms>, "cwd",
//	  "toolName", "toolArgs"} with runtime tool names (bash, view, apply_patch).
type hookInput struct {
	// Windsurf fields
	AgentActionName string   `json:"agent_action_name"`
	TrajectoryID    string   `json:"trajectory_id"`
	ExecutionID     string   `json:"execution_id"`
	ToolInfo        toolInfo `json:"tool_info"`

	// Timestamp is metadata no handler reads. It is held raw because harnesses
	// disagree on its type — Windsurf and Copilot's compat dialect send a
	// string, Copilot's native dialect a number — and a typed field turned the
	// number into a parse failure of the WHOLE payload (#4251).
	Timestamp json.RawMessage `json:"timestamp"`

	// Copilot CLI native dialect (#4251). It carries no event name, so
	// toolName is what identifies it; toolArgs is read raw (rawHookInput).
	ToolNameNative  string `json:"toolName"`
	SessionIDNative string `json:"sessionId"`

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

	// IsText is set when tool_input was a JSON string rather than an object
	// (see UnmarshalJSON). The shell path refuses such input instead of
	// reading it as an empty command.
	IsText bool `json:"-"`
}

// UnmarshalJSON additionally accepts a tool_input that is a JSON STRING:
// Copilot CLI's apply_patch edits send the raw patch text there (#4251), and
// rejecting it failed the parse of the whole payload. The string is not kept
// here — handleClaudeCodeMCPCall reads it from the raw tool_input. Every other
// shape keeps the strict decode, so a malformed shell command (a non-string
// "command") still fails the parse and takes the fail-safe path, as before.
func (c *claudeToolInput) UnmarshalJSON(data []byte) error {
	if trimmed := strings.TrimSpace(string(data)); strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		c.IsText = true
		return nil
	}
	type strict claudeToolInput // drops this method, so no recursion
	return json.Unmarshal(data, (*strict)(c))
}

// rawHookInput is used for a second-pass parse to capture tool_input as raw JSON
// (needed for MCP tool calls where arguments are arbitrary key-value pairs).
type rawHookInput struct {
	ToolInput json.RawMessage `json:"tool_input"`
	ToolArgs  json.RawMessage `json:"toolArgs"` // Copilot CLI native dialect
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
			data, _ := io.ReadAll(hookStdinReader())
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

	// Read the machine id sent with every /api/audit event (#4208) while
	// evaluation runs, not after it: on macOS it execs ioreg.
	go prefetchMachineID()

	data, err := io.ReadAll(hookStdinReader())
	if err != nil {
		return hookInputFailure("hook input read", err)
	}

	var input hookInput
	if err := json.Unmarshal(data, &input); err != nil {
		// Before 2026-09-02 this was `return nil // fail open` with a warning:
		// truncated or malformed stdin on a managed fail_closed host allowed
		// the command with no audit event — the one silent allow left after
		// #3622, found by the adversarial review. Same boundary as every other
		// pre-verdict failure now.
		return hookInputFailure("hook input parse", err)
	}

	// Also capture raw tool_input for MCP argument parsing
	var raw rawHookInput
	_ = json.Unmarshal(data, &raw)

	// A string tool_input is accepted for ONE shape: a Claude-shaped
	// PreToolUse call to a non-shell tool (Copilot CLI's apply_patch edits,
	// #4251). For every other harness and shape it fails the parse exactly as
	// before — a Gemini run_shell_command or a Bash call whose input is a
	// string would otherwise read as an empty command and pass unevaluated.
	if input.ToolInput.IsText && (input.HookEventName != "PreToolUse" || input.ToolName == "Bash") {
		return hookInputFailure("hook input parse", errors.New("tool_input is a string where an object is required"))
	}

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
	// Cursor's documented payload carries hook_event_name on every event
	// (#4261); for the shell hook it is "beforeShellExecution" with the
	// command at the top level and no tool_name. Without this the Claude branch
	// below saw an empty tool name and never evaluated the command.
	if input.HookEventName == "beforeShellExecution" && input.ToolName == "" {
		return handleCursorHook(input)
	}
	if input.HookEventName != "" {
		return handleClaudeCodeHook(input, raw.ToolInput)
	}

	if input.Command != "" {
		return handleCursorHook(input)
	}

	if input.AgentActionName == "pre_run_command" {
		return handleWindsurfHook(input)
	}

	// Copilot CLI's native dialect has no event name; toolName identifies it.
	// Checked LAST, so a stray toolName key on a Cursor or Windsurf payload
	// cannot reroute it away from its own handler (#4251 review).
	if input.ToolNameNative != "" {
		return handleCopilotNativeHook(input, raw.ToolArgs)
	}

	// Unsupported hook events pass through
	return nil
}

// evaluateCommand is the shared policy evaluation logic for all IDE hooks.
// sessionID is the harness's own session identifier (see sessionIDFor); pass
// "" when the harness doesn't provide one.
//
// It never returns an error. Every failure on the way to a verdict — config
// load, audit-log init, policy load, pack parse, engine init — goes through
// failSafeDecision (#3619), so a broken policy or an unwritable log is a
// DECISION: BLOCK under managed fail_closed, AUDIT with a flagged event
// otherwise. Before #3619 two of those sites returned a plain error and every
// harness handler turned it into a silent allow; the signature is what makes
// that impossible to reintroduce.
func evaluateCommand(cmdStr, cwd, source, sessionID string) (*policy.EvalResult, *logger.AuditEvent) {
	return evaluateCommandNoted(cmdStr, cwd, source, sessionID, nil)
}

// evaluateCommandNoted is evaluateCommand plus notes the caller already holds
// about this evaluation (#4452: a payload cwd that could not be used). They go
// on every event the evaluation records, before it is logged or sent; they
// never change a decision.
func evaluateCommandNoted(cmdStr, cwd, source, sessionID string, notes []logger.Note) (*policy.EvalResult, *logger.AuditEvent) {
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
				Notes:          append([]logger.Note(nil), notes...),
			}
			recordSelfProtectBlock(&event)
			return &blockedResult, &event
		}
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return failSafeDecision(evalFailure{stage: "config load", err: err, notes: notes}, cmdStr, cwd, source, sessionID)
	}

	auditLogger, err := logger.New(cfg.LogPath)
	if err != nil {
		return failSafeDecision(evalFailure{stage: "audit log init", err: err, cfg: cfg, notes: notes}, cmdStr, cwd, source, sessionID)
	}
	defer func() {
		_ = auditLogger.Close()
	}()

	cmdArgs := strings.Fields(cmdStr)
	normalized := normalize.NormalizeCommand(cmdStr, cwd)

	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return failSafeDecision(evalFailure{stage: "policy load", err: err, cfg: cfg, log: auditLogger, notes: notes}, cmdStr, cwd, source, sessionID)
	}
	// #3620: on a managed host the local policy cannot weaken the admin's.
	// Applied to the user file BEFORE packs merge in, so a premium pack's own
	// disable_rules (a deliberate tier split) are untouched.
	if dropped := dropLocalDisablesWhenManaged(pol, cfg); len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "[AgentShield] managed mode: ignoring local disable_rules (%s) — only the admin's policy applies\n", strings.Join(dropped, ", "))
	}
	// #3620, path layer: on a managed host the config directory is a protected
	// path unless the command is a plain read. The text rule
	// (sp-block-config-touch) sees spellings; this sees the paths the
	// analyzers materialize — `CFG=$HOME/.agentshield; python3 -c
	// "open('$CFG/policy.yaml','w')"` names the directory nowhere in its text
	// and exited 0 before this.
	protectManagedConfigDir(pol, cfg, cmdStr)

	// Layer 1: embedded community shell packs (always available, no disk dep).
	pol, embeddedInfos, _ := policy.LoadEmbeddedShellPacks(pol)
	embeddedOnlyPolicy := pol

	// Layer 2: disk-installed packs (premium from SaaS, user custom).
	packsPath := filepath.Join(cfg.ConfigDir, "packs")
	pol, diskInfos, packsLoadErr := policy.LoadPacks(packsPath, pol)
	if packsLoadErr != nil {
		// #4071: LoadPacks returns (nil, nil, err) on anything but a missing
		// directory (e.g. permission denied on the packs dir). Assigning that
		// nil straight into pol used to reach NewEngineWithAnalyzers(nil, …)
		// and panic before any command was evaluated — Go's panic exit status
		// (2) reads as BLOCK to Claude Code/Codex, so a total enforcement
		// outage looked like a decision instead of the crash it was, and
		// harnesses expecting a JSON verdict got a stack trace. Restore the
		// embedded-only policy already loaded above (the same fail-open shape
		// `agentshield check` uses) and warn loudly; under managed
		// fail_closed, refuse instead — an entirely unreadable disk layer is
		// at least as degraded as the single-pack-parse-failure case below.
		pol = embeddedOnlyPolicy
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: packs load failed: %v — evaluating with base, user and embedded packs only; disk (premium/custom) rules are NOT loaded\n", packsLoadErr)
		if failClosedEnabled(cfg) {
			return failSafeDecision(evalFailure{
				stage: "packs load",
				err:   fmt.Errorf("disk packs directory unreadable, enforcement would be degraded: %w", packsLoadErr),
				cfg:   cfg,
				log:   auditLogger,
				notes: notes,
			}, cmdStr, cwd, source, sessionID)
		}
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
	if len(failedPacks) > 0 && failClosedEnabled(cfg) {
		return failSafeDecision(evalFailure{
			stage: "policy pack parse",
			err:   fmt.Errorf("%d policy pack(s) failed to parse; enforcement would be degraded", len(failedPacks)),
			cfg:   cfg,
			log:   auditLogger,
			notes: notes,
		}, cmdStr, cwd, source, sessionID)
	}

	// The mode (#1952) and the CI execution context (#3291) are applied in
	// assembly.ShellEngine. The context is detected from this process's
	// environment: the hook binary runs inside the CI runner, so its own
	// environment is the ground truth.
	engine, err := assembly.ShellEngine(pol, cfg.Analyzer.MaxParseDepth, cfg.Mode)
	if err != nil {
		return failSafeDecision(evalFailure{stage: "engine init", err: err, cfg: cfg, log: auditLogger, notes: notes}, cmdStr, cwd, source, sessionID)
	}

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
		Notes:            append(auditNotes(evalResult.Notes), notes...),
	}
	// #4448: a data-label match must not travel in the record it caused.
	// Redacted() scrubs the local line and the SaaS payload alike.
	if scrub := policy.DataLabelScrubber(pol); scrub != nil {
		event = event.WithScrubber(scrub)
	}
	// #4077 pass 1: the fallback above keeps evaluating, so the event must say
	// it ran degraded. Without this note the SaaS receives an ordinary
	// evaluation from a host that has lost every premium and custom rule —
	// an attestation of full enforcement that did not happen. The decision is
	// unchanged; the note is evidence, not a verdict.
	if packsLoadErr != nil {
		event.Notes = append(event.Notes, logger.Note{
			Kind:   analyzer.NotePolicyDegraded,
			Detail: "disk packs unreadable; evaluated with base, user and embedded packs only: " + packsLoadErr.Error(),
		})
	}

	noteLockUnavailable(&event, auditLogger)

	if evalResult.Decision == policy.DecisionBlock || evalResult.Decision == policy.DecisionAudit {
		event.Flagged = true
	}
	link, err := auditLogger.LogLinked(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
	}

	// Queue for the SaaS with the local line's link (#4208). No network
	// here: a detached uploader sends it (audit_queue.go, #4467).
	sendRemoteAudit(&event, link)

	return &evalResult, &event
}

// recordSelfProtectBlock writes a pre-eval (self-protect / bypass-guard) BLOCK
// to the local audit chain and the SaaS (#4333). The block returns before the
// main path opens the logger, and every caller discards the returned event, so
// without this the attempt to tamper with AgentShield was recorded nowhere.
// Best effort: a failure to record never changes the decision.
func recordSelfProtectBlock(event *logger.AuditEvent) {
	var link *logger.ChainLink
	if cfg, err := config.Load(policyPath, logPath, mode); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: self-protect block not logged locally: config load: %v\n", err)
	} else if l, err := logger.New(cfg.LogPath); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: self-protect block not logged locally: %v\n", err)
	} else {
		noteLockUnavailable(event, l)
		if link, err = l.LogLinked(*event); err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
		}
		_ = l.Close()
	}
	sendRemoteAudit(event, link)
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

	evalResult, _ := evaluateCommand(cmdStr, input.ToolInfo.Cwd, "windsurf-hook", sessionIDFor(input))

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

	evalResult, _ := evaluateCommand(cmdStr, input.Cwd, "cursor-hook", sessionIDFor(input))

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
	return handlePreToolUse(input, rawToolInput, hookSourceFor(input, "claude-code-hook"))
}

// handleCopilotNativeHook adapts GitHub Copilot CLI's native "preToolUse"
// dialect (#4251) onto the Claude-shaped core. The shell tools (bash, and
// powershell on Windows) become Bash; every other runtime tool name is kept
// and goes through MCP policy — the same mapping as the agentless PowerShell
// client. toolArgs is decoded exactly as tool_input is, so a malformed shell
// command takes the fail-safe path in both dialects.
func handleCopilotNativeHook(input hookInput, rawToolArgs json.RawMessage) error {
	adapted := hookInput{
		HookEventName: "preToolUse",
		ToolName:      input.ToolNameNative,
		SessionID:     input.SessionIDNative,
		Cwd:           input.Cwd,
	}
	if adapted.ToolName == "bash" || adapted.ToolName == "powershell" {
		adapted.ToolName = "Bash"
	}
	if len(rawToolArgs) > 0 {
		if err := json.Unmarshal(rawToolArgs, &adapted.ToolInput); err != nil {
			return hookInputFailureFor(hookSourceFor(adapted, "copilot-cli-hook"), "hook input parse", err)
		}
	}
	return handlePreToolUse(adapted, rawToolArgs, hookSourceFor(adapted, "copilot-cli-hook"))
}

// handlePreToolUse is the shared core for every Claude-shaped PreToolUse
// payload: Claude Code, Codex CLI, and both Copilot CLI dialects.
func handlePreToolUse(input hookInput, rawToolInput json.RawMessage, source string) error {
	// Shell commands (Bash tool) → evaluate through the analyzer pipeline
	if input.ToolName == "Bash" {
		// A string tool_input is accepted for edits (apply_patch), never for
		// a shell call: no client sends one, and reading it as an empty
		// command would pass the call unevaluated and unrecorded. Before
		// #4251 the shape failed the parse; it still takes the fail-safe path.
		if input.ToolInput.IsText {
			return hookInputFailureFor(source, "hook input parse", errors.New("shell tool_input is a string, not an object"))
		}
		cmdStr := input.ToolInput.Command
		if cmdStr == "" {
			return nil
		}
		// #4452: evaluate where the agent's shell runs the command — the
		// payload's cwd — not where the harness happened to start this
		// process. An unusable payload cwd falls back to the process
		// directory (main's behaviour) with a note on the event.
		cwd, cwdNotes := payloadEvalCwd(input.Cwd)
		evalResult, _ := evaluateCommandNoted(cmdStr, cwd, source, sessionIDFor(input), cwdNotes)
		if evalResult.Decision == policy.DecisionBlock {
			fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED this command\n")
			if len(evalResult.TriggeredRules) > 0 {
				fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(evalResult.TriggeredRules, ", "))
			}
			for _, reason := range evalResult.Reasons {
				fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
			}
			fmt.Fprint(os.Stderr, remediation.SuggestForShell(evalResult.TriggeredRules, cmdStr, enterprise.ManagedHost()))
			emitCopilotDeny(source, "this command", evalResult.TriggeredRules, evalResult.Reasons)
			os.Exit(2)
		}
		return nil
	}

	// MCP tool calls → evaluate through MCP policy
	return handleClaudeCodeMCPCall(input.ToolName, rawToolInput, source, sessionIDFor(input), input.Cwd)
}

// agentIDPattern bounds AGENTSHIELD_AGENT_ID to a plain label, so the value
// that lands in every audit event's source cannot carry anything else.
var agentIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// agentIDFromEnv returns AGENTSHIELD_AGENT_ID when it is a plain label, else "".
func agentIDFromEnv() string {
	if id := os.Getenv("AGENTSHIELD_AGENT_ID"); agentIDPattern.MatchString(id) {
		return id
	}
	return ""
}

// hookSourceFor labels the audit source of a Claude-shaped payload.
// AGENTSHIELD_AGENT_ID, set in the harness's own hook config (`agentshield
// setup copilot-cli` writes it), names the harness when the payload cannot:
// Copilot CLI's Claude-compatible dialect is otherwise indistinguishable from
// Claude Code's. turn_id is Codex-only, as before. The same variable names the
// agent on the agentless clients' verdicts.
func hookSourceFor(input hookInput, fallback string) string {
	if id := agentIDFromEnv(); id != "" {
		return id + "-hook"
	}
	if input.TurnID != "" {
		return "codex-hook"
	}
	return fallback
}

// emitCopilotDeny writes GitHub Copilot CLI's deny verdict to stdout (#4251).
// Copilot treats exit 2 as a deny and shows permissionDecisionReason to the
// agent; without it the agent learns only that a hook refused. It is written
// for a Copilot source only, so Claude Code and Codex output is unchanged.
func emitCopilotDeny(source, what string, rules, reasons []string) {
	if !strings.HasPrefix(source, "copilot-cli") {
		return
	}
	parts := []string{"AgentShield BLOCKED " + what}
	if len(rules) > 0 {
		parts = append(parts, "Rule: "+strings.Join(rules, ", "))
	}
	for _, r := range reasons {
		parts = append(parts, "Reason: "+r)
	}
	out, _ := json.Marshal(map[string]string{
		"permissionDecision":       "deny",
		"permissionDecisionReason": strings.Join(parts, " | "),
	})
	fmt.Fprintln(os.Stdout, string(out))
}

// stringToolInputArguments gives a tool_input that is a JSON string an
// argument map the MCP rules can read, instead of the empty map a failed
// object decode leaves: an apply_patch body ("*** Begin Patch") under "patch",
// anything else under "input" — the keys the agentless PowerShell client
// forwards (#4252). Evaluating each patched file is #4253.
func stringToolInputArguments(raw json.RawMessage) (map[string]interface{}, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	key := "input"
	if strings.HasPrefix(s, "*** Begin Patch") {
		key = "patch"
	}
	return map[string]interface{}{key: s}, true
}

// handleClaudeCodeMCPCall evaluates an MCP tool call against MCP policy packs.
// source identifies the calling agent ("claude-code-hook" or "codex-hook"); it
// is recorded on the audit event and forwarded to SaaS telemetry. sessionID is
// the harness session identifier, carried onto the same audit event so shell
// and MCP evaluations from one session correlate (issue #3111). cwd is the
// payload's session directory, against which a relative write target resolves.
func handleClaudeCodeMCPCall(toolName string, rawToolInput json.RawMessage, source, sessionID, cwd string) error {
	// #4452: the event records the directory the shell path evaluates
	// against — the payload cwd when usable, else the process directory with
	// a note. The managed config-write check below keeps reading the raw
	// payload cwd, exactly as before: routing it through the fallback would
	// change which file a relative write target names for a malformed cwd.
	auditCwd, auditCwdNotes := payloadEvalCwd(cwd)

	// Parse tool_input as map for MCP evaluation
	var arguments map[string]interface{}
	fromText := false
	if len(rawToolInput) > 0 {
		if textArgs, ok := stringToolInputArguments(rawToolInput); ok {
			arguments, fromText = textArgs, true
		} else {
			_ = json.Unmarshal(rawToolInput, &arguments)
		}
	}

	// #4260: on a managed host a harness's own write tool may not touch the
	// config directory. Checked first, like the shell path's SelfProtect
	// middleware: it needs no policy, so a broken ruleset cannot switch it off.
	if result, blocked := managedConfigToolWrite(toolName, arguments, fromText, cwd); blocked {
		auditMCPCall(toolName, arguments, result, source, "managed", sessionID, auditCwd, auditCwdNotes)
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED tool call: %s\n   Rule: %s\n   Reason: %s\n", toolName, strings.Join(result.TriggeredRules, ", "), result.Reasons[0])
		emitCopilotDeny(source, "tool call: "+toolName, result.TriggeredRules, result.Reasons)
		os.Exit(2)
	}

	loaded := loadDeployedMCPPolicy("")
	for _, w := range loaded.Warnings {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %s\n", w)
	}

	// Issue #1952: load the AgentShield config so we can apply audit-only
	// mode to MCP tool calls too. The mode resolution lives in config.Load —
	// don't re-implement it here.
	cfg, cfgErr := config.Load(policyPath, logPath, mode)
	modeForAudit := ""
	if cfg != nil {
		modeForAudit = cfg.Mode
	}

	// The MCP path had no fail-closed boundary (adversarial review of #3622,
	// 2026-09-02): the config error was discarded, and a corrupt MCP policy or
	// pack became a warning plus a silent fallback to whatever loaded. Same
	// contract as the shell path now: on a managed fail_closed host a degraded
	// ruleset blocks; elsewhere it is evaluated but said out loud.
	if degraded := mcpRulesetDegraded(cfgErr, loaded); degraded != "" {
		if failClosedEnabled(cfg) {
			result := mcp.MCPEvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{failClosedRuleID},
				Reasons:        []string{"AgentShield: MCP ruleset failed to load — blocking (fail_closed enabled): " + degraded},
			}
			auditMCPCall(toolName, arguments, result, source, "managed", sessionID, auditCwd, auditCwdNotes)
			fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED MCP tool call: %s\n   Reason: %s\n", toolName, result.Reasons[0])
			emitCopilotDeny(source, "MCP tool call: "+toolName, result.TriggeredRules, result.Reasons)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: MCP ruleset degraded (%s) — evaluated against what loaded (fail-safe default, not enforced as configured)\n", degraded)
	}

	// Enforce mode (""): the verdict is computed as enforce mode computes it,
	// and the configured mode is applied once, last, with the self-protection
	// keep rule the proxies, shield-server and mcp-eval share (#4337 review
	// B1): in audit-only mode a BLOCK on AgentShield's own configuration or an
	// agent hook file still blocks. The downgrade used to happen inside the
	// evaluator, which lowered those BLOCKs too.
	evaluator := assembly.MCPEvaluator(loaded.Policy, "")
	result := evaluator.EvaluateToolCall(toolName, arguments)

	// #4351: Claude Code names an MCP server's tool mcp__<server>__<tool>, and
	// the pack rules are authored against the bare <tool> (write_file, ...), so
	// the wire name alone missed them all. Evaluate the bare name too; the
	// second reading can only ADD a block. shield-server applies the same rule
	// through the same helper.
	if bare, ok := mcp.BareToolName(toolName); ok {
		result = mcp.PreferBlockingBareResult(result, evaluator.EvaluateToolCall(bare, arguments))
	}
	result = evaluator.ApplyModeKeepingSelfProtection(result, modeForAudit, toolName, arguments)

	// Audit log
	auditMCPCall(toolName, arguments, result, source, modeForAudit, sessionID, auditCwd, auditCwdNotes)

	if result.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED MCP tool call: %s\n", toolName)
		if len(result.TriggeredRules) > 0 {
			fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(result.TriggeredRules, ", "))
		}
		for _, reason := range result.Reasons {
			fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
		}
		fmt.Fprint(os.Stderr, remediation.SuggestForMCP(result.TriggeredRules, enterprise.ManagedHost()))
		emitCopilotDeny(source, "MCP tool call: "+toolName, result.TriggeredRules, result.Reasons)
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
// cwd is the evaluation directory (payloadEvalCwd, #4452); "" records the
// process directory, as every MCP event did before. notes go on the event.
func auditMCPCall(toolName string, arguments map[string]interface{}, result mcp.MCPEvalResult, hookSource, enforcementMode, sessionID, cwd string, notes []logger.Note) {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".agentshield", "audit.jsonl")
	// "<agent>-hook" becomes "<agent>-mcp-hook" (claude-code, codex,
	// copilot-cli, …), so one harness's shell and MCP events share a prefix.
	source := "claude-code-mcp-hook"
	if agent, ok := strings.CutSuffix(hookSource, "-hook"); ok && agent != "" {
		source = agent + "-mcp-hook"
	}

	if cwd == "" {
		cwd, _ = os.Getwd()
	}

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
		Notes:            append([]logger.Note(nil), notes...),
	}
	// An unopenable local log still sends the event to the SaaS, with no
	// local_chain (#4208: none is better than a made-up one), as the shell
	// path does in failSafeDecision (#4470).
	auditLogger, err := logger.New(logPath)
	if err != nil {
		sendRemoteAudit(&event, nil)
		return
	}
	defer func() { _ = auditLogger.Close() }()

	noteLockUnavailable(&event, auditLogger)
	link, _ := auditLogger.LogLinked(event)

	// Queue for the SaaS with the local line's link (#4208; audit_queue.go,
	// #4467).
	sendRemoteAudit(&event, link)
}

// lockNoteSource is the slice of the audit logger noteLockUnavailable needs.
type lockNoteSource interface {
	LockUnavailableNote() (logger.Note, bool)
}

// noteLockUnavailable appends the logger's audit_lock_unavailable note to
// event when the logger runs without its cross-process lock (#4052 round 2).
// Log stamps that note on the persisted line itself, but on a copy, so every
// path that also POSTs the event to the SaaS calls this before Log and
// sendRemoteAudit; otherwise the disk line carries a note the wire never saw
// (the #4077 pass-2 class; Opus pass 2 on #4057 found the MCP and fail-safe
// paths without it). Log deduplicates, so the line still carries it once.
// A nil logger is a no-op, typed or untyped: the fail-safe boundary may hold
// no logger at all.
func noteLockUnavailable(event *logger.AuditEvent, l lockNoteSource) {
	if l == nil {
		return
	}
	if note, degraded := l.LockUnavailableNote(); degraded {
		event.Notes = append(event.Notes, note)
	}
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
	evalResult, _ := evaluateCommand(cmdStr, cwd, "gemini-cli-hook", sessionIDFor(input))

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

// auditNotes converts evaluation notes to their audit-event form (#3995).
// The two types are identical by construction; the copy keeps the logger a
// leaf package. nil in, nil out, so an event with no notes omits the key.
func auditNotes(ns []analyzer.Note) []logger.Note {
	if len(ns) == 0 {
		return nil
	}
	out := make([]logger.Note, 0, len(ns))
	for _, n := range ns {
		out = append(out, logger.Note{Kind: n.Kind, Rule: n.Rule, Detail: n.Detail})
	}
	return out
}
