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
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/policy/remediation"
	"github.com/AI-AgentLens/agentshield/internal/route"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
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
	// A call that returns without recording anything (nothing to evaluate,
	// or no lane had anything to read) still answers it: exit 0. Once the
	// decision budget is armed that answer is a claim like any other write
	// (hook_budget.go), so it never races the watchdog's.
	hookBudgetEnabled = true
	defer func() { activeBudget.claimForEvaluation() }()

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
	// Which tool is a shell is the routing table's call (ADR-001). A row that
	// also has the Structured lane (Claude Code's Monitor, #4753) is read and
	// recorded by that lane, as it was before the shell lane joined it.
	if input.ToolInput.IsText && (input.HookEventName != "PreToolUse" || shellOnlyRow(preToolUseCall(claudeShapedHarness(input), input))) {
		return hookInputFailure("hook input parse", errors.New("tool_input is a string where an object is required"))
	}

	// The budget counts from process start, not from arming: a slow step
	// before a handler arms still counts (TestHookBudget_CountsFromProcessStart).
	hookSlowPoint("before-arm")

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
	r := readCommand(cmdStr, cwd, source, sessionID, notes)
	r.record(nil)
	return r.result, r.event
}

// commandReading is one evaluation of a shell command, held before it is
// recorded: the verdict, the event that records it, and write, the path's
// own way of recording that event (the local audit line and the SaaS queue).
// Building one writes nothing; record is the only step that does, so a lane
// the combiner does not keep (ADR-001 D4) leaves no record.
type commandReading struct {
	result *policy.EvalResult
	event  *logger.AuditEvent
	write  func(*logger.AuditEvent)
	close  func() // releases the audit logger the evaluation opened; nil when none
}

// record writes the event, with extra notes after its own, and releases the
// reading. extra is nil for a call one lane decides, so its event is the one
// evaluateCommandNoted has always written. It claims the call first
// (hook_budget.go): past the decision budget the watchdog may already have
// answered it, and then this never returns.
func (r *commandReading) record(extra []logger.Note) {
	activeBudget.claimForEvaluation()
	r.event.Notes = append(r.event.Notes, extra...)
	r.write(r.event)
	r.release()
}

// release drops the reading without recording it.
func (r *commandReading) release() {
	if r.close != nil {
		r.close()
		r.close = nil
	}
}

// readCommand is evaluateCommandNoted up to the point it writes. Every path
// to a verdict (the managed self-protection BLOCK, each failSafeDecision
// stage, and the policy evaluation) returns its reading here with the writer
// that path has always used.
func readCommand(cmdStr, cwd, source, sessionID string, notes []logger.Note) *commandReading {
	return readShellShaped(cmdStr, cwd, source, sessionID, notes, posixEvaluation)
}

// shellShapedEvaluation is how one shell lane decides a command text once the
// hook has built the engine for it (readShellShaped). Every shell lane shares
// the load sequence, the fail-safe boundary and the shell-shaped record; only
// this step differs.
type shellShapedEvaluation struct {
	// stage names a failure of evaluate at the fail-safe boundary.
	stage string
	// middleware runs the enterprise middleware chain (BypassGuard, the sp-*
	// text rules) before anything else. The POSIX lane runs it; the
	// PowerShell lane does not (hook_powershell.go says where the rules reach
	// PowerShell text and where they do not).
	middleware bool
	// parsesPOSIX: the lane parses the command with the bash parser, so a
	// command past the chain bound is decided without parsing it (#4778,
	// chain_bound.go). The PowerShell lane's own reader is not the bash
	// parser; its nested bash texts are bounded where it reads them
	// (psLane.readPOSIX).
	parsesPOSIX bool
	evaluate    func(engine *policy.Engine, cfg *config.Config, cmdStr, cwd string) (policy.EvalResult, error)
}

// posixEvaluation is the POSIX lane: the bash normalizer and the analyzer
// pipeline. A derived text past the chain bound is its error (#4778).
var posixEvaluation = shellShapedEvaluation{
	stage:       "policy evaluation",
	middleware:  true,
	parsesPOSIX: true,
	evaluate: func(engine *policy.Engine, _ *config.Config, cmdStr, cwd string) (policy.EvalResult, error) {
		r, e := readPOSIXText(engine, cmdStr, cwd)
		if e != nil {
			return r, e
		}
		return r, nil
	},
}

// middlewareBlock runs the enterprise middleware chain on cmdStr, and returns
// its BLOCK when it blocked. Empty outside managed mode.
func middlewareBlock(cmdStr, cwd, source string) (*policy.EvalResult, bool) {
	return middlewareBlockWith(buildMiddlewareChain(), cmdStr, cwd, source, selfProtectTaxonomyRefs)
}

// middlewareBlockWith runs chain on cmdStr and returns its BLOCK, with the
// receipt's nodes from refs.
func middlewareBlockWith(chain []enterprise.EvalMiddleware, cmdStr, cwd, source string, refs func(ruleID, command string) []string) (*policy.EvalResult, bool) {
	if len(chain) == 0 {
		return nil, false
	}
	// Run pre-eval middleware (SelfProtect, BypassGuard)
	ctx := &enterprise.EvalContext{Command: cmdStr, Cwd: cwd, Source: source}
	enterprise.RunChain(ctx, chain)
	if !ctx.Blocked {
		return nil, false
	}
	// On a managed host this BLOCK is the only record of the attempt, so it
	// carries the node of the sp-* rule that fired (self_protect_taxonomy.go).
	// The node is per rule, never one for the whole middleware: an audit-log
	// delete is not tampering, and sp-block-config-touch also blocks reads
	// (#4603).
	return &policy.EvalResult{
		Decision:       policy.DecisionBlock,
		TriggeredRules: []string{"enterprise-self-protect"},
		Reasons:        []string{ctx.BlockMsg},
		Explanation:    ctx.BlockMsg,
		TaxonomyRefs:   refs(ctx.BlockRule, ctx.Command),
	}, true
}

// selfProtectReading is the reading of a self-protection BLOCK: a managed
// BLOCK event, recorded by recordSelfProtectBlock.
func selfProtectReading(blocked *policy.EvalResult, cmdStr, cwd, source, sessionID string, notes []logger.Note) *commandReading {
	blockedResult := *blocked
	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Command:        cmdStr,
		Args:           strings.Fields(cmdStr),
		Cwd:            cwd,
		Decision:       "BLOCK",
		Flagged:        true,
		TriggeredRules: blockedResult.TriggeredRules,
		Reasons:        blockedResult.Reasons,
		TaxonomyRefs:   blockedResult.TaxonomyRefs,
		Mode:           "managed",
		Source:         source,
		SessionID:      sessionID,
		Principal:      osPrincipal(),
		Notes:          append([]logger.Note(nil), notes...),
	}
	return &commandReading{result: &blockedResult, event: &event, write: recordSelfProtectBlock}
}

// readShellShaped reads cmdStr with one shell lane and returns the reading,
// unwritten, with the writer its path has always used.
func readShellShaped(cmdStr, cwd, source, sessionID string, notes []logger.Note, lane shellShapedEvaluation) *commandReading {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	failSafe := func(f evalFailure, closer func()) *commandReading {
		result, event, write := failSafeReading(f, cmdStr, cwd, source, sessionID)
		return &commandReading{result: result, event: event, write: write, close: closer}
	}

	// #4778: a command past the chain bound is not parsed, by the middleware
	// or the pipeline (chain_bound.go).
	if lane.parsesPOSIX {
		if e := shellparse.CheckChainBound(cmdStr); e != nil {
			return readPastChainBound(cmdStr, cwd, source, sessionID, notes, e)
		}
	}

	if lane.middleware {
		var blocked *policy.EvalResult
		var ok bool
		if e := shellparse.GuardChainBound(cmdStr, func() { blocked, ok = middlewareBlock(cmdStr, cwd, source) }); e != nil {
			return readPastChainBound(cmdStr, cwd, source, sessionID, notes, e)
		}
		if ok {
			return selfProtectReading(blocked, cmdStr, cwd, source, sessionID, notes)
		}
	}

	hookSlowPoint("load")
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return failSafe(evalFailure{stage: "config load", err: err, notes: notes}, nil)
	}

	auditLogger, err := logger.New(cfg.LogPath)
	if err != nil {
		return failSafe(evalFailure{stage: "audit log init", err: err, cfg: cfg, notes: notes}, nil)
	}
	closeLog := func() { _ = auditLogger.Close() }

	cmdArgs := strings.Fields(cmdStr)

	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return failSafe(evalFailure{stage: "policy load", err: err, cfg: cfg, log: auditLogger, notes: notes}, closeLog)
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
			return failSafe(evalFailure{
				stage: "packs load",
				err:   fmt.Errorf("disk packs directory unreadable, enforcement would be degraded: %w", packsLoadErr),
				cfg:   cfg,
				log:   auditLogger,
				notes: notes,
			}, closeLog)
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
		return failSafe(evalFailure{
			stage: "policy pack parse",
			err:   fmt.Errorf("%d policy pack(s) failed to parse; enforcement would be degraded", len(failedPacks)),
			cfg:   cfg,
			log:   auditLogger,
			notes: notes,
		}, closeLog)
	}

	// #4448, #4805: the data labels this call's record is scrubbed with,
	// compiled once the policy is complete. They scrub the event below, and
	// every fail-safe reading of the call from here on, the decision
	// budget's answer included.
	labels := labelsFor(pol.DataLabels)
	activeBudget.publishLabels(labels)

	// The mode (#1952) and the CI execution context (#3291) are applied in
	// assembly.ShellEngine. The context is detected from this process's
	// environment: the hook binary runs inside the CI runner, so its own
	// environment is the ground truth.
	engine, err := assembly.ShellEngine(pol, cfg.Analyzer.MaxParseDepth, cfg.Mode)
	if err != nil {
		return failSafe(evalFailure{stage: "engine init", err: err, cfg: cfg, log: auditLogger, notes: notes, labels: labels}, closeLog)
	}

	hookSlowPoint("evaluate")
	evalResult, err := lane.evaluate(engine, cfg, cmdStr, cwd)
	if chain, ok := err.(*shellparse.ChainTooLongError); ok {
		// A derived text past the chain bound (#4778).
		return failSafe(evalFailure{stage: commandParseStage, err: chain, cfg: cfg, log: auditLogger, notes: withChainTooLongNote(notes, chain), chainTooLong: true}, closeLog)
	}
	if err != nil {
		return failSafe(evalFailure{stage: lane.stage, err: err, cfg: cfg, log: auditLogger, notes: notes, labels: labels}, closeLog)
	}

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
	// Redacted() scrubs the local line and the SaaS payload alike. A label
	// set that does not compile never gets here (engine init refuses it).
	if labels.scrub != nil {
		event = event.WithScrubber(labels.scrub)
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

	write := func(event *logger.AuditEvent) {
		noteLockUnavailable(event, auditLogger)

		if event.Decision == string(policy.DecisionBlock) || event.Decision == string(policy.DecisionAudit) {
			event.Flagged = true
		}
		// One redaction for the line and the wire entry (#4781).
		red := redactForRecord(event)
		link, err := auditLogger.LogLinkedRedacted(red)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
		}

		// Queue for the SaaS with the local line's link (#4208). No network
		// here: a detached uploader sends it (audit_queue.go, #4467).
		sendRemoteAuditRedacted(red, link)
	}
	return &commandReading{result: &evalResult, event: &event, write: write, close: closeLog}
}

// recordSelfProtectBlock writes a pre-eval (self-protect / bypass-guard) BLOCK
// to the local audit chain and the SaaS (#4333). The block returns before the
// main path opens the logger, and every caller discards the returned event, so
// without this the attempt to tamper with AgentShield was recorded nowhere.
// Best effort: a failure to record never changes the decision.
func recordSelfProtectBlock(event *logger.AuditEvent) {
	var link *logger.ChainLink
	var l *logger.AuditLogger
	if cfg, err := config.Load(policyPath, logPath, mode); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: self-protect block not logged locally: config load: %v\n", err)
	} else if l, err = logger.New(cfg.LogPath); err != nil {
		l = nil
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: self-protect block not logged locally: %v\n", err)
	} else {
		noteLockUnavailable(event, l)
	}
	// One redaction for the line and the wire entry (#4781).
	red := redactForRecord(event)
	if l != nil {
		var err error
		if link, err = l.LogLinkedRedacted(red); err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
		}
		_ = l.Close()
	}
	sendRemoteAuditRedacted(red, link)
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
	if !routesToShell(route.ToolCall{Harness: route.Windsurf, Tool: input.AgentActionName, OS: hostOS(), HasCommand: true}) {
		return nil
	}

	source, sessionID := "windsurf-hook", sessionIDFor(input)
	armHookBudget(shellBudgetCall(route.Windsurf, input.AgentActionName, source, sessionID, cmdStr, literalCwd(input.ToolInfo.Cwd), emitWindsurfVerdict))
	evalResult, _ := evaluateCommand(cmdStr, input.ToolInfo.Cwd, source, sessionID)
	emitWindsurfVerdict(evalResult)
	return nil
}

// emitWindsurfVerdict writes Windsurf's verdict: on a BLOCK the explanation
// on stderr and exit 2; otherwise nothing.
func emitWindsurfVerdict(evalResult *policy.EvalResult) {
	if evalResult.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛑 BLOCKED by AgentShield\n")
		fmt.Fprintf(os.Stderr, "%s\n", evalResult.Explanation)
		os.Exit(2)
	}
}

// handleCursorHook processes Cursor hooks (beforeShellExecution).
// Block = JSON output with permission: "deny".
func handleCursorHook(input hookInput) error {
	cmdStr := input.Command
	if cmdStr == "" {
		outputCursorAllow()
		return nil
	}
	// Both Cursor shapes reaching this handler are its shell event: the
	// documented one names it, the legacy one is the same event without it.
	if !routesToShell(route.ToolCall{Harness: route.Cursor, Tool: cursorShellEvent, OS: hostOS(), HasCommand: true}) {
		outputCursorAllow()
		return nil
	}

	source, sessionID := "cursor-hook", sessionIDFor(input)
	armHookBudget(shellBudgetCall(route.Cursor, cursorShellEvent, source, sessionID, cmdStr, literalCwd(input.Cwd), emitCursorVerdict))
	evalResult, _ := evaluateCommand(cmdStr, input.Cwd, source, sessionID)
	emitCursorVerdict(evalResult)
	return nil
}

// emitCursorVerdict writes Cursor's verdict on stdout: permission deny on a
// BLOCK, allow otherwise.
func emitCursorVerdict(evalResult *policy.EvalResult) {
	if evalResult.Decision == policy.DecisionBlock {
		output := cursorHookOutput{
			Continue:     true,
			Permission:   "deny",
			UserMessage:  "🛑 BLOCKED by AgentShield: " + strings.Join(evalResult.Reasons, "; "),
			AgentMessage: evalResult.Explanation,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return
	}
	outputCursorAllow()
}

// cursorShellEvent is Cursor's shell hook event, the routing key of every
// payload handleCursorHook receives.
const cursorShellEvent = "beforeShellExecution"

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
// The routing table decides which tools are shell calls and which go to MCP
// policy (handlePreToolUse).
// Block → print reason to stderr + exit 2. Allow/Audit → exit 0.
func handleClaudeCodeHook(input hookInput, rawToolInput json.RawMessage) error {
	return handlePreToolUse(input, rawToolInput, hookSourceFor(input, "claude-code-hook"), claudeShapedHarness(input))
}

// handleCopilotNativeHook adapts GitHub Copilot CLI's native "preToolUse"
// dialect (#4251) onto the Claude-shaped core. It keeps the runtime tool
// name: the routing table sends bash and powershell (and Bash) to the shell
// pipeline, as the adapter's rename to Bash did before ADR-001, and every
// other tool to MCP policy. toolArgs is decoded exactly as tool_input is, so
// a malformed shell command takes the fail-safe path in both dialects.
func handleCopilotNativeHook(input hookInput, rawToolArgs json.RawMessage) error {
	adapted := hookInput{
		HookEventName: "preToolUse",
		ToolName:      input.ToolNameNative,
		SessionID:     input.SessionIDNative,
		Cwd:           input.Cwd,
	}
	if len(rawToolArgs) > 0 {
		if err := json.Unmarshal(rawToolArgs, &adapted.ToolInput); err != nil {
			return hookInputFailureFor(hookSourceFor(adapted, "copilot-cli-hook"), "hook input parse", err)
		}
	}
	return handlePreToolUse(adapted, rawToolArgs, hookSourceFor(adapted, "copilot-cli-hook"), route.CopilotCLINative)
}

// handlePreToolUse is the shared core for every Claude-shaped PreToolUse
// payload: Claude Code, Codex CLI, and both Copilot CLI dialects. The routing
// table (internal/route) picks the lanes. A row with more than one lane is
// read by each and combined (combineLanes, ADR-001 D4); a single-lane row
// takes that lane's path below, unchanged.
func handlePreToolUse(input hookInput, rawToolInput json.RawMessage, source string, harness route.Harness) error {
	call := preToolUseCall(harness, input)
	lanes := route.Route(call)

	// A string tool_input is accepted for edits (apply_patch), never for a
	// call only shell lanes read: no client sends one, and reading it as an
	// empty command would pass the call unevaluated and unrecorded. Before
	// #4251 the shape failed the parse; it still takes the fail-safe path,
	// whether the row has one shell lane or two.
	if input.ToolInput.IsText && shellOnlyLanes(lanes) {
		return hookInputFailureFor(source, "hook input parse", errors.New("shell tool_input is a string, not an object"))
	}

	if c, ok := preToolUseBudgetCall(lanes, call, input, rawToolInput, source); ok {
		armHookBudget(c)
	}

	if len(lanes) > 1 {
		return combineLanes(lanes, call, input, rawToolInput, source)
	}

	// Shell commands → evaluate through the analyzer pipeline
	if slices.Contains(lanes, route.POSIX) {
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
		emitShellVerdict(source, cmdStr, evalResult)
		return nil
	}

	if !slices.Contains(lanes, route.Structured) {
		return nil // no lane: not evaluated
	}

	// Tool calls → evaluate through MCP policy. A call carrying command text
	// that no row names is recorded as a routing gap; the note is evidence,
	// never a decision input.
	var routeNotes []logger.Note
	if route.Gap(call) {
		routeNotes = append(routeNotes, routingGapNote(call))
	}
	return handleClaudeCodeMCPCall(input.ToolName, rawToolInput, source, sessionIDFor(input), input.Cwd, routeNotes)
}

// claudeShapedHarness names the harness of a Claude-shaped PreToolUse payload
// the way hookSourceFor labels its audit source: AGENTSHIELD_AGENT_ID first,
// then Codex's turn_id. A label the routing table does not know is routed as
// Claude Code.
func claudeShapedHarness(input hookInput) route.Harness {
	switch id := agentIDFromEnv(); {
	case id == "copilot-cli":
		return route.CopilotCLI
	case id == "codex", id == "" && input.TurnID != "":
		return route.Codex
	}
	return route.ClaudeCode
}

// hostOS is the host OS a routing key names (route.ToolCall.OS):
// runtime.GOOS. It is a variable only so that the internal/cli tests can
// exercise a Windows row on the macOS and Linux CI (pinTestHostOS, called
// from the test binary's TestMain). Nothing in the agentshield binary
// changes it: an environment variable that did would let an agent switch the
// PowerShell lane off (TestHostOSOverride_ProductionBinaryIgnoresIt).
var hostOS = func() string { return runtime.GOOS }

// preToolUseCall is the routing key of a Claude-shaped payload: the harness,
// the tool it names, and this host's OS. The command text is never part of
// it, only whether there is any.
func preToolUseCall(harness route.Harness, input hookInput) route.ToolCall {
	return route.ToolCall{Harness: harness, Tool: input.ToolName, OS: hostOS(), HasCommand: input.ToolInput.Command != ""}
}

// routesToShell reports whether the table sends c to the shell pipeline.
func routesToShell(c route.ToolCall) bool {
	return slices.Contains(route.Route(c), route.POSIX)
}

// shellOnlyRow reports whether the table sends c to a shell lane and no lane
// of its row reads a tool call's arguments, so a string tool_input would
// leave nothing evaluated.
func shellOnlyRow(c route.ToolCall) bool {
	return shellOnlyLanes(route.Route(c))
}

// shellOnlyLanes is shellOnlyRow for a row already looked up: a shell lane
// (POSIX or PowerShell, which read the command text) and no Structured lane.
func shellOnlyLanes(lanes []route.Lane) bool {
	shell := slices.Contains(lanes, route.POSIX) || slices.Contains(lanes, route.PowerShell)
	return shell && !slices.Contains(lanes, route.Structured)
}

// routingGapNote records a tool call that carried command text no shell lane
// read (ADR-001 D5).
func routingGapNote(c route.ToolCall) logger.Note {
	n := assembly.RoutingGapNote(c)
	return logger.Note{Kind: n.Kind, Rule: n.Rule, Detail: n.Detail}
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
func handleClaudeCodeMCPCall(toolName string, rawToolInput json.RawMessage, source, sessionID, cwd string, routeNotes []logger.Note) error {
	r := readToolCall(toolName, rawToolInput, source, sessionID, cwd, routeNotes)
	r.record(nil)
	r.emit()
	return nil
}

// toolCallReading is one MCP-policy evaluation of a tool call, held before it
// is recorded: the result, everything auditMCPCall writes with it, and the
// verdict output of the step that decided it. Building one writes no audit
// event; record does, and emit writes the verdict (exit 2 on a BLOCK).
type toolCallReading struct {
	toolName  string
	arguments map[string]interface{}
	result    mcp.MCPEvalResult
	source    string
	mode      string // the mode recorded on the event: "managed" for the two pre-policy BLOCKs
	sessionID string
	auditCwd  string
	notes     []logger.Note
	errText   string // the failure on a fail-safe reading's event; "" for an evaluation
	emitFor   func(r *toolCallReading)
}

// record writes the reading's audit event, with extra notes after its own.
// extra is nil for a call one lane decides, so its event is the one
// handleClaudeCodeMCPCall has always written. It claims the call first, as
// commandReading.record does.
func (r *toolCallReading) record(extra []logger.Note) {
	activeBudget.claimForEvaluation()
	r.write(extra)
}

// write is record without the claim: the decision budget's watchdog, which
// holds the claim already, records through it (answer).
func (r *toolCallReading) write(extra []logger.Note) {
	notes := r.notes
	if len(extra) > 0 {
		notes = append(slices.Clone(r.notes), extra...)
	}
	auditMCPCallErr(r.toolName, r.arguments, r.result, r.source, r.mode, r.sessionID, r.auditCwd, notes, r.errText)
}

// answer records the reading and writes its verdict, for a caller that
// already holds the call's claim.
func (r *toolCallReading) answer() {
	r.write(nil)
	r.emit()
}

// emit writes the verdict of the step that decided the reading.
func (r *toolCallReading) emit() { r.emitFor(r) }

// toolCallArguments parses tool_input as the argument map MCP policy reads;
// fromText reports a string tool_input (stringToolInputArguments).
func toolCallArguments(rawToolInput json.RawMessage) (arguments map[string]interface{}, fromText bool) {
	if len(rawToolInput) > 0 {
		if textArgs, ok := stringToolInputArguments(rawToolInput); ok {
			return textArgs, true
		}
		_ = json.Unmarshal(rawToolInput, &arguments)
	}
	return arguments, false
}

// readToolCall is handleClaudeCodeMCPCall up to the point it writes.
func readToolCall(toolName string, rawToolInput json.RawMessage, source, sessionID, cwd string, routeNotes []logger.Note) *toolCallReading {
	// #4452: the event records the directory the shell path evaluates
	// against — the payload cwd when usable, else the process directory with
	// a note. The managed config-write check below keeps reading the raw
	// payload cwd, exactly as before: routing it through the fallback would
	// change which file a relative write target names for a malformed cwd.
	auditCwd, auditCwdNotes := payloadEvalCwd(cwd)
	// routeNotes (a routing gap, ADR-001) go on every event this call
	// records, after the cwd notes. Evidence only: no decision reads them.
	eventNotes := append(slices.Clone(auditCwdNotes), routeNotes...)

	arguments, fromText := toolCallArguments(rawToolInput)

	reading := func(result mcp.MCPEvalResult, mode string, emit func(*toolCallReading)) *toolCallReading {
		return &toolCallReading{toolName: toolName, arguments: arguments, result: result, source: source,
			mode: mode, sessionID: sessionID, auditCwd: auditCwd, notes: eventNotes, emitFor: emit}
	}

	// #4260: on a managed host a harness's own write tool may not touch the
	// config directory. Checked first, like the shell path's SelfProtect
	// middleware: it needs no policy, so a broken ruleset cannot switch it off.
	if result, blocked := managedConfigToolWrite(toolName, arguments, fromText, cwd); blocked {
		return reading(result, "managed", emitManagedToolWriteBlock)
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

	// #4645: the customer's protected_paths (policy.yaml and packs, as the
	// shell path loads them) apply to the tool call's file-path arguments. A
	// layer that cannot be read degrades this ruleset like a broken MCP pack.
	shellProtected, ppWarnings := shellProtectedPathsFor(cfg)
	for _, w := range ppWarnings {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: %s\n", w)
	}
	loaded.Warnings = append(loaded.Warnings, ppWarnings...)

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
			return reading(result, "managed", emitMCPFailClosedBlock)
		}
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: MCP ruleset degraded (%s) — evaluated against what loaded (fail-safe default, not enforced as configured)\n", degraded)
	}

	// Enforce mode (""): the verdict is computed as enforce mode computes it,
	// and the configured mode is applied once, last, with the self-protection
	// keep rule the proxies, shield-server and mcp-eval share (#4337 review
	// B1): in audit-only mode a BLOCK on AgentShield's own configuration or an
	// agent hook file still blocks. The downgrade used to happen inside the
	// evaluator, which lowered those BLOCKs too.
	//
	// #4653: the protected-path check resolves file-path arguments against
	// the directory the shell path evaluates in: the payload's cwd when
	// usable (payloadEvalCwd, #4452), else this process's, as
	// evaluateCommand falls back. A relative customer pattern then matches
	// the absolute paths Claude Code sends.
	evaluator := assembly.MCPEvaluator(loaded.Policy, shellProtected, "").InWorkingDir(toolCallWorkDir(auditCwd))
	hookSlowPoint("evaluate")
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
	return reading(result, modeForAudit, emitMCPPolicyVerdict)
}

// emitManagedToolWriteBlock is the verdict of the managed-host tool-write
// check (#4260).
func emitManagedToolWriteBlock(r *toolCallReading) {
	if r.result.Decision != policy.DecisionBlock {
		return
	}
	fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED tool call: %s\n   Rule: %s\n   Reason: %s\n", r.toolName, strings.Join(r.result.TriggeredRules, ", "), r.result.Reasons[0])
	emitCopilotDeny(r.source, "tool call: "+r.toolName, r.result.TriggeredRules, r.result.Reasons)
	os.Exit(2)
}

// emitMCPFailClosedBlock is the verdict of a degraded MCP ruleset under
// managed fail_closed.
func emitMCPFailClosedBlock(r *toolCallReading) {
	if r.result.Decision != policy.DecisionBlock {
		return
	}
	fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED MCP tool call: %s\n   Reason: %s\n", r.toolName, r.result.Reasons[0])
	emitCopilotDeny(r.source, "MCP tool call: "+r.toolName, r.result.TriggeredRules, r.result.Reasons)
	os.Exit(2)
}

// emitMCPPolicyVerdict is the verdict of an MCP policy evaluation.
func emitMCPPolicyVerdict(r *toolCallReading) {
	result, toolName := r.result, r.toolName
	if result.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED MCP tool call: %s\n", toolName)
		if len(result.TriggeredRules) > 0 {
			fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(result.TriggeredRules, ", "))
		}
		for _, reason := range result.Reasons {
			fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
		}
		fmt.Fprint(os.Stderr, remediation.SuggestForMCP(result.TriggeredRules, enterprise.ManagedHost()))
		emitCopilotDeny(r.source, "MCP tool call: "+toolName, result.TriggeredRules, result.Reasons)
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
	auditMCPCallErr(toolName, arguments, result, hookSource, enforcementMode, sessionID, cwd, notes, "")
}

// auditMCPCallErr is auditMCPCall for a fail-safe reading: errText is the
// failure it records on the event's error field ("" for an evaluation).
func auditMCPCallErr(toolName string, arguments map[string]interface{}, result mcp.MCPEvalResult, hookSource, enforcementMode, sessionID, cwd string, notes []logger.Note, errText string) {
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
		Error:            errText,
		Notes:            append([]logger.Note(nil), notes...),
	}
	// An unopenable local log still sends the event to the SaaS, with no
	// local_chain (#4208: none is better than a made-up one), as the shell
	// path does in failSafeDecision (#4470).
	auditLogger, err := logger.New(logPath)
	if err != nil {
		sendRemoteAuditRedacted(redactForRecord(&event), nil)
		return
	}
	defer func() { _ = auditLogger.Close() }()

	noteLockUnavailable(&event, auditLogger)
	// One redaction for the line and the wire entry (#4781).
	red := redactForRecord(&event)
	link, _ := auditLogger.LogLinkedRedacted(red)

	// Queue for the SaaS with the local line's link (#4208; audit_queue.go,
	// #4467).
	sendRemoteAuditRedacted(red, link)
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
// The routing table sends run_shell_command to the shell pipeline; other
// tools pass through.
// Responds with JSON {"decision": "allow"} or {"decision": "deny", "reason": "..."} on stdout.
func handleGeminiCLIHook(input hookInput) error {
	if !routesToShell(route.ToolCall{Harness: route.GeminiCLI, Tool: input.ToolName, OS: hostOS(), HasCommand: input.ToolInput.Command != ""}) {
		outputGeminiAllow()
		return nil
	}

	cmdStr := input.ToolInput.Command
	if cmdStr == "" {
		outputGeminiAllow()
		return nil
	}

	cwd := input.ToolInput.DirPath
	source, sessionID := "gemini-cli-hook", sessionIDFor(input)
	armHookBudget(shellBudgetCall(route.GeminiCLI, input.ToolName, source, sessionID, cmdStr, literalCwd(cwd), emitGeminiVerdict))
	evalResult, _ := evaluateCommand(cmdStr, cwd, source, sessionID)
	emitGeminiVerdict(evalResult)
	return nil
}

// emitGeminiVerdict writes Gemini CLI's verdict on stdout: decision deny on a
// BLOCK, allow otherwise.
func emitGeminiVerdict(evalResult *policy.EvalResult) {
	if evalResult.Decision == policy.DecisionBlock {
		output := geminiHookOutput{
			Decision:      "deny",
			Reason:        "BLOCKED by AgentShield: " + strings.Join(evalResult.Reasons, "; "),
			SystemMessage: evalResult.Explanation,
		}
		data, _ := json.Marshal(output)
		fmt.Println(string(data))
		return
	}
	outputGeminiAllow()
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
