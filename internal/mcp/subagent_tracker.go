package mcp

import (
	"regexp"
	"strings"
	"time"
)

// SubAgentEscalationSignal identifies a detected sub-agent scope escalation pattern.
type SubAgentEscalationSignal string

const (
	// SignalSubAgentTaskEscalation fires when a delegation tool's task/goal/instruction
	// argument contains explicit credential paths or shell exfiltration patterns.
	// BLOCK-level signal: intent to route dangerous work to a wider-scope sub-agent.
	SignalSubAgentTaskEscalation SubAgentEscalationSignal = "subagent_task_escalation"

	// SignalSubAgentScopeWidening fires when the session was entirely read-only,
	// a delegation tool was called, then a destructive tool fires within the window.
	// AUDIT-level signal: session scope widened after delegation.
	SignalSubAgentScopeWidening SubAgentEscalationSignal = "subagent_scope_widening"
)

const (
	syntheticSubAgentTaskEscalation = "__mcp_subagent_task_escalation__"
	syntheticSubAgentScopeWidening  = "__mcp_subagent_scope_widening__"

	subAgentWindow       = 120 * time.Second
	subAgentHistoryMax   = 80
	subAgentMinReadCalls = 2 // read-only calls before delegation needed to flag scope widening
)

type subAgentRecord struct {
	at            time.Time
	toolName      string
	isDelegation  bool
	isReadOnly    bool
	isDestructive bool
}

// SubAgentTracker tracks per-session tool calls to detect sub-agent scope escalation.
//
// Two detection modes:
//  1. ScanDelegationContent (stateless) — checks delegation tool call arguments
//     for dangerous task content (credential paths, shell exfiltration).
//  2. Scan (stateful) — detects scope widening when a read-only session delegates
//     and then makes destructive calls.
//
// Add SubAgentTracker to MessageHandler; nil disables all detection silently.
type SubAgentTracker struct {
	history boundedHistory[subAgentRecord]
}

// NewSubAgentTracker returns a ready tracker.
func NewSubAgentTracker() *SubAgentTracker {
	return &SubAgentTracker{history: newBoundedHistory[subAgentRecord](subAgentHistoryMax)}
}

// isDelegationTool returns true for tool names that route work to sub-agents.
// Covers LangGraph (transfer_to_*), CrewAI (delegate_work_to_coworker),
// AutoGen and generic orchestration conventions.
func isDelegationTool(name string) bool {
	lower := strings.ToLower(strings.ReplaceAll(name, " ", "_"))

	exact := []string{
		"delegate_to", "transfer_to", "hand_off_to", "handoff_to",
		"route_to", "escalate_to", "pass_to", "forward_to",
		"hand_off", "handoff",
		"delegate_work_to_coworker", "delegate_work_to_agent",
	}
	for _, e := range exact {
		if lower == e {
			return true
		}
	}

	// LangGraph transfer_to_<agent> and generic _to_<agent> routing patterns.
	prefixes := []string{
		"transfer_to_", "delegate_to_", "hand_off_to_", "handoff_to_",
		"route_to_", "escalate_to_", "pass_to_", "forward_to_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) && len(lower) > len(p) {
			return true
		}
	}
	return false
}

// dangerousTaskRe matches free-form task/goal text that explicitly references
// credential paths or shell exfiltration patterns in delegation arguments.
// Kept high-precision to minimize FP on legitimate delegation tasks.
var dangerousTaskRe = regexp.MustCompile(
	`(?i)(` +
		// Credential paths — require specific sensitive filenames, not just directory keywords.
		`(~|/home/[^/\s]+|/root)/\.(ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)|aws/credentials|gnupg/|vault-token|kube/config|terraform\.d/)` +
		`|/etc/(shadow|passwd|sudoers|master\.passwd)` +
		`|\.vault-token(\b|$)` +
		// Shell exfiltration: curl/wget/nc with an HTTP URL (URL may appear before or after flags).
		`|(curl|wget|nc)\s+.*https?://\S+` +
		// Pipe to shell — agent routing bash/sh execution via delegation.
		`|\|\s*(bash|sh)\s*($|\|)` +
		`)`,
)

// taskArgNames covers the field names used for the task/goal/prompt in common
// multi-agent frameworks: CrewAI (task, context), AutoGen (message), generic (goal,
// instruction, objective, prompt, command).
var taskArgNames = []string{
	"task", "goal", "instruction", "instructions",
	"context", "prompt", "message", "objective", "command",
}

// ScanDelegationContent checks the arguments of a delegation tool call for dangerous
// task content indicating scope escalation. Returns the signal and the matched argument
// name for audit details. Returns ("", "") if no escalation is detected.
//
// This is a stateless check — no session history is needed.
func (t *SubAgentTracker) ScanDelegationContent(toolName string, arguments map[string]interface{}) (SubAgentEscalationSignal, string) {
	if !isDelegationTool(toolName) {
		return "", ""
	}
	for _, argName := range taskArgNames {
		val, ok := arguments[argName]
		if !ok {
			continue
		}
		text := argValueToString(val)
		if dangerousTaskRe.MatchString(text) {
			return SignalSubAgentTaskEscalation, argName
		}
	}
	return "", ""
}

// Scan checks whether the incoming tool call triggers the stateful scope-widening
// signal given prior session history. Call this BEFORE Record so that "prior" history
// is evaluated without the current call.
func (t *SubAgentTracker) Scan(toolName string) []SubAgentEscalationSignal {
	var signals []SubAgentEscalationSignal

	t.history.view(func(history []subAgentRecord) {
		// Scope-widening: session was read-only → delegation → destructive tool.
		if isDestructiveTool(toolName) {
			cutoff := time.Now().Add(-subAgentWindow)
			delegationIdx := -1
			for i := len(history) - 1; i >= 0; i-- {
				if history[i].isDelegation && history[i].at.After(cutoff) {
					delegationIdx = i
					break
				}
			}
			if delegationIdx >= 0 {
				readOnlyBefore := 0
				hadWriteBefore := false
				for i := 0; i < delegationIdx; i++ {
					r := history[i]
					if r.isDestructive || (!r.isReadOnly && !r.isDelegation) {
						hadWriteBefore = true
						break
					}
					if r.isReadOnly {
						readOnlyBefore++
					}
				}
				if !hadWriteBefore && readOnlyBefore >= subAgentMinReadCalls {
					signals = append(signals, SignalSubAgentScopeWidening)
				}
			}
		}
	})

	return signals
}

// Record adds the current tool call to session history.
func (t *SubAgentTracker) Record(toolName string) {
	t.history.append(subAgentRecord{
		at:            time.Now(),
		toolName:      toolName,
		isDelegation:  isDelegationTool(toolName),
		isReadOnly:    isReadOnlyTool(toolName),
		isDestructive: isDestructiveTool(toolName),
	})
}
