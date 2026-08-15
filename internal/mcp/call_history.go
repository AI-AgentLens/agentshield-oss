package mcp

import (
	"time"
)

// RecordedCall is one MCP tool call captured in per-session history so that
// cross-call sequence/chain rules (#2493) can match multi-step agent
// trajectories — e.g. OSINT reads → LLM generation → bulk send.
type RecordedCall struct {
	ToolName string
	Args     map[string]interface{}
	At       time.Time
}

// callHistoryMax bounds per-session memory.
const callHistoryMax = 100

// MCPCallHistoryTracker records the recent MCP tool-call history for one
// session so sequence rules can match cross-call chains. It is modeled on
// ApprovalFatigueTracker: add it to MessageHandler; a nil tracker disables
// history (sequence rules then simply never fire).
//
// Session scope mirrors the other handler trackers: for the stdio proxy one
// MessageHandler == one agent == one exact session. For the HTTP Streamable
// proxy a single handler serves all clients, so history crosses sessions until
// it is keyed by Mcp-Session-Id (tracked for a later slice).
type MCPCallHistoryTracker struct {
	history boundedHistory[RecordedCall]
}

// NewMCPCallHistoryTracker returns a ready tracker.
func NewMCPCallHistoryTracker() *MCPCallHistoryTracker {
	return &MCPCallHistoryTracker{history: newBoundedHistory[RecordedCall](callHistoryMax)}
}

// Record appends a tool call to session history, trimming to callHistoryMax.
// Callers Record after capturing the call so that History (including this
// call) reflects the trajectory up to and including the triggering call.
func (t *MCPCallHistoryTracker) Record(toolName string, args map[string]interface{}) {
	if t == nil {
		return
	}
	t.history.append(RecordedCall{ToolName: toolName, Args: args, At: time.Now()})
}

// History returns a copy of the recorded calls, oldest first. Returns nil for a
// nil tracker.
func (t *MCPCallHistoryTracker) History() []RecordedCall {
	if t == nil {
		return nil
	}
	return t.history.snapshot()
}
