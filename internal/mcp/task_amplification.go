package mcp

import (
	"encoding/json"
	"strings"
	"time"
)

// TaskAmplificationSignal identifies a detected SEP-1686 ("Tasks") amplification
// pattern. See taxonomy: unauthorized-execution/agentic-attacks/mcp-async-task-amplification-dos.
type TaskAmplificationSignal string

const (
	// SignalTaskAmplificationUnpolledBurst fires when a session opens
	// ≥taskAmplificationBurstThreshold task-augmented requests within
	// taskAmplificationBurstWindow with zero tasks/get or tasks/result polls
	// recorded in the same window — a fire-and-forget fan-out pattern rather
	// than the normal create-then-retrieve usage. AUDIT.
	SignalTaskAmplificationUnpolledBurst TaskAmplificationSignal = "task_amplification_unpolled_burst"
)

// Synthetic virtual tool name injected into the policy engine when the
// session-composite signal fires — mirroring the lethal-trifecta / approval-
// fatigue trackers' approach.
const syntheticTaskAmplificationBurst = "__mcp_task_amplification_burst__"

const (
	taskAmplificationBurstWindow    = 30 * time.Second
	taskAmplificationBurstThreshold = 5 // task-augmented creates in window with 0 polls
	taskAmplificationHistoryMax     = 60

	// taskAmplificationMaxTokensThreshold is the maxTokens value above which a
	// task-augmented sampling/createMessage request is flagged as an
	// expensive-operation wrap (SEP-1686 1:N cost asymmetry). Chosen well
	// above typical default completion lengths (4K-8K) and comfortably below
	// the taxonomy's own worked example (200000) so genuinely large-but-normal
	// completions aren't the trigger — only requests approaching max
	// context/output limits combined with the disconnect-immune task wrapper.
	taskAmplificationMaxTokensThreshold = 50000
)

// IsTaskAugmented reports whether a request carries the SEP-1686 "task"
// augmentation. The spec allows both a bare `"task": true` and a task-config
// object; both are treated as augmented. Absent, null, or literal false are
// not augmented.
func IsTaskAugmented(task json.RawMessage) bool {
	if len(task) == 0 {
		return false
	}
	switch strings.TrimSpace(string(task)) {
	case "", "null", "false":
		return false
	default:
		return true
	}
}

// taskAmplificationRecord is one entry in the per-session task-create/poll
// history.
type taskAmplificationRecord struct {
	at     time.Time
	isPoll bool // true for tasks/get / tasks/result; false for a task-augmented create
}

// TaskAmplificationTracker tracks per-session task-augmented request creation
// and tasks/get|tasks/result polling to detect the SEP-1686 "Tasks" primitive
// amplification-DoS pattern: a burst of task-creation requests with no
// corresponding polls, which the taxonomy documents as a fire-and-forget
// fan-out that keeps consuming server resources (and can accumulate
// unretrieved results in memory) even after the client disconnects.
//
// Static per-argument matching cannot see this — it requires session-level
// tracking at the MCP proxy, mirroring LethalTrifectaTracker /
// ApprovalFatigueTracker. Add it to MessageHandler; a nil tracker silently
// disables detection.
type TaskAmplificationTracker struct {
	history boundedHistory[taskAmplificationRecord]
}

// NewTaskAmplificationTracker returns a ready tracker.
func NewTaskAmplificationTracker() *TaskAmplificationTracker {
	return &TaskAmplificationTracker{history: newBoundedHistory[taskAmplificationRecord](taskAmplificationHistoryMax)}
}

// ScanCreate checks whether the incoming task-augmented request (about to be
// recorded via RecordCreate) completes an unpolled burst, given prior
// session history. Call this BEFORE RecordCreate so the current call is
// counted exactly once.
func (t *TaskAmplificationTracker) ScanCreate() TaskAmplificationSignal {
	var signal TaskAmplificationSignal
	t.history.view(func(history []taskAmplificationRecord) {
		cutoff := time.Now().Add(-taskAmplificationBurstWindow)
		creates, polls := 0, 0
		for _, r := range history {
			if r.at.After(cutoff) {
				if r.isPoll {
					polls++
				} else {
					creates++
				}
			}
		}
		// +1 for the current call, which is not yet recorded.
		if creates+1 >= taskAmplificationBurstThreshold && polls == 0 {
			signal = SignalTaskAmplificationUnpolledBurst
		}
	})
	return signal
}

// RecordCreate adds a task-augmented request to session history.
func (t *TaskAmplificationTracker) RecordCreate() {
	t.history.append(taskAmplificationRecord{at: time.Now(), isPoll: false})
}

// RecordPoll adds a tasks/get or tasks/result poll to session history.
func (t *TaskAmplificationTracker) RecordPoll() {
	t.history.append(taskAmplificationRecord{at: time.Now(), isPoll: true})
}
