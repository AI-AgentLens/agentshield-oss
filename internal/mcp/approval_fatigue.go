package mcp

import (
	"strings"
	"time"
)

// ApprovalFatigueSignal identifies a detected approval-fatigue pattern.
type ApprovalFatigueSignal string

const (
	// SignalApprovalBurst is raised when ≥5 tool calls arrive within 30 s and the
	// current call targets a high-impact tool. AUDIT decision.
	SignalApprovalBurst ApprovalFatigueSignal = "approval_burst"

	// SignalApprovalBaitSwitch is raised when the last approvalBaitSwitchLookback
	// calls were all read-only and the current call is destructive. BLOCK decision.
	// This encodes the "8 reads then one delete" social-engineering pattern.
	SignalApprovalBaitSwitch ApprovalFatigueSignal = "approval_bait_and_switch"
)

// Synthetic virtual tool names injected into the policy engine when the above
// signals fire — mirroring the elicitation scanner's approach.
const (
	syntheticApprovalBurst      = "__mcp_approval_burst__"
	syntheticApprovalBaitSwitch = "__mcp_approval_bait_switch__"
)

const (
	approvalBurstWindow       = 30 * time.Second
	approvalBurstThreshold    = 5
	approvalBaitSwitchLookback = 4 // last N calls must all be read-only
	approvalHistoryMax        = 60 // bound memory
)

// approvalRecord is one entry in the per-session tool call history.
type approvalRecord struct {
	at         time.Time
	toolName   string
	isReadOnly bool
}

// ApprovalFatigueTracker tracks per-session tool call history to detect
// approval-fatigue exploitation patterns. Add it to MessageHandler; a nil
// tracker silently disables detection.
//
// Note: in HTTP Streamable proxy mode one MessageHandler serves all clients,
// so this tracker crosses session boundaries. The AUDIT burst rule remains
// useful (aggregate anomaly signal) but the BLOCK bait-and-switch rule may
// produce cross-session FPs in high-concurrency HTTP deployments. The primary
// use case (stdio proxy, one agent = one session) is exact.
type ApprovalFatigueTracker struct {
	history boundedHistory[approvalRecord]
}

// NewApprovalFatigueTracker returns a ready tracker.
func NewApprovalFatigueTracker() *ApprovalFatigueTracker {
	return &ApprovalFatigueTracker{history: newBoundedHistory[approvalRecord](approvalHistoryMax)}
}

// Scan checks whether the incoming tool call triggers any approval-fatigue
// signals given the prior session history. Call this BEFORE Record so the
// current call is not yet in history when evaluating "prior" patterns.
func (t *ApprovalFatigueTracker) Scan(toolName string) []ApprovalFatigueSignal {
	var signals []ApprovalFatigueSignal

	t.history.view(func(history []approvalRecord) {
		// Bait-and-switch: last N calls all read-only + current is destructive.
		if isDestructiveTool(toolName) && len(history) >= approvalBaitSwitchLookback {
			prior := history[len(history)-approvalBaitSwitchLookback:]
			allRO := true
			for _, r := range prior {
				if !r.isReadOnly {
					allRO = false
					break
				}
			}
			if allRO {
				signals = append(signals, SignalApprovalBaitSwitch)
			}
		}

		// Burst: ≥approvalBurstThreshold calls in the window + current is high-impact.
		if isHighImpactTool(toolName) {
			cutoff := time.Now().Add(-approvalBurstWindow)
			count := 0
			for _, r := range history {
				if r.at.After(cutoff) {
					count++
				}
			}
			if count >= approvalBurstThreshold {
				signals = append(signals, SignalApprovalBurst)
			}
		}
	})

	return signals
}

// Record adds the current tool call to session history.
func (t *ApprovalFatigueTracker) Record(toolName string) {
	t.history.append(approvalRecord{
		at:         time.Now(),
		toolName:   toolName,
		isReadOnly: isReadOnlyTool(toolName),
	})
}

// isReadOnlyTool returns true for tool names that are clearly idempotent/
// read-only — get_, read_, list_, search_, stat_, describe_, show_, fetch_.
// Conservatively returns false for unknown names (avoids suppressing signals).
func isReadOnlyTool(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{
		"get_", "read_", "list_", "search_", "stat_", "describe_",
		"show_", "fetch_", "find_", "lookup_", "query_", "view_",
		"check_", "inspect_", "scan_", "peek_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// isDestructiveTool returns true for tool names that perform truly destructive
// or permission-changing operations. These are the target of bait-and-switch.
func isDestructiveTool(name string) bool {
	lower := strings.ToLower(name)
	// Exact high-risk prefixes.
	destructivePrefixes := []string{
		"delete_", "remove_", "exec_", "execute_", "chmod_",
		"kill_", "revoke_", "grant_", "disable_", "drop_",
		"truncate_", "purge_", "destroy_", "wipe_",
	}
	for _, p := range destructivePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	// Mid-word patterns that indicate destructive intent.
	destructiveContains := []string{
		"_delete", "_remove", "_exec", "_chmod", "_kill",
		"_revoke", "_grant", "_disable", "_drop",
	}
	for _, s := range destructiveContains {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// isHighImpactTool is a superset of isDestructiveTool that also includes write
// and create operations — used for the AUDIT burst rule.
func isHighImpactTool(name string) bool {
	if isDestructiveTool(name) {
		return true
	}
	lower := strings.ToLower(name)
	highImpactPrefixes := []string{
		"write_", "create_", "update_", "edit_", "set_", "put_",
		"append_", "insert_", "push_", "publish_",
	}
	for _, p := range highImpactPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
