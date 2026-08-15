package mcp

import (
	"sort"
	"sync"
)

// CapabilityExpansionTracker detects within-session tool capability expansion.
// An MCP server may send notifications/tools/list_changed to signal its tool
// set changed. If the refetched tools/list introduces new tool IDs not present
// in the initial set, the agent gained capabilities it was never authorized to have.
// This is distinct from mcp-tool-rug-pull (description mutation on an existing tool)
// — here, entirely new tools are added post-approval.
type CapabilityExpansionTracker struct {
	mu           sync.Mutex
	initialTools map[string]bool
	listChanged  bool
}

// NewCapabilityExpansionTracker returns a new tracker with no baseline.
func NewCapabilityExpansionTracker() *CapabilityExpansionTracker {
	return &CapabilityExpansionTracker{}
}

// RecordInitialTools sets the session-start tool baseline. Only the first call
// has effect; subsequent calls are no-ops unless the baseline was never set.
func (t *CapabilityExpansionTracker) RecordInitialTools(tools []ToolDefinition) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.initialTools != nil {
		return
	}
	t.initialTools = make(map[string]bool, len(tools))
	for _, tool := range tools {
		t.initialTools[tool.Name] = true
	}
}

// NotifyListChanged signals that a notifications/tools/list_changed was received.
// The next tools/list response will be checked against the session baseline.
func (t *CapabilityExpansionTracker) NotifyListChanged() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.listChanged = true
}

// CheckExpansion returns any tool names in the given list that were not present
// in the initial set, but ONLY when a list_changed notification was previously
// received. Returns nil if no expansion, no pending check, or no baseline.
// Resets the listChanged flag after checking.
func (t *CapabilityExpansionTracker) CheckExpansion(tools []ToolDefinition) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.listChanged || t.initialTools == nil {
		return nil
	}
	t.listChanged = false
	var newTools []string
	for _, tool := range tools {
		if !t.initialTools[tool.Name] {
			newTools = append(newTools, tool.Name)
		}
	}
	sort.Strings(newTools)
	return newTools
}
