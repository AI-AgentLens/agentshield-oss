package mcp

import (
	"testing"
)

func TestCapabilityExpansionTracker_NoExpansionWithoutNotification(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	initial := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}}
	tracker.RecordInitialTools(initial)

	// New tools appear but no notification was received — should not flag
	expanded := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}, {Name: "exec_shell"}}
	if newTools := tracker.CheckExpansion(expanded); len(newTools) != 0 {
		t.Errorf("expected no expansion without notification, got %v", newTools)
	}
}

func TestCapabilityExpansionTracker_DetectsExpansion(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	initial := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}}
	tracker.RecordInitialTools(initial)
	tracker.NotifyListChanged()

	// exec_shell and delete_file are new — both should be flagged
	expanded := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}, {Name: "exec_shell"}, {Name: "delete_file"}}
	newTools := tracker.CheckExpansion(expanded)
	if len(newTools) != 2 {
		t.Fatalf("expected 2 new tools, got %v", newTools)
	}
	if newTools[0] != "delete_file" || newTools[1] != "exec_shell" {
		t.Errorf("unexpected new tools: %v", newTools)
	}
}

func TestCapabilityExpansionTracker_NoFalsePositiveOnStableList(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	initial := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}}
	tracker.RecordInitialTools(initial)
	tracker.NotifyListChanged()

	// Same tools, no new ones — no expansion
	sameTools := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}}
	if newTools := tracker.CheckExpansion(sameTools); len(newTools) != 0 {
		t.Errorf("expected no expansion on stable list, got %v", newTools)
	}
}

func TestCapabilityExpansionTracker_ToolRemovalIsNotFlagged(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	initial := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}, {Name: "write_file"}}
	tracker.RecordInitialTools(initial)
	tracker.NotifyListChanged()

	// Server removes a tool — tool removal is safe, should not flag
	reduced := []ToolDefinition{{Name: "read_file"}, {Name: "list_directory"}}
	if newTools := tracker.CheckExpansion(reduced); len(newTools) != 0 {
		t.Errorf("expected no expansion on tool removal, got %v", newTools)
	}
}

func TestCapabilityExpansionTracker_FlagResetAfterCheck(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	initial := []ToolDefinition{{Name: "read_file"}}
	tracker.RecordInitialTools(initial)
	tracker.NotifyListChanged()

	// First check: flags exec_shell
	expanded := []ToolDefinition{{Name: "read_file"}, {Name: "exec_shell"}}
	newTools := tracker.CheckExpansion(expanded)
	if len(newTools) != 1 || newTools[0] != "exec_shell" {
		t.Fatalf("expected exec_shell, got %v", newTools)
	}

	// Second check without another notification: no expansion reported
	if newTools := tracker.CheckExpansion(expanded); len(newTools) != 0 {
		t.Errorf("expected no expansion after flag reset, got %v", newTools)
	}
}

func TestCapabilityExpansionTracker_MultipleNotificationsBeforeRefetch(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	initial := []ToolDefinition{{Name: "read_file"}}
	tracker.RecordInitialTools(initial)
	tracker.NotifyListChanged()
	tracker.NotifyListChanged() // second notification before refetch

	expanded := []ToolDefinition{{Name: "read_file"}, {Name: "exec_shell"}}
	newTools := tracker.CheckExpansion(expanded)
	if len(newTools) != 1 || newTools[0] != "exec_shell" {
		t.Errorf("expected exec_shell, got %v", newTools)
	}
}

func TestHandleToolsListChangedNotification(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	h := &MessageHandler{
		Evaluator:           &PolicyEvaluator{},
		CapabilityExpansion: tracker,
	}

	msg := &Message{Method: MethodNotificationsToolsListChanged}
	dropped := h.HandleToolsListChangedNotification(msg)
	if dropped {
		t.Error("notifications/tools/list_changed should not be dropped — client needs it to trigger refetch")
	}
	if !tracker.listChanged {
		t.Error("expected listChanged flag to be set after notification")
	}
}

func TestHandleToolsListChangedNotification_WrongMethod(t *testing.T) {
	tracker := NewCapabilityExpansionTracker()
	h := &MessageHandler{
		Evaluator:           &PolicyEvaluator{},
		CapabilityExpansion: tracker,
	}

	msg := &Message{Method: "notifications/message"}
	h.HandleToolsListChangedNotification(msg)
	if tracker.listChanged {
		t.Error("wrong method should not set listChanged")
	}
}
