package mcp

import (
	"testing"
	"time"
)

func TestApprovalFatigue_BaitAndSwitch(t *testing.T) {
	tracker := NewApprovalFatigueTracker()

	// Record approvalBaitSwitchLookback read-only calls.
	for i := 0; i < approvalBaitSwitchLookback; i++ {
		signals := tracker.Scan("read_file")
		for _, s := range signals {
			// No signal should fire for read-only calls.
			t.Errorf("unexpected signal %q on read_file call %d", s, i+1)
		}
		tracker.Record("read_file")
	}

	// Now a destructive call should trigger bait-and-switch.
	signals := tracker.Scan("delete_file")
	found := false
	for _, s := range signals {
		if s == SignalApprovalBaitSwitch {
			found = true
		}
	}
	if !found {
		t.Error("expected SignalApprovalBaitSwitch after consecutive read-only calls before delete_file")
	}
}

func TestApprovalFatigue_BaitAndSwitch_NotTriggeredWhenMixed(t *testing.T) {
	tracker := NewApprovalFatigueTracker()

	// Mix of read-only and high-impact: bait-and-switch must NOT fire.
	calls := []string{"read_file", "write_file", "read_file", "list_directory"}
	for _, call := range calls {
		tracker.Scan(call)
		tracker.Record(call)
	}

	// A destructive call after mixed history must not trigger bait-and-switch.
	signals := tracker.Scan("delete_file")
	for _, s := range signals {
		if s == SignalApprovalBaitSwitch {
			t.Error("bait-and-switch should not fire when prior calls include non-read-only operations")
		}
	}
}

func TestApprovalFatigue_BurstDetection(t *testing.T) {
	tracker := NewApprovalFatigueTracker()

	// Simulate approvalBurstThreshold rapid calls.
	for i := 0; i < approvalBurstThreshold; i++ {
		tracker.Scan("read_file")
		tracker.Record("read_file")
	}

	// A high-impact call now should trigger burst.
	signals := tracker.Scan("write_file")
	found := false
	for _, s := range signals {
		if s == SignalApprovalBurst {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SignalApprovalBurst after %d rapid calls followed by write_file", approvalBurstThreshold)
	}
}

func TestApprovalFatigue_BurstNotTriggeredOnLowCadence(t *testing.T) {
	tracker := NewApprovalFatigueTracker()

	// Inject stale records (beyond the window) by backdating history directly.
	staleTime := time.Now().Add(-2 * approvalBurstWindow)
	for i := 0; i < approvalBurstThreshold+2; i++ {
		tracker.history.append(approvalRecord{
			at:         staleTime,
			toolName:   "read_file",
			isReadOnly: true,
		})
	}

	// write_file with only stale history must NOT trigger burst.
	signals := tracker.Scan("write_file")
	for _, s := range signals {
		if s == SignalApprovalBurst {
			t.Error("burst should not fire when prior calls are outside the time window")
		}
	}
}

func TestApprovalFatigue_NoSignalOnBenignSequence(t *testing.T) {
	tracker := NewApprovalFatigueTracker()

	// Normal developer flow: one read, one write. No signal.
	tracker.Scan("read_file")
	tracker.Record("read_file")

	signals := tracker.Scan("delete_file")
	for _, s := range signals {
		if s == SignalApprovalBaitSwitch {
			t.Error("bait-and-switch must not fire with only 1 prior read (lookback requires >= approvalBaitSwitchLookback)")
		}
	}
}

func TestIsReadOnlyTool(t *testing.T) {
	readOnly := []string{
		"read_file", "get_file", "list_directory", "search_files",
		"stat_file", "describe_resource", "show_config", "fetch_page",
		"find_symbol", "lookup_key", "query_db", "view_file",
		"check_status", "inspect_object", "scan_dir", "peek_content",
	}
	for _, name := range readOnly {
		if !isReadOnlyTool(name) {
			t.Errorf("isReadOnlyTool(%q) = false, want true", name)
		}
	}
}

func TestIsDestructiveTool(t *testing.T) {
	destructive := []string{
		"delete_file", "remove_file", "exec_shell", "execute_command",
		"chmod_file", "kill_process", "revoke_token", "grant_access",
		"disable_feature", "drop_table", "truncate_db", "purge_cache",
		"destroy_resource", "wipe_disk", "file_delete", "log_exec",
	}
	for _, name := range destructive {
		if !isDestructiveTool(name) {
			t.Errorf("isDestructiveTool(%q) = false, want true", name)
		}
	}

	notDestructive := []string{
		"read_file", "list_directory", "write_file", "create_file",
		"search_files", "get_contents",
	}
	for _, name := range notDestructive {
		if isDestructiveTool(name) {
			t.Errorf("isDestructiveTool(%q) = true, want false", name)
		}
	}
}

func TestIsHighImpactTool(t *testing.T) {
	highImpact := []string{
		"write_file", "create_file", "update_record", "edit_config",
		"set_secret", "put_object", "append_text", "insert_row",
		"push_branch", "publish_package", "delete_file", "exec_shell",
	}
	for _, name := range highImpact {
		if !isHighImpactTool(name) {
			t.Errorf("isHighImpactTool(%q) = false, want true", name)
		}
	}

	notHighImpact := []string{
		"read_file", "list_directory", "search_files", "get_contents",
	}
	for _, name := range notHighImpact {
		if isHighImpactTool(name) {
			t.Errorf("isHighImpactTool(%q) = true, want false", name)
		}
	}
}
