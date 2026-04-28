package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteClaudeSettings_CreatesParentDir locks in the fix for a real bug
// found via E2E (2026-04-27): a brand-new user running
// `agentshield setup claude-code` before ever launching Claude Code itself
// would hit "no such file or directory" because writeClaudeSettings did
// os.WriteFile on a path under a non-existent ~/.claude/.
//
// The fix: MkdirAll the parent directory before writing.
func TestWriteClaudeSettings_CreatesParentDir(t *testing.T) {
	tmp := t.TempDir()
	// Path under a directory that doesn't exist yet — mirrors the real failure.
	target := filepath.Join(tmp, "claude-fresh", "settings.json")

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{},
		},
	}

	if err := writeClaudeSettings(target, settings); err != nil {
		t.Fatalf("writeClaudeSettings: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	if info.Size() == 0 {
		t.Error("settings.json is empty")
	}

	// The parent dir should now exist with the expected mode.
	parentInfo, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatalf("parent dir not created: %v", err)
	}
	if !parentInfo.IsDir() {
		t.Error("parent path exists but is not a directory")
	}
}

// TestWriteClaudeSettings_OverwritesExistingFile — round-trip on an existing
// settings.json must not error. (Sanity check — easy to break with a stat
// guard refactor.)
func TestWriteClaudeSettings_OverwritesExistingFile(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(`{"existing": true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeClaudeSettings(target, map[string]interface{}{"updated": true}); err != nil {
		t.Fatalf("writeClaudeSettings: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == `{"existing": true}` {
		t.Error("file was not overwritten")
	}
}
