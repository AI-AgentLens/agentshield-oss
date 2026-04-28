package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test_audit.jsonl")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() {
		_ = logger.Close()
	}()

	event := AuditEvent{
		Timestamp:      "2026-02-02T12:00:00Z",
		Command:        "echo hello",
		Args:           []string{"echo", "hello"},
		Cwd:            "/tmp",
		Decision:       "ALLOW",
		TriggeredRules: []string{},
		Mode:           "policy-only",
	}

	if err := logger.Log(event); err != nil {
		t.Fatalf("failed to log event: %v", err)
	}

	_ = logger.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	var parsed AuditEvent
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse log line as JSON: %v", err)
	}

	if parsed.Command != "echo hello" {
		t.Errorf("expected command 'echo hello', got '%s'", parsed.Command)
	}

	if parsed.Decision != "ALLOW" {
		t.Errorf("expected decision 'ALLOW', got '%s'", parsed.Decision)
	}
}

func TestAuditLogger_Rotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	// Pre-create the log file already at the rotation limit.
	big := make([]byte, defaultMaxLogBytes)
	if err := os.WriteFile(logPath, big, 0600); err != nil {
		t.Fatalf("failed to seed large log file: %v", err)
	}

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer func() { _ = lg.Close() }()

	event := AuditEvent{
		Timestamp: "2026-03-01T00:00:00Z",
		Command:   "echo hi",
		Decision:  "ALLOW",
		Mode:      "policy-only",
	}
	if err := lg.Log(event); err != nil {
		t.Fatalf("Log after rotation failed: %v", err)
	}

	// .1 backup must exist
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Errorf("expected rotated file %s.1 to exist: %v", logPath, err)
	}

	// Fresh log must be small (just the one new line)
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("fresh log file missing: %v", err)
	}
	if info.Size() >= defaultMaxLogBytes {
		t.Errorf("fresh log file is still %d bytes; expected < %d", info.Size(), defaultMaxLogBytes)
	}
}

func TestAuditLogger_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "secure_audit.jsonl")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	_ = logger.Close()

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat log file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}
