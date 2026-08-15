package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		Mode:           "enforce",
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
		Mode:      "enforce",
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

// TestAuditLogger_AuditOnlyPayload pins the SaaS contract for issue #1952:
// audit-only events MUST carry mode="audit-only" and original_decision="BLOCK"
// in the JSON written to the audit log. Without this, the SaaS would see the
// downgraded AUDIT and not know it was a shadow-block — the "would have
// blocked" UI would be lying. Test the raw JSON, not just the struct, because
// the JSON field names + omitempty behavior IS the contract.
func TestAuditLogger_AuditOnlyPayload(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit_only.jsonl")

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer func() { _ = lg.Close() }()

	if err := lg.Log(AuditEvent{
		Timestamp:        "2026-05-17T20:15:10Z",
		Command:          "telnet legacy-router.lan 23",
		Decision:         "AUDIT",
		Mode:             "audit-only",
		OriginalDecision: "BLOCK",
		TriggeredRules:   []string{"ne-block-telnet"},
	}); err != nil {
		t.Fatalf("Log(): %v", err)
	}
	_ = lg.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}

	// Field-name level assertions: the SaaS ingest reads these exact keys.
	raw := string(data)
	for _, want := range []string{
		`"mode":"audit-only"`,
		`"original_decision":"BLOCK"`,
		`"decision":"AUDIT"`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("audit-only payload missing %s; got: %s", want, raw)
		}
	}

	// Round-trip back into the struct so we also catch silent renames.
	var parsed AuditEvent
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if parsed.Mode != "audit-only" {
		t.Errorf("Mode round-trip: want audit-only, got %q", parsed.Mode)
	}
	if parsed.OriginalDecision != "BLOCK" {
		t.Errorf("OriginalDecision round-trip: want BLOCK, got %q", parsed.OriginalDecision)
	}
}

// TestAuditLogger_EnforceModeOmitsOriginalDecision pins the other half of the
// contract: in enforce mode (the default), original_decision MUST be omitted
// from the JSON entirely — its presence is the dashboard's "this would have
// blocked" signal, so a stray empty field would create false positives.
func TestAuditLogger_EnforceModeOmitsOriginalDecision(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "enforce.jsonl")

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer func() { _ = lg.Close() }()

	if err := lg.Log(AuditEvent{
		Timestamp: "2026-05-17T20:15:10Z",
		Command:   "rm -rf /tmp/safe",
		Decision:  "BLOCK",
		Mode:      "enforce",
		// OriginalDecision intentionally empty
	}); err != nil {
		t.Fatalf("Log(): %v", err)
	}
	_ = lg.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	raw := string(data)

	if strings.Contains(raw, "original_decision") {
		t.Errorf("enforce mode must omit original_decision key entirely; got: %s", raw)
	}
	if !strings.Contains(raw, `"mode":"enforce"`) {
		t.Errorf("enforce mode must still emit mode field (always-on for cohort segmentation); got: %s", raw)
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
