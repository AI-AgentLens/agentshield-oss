package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeChainedLog(t *testing.T, path string, events []AuditEvent) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	prevHash := ""
	for _, e := range events {
		ce := ChainedEvent{
			AuditEvent: e,
			PrevHash:   prevHash,
		}
		ce.EntryHash = ComputeEntryHash(ce)
		prevHash = ComputeChainedHash(ce)

		data, err := json.Marshal(ce)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(data)
		_, _ = f.Write([]byte("\n"))
	}
}

func TestVerifyChain_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	events := []AuditEvent{
		{Timestamp: "2026-03-14T00:00:00Z", Command: "echo hello", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:01:00Z", Command: "ls -la", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:02:00Z", Command: "rm -rf /", Decision: "BLOCK"},
	}
	writeChainedLog(t, logPath, events)

	result := VerifyChain(logPath)
	if !result.Valid {
		t.Errorf("expected valid chain, got: %s", result.Message)
	}
	if result.Entries != 3 {
		t.Errorf("expected 3 entries, got %d", result.Entries)
	}
	if result.BrokenAt != -1 {
		t.Errorf("expected BrokenAt=-1, got %d", result.BrokenAt)
	}
}

func TestVerifyChain_TamperedEntry(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	events := []AuditEvent{
		{Timestamp: "2026-03-14T00:00:00Z", Command: "echo hello", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:01:00Z", Command: "ls -la", Decision: "ALLOW"},
	}
	writeChainedLog(t, logPath, events)

	// Tamper with the second entry by modifying the file
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Replace "ls -la" with "rm -rf" to simulate tampering
	tampered := []byte{}
	lines := splitLines(data)
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		if i == 1 {
			var entry ChainedEvent
			_ = json.Unmarshal(line, &entry)
			entry.Command = "rm -rf /" // tamper!
			line, _ = json.Marshal(entry)
		}
		tampered = append(tampered, line...)
		tampered = append(tampered, '\n')
	}
	_ = os.WriteFile(logPath, tampered, 0600)

	result := VerifyChain(logPath)
	if result.Valid {
		t.Error("expected tampered chain to be invalid")
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1, got %d", result.BrokenAt)
	}
}

func TestVerifyChain_DeletedEntry(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	events := []AuditEvent{
		{Timestamp: "2026-03-14T00:00:00Z", Command: "echo hello", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:01:00Z", Command: "ls -la", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:02:00Z", Command: "rm -rf /", Decision: "BLOCK"},
	}
	writeChainedLog(t, logPath, events)

	// Delete the middle entry
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(data)
	var modified []byte
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		if i == 1 {
			continue // skip middle entry
		}
		modified = append(modified, line...)
		modified = append(modified, '\n')
	}
	_ = os.WriteFile(logPath, modified, 0600)

	result := VerifyChain(logPath)
	if result.Valid {
		t.Error("expected chain with deleted entry to be invalid")
	}
}

func TestVerifyChain_EmptyLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")
	_ = os.WriteFile(logPath, []byte(""), 0600)

	result := VerifyChain(logPath)
	if !result.Valid {
		t.Errorf("expected empty log to be valid, got: %s", result.Message)
	}
	if result.Entries != 0 {
		t.Errorf("expected 0 entries, got %d", result.Entries)
	}
}

// splitLines splits data by newline, returning non-empty byte slices.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
