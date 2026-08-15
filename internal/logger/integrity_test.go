package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if result.State != ChainStateVerified {
		t.Errorf("expected state %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if !result.Protected() {
		t.Error("expected Protected() to be true for a fully chained log")
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
	if result.State != ChainStateBroken {
		t.Errorf("expected tampered chain to be broken, got %q", result.State)
	}
	if result.Protected() {
		t.Error("a tampered log must never report Protected()")
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
	if result.State != ChainStateBroken {
		t.Errorf("expected chain with deleted entry to be broken, got %q", result.State)
	}
}

func TestVerifyChain_EmptyLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")
	_ = os.WriteFile(logPath, []byte(""), 0600)

	result := VerifyChain(logPath)
	if result.State != ChainStateEmpty {
		t.Errorf("expected empty log to report %q, got %q: %s", ChainStateEmpty, result.State, result.Message)
	}
	if result.Entries != 0 {
		t.Errorf("expected 0 entries, got %d", result.Entries)
	}
	if result.Protected() {
		t.Error("an empty log protects nothing; Protected() must be false")
	}
}

// writeUnchainedLog writes plain AuditEvents with no chain fields — exactly
// what every build before this change produced.
func writeUnchainedLog(t *testing.T, path string, events []AuditEvent) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	for _, e := range events {
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(append(data, '\n'))
	}
}

// TestVerifyChain_UnprotectedLog is the regression test for the headline bug in
// issue #3112: a log with no chain fields used to report Valid, and `scan`
// rendered a green "verified" tick over it. It must now report a state that no
// caller can mistake for a pass.
func TestVerifyChain_UnprotectedLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeUnchainedLog(t, logPath, []AuditEvent{
		{Timestamp: "2026-03-14T00:00:00Z", Command: "echo hello", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:01:00Z", Command: "ls -la", Decision: "ALLOW"},
	})

	result := VerifyChain(logPath)
	if result.State != ChainStateUnprotected {
		t.Errorf("expected %q, got %q: %s", ChainStateUnprotected, result.State, result.Message)
	}
	if result.Protected() {
		t.Error("a log with no chain fields must never report Protected()")
	}
	if result.Entries != 2 || result.LegacyEntries != 2 {
		t.Errorf("expected 2 entries / 2 legacy, got %d / %d", result.Entries, result.LegacyEntries)
	}
}

// TestVerifyChain_LegacyPrefixThenChain covers the upgrade path: an existing
// customer log gets chained entries appended to it. The pre-upgrade entries are
// not retroactively protected, but the file must not read as broken either.
func TestVerifyChain_LegacyPrefixThenChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeUnchainedLog(t, logPath, []AuditEvent{
		{Timestamp: "2026-03-14T00:00:00Z", Command: "echo one", Decision: "ALLOW"},
		{Timestamp: "2026-03-14T00:01:00Z", Command: "echo two", Decision: "ALLOW"},
	})

	lg, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"echo three", "echo four"} {
		if err := lg.Log(AuditEvent{Timestamp: "2026-03-14T00:02:00Z", Command: cmd, Decision: "ALLOW"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = lg.Close()

	result := VerifyChain(logPath)
	if result.State != ChainStatePartial {
		t.Errorf("expected %q, got %q: %s", ChainStatePartial, result.State, result.Message)
	}
	if result.Protected() {
		t.Error("a log with unprotected legacy entries must not report Protected()")
	}
	if result.Entries != 4 || result.LegacyEntries != 2 {
		t.Errorf("expected 4 entries / 2 legacy, got %d / %d", result.Entries, result.LegacyEntries)
	}
}

// TestVerifyChain_UnchainedAfterChained pins the other half of the legacy rule.
// Unchained entries are tolerated as a prefix only — once chaining has started,
// an entry with no hash is an inserted record or a downgraded writer, and that
// is exactly the edit the chain exists to catch.
func TestVerifyChain_UnchainedAfterChained(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainedLog(t, logPath, []AuditEvent{
		{Timestamp: "2026-03-14T00:00:00Z", Command: "echo one", Decision: "ALLOW"},
	})
	writeUnchainedLog(t, logPath, []AuditEvent{
		{Timestamp: "2026-03-14T00:01:00Z", Command: "rm -rf /", Decision: "ALLOW"},
	})

	result := VerifyChain(logPath)
	if result.State != ChainStateBroken {
		t.Errorf("expected %q, got %q: %s", ChainStateBroken, result.State, result.Message)
	}
	if result.BrokenAt != 1 {
		t.Errorf("expected BrokenAt=1, got %d", result.BrokenAt)
	}
}

func TestVerifyChain_MissingLog(t *testing.T) {
	result := VerifyChain(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if result.State != ChainStateEmpty {
		t.Errorf("expected %q for a missing log, got %q", ChainStateEmpty, result.State)
	}
	if result.Protected() {
		t.Error("a missing log must not report Protected()")
	}
}

func TestChainHead(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		if got := ChainHead(filepath.Join(dir, "nope.jsonl")); got != "" {
			t.Errorf("expected empty head, got %q", got)
		}
	})

	t.Run("legacy tail starts a fresh chain", func(t *testing.T) {
		p := filepath.Join(dir, "legacy.jsonl")
		writeUnchainedLog(t, p, []AuditEvent{{Timestamp: "t", Command: "echo hi", Decision: "ALLOW"}})
		if got := ChainHead(p); got != "" {
			t.Errorf("expected empty head for an unchained tail, got %q", got)
		}
	})

	t.Run("chained tail", func(t *testing.T) {
		p := filepath.Join(dir, "chained.jsonl")
		events := []AuditEvent{
			{Timestamp: "t1", Command: "echo one", Decision: "ALLOW"},
			{Timestamp: "t2", Command: "echo two", Decision: "ALLOW"},
		}
		writeChainedLog(t, p, events)

		last := ChainedEvent{AuditEvent: events[1]}
		first := ChainedEvent{AuditEvent: events[0]}
		first.EntryHash = ComputeEntryHash(first)
		last.PrevHash = ComputeChainedHash(first)
		last.EntryHash = ComputeEntryHash(last)

		if got, want := ChainHead(p), ComputeChainedHash(last); got != want {
			t.Errorf("head mismatch:\n got %q\nwant %q", got, want)
		}
	})

	t.Run("record larger than the first tail window", func(t *testing.T) {
		p := filepath.Join(dir, "big.jsonl")
		big := strings.Repeat("A", tailReadBytes+4096)
		events := []AuditEvent{
			{Timestamp: "t1", Command: "echo small", Decision: "ALLOW"},
			{Timestamp: "t2", Command: big, Decision: "ALLOW"},
		}
		writeChainedLog(t, p, events)
		if got := ChainHead(p); got == "" {
			t.Error("expected the tail read to escalate and recover the head")
		}
		if result := VerifyChain(p); result.State != ChainStateVerified {
			t.Errorf("expected verified, got %q: %s", result.State, result.Message)
		}
	})
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
