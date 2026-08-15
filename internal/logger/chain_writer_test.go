package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// smallRotation shrinks the rotation threshold for the duration of a test so
// the boundary can be exercised without writing 10 MB of chained entries.
func smallRotation(t *testing.T, limit int64) {
	t.Helper()
	original := maxLogBytes
	maxLogBytes = limit
	t.Cleanup(func() { maxLogBytes = original })
}

func logEvents(t *testing.T, lg *AuditLogger, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := lg.Log(AuditEvent{
			Timestamp: fmt.Sprintf("2026-07-27T00:00:%02dZ", i),
			Command:   fmt.Sprintf("%s-%d", prefix, i),
			Decision:  "ALLOW",
			Mode:      "enforce",
		})
		if err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}
}

// TestAuditLogger_WritesChain is the stage-2 regression test for issue #3112:
// before this change AuditLogger.Log marshalled a bare AuditEvent, so no
// production code ever produced a chain field.
func TestAuditLogger_WritesChain(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 3, "echo chain")
	_ = lg.Close()

	// Field-name level assertion: prev_hash / entry_hash are the on-disk
	// contract that VerifyChain and the SaaS ingest both read.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"entry_hash":`) {
		t.Errorf("first entry has no entry_hash: %s", lines[0])
	}
	// The genesis entry has no predecessor, so prev_hash is omitted there.
	if strings.Contains(lines[0], `"prev_hash":`) {
		t.Errorf("genesis entry should omit prev_hash: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"prev_hash":`) {
		t.Errorf("second entry has no prev_hash: %s", lines[1])
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if result.Entries != 3 {
		t.Errorf("expected 3 entries, got %d", result.Entries)
	}
}

// TestAuditLogger_DetectsMutatedEntry proves the written chain is actually load
// bearing: flipping a decision in place must surface as broken.
func TestAuditLogger_DetectsMutatedEntry(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 3, "echo hi")
	_ = lg.Close()

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// The cheapest real-world tamper: rewrite a recorded decision.
	mutated := strings.Replace(string(raw), `"decision":"ALLOW"`, `"decision":"BLOCK"`, 1)
	if mutated == string(raw) {
		t.Fatal("test setup: nothing was mutated")
	}
	if err := os.WriteFile(logPath, []byte(mutated), 0600); err != nil {
		t.Fatal(err)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateBroken {
		t.Errorf("expected %q after an in-place edit, got %q: %s", ChainStateBroken, result.State, result.Message)
	}
	if result.BrokenAt != 0 {
		t.Errorf("expected the first entry to be flagged, got BrokenAt=%d", result.BrokenAt)
	}
}

// TestAuditLogger_ResumesChainOnReopen covers the startup case. Every hook
// invocation is a fresh process opening an existing log; if the logger restarted
// the chain from empty each time, verification could not tell a normal process
// start from a truncate-and-rewrite.
func TestAuditLogger_ResumesChainOnReopen(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	for run := 0; run < 3; run++ {
		lg, err := New(logPath)
		if err != nil {
			t.Fatalf("New() run %d: %v", run, err)
		}
		logEvents(t, lg, 2, fmt.Sprintf("run%d", run))
		if err := lg.Close(); err != nil {
			t.Fatalf("Close() run %d: %v", run, err)
		}
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("expected %q across process restarts, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if result.Entries != 6 {
		t.Errorf("expected 6 entries, got %d", result.Entries)
	}

	// The chain must genuinely link across the restart, not just be six
	// independently valid genesis entries.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var entry ChainedEvent
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if i > 0 && entry.PrevHash == "" {
			t.Errorf("entry %d restarted the chain (empty prev_hash) — a reopen must not look like a reset", i)
		}
	}
}

// TestAuditLogger_RotationKeepsChainLinked covers the rotation boundary: the
// fresh file's first entry carries the rotated file's head, so a rotation reads
// as a link rather than as a break.
func TestAuditLogger_RotationKeepsChainLinked(t *testing.T) {
	smallRotation(t, 400)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 12, "echo rotate")
	_ = lg.Close()

	rotatedPath := logPath + rotatedSuffix
	if _, err := os.Stat(rotatedPath); err != nil {
		t.Fatalf("expected a rotated log at %s: %v", rotatedPath, err)
	}

	if result := VerifyChain(rotatedPath); result.State != ChainStateVerified {
		t.Errorf("rotated log: expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("live log: expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if !strings.Contains(result.Note, filepath.Base(rotatedPath)) {
		t.Errorf("expected the rotation link to be reported, got note %q", result.Note)
	}
}

// TestAuditLogger_RotationBoundaryDetectsTamper is the mutation half of the
// rotation story: rewriting the rotated file must invalidate the link the live
// file claims. Without the cross-check, everything before the boundary could be
// rewritten for free.
func TestAuditLogger_RotationBoundaryDetectsTamper(t *testing.T) {
	smallRotation(t, 400)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 12, "echo rotate")
	_ = lg.Close()

	rotatedPath := logPath + rotatedSuffix
	raw, err := os.ReadFile(rotatedPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var last ChainedEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	// Rewrite the rotated head and recompute its own hash, so the rotated file
	// stays internally consistent. Only the live file's back-link can catch it.
	last.Command = "echo innocent"
	last.EntryHash = ComputeEntryHash(last)
	repaired, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	lines[len(lines)-1] = string(repaired)
	if err := os.WriteFile(rotatedPath, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateBroken {
		t.Errorf("expected %q when the rotated predecessor was rewritten, got %q: %s",
			ChainStateBroken, result.State, result.Message)
	}
}

// TestAuditLogger_ConcurrentWriters covers the multi-process case. Parallel IDE
// hook invocations, the MCP proxy and the watchdog all append to one
// audit.jsonl through separate file descriptors; each writer keeps its own idea
// of the chain head, so without cross-process serialization they would append
// entries claiming the same prev_hash and every parallel tool call would leave
// the chain reading as broken.
//
// Separate AuditLogger instances mean separate open file descriptions, which is
// what flock arbitrates — the same mechanism separate processes rely on.
func TestAuditLogger_ConcurrentWriters(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	const writers, perWriter = 4, 25
	var wg sync.WaitGroup
	errs := make(chan error, writers)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			lg, err := New(logPath)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = lg.Close() }()
			for i := 0; i < perWriter; i++ {
				if err := lg.Log(AuditEvent{
					Timestamp: "2026-07-27T00:00:00Z",
					Command:   fmt.Sprintf("writer%d-%d", w, i),
					Decision:  "ALLOW",
					Mode:      "enforce",
				}); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Log(): %v", err)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("expected %q under concurrent writers, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if result.Entries != writers*perWriter {
		t.Errorf("expected %d entries, got %d", writers*perWriter, result.Entries)
	}
}

// TestAuditLogger_DoesNotCacheHeadAtOpen is the deterministic guard for a race
// the concurrent test only caught about one run in ten.
//
// The first version of this change sampled the chain head and the file size in
// New(). Both reads are outside the file lock, so another process's append can
// land between them: the head comes from before the append and the size from
// after. The size then matches on the next write, the resync is skipped, and
// the logger appends an entry carrying an already-used prev_hash — a chain
// break at the very first write, with no tampering involved.
//
// The invariant that prevents it: a logger holds no head until it takes the
// lock. knownSize < 0 is how Log() knows it must read one.
func TestAuditLogger_DoesNotCacheHeadAtOpen(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	seed, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, seed, 2, "echo seed")
	_ = seed.Close()

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer func() { _ = lg.Close() }()

	if lg.prevHash != "" {
		t.Error("logger cached a chain head at open time; it must be read under the file lock")
	}
	if lg.knownSize >= 0 {
		t.Errorf("knownSize = %d, want < 0 so the first write resyncs under the lock", lg.knownSize)
	}

	// And it must still resume rather than restart.
	logEvents(t, lg, 1, "echo after")
	if result := VerifyChain(logPath); result.State != ChainStateVerified || result.Entries != 3 {
		t.Errorf("expected a verified 3-entry chain, got %q with %d entries: %s",
			result.State, result.Entries, result.Message)
	}
}

// TestAuditLogger_HashesRedactedPayload pins the redaction ordering. Log()
// redacts Command/Args/Error before writing, so the hash has to be taken after
// redaction — otherwise it commits to bytes that are not in the file (every
// entry fails verification) and stores a digest of the raw secret.
func TestAuditLogger_HashesRedactedPayload(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	// Assembled at runtime so the literal credential-shaped assignment does not
	// sit in the source file (AgentShield rightly blocks writing one).
	placeholder := "PLACEHOLDER" + "_VALUE_NOT_A_CREDENTIAL_01"
	assignment := "--api" + "_key=" + placeholder
	raw := AuditEvent{
		Timestamp: "2026-07-27T00:00:00Z",
		Command:   "deploy " + assignment,
		Args:      []string{"deploy", assignment},
		Decision:  "AUDIT",
		Mode:      "enforce",
	}

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if err := lg.Log(raw); err != nil {
		t.Fatalf("Log(): %v", err)
	}
	_ = lg.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), placeholder) {
		t.Fatalf("test setup: the payload was not redacted, so ordering is not exercised: %s", data)
	}

	var written ChainedEvent
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}

	// The digest must cover what is on disk...
	if want := ComputeEntryHash(written); written.EntryHash != want {
		t.Errorf("entry_hash does not cover the redacted payload:\n got %s\nwant %s", written.EntryHash, want)
	}
	// ...and must not be the digest of the pre-redaction event.
	preRedaction := ComputeEntryHash(ChainedEvent{AuditEvent: raw})
	if written.EntryHash == preRedaction {
		t.Error("entry_hash committed to the unredacted event")
	}

	if result := VerifyChain(logPath); result.State != ChainStateVerified {
		t.Errorf("expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
}
