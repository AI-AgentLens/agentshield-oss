package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// seedLogAtThreshold writes n chained entries with one writer, closes it, and
// lowers the rotation threshold to exactly the resulting file size, so the
// very next Log() from any writer rotates. Returns the head the rotated file
// will have, computed the same way VerifyChain's cross-check computes it.
func seedLogAtThreshold(t *testing.T, logPath string, n int) string {
	t.Helper()
	seed, err := New(logPath)
	if err != nil {
		t.Fatalf("New(seed): %v", err)
	}
	logEvents(t, seed, n, "echo seed")
	_ = seed.Close()

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	smallRotation(t, info.Size())
	head := ChainHead(logPath)
	if head == "" {
		t.Fatal("seed log has no chain head; the fixture is wrong")
	}
	return head
}

func firstEntry(t *testing.T, path string) ChainedEvent {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var first ChainedEvent
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first entry of %s: %v", filepath.Base(path), err)
	}
	return first
}

// TestAuditLogger_RotationOnFirstWriteLinksToPredecessor is the regression
// test for issue #4033. A hook invocation is a short-lived process whose FIRST
// write may be the one that trips the rotation threshold. Before the fix that
// process had never read a head (knownSize -1), rotation reset knownSize to 0,
// and resyncHead then saw "size 0 == knownSize 0" and skipped the read, so the
// fresh file's first entry carried an empty prev_hash: an unlinked chain that
// VerifyChain never cross-checks against the rotated file.
func TestAuditLogger_RotationOnFirstWriteLinksToPredecessor(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	expectedHead := seedLogAtThreshold(t, logPath, 5)

	// A fresh process: no head read yet, first Log() triggers the rotation.
	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 1, "echo first-write-rotates")
	_ = lg.Close()

	rotatedPath := logPath + rotatedSuffix
	if _, err := os.Stat(rotatedPath); err != nil {
		t.Fatalf("expected the first write to rotate the log: %v", err)
	}
	if got := ChainHead(rotatedPath); got != expectedHead {
		t.Fatalf("rotated file head changed: got %s, want %s", got, expectedHead)
	}

	first := firstEntry(t, logPath)
	if first.PrevHash != expectedHead {
		t.Errorf("first entry after a first-write rotation: prev_hash %q, want the rotated file's head %s",
			first.PrevHash, expectedHead)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("live log: expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if !strings.Contains(result.Note, filepath.Base(rotatedPath)) {
		t.Errorf("expected the rotation link to be reported, got note %q", result.Note)
	}
}

// TestAuditLogger_RotationOnFirstWriteCrossCheckRuns is the negative half of
// #4033: with the link in place, replacing the rotated file is reported as
// broken and deleting it is reported in the note. Before the fix both went
// unnoticed (state verified, no note), because an empty prev_hash means
// VerifyChain has nothing to cross-check.
func TestAuditLogger_RotationOnFirstWriteCrossCheckRuns(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	seedLogAtThreshold(t, logPath, 5)

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 1, "echo first-write-rotates")
	_ = lg.Close()
	rotatedPath := logPath + rotatedSuffix

	t.Run("replaced predecessor is broken", func(t *testing.T) {
		// An internally consistent but different chain in place of .1: the
		// rotated file verifies on its own, only the live file's back-link
		// can catch the swap.
		forgedPath := filepath.Join(t.TempDir(), "forged.jsonl")
		forger, err := New(forgedPath)
		if err != nil {
			t.Fatal(err)
		}
		logEvents(t, forger, 5, "echo innocent")
		_ = forger.Close()
		forged, err := os.ReadFile(forgedPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rotatedPath, forged, 0600); err != nil {
			t.Fatal(err)
		}
		if r := VerifyChain(rotatedPath); r.State != ChainStateVerified {
			t.Fatalf("forged predecessor should verify on its own, got %q: %s", r.State, r.Message)
		}

		result := VerifyChain(logPath)
		if result.State != ChainStateBroken {
			t.Errorf("expected %q after the rotated predecessor was replaced, got %q (note %q)",
				ChainStateBroken, result.State, result.Note)
		}
	})

	t.Run("deleted predecessor is noted", func(t *testing.T) {
		if err := os.Remove(rotatedPath); err != nil {
			t.Fatal(err)
		}
		result := VerifyChain(logPath)
		if result.State != ChainStateVerified {
			t.Fatalf("expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
		}
		if !strings.Contains(result.Note, "predecessor unavailable") {
			t.Errorf("expected the missing predecessor to be noted, got note %q", result.Note)
		}
	})
}

// TestAuditLogger_RotationLinksToTrueHeadNotStaleInProcessHead is the same
// skipped read seen from a long-running writer (MCP proxy, shield-server):
// another process appended after this writer's last write, then this writer's
// next write rotates. Before the fix the rotation reused the in-process head,
// which was stale, so the fresh file linked to an entry that is not the
// rotated file's head and VerifyChain raised a false tamper alarm.
func TestAuditLogger_RotationLinksToTrueHeadNotStaleInProcessHead(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")

	smallRotation(t, 1<<20) // no rotation during setup
	longRunning, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, longRunning, 3, "echo proxy")

	other, err := New(logPath)
	if err != nil {
		t.Fatalf("New(other): %v", err)
	}
	logEvents(t, other, 2, "echo hook")
	_ = other.Close()

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	smallRotation(t, info.Size())
	expectedHead := ChainHead(logPath)

	logEvents(t, longRunning, 1, "echo proxy-rotates")
	_ = longRunning.Close()

	rotatedPath := logPath + rotatedSuffix
	if got := ChainHead(rotatedPath); got != expectedHead {
		t.Fatalf("rotated file head changed: got %s, want %s", got, expectedHead)
	}
	first := firstEntry(t, logPath)
	if first.PrevHash != expectedHead {
		t.Errorf("first entry after rotation: prev_hash %q, want the rotated file's head %s",
			first.PrevHash, expectedHead)
	}
	if result := VerifyChain(logPath); result.State != ChainStateVerified {
		t.Errorf("live log: expected %q, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
}

// countLines returns how many records in path contain sub.
func countLines(t *testing.T, path, sub string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// assertGenerationSurvives is shared by the two re-rotation tests: the seed
// generation must still be on disk as <path>.1, and the live file must verify
// with a link to it. Before the inode check in rotateIfNeeded, the second
// writer's os.Remove(.1) deleted the seed generation and the verifier still
// said "verified, linked" (on main it said "broken": a misread, but at least
// a signal).
func assertGenerationSurvives(t *testing.T, logPath string, seedWant int) {
	t.Helper()
	rotatedPath := logPath + rotatedSuffix
	if got := countLines(t, rotatedPath, "seed-"); got != seedWant {
		t.Errorf("seed entries surviving in %s: %d of %d", filepath.Base(rotatedPath), got, seedWant)
	}
	if got := countLines(t, logPath, "seed-"); got != 0 {
		t.Errorf("seed entries unexpectedly in the live file: %d", got)
	}
	if r := VerifyChain(rotatedPath); r.State != ChainStateVerified {
		t.Errorf("rotated log: expected %q, got %q: %s", ChainStateVerified, r.State, r.Message)
	}
	r := VerifyChain(logPath)
	if r.State != ChainStateVerified {
		t.Errorf("live log: expected %q, got %q: %s", ChainStateVerified, r.State, r.Message)
	}
	if !strings.Contains(r.Note, filepath.Base(rotatedPath)) {
		t.Errorf("expected the live log to link to %s, got note %q", filepath.Base(rotatedPath), r.Note)
	}
	t.Logf("seed entries surviving on disk: %d of %d; live=%s note=%q",
		countLines(t, rotatedPath, "seed-"), seedWant, r.State, r.Note)
}

// TestAuditLogger_LongRunningWriterDoesNotReRotate covers the enterprise
// watchdog / shield-server topology (PR #4041 review, pass 1). A long-running
// writer holds its descriptor on generation 0; a hook rotates that generation
// to .1; the long-running writer's next write sees its own descriptor still
// over the threshold. Rotating again would delete the .1 the hook produced.
// It must reopen the live file and link to it instead. No race is needed:
// the two writes are sequential.
func TestAuditLogger_LongRunningWriterDoesNotReRotate(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	smallRotation(t, 1<<20)

	longRunning, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, longRunning, 3, "echo seed-lr")
	seedLogAtThreshold(t, logPath, 2) // a hook's two entries; threshold = current size

	hook, err := New(logPath)
	if err != nil {
		t.Fatalf("New(hook): %v", err)
	}
	logEvents(t, hook, 1, "echo hook-rotates")
	_ = hook.Close()
	if _, err := os.Stat(logPath + rotatedSuffix); err != nil {
		t.Fatalf("expected the hook to rotate: %v", err)
	}

	logEvents(t, longRunning, 1, "echo lr-after")
	_ = longRunning.Close()

	assertGenerationSurvives(t, logPath, 5)
	if got := countLines(t, logPath, "lr-after"); got != 1 {
		t.Errorf("long-running writer's entry should land in the live file, found %d", got)
	}
}

// TestAuditLogger_HookOpenedBeforeSiblingRotationDoesNotReRotate is the same
// shape with two hooks: B opened the log before A rotated it, then B writes.
func TestAuditLogger_HookOpenedBeforeSiblingRotationDoesNotReRotate(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	seedLogAtThreshold(t, logPath, 5)

	hookA, err := New(logPath)
	if err != nil {
		t.Fatalf("New(A): %v", err)
	}
	hookB, err := New(logPath)
	if err != nil {
		t.Fatalf("New(B): %v", err)
	}
	logEvents(t, hookA, 1, "echo hookA-rotates")
	_ = hookA.Close()
	logEvents(t, hookB, 1, "echo hookB-after")
	_ = hookB.Close()

	assertGenerationSurvives(t, logPath, 5)
	for _, want := range []string{"hookA-rotates", "hookB-after"} {
		if got := countLines(t, logPath, want); got != 1 {
			t.Errorf("expected %q once in the live file, found %d", want, got)
		}
	}
}

// TestAuditLogger_TransientOpenFailureKeepsDescriptor (PR #4041 review, pass
// 2). A stat error that is not ENOENT must not take the reopen path, and a
// reopen that fails to open the new descriptor must keep the old one. Pass 1
// did neither: any stat error reopened, and the old descriptor was closed
// before the new open, so a transient failure (directory briefly
// unreadable, EMFILE) left the logger with no file at all: "file already
// closed" on every later write, silently, since the watchdog and
// shield-server discard Log errors.
func TestAuditLogger_TransientOpenFailureKeepsDescriptor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	smallRotation(t, 1<<20)

	lr, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lr, 2, "echo before")

	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	errDuring := lr.Log(AuditEvent{Timestamp: "t", Command: "echo during", Decision: "ALLOW", Mode: "enforce"})
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	errAfter1 := lr.Log(AuditEvent{Timestamp: "t", Command: "echo after-1", Decision: "ALLOW", Mode: "enforce"})
	errAfter2 := lr.Log(AuditEvent{Timestamp: "t", Command: "echo after-2", Decision: "ALLOW", Mode: "enforce"})
	_ = lr.Close()

	for name, err := range map[string]error{"during": errDuring, "after-1": errAfter1, "after-2": errAfter2} {
		if err != nil {
			t.Errorf("Log(%s) through the held descriptor: %v", name, err)
		}
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimRight(string(raw), "\n"), "\n")); got != 5 {
		t.Errorf("lines on disk: %d, want 5", got)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("expected %q, got %q: %s", ChainStateVerified, r.State, r.Message)
	}
}

// TestAuditLogger_ReopenRereadsHeadRegardlessOfSize: after a reopen the head
// must be re-read even when the new live file is exactly as long as the old
// generation was at this writer's last write, so knownSize alone cannot tell
// the two apart. Kills the "skip knownSize = -1 on reopen" mutant.
func TestAuditLogger_ReopenRereadsHeadRegardlessOfSize(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	smallRotation(t, 1<<20)
	lr, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lr, 3, "echo lr")
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	staleSize := info.Size() // lr.knownSize

	seedLogAtThreshold(t, logPath, 1) // another process appends after lr
	if err := os.Rename(logPath, logPath+rotatedSuffix); err != nil {
		t.Fatal(err)
	}

	// Fill the new live file to exactly staleSize bytes with one entry. The
	// probe gets the same .1 beside it as the live file has: the first line
	// of an empty log links to <path>.1 when one exists (#4057 pass 3), so a
	// probe without one would be a genesis line, 79 bytes shorter than the
	// entry w writes below.
	rotatedBytes, err := os.ReadFile(logPath + rotatedSuffix)
	if err != nil {
		t.Fatal(err)
	}
	pad := -1
	for n := 0; n < 4096 && pad < 0; n++ {
		probe := filepath.Join(t.TempDir(), "probe.jsonl")
		if err := os.WriteFile(probe+rotatedSuffix, rotatedBytes, 0600); err != nil {
			t.Fatal(err)
		}
		pw, err := New(probe)
		if err != nil {
			t.Fatal(err)
		}
		if err := pw.Log(AuditEvent{Timestamp: "t", Command: "echo " + strings.Repeat("p", n), Decision: "ALLOW", Mode: "enforce"}); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		if pi, err := os.Stat(probe); err == nil && pi.Size() == staleSize {
			pad = n
		}
	}
	if pad < 0 {
		t.Fatalf("could not pad an entry to %d bytes", staleSize)
	}
	w, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Log(AuditEvent{Timestamp: "t", Command: "echo " + strings.Repeat("p", pad), Decision: "ALLOW", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if st, err := os.Stat(logPath); err != nil || st.Size() != staleSize {
		t.Fatalf("fixture: new live file is %d bytes, want %d", st.Size(), staleSize)
	}

	logEvents(t, lr, 1, "echo lr-after")
	_ = lr.Close()
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("reopen skipped the head re-read: got %q: %s", r.State, r.Message)
	}
}

// TestAuditLogger_StaleReopenersConcurrent: after one rotation, N writers
// holding stale descriptors reopen and append concurrently. Every chain must
// verify. Kills the "skip the re-lock after reopen" mutant in Log, which
// nothing else in the package exercises (the reviewer measured 198 of 200
// trials broken with it).
func TestAuditLogger_StaleReopenersConcurrent(t *testing.T) {
	const trials, writers, writes = 200, 8, 3
	original := maxLogBytes
	t.Cleanup(func() { maxLogBytes = original })

	broken := 0
	firstMsg := ""
	for trial := 0; trial < trials; trial++ {
		logPath := filepath.Join(t.TempDir(), "audit.jsonl")
		maxLogBytes = 1 << 30
		seedLogAtThreshold(t, logPath, 5)

		stale := make([]*AuditLogger, writers)
		for i := range stale {
			lg, err := New(logPath)
			if err != nil {
				t.Fatal(err)
			}
			stale[i] = lg
		}
		rotator, err := New(logPath)
		if err != nil {
			t.Fatal(err)
		}
		logEvents(t, rotator, 1, "echo rotator")
		_ = rotator.Close()
		maxLogBytes = 1 << 30

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range stale {
			wg.Add(1)
			go func(lg *AuditLogger) {
				defer wg.Done()
				<-start
				for k := 0; k < writes; k++ {
					_ = lg.Log(AuditEvent{Timestamp: "t", Command: "echo stale", Decision: "ALLOW", Mode: "enforce"})
				}
				_ = lg.Close()
			}(stale[i])
		}
		close(start)
		wg.Wait()

		if r := VerifyChain(logPath); r.State != ChainStateVerified {
			broken++
			if firstMsg == "" {
				firstMsg = string(r.State) + ": " + r.Message
			}
		}
	}
	t.Logf("trials=%d writers=%d writes/trial=%d: chains not verified in %d trials", trials, writers, writers*writes, broken)
	if broken != 0 {
		t.Errorf("%d of %d trials left the chain unverified (first: %s)", broken, trials, firstMsg)
	}
}

// TestAuditLogger_ReopenOpenFailureKeepsDescriptor (PR #4041 review, pass
// 3): the log directory disappears under a long-running writer. The stat
// says ENOENT, so the reopen path is taken and the open fails; the writer
// must keep its descriptor (the write lands on the orphaned inode, warned,
// not fatal). When the directory comes back the next write must reopen and
// land in the new live file. Deterministically kills two mutants that the
// rest of the suite catches only probabilistically or not at all: dropping
// the fs.ErrNotExist clause (the writer never reopens and every entry is
// lost to the orphan) and closing the old descriptor before opening the new
// one (the logger is dead after the failed open).
func TestAuditLogger_ReopenOpenFailureKeepsDescriptor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "as")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	smallRotation(t, 1<<20)

	lr, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lr, 2, "echo before")

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	_ = lr.Log(AuditEvent{Timestamp: "t", Command: "echo dir-gone", Decision: "ALLOW", Mode: "enforce"})

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	errBack := lr.Log(AuditEvent{Timestamp: "t", Command: "echo dir-back", Decision: "ALLOW", Mode: "enforce"})
	_ = lr.Close()

	if errBack != nil {
		t.Errorf("Log after the directory came back: %v", errBack)
	}
	if got := countLines(t, logPath, "dir-back"); got != 1 {
		t.Errorf("entry written after the directory came back: found %d in the new live file, want 1", got)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("new live file: expected %q, got %q: %s", ChainStateVerified, r.State, r.Message)
	}
}
