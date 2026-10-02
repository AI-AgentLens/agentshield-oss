package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestAuditLogger_ConcurrentRotationLosesNoEntries is the regression test for
// the concurrent half of #4042: a lock tied to the data file's own descriptor
// (l.file) is released the instant rotateIfNeeded closes that descriptor —
// which it does on every branch, the size-triggered rotate included — so the
// stat -> close -> remove -> rename -> reopen sequence used to run with no
// lock held at all for part of its length. When several writers open the log
// while it is already at the rotation threshold and then log concurrently,
// more than one can observe "needs rotating" and enter that sequence; if a
// second one's os.Remove(<path>.1) fires after a first has already produced
// it, the first writer's rotated generation — and its entry — is gone.
//
// TestAuditLogger_StaleReopenersConcurrent already drives concurrent writers
// through rotation but stages a single dedicated writer to perform the
// size-triggered rotation before the rest even open the log, so the rest only
// ever take the (already fixed, #4041) rotated-away reopen branch — it cannot
// exercise two writers racing to perform the SAME rotation. It also only
// asserts VerifyChain's state, and #4042 measured VerifyChain reporting
// verified while entries silently never made it to disk: the chain is
// self-consistent over whatever survived, so entry loss leaves no trace
// there. This test opens every writer before any rotation happens, so their
// first Log() calls race for the same rotation, and it counts every entry
// each writer sent — across both the live file and the rotated file — to
// catch loss the chain state alone would miss.
func TestAuditLogger_ConcurrentRotationLosesNoEntries(t *testing.T) {
	const trials, writers = 100, 6
	original := maxLogBytes
	t.Cleanup(func() { maxLogBytes = original })

	for trial := 0; trial < trials; trial++ {
		logPath := filepath.Join(t.TempDir(), "audit.jsonl")
		maxLogBytes = 1 << 30
		seedLogAtThreshold(t, logPath, 5) // log is now sitting exactly at the (lowered) threshold

		loggers := make([]*AuditLogger, writers)
		for i := range loggers {
			// Every writer opens while the log is still at the pre-rotation
			// size, so each independently discovers "needs rotating" on its
			// first Log() below — none of them is staged as the designated
			// rotator the way TestAuditLogger_StaleReopenersConcurrent's
			// "rotator" is.
			lg, err := New(logPath)
			if err != nil {
				t.Fatal(err)
			}
			loggers[i] = lg
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range loggers {
			wg.Add(1)
			go func(idx int, lg *AuditLogger) {
				defer wg.Done()
				<-start
				tag := fmt.Sprintf("w%d", idx)
				if err := lg.Log(AuditEvent{Timestamp: "t", Command: "echo " + tag, Decision: "ALLOW", Mode: "enforce"}); err != nil {
					t.Errorf("trial %d writer %d: %v", trial, idx, err)
				}
				_ = lg.Close()
			}(i, loggers[i])
		}
		close(start)
		wg.Wait()

		missing := 0
		for i := 0; i < writers; i++ {
			tag := fmt.Sprintf("w%d", i)
			total := countLines(t, logPath, tag) + countLines(t, logPath+rotatedSuffix, tag)
			if total != 1 {
				missing++
				t.Logf("trial %d: writer %d's entry appears %d times (want 1)", trial, i, total)
			}
		}
		if missing != 0 {
			t.Errorf("trial %d: %d of %d writers' entries missing or duplicated across %s and its rotated generation",
				trial, missing, writers, logPath)
		}
		if r := VerifyChain(logPath); r.State != ChainStateVerified {
			t.Errorf("trial %d: chain %q: %s", trial, r.State, r.Message)
		}
	}
}

// TestAuditLogger_RenameFailureReopensRatherThanPoisons is the regression test
// for the other #4042 fix: before it, a rotation whose os.Rename failed after
// l.file.Close() had already succeeded left l.file a closed descriptor with
// no replacement — every later Log() failed with "file already closed" until
// the process restarted, and both the watchdog and shield-server discard Log
// errors, so that death was silent. l.path still holds the original file
// when only the rename fails (nothing has moved it), so reopening it in place
// is always available; this pins that the fix takes it.
//
// A directory with read+execute but no write permission is what forces
// os.Rename (which modifies a directory entry) to fail while leaving
// os.OpenFile on the still-present, already-existing path unaffected (opening
// an existing file needs permission on the file, not the directory).
func TestAuditLogger_RenameFailureReopensRatherThanPoisons(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	smallRotation(t, 1<<20)

	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	logEvents(t, lg, 2, "echo before")

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	smallRotation(t, info.Size()) // the next Log() decides it needs to rotate

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	errDuring := lg.Log(AuditEvent{Timestamp: "t", Command: "echo during", Decision: "ALLOW", Mode: "enforce"})
	if errDuring != nil {
		t.Errorf("Log() during the failed rotation: %v (rotation failures are a warning, not a Log() error)", errDuring)
	}
	if _, err := os.Stat(logPath + rotatedSuffix); err == nil {
		t.Fatalf("rotation should not have happened (rename was blocked); found %s", logPath+rotatedSuffix)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The threshold is still the pre-rotation size, and "during" grew the
	// file past it, so without raising it here the next Log() would
	// legitimately rotate again (now that permissions allow it) — a real
	// rotation, not a poisoned descriptor, but it would confuse this
	// assertion with a different, already-covered scenario. Raise it so
	// this write isolates "is the reopened descriptor usable at all".
	smallRotation(t, 1<<20)
	errAfter := lg.Log(AuditEvent{Timestamp: "t", Command: "echo after", Decision: "ALLOW", Mode: "enforce"})
	_ = lg.Close()

	if errAfter != nil {
		t.Errorf("Log() after permissions were restored: %v — the descriptor was left poisoned", errAfter)
	}
	if strings.Contains(fmt.Sprint(errAfter), "file already closed") {
		t.Errorf("logger left with a closed descriptor after the failed rotation")
	}
	if _, err := os.Stat(logPath + rotatedSuffix); err == nil {
		t.Fatalf("still should not have rotated (threshold was raised before this write)")
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 4 {
		t.Errorf("lines on disk: %d, want 4 (2 before + during + after, all in the same never-rotated file)", len(lines))
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("expected %q, got %q: %s", ChainStateVerified, r.State, r.Message)
	}
}
