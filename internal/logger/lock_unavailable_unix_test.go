//go:build unix

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// countIn reports how many times needle occurs in the file at path; 0 when
// the file does not exist.
func countIn(path, needle string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), needle)
}

// logUntilRotated appends through l until the live path names a different
// file than it did on entry, i.e. l rotated it. Bounded so a logger that
// never rotates fails the test instead of spinning.
func logUntilRotated(t *testing.T, l *AuditLogger, logPath, prefix string) {
	t.Helper()
	before, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if err := l.Log(AuditEvent{Timestamp: "2026-09-30T00:00:00Z", Command: fmt.Sprintf("%s-%d", prefix, i), Decision: "ALLOW", Mode: "enforce"}); err != nil {
			t.Fatal(err)
		}
		if after, err := os.Stat(logPath); err == nil && !os.SameFile(before, after) {
			return
		}
	}
	t.Fatalf("%s never rotated in 200 appends", prefix)
}

// TestDegradedLogger_FollowsSiblingRotation is E1 from the Opus pass 2 on
// #4057 (C1). A long-lived writer D opens while the lock file is unopenable,
// the operator repairs the lock, and a healthy writer H then rotates the
// log twice. Round 1 skipped all of rotateIfNeeded while degraded, which
// also skipped the follow-the-rotation reopen, so D kept writing to the
// inode H had renamed to .1 and, after the second rotation, unlinked: D's
// later events (the watchdog's tamper record among them) landed in no
// file, and after the first rotation D's prev_hash, read from the live
// path it was not writing to, made VerifyChain(live) report a false break
// at entry 0. The reopen renames and removes nothing, so it is safe
// without the lock and a degraded writer must still run it.
func TestDegradedLogger_FollowsSiblingRotation(t *testing.T) {
	smallRotation(t, 600)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Mkdir(logPath+lockSuffix, 0755); err != nil {
		t.Fatal(err)
	}
	D, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer D.Close()
	if D.lockFd != nil {
		t.Fatal("control: D opened the lock; the fixture did not make it unopenable")
	}
	// The operator repairs the lock. New processes lock normally; D stays
	// degraded for its lifetime.
	if err := os.Remove(logPath + lockSuffix); err != nil {
		t.Fatal(err)
	}
	H, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer H.Close()
	if H.lockFd == nil {
		t.Fatal("control: H is degraded; the lock repair did not take")
	}

	if err := D.Log(AuditEvent{Command: "D-EVENT-0", Decision: "BLOCK", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	logUntilRotated(t, H, logPath, "H-gen1")

	if err := D.Log(AuditEvent{Command: "D-EVENT-AFTER-ROT1", Decision: "BLOCK", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	if live, old := countIn(logPath, "D-EVENT-AFTER-ROT1"), countIn(logPath+rotatedSuffix, "D-EVENT-AFTER-ROT1"); live != 1 || old != 0 {
		t.Fatalf("after rotation 1, D's event is in live=%d and .1=%d; want live=1 .1=0 (D did not follow H's rotation)", live, old)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Fatalf("VerifyChain(live) after rotation 1 + D's append = %+v; want verified (the round-1 false break at entry 0)", r)
	}

	logUntilRotated(t, H, logPath, "H-gen2")
	for _, cmd := range []string{"D-EVENT-AFTER-ROT2", "watchdog-tamper-detected"} {
		if err := D.Log(AuditEvent{Command: cmd, Decision: "AUDIT", Mode: "watchdog"}); err != nil {
			t.Fatal(err)
		}
		if live, old := countIn(logPath, cmd), countIn(logPath+rotatedSuffix, cmd); live != 1 || old != 0 {
			t.Fatalf("after rotation 2, %q is in live=%d and .1=%d; want live=1 .1=0", cmd, live, old)
		}
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(int(D.file.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if st.Nlink < 1 {
		t.Fatalf("D's descriptor has nlink=%d: it is writing into an unlinked inode", st.Nlink)
	}

	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Fatalf("VerifyChain(live) at the end = %+v; want verified across both rotations", r)
	}
	for i, ev := range readEvents(t, logPath) {
		fromD := !strings.HasPrefix(ev.Command, "H-gen")
		if fromD == (lockNote(ev.Notes) == nil) {
			t.Errorf("event %d %q notes = %+v; D's events carry the lock note and H's do not", i, ev.Command, ev.Notes)
		}
	}
}
