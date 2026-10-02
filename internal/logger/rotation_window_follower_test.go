//go:build unix

package logger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests in this file are F1 from the Opus pass 3 on #4057. A writer
// that only follows a rotation — it did not perform it — reaches resyncHead
// with an empty live file and no head of its own. Reading ChainHead(live)
// there gave "", so it wrote a genesis line into the fresh file, and the
// healthy rotator then linked to that line. VerifyChain(live) said verified
// with no "linked to audit.jsonl.1" note, and an entry deleted from .1's
// tail went undetected: the rotation link was silently cut. The fix reads
// the head of <path>.1 when the live file is empty, the same source
// rotateIfNeeded uses for the rotator's own first line.

// newDegradedThenHealthy opens D while the lock path is a directory, repairs
// the lock, then opens H healthy. Both write one log.
func newDegradedThenHealthy(t *testing.T) (D, H *AuditLogger, logPath string) {
	t.Helper()
	logPath = filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Mkdir(logPath+lockSuffix, 0755); err != nil {
		t.Fatal(err)
	}
	var err error
	if D, err = New(logPath); err != nil {
		t.Fatal(err)
	}
	if D.lockFd != nil {
		t.Fatal("control: D opened the lock; the fixture did not make it unopenable")
	}
	if err := os.Remove(logPath + lockSuffix); err != nil {
		t.Fatal(err)
	}
	if H, err = New(logPath); err != nil {
		t.Fatal(err)
	}
	if H.lockFd == nil {
		t.Fatal("control: H is degraded; the lock repair did not take")
	}
	t.Cleanup(func() { _ = D.Close(); _ = H.Close() })
	return D, H, logPath
}

func windowEvent(cmd string) AuditEvent {
	return AuditEvent{Timestamp: "2026-09-30T00:00:00Z", Command: cmd, Decision: "ALLOW", Mode: "enforce"}
}

// dropLastRecord deletes the last record of path: an attacker removing the
// most recent entry of the rotated generation.
func dropLastRecord(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.TrimRight(b, "\n")
	i := bytes.LastIndexByte(b, '\n')
	if i < 0 {
		t.Fatalf("%s holds one record; nothing to drop", filepath.Base(path))
	}
	if err := os.WriteFile(path, b[:i+1], 0600); err != nil {
		t.Fatal(err)
	}
}

// fillToRotationThreshold appends through l until the live file is at or
// past maxLogBytes without having rotated, so l's next rotateIfNeeded rotates.
func fillToRotationThreshold(t *testing.T, l *AuditLogger, logPath string) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if st, err := os.Stat(logPath); err == nil && st.Size() >= maxLogBytes {
			return
		}
		if err := l.Log(windowEvent(fmt.Sprintf("H-fill-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("the live file never reached the rotation threshold")
}

// assertLinkedToRotated is the contract of a follower's first line in a
// fresh live file: it links to .1's head, VerifyChain says so, and deleting
// .1's last entry is detected through that link.
func assertLinkedToRotated(t *testing.T, logPath, firstCmd string) {
	t.Helper()
	rotated := logPath + rotatedSuffix
	evs := readEvents(t, logPath)
	if evs[0].Command != firstCmd {
		t.Fatalf("live[0] = %q, want %q (the fixture did not land the follower's line first)", evs[0].Command, firstCmd)
	}
	if head := ChainHead(rotated); evs[0].PrevHash != head {
		t.Errorf("live[0].prev_hash = %q, want .1's head %q (a genesis line cuts the rotation link)", evs[0].PrevHash, head)
	}
	r := VerifyChain(logPath)
	if r.State != ChainStateVerified || r.Note != "linked to "+filepath.Base(rotated) {
		t.Errorf("VerifyChain(live) = %s note=%q; want verified and linked to .1 (%s)", r.State, r.Note, r.Message)
	}
	dropLastRecord(t, rotated)
	r = VerifyChain(logPath)
	if r.State != ChainStateBroken || r.Protected() {
		t.Errorf("after deleting .1's last entry: VerifyChain(live) = %s Protected=%v; want broken (the deletion went undetected)", r.State, r.Protected())
	}
}

// TestDegradedFollower_InsideRename_LinksToRotated is window w1: D's Log runs
// after H's rename(live, .1) and before H's OpenFile(live). The live path is
// gone, so D's followRotation creates the fresh file and D writes its first
// line; H then opens the same file and links to D.
func TestDegradedFollower_InsideRename_LinksToRotated(t *testing.T) {
	smallRotation(t, 1500)
	D, H, logPath := newDegradedThenHealthy(t)
	if err := D.Log(windowEvent("D-before")); err != nil {
		t.Fatal(err)
	}
	fillToRotationThreshold(t, H, logPath)

	// rotateIfNeeded inlined, with D's Log between the rename and the open.
	// D takes no lock, so H holding it does not block D.
	H.mu.Lock()
	release := lockFile(H.lockFd)
	if err := H.file.Close(); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(logPath + rotatedSuffix)
	if err := os.Rename(logPath, logPath+rotatedSuffix); err != nil {
		t.Fatal(err)
	}
	if err := D.Log(windowEvent("D-in-window")); err != nil {
		t.Fatal(err)
	}
	H.prevHash = ChainHead(logPath + rotatedSuffix)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	H.file = f
	H.knownSize = 0
	release()
	H.mu.Unlock()

	for i := 0; i < 3; i++ {
		if err := H.Log(windowEvent(fmt.Sprintf("H-after-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if live, old := countIn(logPath, "D-in-window"), countIn(logPath+rotatedSuffix, "D-in-window"); live != 1 || old != 0 {
		t.Fatalf("D-in-window is in live=%d .1=%d; want live=1 .1=0", live, old)
	}
	assertLinkedToRotated(t, logPath, "D-in-window")
}

// TestDegradedFollower_AfterRotateBeforeFirstWrite_LinksToRotated is window
// w2: H's rotateIfNeeded has returned (fresh live file, empty) and D's Log
// runs before H's resyncHead and first write.
func TestDegradedFollower_AfterRotateBeforeFirstWrite_LinksToRotated(t *testing.T) {
	smallRotation(t, 1500)
	D, H, logPath := newDegradedThenHealthy(t)
	if err := D.Log(windowEvent("D-before")); err != nil {
		t.Fatal(err)
	}
	fillToRotationThreshold(t, H, logPath)

	H.mu.Lock()
	release := lockFile(H.lockFd)
	if err := H.rotateIfNeeded(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(logPath); err != nil || st.Size() != 0 {
		t.Fatalf("control: after H's rotation the live file is %v bytes, want an empty file", st)
	}
	if err := D.Log(windowEvent("D-in-window")); err != nil {
		t.Fatal(err)
	}
	release()
	H.mu.Unlock()

	for i := 0; i < 3; i++ {
		if err := H.Log(windowEvent(fmt.Sprintf("H-after-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	assertLinkedToRotated(t, logPath, "D-in-window")
}

// TestExternalRotationFollower_LinksToRotated: nothing in-process rotated.
// An operator (or logrotate in "create" mode) does `mv live .1 && touch live`
// under a running writer. Healthy or degraded, the writer's next line must
// link to .1 rather than start a chain the verifier accepts on its own.
func TestExternalRotationFollower_LinksToRotated(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(fmt.Sprintf("degraded=%v", degraded), func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "audit.jsonl")
			if degraded {
				if err := os.Mkdir(logPath+lockSuffix, 0755); err != nil {
					t.Fatal(err)
				}
			}
			l, err := New(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			if (l.lockFd == nil) != degraded {
				t.Fatalf("control: lockFd nil=%v, want degraded=%v", l.lockFd == nil, degraded)
			}
			logEvents(t, l, 3, "pre")

			if err := os.Rename(logPath, logPath+rotatedSuffix); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(logPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			logEvents(t, l, 2, "post")
			assertLinkedToRotated(t, logPath, "post-0")
		})
	}
}

// TestFreshLogWithoutRotatedFile_StartsAtGenesis pins the other branch: with
// no <path>.1 on disk the first line of an empty log is a genesis line, as
// before. The .1-head rule applies only when there is a .1 to link to.
func TestFreshLogWithoutRotatedFile_StartsAtGenesis(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	logEvents(t, l, 2, "fresh")
	evs := readEvents(t, logPath)
	if evs[0].PrevHash != "" {
		t.Errorf("live[0].prev_hash = %q on a log with no .1; want a genesis line", evs[0].PrevHash)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified || r.Note != "" {
		t.Errorf("VerifyChain = %s note=%q; want verified with no link note", r.State, r.Note)
	}
}

// TestDegradedLogger_ReopenFailureKeepsDescriptor pins what Log does when
// the degraded follow-the-rotation reopen fails (pass 3 mutation n14): it
// warns, appends through the held descriptor rather than skip the write,
// and keeps the descriptor, so the logger is alive again once the
// directory is back. What changed in round 4: the held inode here has no
// name (the directory is gone), so that append is in no retained file, and
// Log now says so, an error and a stderr warning (reappendIfUnlinked),
// instead of the nil that claimed persistence. The hook warns and enforces
// on that error; the watchdog and shield-server discard it and get the
// stderr line. The healthy path is unchanged
// (TestAuditLogger_ReopenOpenFailureKeepsDescriptor).
func TestDegradedLogger_ReopenFailureKeepsDescriptor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "as")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
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
	logEvents(t, D, 2, "before")

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := D.Log(windowEvent("dir-gone")); err == nil || !strings.Contains(err.Error(), "audit event lost") {
		t.Errorf("Log while the reopen fails = %v; want an error naming the loss (the held inode has no name, so the append is in no retained file)", err)
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := D.Log(windowEvent("dir-back")); err != nil {
		t.Errorf("Log after the directory came back = %v; want nil", err)
	}
	if got := countIn(logPath, "dir-back"); got != 1 {
		t.Errorf("dir-back is in the new live file %d times, want 1", got)
	}
	evs := readEvents(t, logPath)
	if len(evs) != 1 || lockNote(evs[0].Notes) == nil {
		t.Errorf("new live file = %d events, first notes %+v; want the one dir-back event carrying the lock note", len(evs), evs[0].Notes)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("VerifyChain(new live) = %s: %s; want verified", r.State, r.Message)
	}
}
