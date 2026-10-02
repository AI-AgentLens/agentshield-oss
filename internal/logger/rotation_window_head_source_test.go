//go:build unix

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The tests in this file are Codex pass 2 on #4057, reproduced by Kai: a
// degraded writer D derived its prev_hash from the PATH (ChainHead(path))
// while its bytes went to the HELD descriptor. Inside a healthy sibling's
// rotation those name different inodes: H had renamed live -> .1 and not
// yet created the new live file, so D read "" from the absent path and
// wrote a genesis line into what was now .1. nlink was 1, so no re-append
// ran; H then linked the fresh live file to D's genesis line, and
// VerifyChain(live) said verified while VerifyChain(.1) was broken at D's
// line. Round 5 reads a non-empty file's head from the held descriptor.

// renameLiveAway is the first half of a sibling's rotation, without the
// second: live becomes .1 and no new live file exists yet.
func renameLiveAway(t *testing.T, logPath string) {
	t.Helper()
	_ = os.Remove(logPath + rotatedSuffix)
	if err := os.Rename(logPath, logPath+rotatedSuffix); err != nil {
		t.Fatal(err)
	}
}

// TestDegradedFollower_RenameInWindow_HeadFromHeldFile is Kai's replay of
// the Codex pass 2 finding. H appended after D's last write (so D's head is
// stale and resyncHead must re-read it), and the rename lands between D's
// follow and its head read. D's line must chain onto the line before it in
// .1 (H-1), so that .1 verifies on its own and the live file's link to .1
// covers D's line rather than a genesis reset.
func TestDegradedFollower_RenameInWindow_HeadFromHeldFile(t *testing.T) {
	smallRotation(t, 1<<20)
	D, H, logPath := newDegradedThenHealthy(t)
	if err := D.Log(windowEvent("D-1")); err != nil {
		t.Fatal(err)
	}
	if err := H.Log(windowEvent("H-1")); err != nil {
		t.Fatal(err)
	}
	headBeforeRename := ChainHead(logPath)
	if headBeforeRename == "" {
		t.Fatal("control: the live file has no chained head to link to")
	}

	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		renameLiveAway(t, logPath)
	}
	t.Cleanup(func() { afterDegradedFollow = nil })
	if err := D.Log(windowEvent("D-2-in-window")); err != nil {
		t.Fatalf("Log = %v; want nil (the line is retained in .1)", err)
	}
	if afterDegradedFollow != nil {
		t.Fatal("control: the seam never fired")
	}
	// H resumes: its next Log finds the path gone, follows onto a fresh
	// live file and links its first line to .1's head.
	for i := 0; i < 3; i++ {
		if err := H.Log(windowEvent(fmt.Sprintf("H-after-%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	if live, old := countIn(logPath, "D-2-in-window"), countIn(logPath+rotatedSuffix, "D-2-in-window"); live != 0 || old != 1 {
		t.Fatalf("D-2-in-window is in live=%d .1=%d; want live=0 .1=1", live, old)
	}
	old := readEvents(t, logPath+rotatedSuffix)
	last := old[len(old)-1]
	if last.Command != "D-2-in-window" {
		t.Fatalf(".1's last line is %q; want D-2-in-window", last.Command)
	}
	if last.PrevHash != headBeforeRename {
		t.Errorf("D's line in .1 has prev_hash %q; want the head of the file it was appended to %q (a head read from the path gives \"\", a genesis line)", last.PrevHash, headBeforeRename)
	}
	if r := VerifyChain(logPath + rotatedSuffix); r.State != ChainStateVerified {
		t.Errorf("VerifyChain(.1) = %s: %s; want verified", r.State, r.Message)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified || r.Note != "linked to "+filepath.Base(logPath+rotatedSuffix) {
		t.Errorf("VerifyChain(live) = %s note=%q: %s; want verified and linked to .1", r.State, r.Note, r.Message)
	}
	// The link covers D's line: deleting it from .1's tail is detected.
	dropLastRecord(t, logPath+rotatedSuffix)
	if r := VerifyChain(logPath); r.State != ChainStateBroken {
		t.Errorf("after dropping D's line from .1, VerifyChain(live) = %s; want broken", r.State)
	}
}

// TestDegradedFollower_AppendInWindow_HeadFromHeldFile is the same class
// without a rename: H appends to the live file inside D's window. Both
// sources agree here, and the head must be H's newest line either way.
func TestDegradedFollower_AppendInWindow_HeadFromHeldFile(t *testing.T) {
	smallRotation(t, 1<<20)
	D, H, logPath := newDegradedThenHealthy(t)
	if err := D.Log(windowEvent("D-1")); err != nil {
		t.Fatal(err)
	}
	want := ""
	afterDegradedFollow = func() {
		afterDegradedFollow = nil
		if err := H.Log(windowEvent("H-in-window")); err != nil {
			t.Fatal(err)
		}
		want = ChainHead(logPath)
	}
	t.Cleanup(func() { afterDegradedFollow = nil })
	if err := D.Log(windowEvent("D-2")); err != nil {
		t.Fatal(err)
	}
	evs := readEvents(t, logPath)
	if got := evs[len(evs)-1]; got.Command != "D-2" || got.PrevHash != want {
		t.Errorf("last line %q prev_hash %q; want D-2 linked to %q", got.Command, got.PrevHash, want)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("VerifyChain = %s: %s", r.State, r.Message)
	}
}

// TestOpenLog_WriteOnlyFileStillOpens pins openLog's fallback: a log file
// we may write but not read must not fail New (the hook would skip
// evaluation, #4052) and must still take appends. The head read has no
// readable source in that mode, so the line is a genesis line, as on main.
func TestOpenLog_WriteOnlyFileStillOpens(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads regardless of mode")
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(windowEvent("before")); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := os.Chmod(logPath, 0200); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(logPath, 0600) })

	w, err := New(logPath)
	if err != nil {
		t.Fatalf("New on a write-only log = %v; want it to open (main opened it write-only)", err)
	}
	defer func() { _ = w.Close() }()
	if _, readable := chainHeadFile(w.file); readable {
		t.Fatal("control: the descriptor is readable; the fixture did not exercise the fallback")
	}
	if err := w.Log(windowEvent("after")); err != nil {
		t.Fatalf("Log through the write-only descriptor = %v", err)
	}
	if err := os.Chmod(logPath, 0600); err != nil {
		t.Fatal(err)
	}
	evs := readEvents(t, logPath)
	if len(evs) != 2 || evs[1].Command != "after" {
		t.Fatalf("events = %d, want 2 with the second being \"after\"", len(evs))
	}
}
