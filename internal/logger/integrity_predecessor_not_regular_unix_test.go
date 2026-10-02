//go:build unix

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// #4133 Opus pass 4: the rotated predecessor is opened only when it is a
// regular file. A FIFO at audit.jsonl.1 blocked VerifyChain — and `scan` —
// on open until something wrote to it; a symlink was followed. Both read
// Unreadable now: not a tampering claim, not a verification.

// verifyWithin runs VerifyChain and fails the test if it has not returned
// after d — a hung open would otherwise stall the whole package run.
func verifyWithin(t *testing.T, path string, d time.Duration) ChainVerifyResult {
	t.Helper()
	done := make(chan ChainVerifyResult, 1)
	go func() { done <- VerifyChain(path) }()
	select {
	case r := <-done:
		return r
	case <-time.After(d):
		t.Fatalf("VerifyChain(%s) did not return within %s", filepath.Base(path), d)
		return ChainVerifyResult{}
	}
}

func assertPredecessorNotRegular(t *testing.T, r ChainVerifyResult, wantEntries int) {
	t.Helper()
	if r.State != ChainStateUnreadable || r.Protected() || r.Entries != wantEntries {
		t.Fatalf("got %q (%d entries, protected=%v): %s", r.State, r.Entries, r.Protected(), r.Message)
	}
	if !strings.HasPrefix(r.Message, "audit.jsonl.1 unreadable, not verified: not a regular file") {
		t.Errorf("message = %q", r.Message)
	}
	if strings.Contains(r.Note, "linked") {
		t.Errorf("note %q must not claim a link", r.Note)
	}
}

func TestVerifyChain_FIFOPredecessorDoesNotHang(t *testing.T) {
	for _, live := range []struct {
		name  string
		stage func(t *testing.T, p string)
		want  int
	}{
		{"genesis live", func(t *testing.T, p string) { hookWrite(t, p, "genesis") }, 1},
		{"linked live", func(t *testing.T, p string) {
			// Two rotations by the real writer, then the FIFO replaces .1.
			smallRotation(t, 1500)
			for i := 0; i < 12; i++ {
				hookWrite(t, p, fmt.Sprintf("hook-%d", i))
			}
			fe := firstEntry(t, p)
			if fe.PrevHash == "" {
				t.Skip("fixture did not produce a linked live file")
			}
			if err := os.Remove(p + rotatedSuffix); err != nil {
				t.Fatal(err)
			}
		}, -1},
		{"empty live", func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}, 0},
	} {
		t.Run(live.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			live.stage(t, p)
			if err := syscall.Mkfifo(p+rotatedSuffix, 0600); err != nil {
				t.Fatal(err)
			}
			r := verifyWithin(t, p, 5*time.Second)
			want := live.want
			if want < 0 {
				want = verifyFile(p).result.Entries
			}
			assertPredecessorNotRegular(t, r, want)
		})
	}
}

// A symlink at .1 is no longer followed: it reads Unreadable (⚠) rather
// than verifying whatever it points at (which, for a dangling link, was the
// deletion-equivalent ✅). Intended.
func TestVerifyChain_SymlinkPredecessorIsUnreadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	hookWrite(t, p, "genesis")
	target := filepath.Join(t.TempDir(), "elsewhere.jsonl")
	for i := 0; i < 3; i++ {
		hookWrite(t, target, fmt.Sprintf("elsewhere-%d", i))
	}
	if err := os.Symlink(target, p+rotatedSuffix); err != nil {
		t.Fatal(err)
	}
	assertPredecessorNotRegular(t, verifyWithin(t, p, 5*time.Second), 1)

	// Dangling as well.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	assertPredecessorNotRegular(t, verifyWithin(t, p, 5*time.Second), 1)
}

// Opus pass 4 R12 on real files: a live file stripped of every chain field
// (unprotected on its own) beside a broken .1 is broken in .1, not ⚠
// unprotected.
func TestVerifyChain_UnprotectedLiveDoesNotSkipPredecessor(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
	lines := readLines(t, live)
	for i := range lines {
		lines[i] = stripChain(t, lines[i])
	}
	writeLines(t, live, lines)
	if fs := verifyFile(live); fs.result.State != ChainStateUnprotected {
		t.Fatalf("fixture: live should be unprotected on its own, got %q", fs.result.State)
	}
	writeLines(t, rotated, dropLine(readLines(t, rotated), 3))
	assertBrokenInPredecessor(t, VerifyChain(live), 3)
}
