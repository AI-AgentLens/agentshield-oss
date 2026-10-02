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

// #4057 Codex pass 6 (Kai's replay): an empty live file beside a FIFO at
// audit.jsonl.1 hung Log — resyncHead takes an empty file's head from
// ChainHead(<path>.1), whose open blocked until a writer arrived. The hook
// logs before it prints its decision, so a hung Log is a missing verdict
// and a harness timeout. The head read now opens without blocking and
// reads only a regular file; a FIFO there is "no head", a genesis line.

// logWithin runs one Log and fails the test if it has not returned after
// d, unblocking the FIFO so the package run does not stall behind it.
func logWithin(t *testing.T, l *AuditLogger, fifo string, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- l.Log(AuditEvent{Timestamp: "2026-09-30T00:00:00Z", Command: "x", Decision: "BLOCK", Mode: "enforce"})
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatalf("Log did not return within %s with a FIFO at %s", d, filepath.Base(fifo))
		return nil
	}
}

func TestLog_FIFOPredecessorDoesNotHangWriter(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(fmt.Sprintf("degraded=%v", degraded), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			if degraded {
				// A directory at the lock path: New cannot open the lock
				// and runs in the lock-unavailable mode.
				if err := os.Mkdir(p+lockSuffix, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
			fifo := p + rotatedSuffix
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			l, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()

			start := time.Now()
			if err := logWithin(t, l, fifo, 2*time.Second); err != nil {
				t.Fatalf("Log: %v", err)
			}
			t.Logf("Log returned in %s", time.Since(start))

			lines := readLines(t, p)
			if len(lines) != 1 {
				t.Fatalf("live file has %d lines, want 1", len(lines))
			}
			fe := firstEntry(t, p)
			if fe.PrevHash != "" || fe.EntryHash == "" {
				t.Fatalf("entry prev_hash=%q entry_hash=%q: want a genesis line with no head taken from the FIFO", fe.PrevHash, fe.EntryHash)
			}
			if !strings.Contains(lines[0], `"command":"x"`) {
				t.Errorf("event not written to the live file: %s", lines[0])
			}
			if degraded != (l.lockFd == nil) {
				t.Fatalf("fixture: degraded=%v but lockFd nil=%v", degraded, l.lockFd == nil)
			}
		})
	}
}

// A symlink at .1 pointing at a regular rotated file still yields its head:
// the kind check is made on the open descriptor, which follows the link.
// (The verifier deliberately refuses a symlinked .1; the writer linking to
// it is the pre-existing behaviour and is pinned, not endorsed.)
func TestLog_SymlinkPredecessorHeadStillRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	target := filepath.Join(t.TempDir(), "rotated.jsonl")
	for i := 0; i < 3; i++ {
		hookWrite(t, target, fmt.Sprintf("rotated-%d", i))
	}
	want := ChainHead(target)
	if want == "" {
		t.Fatal("fixture: rotated file has no head")
	}
	if err := os.Symlink(target, p+rotatedSuffix); err != nil {
		t.Fatal(err)
	}
	if got := ChainHead(p + rotatedSuffix); got != want {
		t.Fatalf("ChainHead through symlink = %q, want %q", got, want)
	}
	if err := os.WriteFile(p, nil, 0600); err != nil {
		t.Fatal(err)
	}
	hookWrite(t, p, "after-link")
	if fe := firstEntry(t, p); fe.PrevHash != want {
		t.Fatalf("first live entry prev_hash = %q, want the symlinked .1 head %q", fe.PrevHash, want)
	}
}

// Non-regular kinds other than a FIFO read as "no head" too, with no
// error path left to a blocking or failing read.
func TestChainHead_NonRegularPredecessorIsNoHead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.Mkdir(p+rotatedSuffix, 0700); err != nil {
		t.Fatal(err)
	}
	if got := ChainHead(p + rotatedSuffix); got != "" {
		t.Fatalf("ChainHead(directory) = %q, want \"\"", got)
	}
}
