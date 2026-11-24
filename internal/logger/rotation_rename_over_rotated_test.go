package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestRotation_WhatIsAtRotatedDoesNotStopRotation pins renameOverRotated's
// retry (#5038). Rotation now renames first and removes <path>.1 only when
// the rename was refused because of what is there, so each shape main's
// os.Remove-first order cleared must still be cleared:
//
//   - a regular file: rename replaces it on every OS (the control);
//   - a read-only file: unix renames over it; Windows refuses with
//     ERROR_ACCESS_DENIED, and os.Remove clears the attribute and deletes it;
//   - an empty directory: rename refuses it everywhere (EISDIR on unix,
//     ERROR_ACCESS_DENIED on Windows), and os.Remove deletes it.
//
// A held <path>.1, the case the retry exists for on Windows, is
// TestRotation_HeldByALoggerAcrossTwoRotations below.
func TestRotation_WhatIsAtRotatedDoesNotStopRotation(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, rotated string)
	}{
		{"regular file", func(t *testing.T, rotated string) {
			if err := os.WriteFile(rotated, []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"read-only file", func(t *testing.T, rotated string) {
			if err := os.WriteFile(rotated, []byte("{}\n"), 0400); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty directory", func(t *testing.T, rotated string) {
			if err := os.Mkdir(rotated, 0700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			rotated := p + rotatedSuffix
			seedLogAtThreshold(t, p, 3)
			tc.setup(t, rotated)
			t.Cleanup(func() { _ = os.Chmod(rotated, 0600) })

			hookWrite(t, p, "rotates")

			info, err := os.Lstat(rotated)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatalf("%s after the rotation: %v, %v; want the rotated log", filepath.Base(rotated), info, err)
			}
			if got := countLines(t, rotated, "seed-"); got != 3 {
				t.Errorf("seed entries in %s: %d, want 3", filepath.Base(rotated), got)
			}
			if got := countLines(t, p, "rotates"); got != 1 {
				t.Errorf("the rotating write should open a fresh live file, found it %d times there", got)
			}
			if r := VerifyChain(p); r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1" {
				t.Errorf("got %q note %q: %s", r.State, r.Note, r.Message)
			}
		})
	}
}

// fillGeneration writes hook entries tagged tag until the live file reaches
// maxLogBytes, and returns how many it wrote.
func fillGeneration(t *testing.T, p, tag string) int {
	t.Helper()
	n := 0
	for {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() >= maxLogBytes {
			return n
		}
		hookWrite(t, p, fmt.Sprintf("%s-%d", tag, n))
		n++
	}
}

// TestRotation_HeldByALoggerAcrossTwoRotations: a long-running writer (the
// watchdog's or shield-server's logger, or a hook process still alive) holds
// audit.jsonl through New while hooks rotate it twice, and loses nothing. On
// unix that always held. On Windows, before #5038, the first rotation failed
// for as long as the holder lived: the live file grew without bound and
// <path>.1 was deleted. Now the logger opens with FILE_SHARE_DELETE there,
// so on every OS:
//
//   - the first rotation renames the held file to <path>.1 (the holder's
//     handle follows it, as on unix);
//   - the second has to replace a <path>.1 the holder still has open. Unix
//     renames over it; Windows refuses (ERROR_ACCESS_DENIED) even with
//     FILE_SHARE_DELETE, so renameOverRotated removes it and renames again;
//   - the holder's next write finds its file gone and reopens the live path
//     (followRotation): its entry lands in the live file once, linked.
func TestRotation_HeldByALoggerAcrossTwoRotations(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	rotated := p + rotatedSuffix

	holder, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Close() })
	logEvents(t, holder, 1, "echo holder-hello")
	seedLogAtThreshold(t, p, 4) // the threshold is now the live file's size

	hookWrite(t, p, "gen1-rotates")
	if got := countLines(t, rotated, "seed-"); got != 4 {
		t.Fatalf("first rotation, the live file held by a logger: %d of 4 seed entries in %s, want all", got, filepath.Base(rotated))
	}
	if got := countLines(t, p, "gen1-rotates"); got != 1 {
		t.Fatalf("the rotating write should open a fresh live file, found it %d times there", got)
	}
	gen1 := 1 + fillGeneration(t, p, "gen1")

	// The holder has not written since the first rotation, so it still
	// holds the file now named <path>.1. This write has to replace it.
	hookWrite(t, p, "gen2-rotates")
	if got := countLines(t, rotated, "gen1-"); got != gen1 {
		t.Fatalf("second rotation, %s held by a logger: %d of %d generation-1 entries in it, want all", filepath.Base(rotated), got, gen1)
	}
	if got := countLines(t, rotated, "seed-"); got != 0 {
		t.Errorf("the seed generation should have been replaced, found %d of its entries in %s", got, filepath.Base(rotated))
	}

	logEvents(t, holder, 1, "echo holder-after")
	if got := countLines(t, p, "holder-after"); got != 1 {
		t.Errorf("the holder's write after two rotations: %d times in the live file, want 1", got)
	}
	for _, path := range []string{p, rotated} {
		if r := VerifyChain(path); r.State != ChainStateVerified {
			t.Errorf("%s: got %q: %s", filepath.Base(path), r.State, r.Message)
		}
	}
	if r := VerifyChain(p); r.Note != "linked to audit.jsonl.1" {
		t.Errorf("live file note %q, want it linked", r.Note)
	}
}
