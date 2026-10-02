package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests cover #4132 item 2 (Gary, 2026-09-30): when the live log links
// to audit.jsonl.1, VerifyChain(live) must verify the predecessor's own chain,
// not just its tail hash. Before this, a middle line deleted from .1 (#4057
// pass-4 row R02) or an entry mis-linked inside .1 (the Codex pass-3 schedule
// on #4057) sat behind a live log that reported Protected().

// rotatedPair writes a chained predecessor of n entries at <path>.1 and a
// live log of m entries whose first entry links to the predecessor's head.
// It returns both paths.
func rotatedPair(t *testing.T, dir string, n, m int) (live, rotated string) {
	t.Helper()
	live = filepath.Join(dir, "audit.jsonl")
	rotated = live + rotatedSuffix

	events := func(prefix string, count int) []AuditEvent {
		out := make([]AuditEvent, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, AuditEvent{
				Timestamp: "2026-09-30T00:00:00Z",
				Command:   prefix + "-" + strings.Repeat("x", i),
				Decision:  "ALLOW",
			})
		}
		return out
	}
	writeChainedLog(t, rotated, events("old", n))
	writeChainedLogFrom(t, live, ChainHead(rotated), events("new", m))
	return live, rotated
}

// writeChainedLogFrom is writeChainedLog with a caller-supplied genesis
// prev_hash, so a live file can be written as the continuation of a rotated
// predecessor exactly as AuditLogger does at a rotation boundary.
func writeChainedLogFrom(t *testing.T, path, prevHash string, events []AuditEvent) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, e := range events {
		ce := ChainedEvent{AuditEvent: e, PrevHash: prevHash}
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

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertBrokenInPredecessor(t *testing.T, r ChainVerifyResult, wantAt int) {
	t.Helper()
	if r.State != ChainStateBroken {
		t.Fatalf("expected %q, got %q: %s (note %q)", ChainStateBroken, r.State, r.Message, r.Note)
	}
	if r.Protected() {
		t.Error("a live log linked to a broken predecessor must never report Protected()")
	}
	if r.BrokenIn != "audit.jsonl.1" {
		t.Errorf("BrokenIn = %q, want audit.jsonl.1", r.BrokenIn)
	}
	if r.BrokenAt != wantAt {
		t.Errorf("BrokenAt = %d, want %d (%s)", r.BrokenAt, wantAt, r.Message)
	}
	if !strings.HasPrefix(r.Message, "audit.jsonl.1 entry ") {
		t.Errorf("message must name the rotated file and entry, got %q", r.Message)
	}
}

// R02 from the #4057 pass-4 table: a line deleted from the middle of .1 while
// the live file still links cleanly to .1's (unchanged) head.
func TestVerifyChain_LinkedPredecessorMiddleLineDeleted(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 5, 3)

	lines := readLines(t, rotated)
	writeLines(t, rotated, append(lines[:2:2], lines[3:]...))

	if r := VerifyChain(rotated); r.State != ChainStateBroken || r.BrokenAt != 2 {
		t.Fatalf("control: .1 on its own should be broken at 2, got %q at %d", r.State, r.BrokenAt)
	}
	r := VerifyChain(live)
	assertBrokenInPredecessor(t, r, 2)
	if !strings.Contains(r.Message, "prev_hash mismatch") {
		t.Errorf("message should carry the predecessor's finding, got %q", r.Message)
	}
	if r.Entries != 3 {
		t.Errorf("Entries should still count the live log (3), got %d", r.Entries)
	}
}

// The Codex pass-3 schedule on #4057: an entry inside .1 whose prev_hash
// skips its predecessor (a stale head adopted across a rotation), with the
// live file linked to that entry. The neighbour carries the note kind a
// degraded writer attaches, so the message says so — as a hint only.
func TestVerifyChain_LinkedPredecessorMisLinkedEntry(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 3, 2)
	lines := readLines(t, rotated)

	// Rewrite entry 2 to link to entry 0 instead of entry 1, keeping its own
	// entry_hash valid, then relink the live file to the new head so the
	// tail-hash check that existed before this change is satisfied.
	var e0, e2 ChainedEvent
	if err := json.Unmarshal([]byte(lines[0]), &e0); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &e2); err != nil {
		t.Fatal(err)
	}
	e2.Notes = []Note{{Kind: "audit_lock_unavailable", Detail: "flock: EAGAIN"}}
	e2.PrevHash = rawChainedHash([]byte(lines[0]))
	e2.EntryHash = ComputeEntryHash(e2)
	stale, err := json.Marshal(e2)
	if err != nil {
		t.Fatal(err)
	}
	lines[2] = string(stale)
	writeLines(t, rotated, lines)
	writeChainedLogFrom(t, live, ChainHead(rotated), []AuditEvent{
		{Timestamp: "2026-09-30T00:00:01Z", Command: "new-0", Decision: "ALLOW"},
		{Timestamp: "2026-09-30T00:00:02Z", Command: "new-1", Decision: "ALLOW"},
	})

	if r := VerifyChain(rotated); r.State != ChainStateBroken || r.BrokenAt != 2 {
		t.Fatalf("control: .1 on its own should be broken at 2, got %q at %d: %s", r.State, r.BrokenAt, r.Message)
	}
	r := VerifyChain(live)
	assertBrokenInPredecessor(t, r, 2)
	if !strings.Contains(r.Message, "lost lock race") {
		t.Errorf("a break next to a lock-unavailable note should say so, got %q", r.Message)
	}
}

// The lock-unavailable hint is words in a BROKEN message and nothing more: a
// note-bearing entry anywhere near the break never turns it into a pass, and a
// break with no noted neighbour does not claim one.
func TestVerifyChain_LinkedPredecessorLockNoteIsOnlyAHint(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
	lines := readLines(t, rotated)
	writeLines(t, rotated, append(lines[:2:2], lines[3:]...))

	r := VerifyChain(live)
	assertBrokenInPredecessor(t, r, 2)
	if strings.Contains(r.Message, "lock") {
		t.Errorf("no entry carries a lock note; message must not suggest one: %q", r.Message)
	}
}

// Control: a clean rotation is verified and reports the link, exactly as
// before this change.
func TestVerifyChain_LinkedPredecessorClean(t *testing.T) {
	live, _ := rotatedPair(t, t.TempDir(), 4, 3)
	r := VerifyChain(live)
	if r.State != ChainStateVerified || !r.Protected() {
		t.Fatalf("expected verified, got %q: %s", r.State, r.Message)
	}
	if r.Note != "linked to audit.jsonl.1" {
		t.Errorf("note = %q", r.Note)
	}
	if r.BrokenIn != "" || r.BrokenAt != -1 {
		t.Errorf("BrokenIn=%q BrokenAt=%d on a verified chain", r.BrokenIn, r.BrokenAt)
	}
}

// Control: .1 absent or empty is "predecessor unavailable", unchanged (R06/R07).
func TestVerifyChain_LinkedPredecessorAbsentOrEmpty(t *testing.T) {
	for _, shape := range []string{"absent", "empty"} {
		t.Run(shape, func(t *testing.T) {
			live, rotated := rotatedPair(t, t.TempDir(), 3, 2)
			if shape == "absent" {
				if err := os.Remove(rotated); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(rotated, nil, 0600); err != nil {
				t.Fatal(err)
			}
			r := VerifyChain(live)
			if r.State != ChainStateVerified || !r.Protected() {
				t.Fatalf("expected verified, got %q: %s", r.State, r.Message)
			}
			if r.Note != "continues a rotated log (predecessor unavailable)" {
				t.Errorf("note = %q", r.Note)
			}
		})
	}
}

// Control: only one generation is retained, so .1's own first entry linking
// to a .2 that no longer exists is not a break — the live log stays verified.
func TestVerifyChain_LinkedPredecessorItselfContinuesAnExpiredGeneration(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.jsonl")
	rotated := live + rotatedSuffix
	older := []AuditEvent{{Timestamp: "2026-09-30T00:00:00Z", Command: "gen-2", Decision: "ALLOW"}}
	gen2 := filepath.Join(dir, "gen2.jsonl")
	writeChainedLog(t, gen2, older)
	writeChainedLogFrom(t, rotated, ChainHead(gen2), []AuditEvent{
		{Timestamp: "2026-09-30T00:00:01Z", Command: "old-0", Decision: "ALLOW"},
		{Timestamp: "2026-09-30T00:00:02Z", Command: "old-1", Decision: "ALLOW"},
	})
	if err := os.Remove(gen2); err != nil {
		t.Fatal(err)
	}
	writeChainedLogFrom(t, live, ChainHead(rotated), []AuditEvent{
		{Timestamp: "2026-09-30T00:00:03Z", Command: "new-0", Decision: "ALLOW"},
	})

	r := VerifyChain(live)
	if r.State != ChainStateVerified || !r.Protected() {
		t.Fatalf("expected verified, got %q: %s", r.State, r.Message)
	}
	if r.Note != "linked to audit.jsonl.1" {
		t.Errorf("note = %q", r.Note)
	}
}

// Deleting .1's LAST line is caught at the live boundary as before: the live
// file's first entry no longer matches .1's head. Unchanged behaviour.
func TestVerifyChain_LinkedPredecessorLastLineDeleted(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 4, 2)
	lines := readLines(t, rotated)
	writeLines(t, rotated, lines[:len(lines)-1])

	r := VerifyChain(live)
	if r.State != ChainStateBroken || r.Protected() {
		t.Fatalf("expected broken, got %q: %s", r.State, r.Message)
	}
	if r.BrokenAt != 0 || r.BrokenIn != "" {
		t.Errorf("break belongs to the live boundary (entry 0), got BrokenAt=%d BrokenIn=%q", r.BrokenAt, r.BrokenIn)
	}
	if !strings.Contains(r.Message, "head of audit.jsonl.1") {
		t.Errorf("message = %q", r.Message)
	}
}

// A live log that does not link (genesis first entry) still has .1 verified
// beside it (#4133 pass 3): a broken .1 is reported as broken in .1, exactly
// as it is behind a linked live log. Until round 3 this shape read verified
// with no note, which is what the forced-genesis rotation and the stripped
// prev_hash in integrity_unlinked_predecessor_test.go exploited.
func TestVerifyChain_UnlinkedLiveStillVerifiesPredecessor(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 4, 2)
	lines := readLines(t, rotated)
	writeLines(t, rotated, append(lines[:1:1], lines[2:]...))
	writeChainedLog(t, live, []AuditEvent{{Timestamp: "2026-09-30T00:00:00Z", Command: "fresh", Decision: "ALLOW"}})

	assertBrokenInPredecessor(t, VerifyChain(live), 1)
}

// .1 is bounded by maxLogBytes (10 MB), so verifying it on every scan has a
// bounded cost. This measures it once and reports the figure; it fails only
// if the walk is grossly slower than a linear read of 10 MB.
func TestVerifyChain_LinkedPredecessorTenMegabytes(t *testing.T) {
	if testing.Short() {
		t.Skip("10 MB fixture")
	}
	dir := t.TempDir()
	live := filepath.Join(dir, "audit.jsonl")
	rotated := live + rotatedSuffix

	f, err := os.Create(rotated)
	if err != nil {
		t.Fatal(err)
	}
	prev := ""
	var size int64
	for i := 0; size < defaultMaxLogBytes; i++ {
		ce := ChainedEvent{AuditEvent: AuditEvent{
			Timestamp: "2026-09-30T00:00:00Z",
			Command:   "echo " + strings.Repeat("payload ", 40),
			Args:      []string{"-n", "one", "two"},
			Cwd:       "/home/user/project",
			Decision:  "ALLOW",
		}, PrevHash: prev}
		ce.EntryHash = ComputeEntryHash(ce)
		prev = ComputeChainedHash(ce)
		data, _ := json.Marshal(ce)
		data = append(data, '\n')
		n, _ := f.Write(data)
		size += int64(n)
	}
	_ = f.Close()
	writeChainedLogFrom(t, live, ChainHead(rotated), []AuditEvent{
		{Timestamp: "2026-09-30T00:00:01Z", Command: "new-0", Decision: "ALLOW"},
	})

	start := time.Now()
	r := VerifyChain(live)
	elapsed := time.Since(start)
	if r.State != ChainStateVerified {
		t.Fatalf("expected verified, got %q: %s", r.State, r.Message)
	}
	pred := VerifyChain(rotated)
	t.Logf("VerifyChain(live) with a %d-byte, %d-entry linked predecessor: %s", size, pred.Entries, elapsed)
	if elapsed > 5*time.Second {
		t.Errorf("verifying a 10 MB predecessor took %s", elapsed)
	}
}
