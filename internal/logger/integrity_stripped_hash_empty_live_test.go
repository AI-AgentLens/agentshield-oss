package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #4133 round 4 (Codex pass 4): two ways the predecessor check could still be
// talked out of a verdict. A record carrying prev_hash but no entry_hash was
// counted as legacy, so stripping entry_hash from every record in .1 turned a
// tampered generation into "pre-chain entries" (⚠ instead of ❌); and an
// empty or absent live file beside a legacy or partial .1 read Empty, which
// `scan` renders as "no entries yet" and leaves out of the summary.

// stripEntryHash removes only entry_hash from a record, leaving prev_hash in
// place: the shape a record has after its chain proof, but not its link, is
// removed.
func stripEntryHash(t *testing.T, line string) string {
	t.Helper()
	out, err := stripJSONKeys([]byte(line), "entry_hash")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// stripEntryHashes rewrites every record of path without entry_hash and edits
// the command of one of them, so the file would be broken if it were still
// read as chained.
func stripEntryHashes(t *testing.T, path string, editIdx int) {
	t.Helper()
	lines := readLines(t, path)
	for i := range lines {
		lines[i] = stripEntryHash(t, lines[i])
	}
	edited := strings.Replace(lines[editIdx], `"command":"`, `"command":"EDITED-`, 1)
	if edited == lines[editIdx] {
		t.Fatalf("fixture: no command to edit in %q", lines[editIdx])
	}
	lines[editIdx] = edited
	writeLines(t, path, lines)
}

func assertBrokenAt(t *testing.T, r ChainVerifyResult, wantIn string, wantAt int) {
	t.Helper()
	if r.State != ChainStateBroken || r.Protected() || r.BrokenIn != wantIn || r.BrokenAt != wantAt {
		t.Fatalf("got %q at %d in %q (protected=%v): %s", r.State, r.BrokenAt, r.BrokenIn, r.Protected(), r.Message)
	}
	if !strings.Contains(r.Message, "prev_hash without entry_hash") {
		t.Errorf("message = %q, want the stripped-record reason", r.Message)
	}
}

// Codex pass 4 finding 1. A record with prev_hash and no entry_hash was never
// written by any AgentShield build: pre-chain writers wrote neither, chaining
// writers write both. It is a chained record with its proof removed, and it
// is broken wherever it sits. Record 0 of a genesis generation carries no
// prev_hash, so it does read as legacy once stripped — the first record that
// can be told apart is 1.
func TestVerifyChain_StrippedEntryHashIsNotLegacy(t *testing.T) {
	t.Run("genesis live behind a .1 stripped of every entry_hash: broken in .1", func(t *testing.T) {
		smallRotation(t, 1<<30)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		for i := 0; i < 6; i++ {
			hookWrite(t, p, fmt.Sprintf("before-%d", i))
		}
		if err := os.Rename(p, p+rotatedSuffix); err != nil {
			t.Fatal(err)
		}
		// A genesis live file beside the rotated one. Since #4057 a writer
		// that finds the live file empty links it to .1, so the genesis
		// layout (a lock-race follower's, #4131) is built directly.
		writeChainedLogFrom(t, p, "", []AuditEvent{{Timestamp: "2026-09-30T00:00:00Z", Command: "genesis after external rotation", Decision: "ALLOW"}})
		if fe := firstEntry(t, p); fe.PrevHash != "" {
			t.Fatalf("fixture: live should open at genesis, got prev_hash %q", fe.PrevHash)
		}
		stripEntryHashes(t, p+rotatedSuffix, 3)

		assertBrokenAt(t, VerifyChain(p), "audit.jsonl.1", 1)
	})

	t.Run("linked live behind a .1 stripped of every entry_hash: broken in .1, not at the boundary", func(t *testing.T) {
		live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
		stripEntryHashes(t, rotated, 2)

		assertBrokenAt(t, VerifyChain(live), "audit.jsonl.1", 1)
	})

	t.Run("the live file alone, stripped of every entry_hash: broken", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainedLog(t, p, []AuditEvent{{Command: "a"}, {Command: "b"}, {Command: "c"}, {Command: "d"}})
		stripEntryHashes(t, p, 2)

		assertBrokenAt(t, VerifyChain(p), "", 1)
	})

	t.Run("a single stripped record inside an otherwise legacy prefix: broken there", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		writeUnchainedLog(t, p, []AuditEvent{{Command: "legacy-0"}, {Command: "legacy-1"}})
		appendRaw(t, p, `{"command":"planted","prev_hash":"deadbeef"}`+"\n")
		writeChainedLogFrom(t, p+".tmp", "", []AuditEvent{{Command: "chained"}})
		appendRaw(t, p, readLines(t, p+".tmp")[0]+"\n")

		assertBrokenAt(t, VerifyChain(p), "", 2)
	})

	// Genuine pre-chain records carry neither field and are still legacy.
	t.Run("a genuine legacy .1 behind a genesis live is still partial, and a legacy prefix still partial", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		writeUnchainedLog(t, p+rotatedSuffix, []AuditEvent{{Command: "l0"}, {Command: "l1"}, {Command: "l2"}})
		hookWrite(t, p, "genesis")
		if r := VerifyChain(p); r.State != ChainStatePartial || r.Message != "audit.jsonl.1 holds 3 pre-chain entries" {
			t.Fatalf("legacy .1: got %q: %s", r.State, r.Message)
		}

		q := filepath.Join(t.TempDir(), "audit.jsonl")
		writeUnchainedLog(t, q, []AuditEvent{{Command: "l0"}, {Command: "l1"}})
		hookWrite(t, q, "first chained")
		hookWrite(t, q, "second chained")
		if r := VerifyChain(q); r.State != ChainStatePartial || r.LegacyEntries != 2 || r.Entries != 4 {
			t.Fatalf("legacy prefix: got %q (%d/%d): %s", r.State, r.LegacyEntries, r.Entries, r.Message)
		}
		if r := VerifyChain(q + rotatedSuffix); r.State != ChainStateEmpty {
			t.Fatalf("fixture: no .1 expected, got %q", r.State)
		}
	})
}

// Codex pass 4 finding 2. `mv audit.jsonl audit.jsonl.1` by an external tool
// on a legacy or partially chained log leaves an empty (or no) live file. The
// live file asserts nothing, but .1 does: its pre-chain entries are as
// unprotected as they were before the move, and a break in it is still a
// break. Only a wholly verified .1 leaves the verdict at Empty — `scan` then
// says "no entries yet" and does not count a pass on a file that holds
// nothing, which is the #3112 rule: no ✅ from "nothing detected".
func TestVerifyChain_EmptyLiveDoesNotHidePredecessor(t *testing.T) {
	for _, live := range []struct {
		name  string
		stage func(t *testing.T, p string)
	}{
		{"empty live", func(t *testing.T, p string) {
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"absent live", func(*testing.T, string) {}},
	} {
		t.Run(live.name, func(t *testing.T) {
			t.Run("legacy .1 → partial naming every entry", func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "audit.jsonl")
				writeUnchainedLog(t, p+rotatedSuffix, []AuditEvent{{Command: "l0"}, {Command: "l1"}, {Command: "l2"}})
				live.stage(t, p)
				r := VerifyChain(p)
				if r.State != ChainStatePartial || r.Protected() || r.Entries != 0 {
					t.Fatalf("got %q (%d entries, protected=%v): %s", r.State, r.Entries, r.Protected(), r.Message)
				}
				if r.Message != "audit.jsonl.1 holds 3 pre-chain entries" {
					t.Errorf("message = %q", r.Message)
				}
			})
			t.Run("partial .1 → partial naming its pre-chain entries", func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "audit.jsonl")
				writeUnchainedLog(t, p+rotatedSuffix, []AuditEvent{{Command: "l0"}, {Command: "l1"}})
				hookWrite(t, p+rotatedSuffix, "chained-0")
				hookWrite(t, p+rotatedSuffix, "chained-1")
				live.stage(t, p)
				r := VerifyChain(p)
				if r.State != ChainStatePartial || r.Protected() || r.Message != "audit.jsonl.1 holds 2 pre-chain entries" {
					t.Fatalf("got %q (protected=%v): %s", r.State, r.Protected(), r.Message)
				}
			})
			t.Run("broken .1 → broken in .1", func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "audit.jsonl")
				for i := 0; i < 5; i++ {
					hookWrite(t, p+rotatedSuffix, fmt.Sprintf("c-%d", i))
				}
				writeLines(t, p+rotatedSuffix, dropLine(readLines(t, p+rotatedSuffix), 2))
				live.stage(t, p)
				assertBrokenInPredecessor(t, VerifyChain(p), 2)
			})
			t.Run("unreadable .1 → unreadable", func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "audit.jsonl")
				if err := os.Mkdir(p+rotatedSuffix, 0700); err != nil {
					t.Fatal(err)
				}
				live.stage(t, p)
				r := VerifyChain(p)
				if r.State != ChainStateUnreadable || r.Protected() || !strings.HasPrefix(r.Message, "audit.jsonl.1 unreadable, not verified: ") {
					t.Fatalf("got %q (protected=%v): %s", r.State, r.Protected(), r.Message)
				}
			})
			t.Run("verified .1 → empty, noted", func(t *testing.T) {
				p := filepath.Join(t.TempDir(), "audit.jsonl")
				for i := 0; i < 3; i++ {
					hookWrite(t, p+rotatedSuffix, fmt.Sprintf("c-%d", i))
				}
				live.stage(t, p)
				r := VerifyChain(p)
				if r.State != ChainStateEmpty || r.Protected() || r.Note != "audit.jsonl.1 verified (not linked)" {
					t.Fatalf("got %q (protected=%v) note %q: %s", r.State, r.Protected(), r.Note, r.Message)
				}
			})
		})
	}
}

// The same on the pure composition, so the table is complete without a
// filesystem.
func TestRelateToPredecessor_EmptyLiveCompositions(t *testing.T) {
	const base = "audit.jsonl.1"
	for _, live := range []fileScan{
		{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "empty log"}},
		{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "no audit log yet"}},
	} {
		t.Run(live.result.Message, func(t *testing.T) {
			partial := fileScan{result: ChainVerifyResult{State: ChainStatePartial, Entries: 6, LegacyEntries: 4, BrokenAt: -1}, head: "H"}
			if r := relateToPredecessor(live, partial, base); r.State != ChainStatePartial || r.Entries != 0 || r.Message != "audit.jsonl.1 holds 4 pre-chain entries" {
				t.Errorf("partial .1: got %+v", r)
			}
			unprotected := fileScan{result: ChainVerifyResult{State: ChainStateUnprotected, Entries: 3, LegacyEntries: 3, BrokenAt: -1}}
			if r := relateToPredecessor(live, unprotected, base); r.State != ChainStatePartial || r.Entries != 0 || r.Message != "audit.jsonl.1 holds 3 pre-chain entries" {
				t.Errorf("unprotected .1: got %+v", r)
			}
			verified := fileScan{result: ChainVerifyResult{State: ChainStateVerified, Entries: 3, BrokenAt: -1}, head: "H"}
			want := live.result
			want.Note = "audit.jsonl.1 verified (not linked)"
			if r := relateToPredecessor(live, verified, base); r != want {
				t.Errorf("verified .1: got %+v", r)
			}
			empty := fileScan{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1}}
			if r := relateToPredecessor(live, empty, base); r != live.result {
				t.Errorf("empty .1: got %+v", r)
			}
		})
	}
}
