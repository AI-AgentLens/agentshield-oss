package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin the round-1 findings of the #4133 adversarial passes (Codex
// F1/F3, Opus 1-5) on the predecessor verification that #4132 item 2 added:
// a tail tweak that used to switch the check off, lines over the old 1 MB
// scanner limit, an unreadable predecessor claimed as linked, a spoofable
// lock-race hint, a partial predecessor continuing an earlier chain, and the
// rotation race that produced a false boundary break.

// stripChain rewrites a chained line as the bare AuditEvent (no chain fields).
func stripChain(t *testing.T, line string) string {
	t.Helper()
	var e ChainedEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e.AuditEvent)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func dropLine(lines []string, i int) []string {
	return append(lines[:i:i], lines[i+1:]...)
}

// Codex F1 / Opus 1: with a middle line deleted from .1 (R02), any tweak to
// .1's tail used to empty ChainHead(.1), which read as "predecessor
// unavailable" and left the live log verified. The predecessor is now always
// verified when it is present, non-empty and readable, so every variant is a
// break inside .1 at the deletion.
func TestVerifyChain_PredecessorTailTweakDoesNotDisableCheck(t *testing.T) {
	tweaks := map[string]func(t *testing.T, rotated string){
		"append {}":              func(t *testing.T, p string) { appendRaw(t, p, "{}\n") },
		"append x":               func(t *testing.T, p string) { appendRaw(t, p, "x\n") },
		"append { no newline":    func(t *testing.T, p string) { appendRaw(t, p, "{") },
		"append whitespace line": func(t *testing.T, p string) { appendRaw(t, p, "  \n") },
		"strip chain from last line": func(t *testing.T, p string) {
			lines := readLines(t, p)
			lines[len(lines)-1] = stripChain(t, lines[len(lines)-1])
			writeLines(t, p, lines)
		},
		"append 1.1 MB junk line": func(t *testing.T, p string) {
			appendRaw(t, p, strings.Repeat("a", 1100*1024)+"\n")
		},
	}
	for name, tweak := range tweaks {
		t.Run("R02 + "+name, func(t *testing.T) {
			live, rotated := rotatedPair(t, t.TempDir(), 5, 3)
			writeLines(t, rotated, dropLine(readLines(t, rotated), 2))
			tweak(t, rotated)
			assertBrokenInPredecessor(t, VerifyChain(live), 2)
		})
	}

	// The tweak alone, with nothing deleted: an unchained record after the
	// chain is the break, at the appended line.
	t.Run("append {} alone", func(t *testing.T) {
		live, rotated := rotatedPair(t, t.TempDir(), 5, 3)
		appendRaw(t, rotated, "{}\n")
		r := VerifyChain(live)
		assertBrokenInPredecessor(t, r, 5)
		if !strings.Contains(r.Message, "unchained entry after a chained entry") {
			t.Errorf("message = %q", r.Message)
		}
	})
}

// Opus mutant M1: a break at .1's very first entry counts (A10).
func TestVerifyChain_PredecessorFirstEntryAltered(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 4, 2)
	lines := readLines(t, rotated)
	lines[0] = strings.Replace(lines[0], `"command":"old-"`, `"command":"X-"`, 1)
	writeLines(t, rotated, lines)

	r := VerifyChain(live)
	assertBrokenInPredecessor(t, r, 0)
	if !strings.Contains(r.Message, "entry hash mismatch") {
		t.Errorf("message = %q", r.Message)
	}
}

// Verdicts compose in chain order: a break inside .1 is reported before the
// boundary. With a middle line AND the last line deleted from .1, the result
// names the interior deletion, not "does not match the head".
func TestVerifyChain_PredecessorBreakReportedBeforeBoundary(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
	lines := readLines(t, rotated)
	writeLines(t, rotated, dropLine(lines[:len(lines)-1], 2))

	r := VerifyChain(live)
	assertBrokenInPredecessor(t, r, 2)
	if strings.Contains(r.Message, "head of") {
		t.Errorf("the interior break precedes the boundary in chain order, got %q", r.Message)
	}
}

// Opus 2: bufio.Scanner's 1 MB token limit made a longer line report the
// whole file unreadable. For .1 that silently skipped the check while the
// live log still said "linked"; for a legitimate 1.1 MB event written by the
// logger it was a false "cannot verify". Lines are now unbounded.
func TestVerifyChain_LinesOverOneMegabyte(t *testing.T) {
	big := strings.Repeat("B", 1100*1024)
	junk := strings.Repeat("a", 1100*1024)
	oldEvents := func() []AuditEvent {
		return []AuditEvent{
			{Timestamp: "t", Command: "old-0", Decision: "ALLOW"},
			{Timestamp: "t", Command: big, Decision: "ALLOW"},
			{Timestamp: "t", Command: "old-2", Decision: "ALLOW"},
			{Timestamp: "t", Command: "old-3", Decision: "ALLOW"},
		}
	}
	newEvents := []AuditEvent{{Timestamp: "t", Command: "new-0", Decision: "ALLOW"}}

	t.Run("B04 legitimate 1.1 MB entry inside .1 verifies and links", func(t *testing.T) {
		dir := t.TempDir()
		live := filepath.Join(dir, "audit.jsonl")
		rotated := live + rotatedSuffix
		writeChainedLog(t, rotated, oldEvents())
		writeChainedLogFrom(t, live, ChainHead(rotated), newEvents)
		r := VerifyChain(live)
		if r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1" {
			t.Fatalf("got %q note %q: %s", r.State, r.Note, r.Message)
		}
		if one := VerifyChain(rotated); one.State != ChainStateVerified || one.Entries != 4 {
			t.Errorf(".1 alone: %q (%d entries): %s", one.State, one.Entries, one.Message)
		}
	})

	t.Run("a 1.1 MB entry in the live log verifies", func(t *testing.T) {
		live := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainedLog(t, live, oldEvents())
		if r := VerifyChain(live); r.State != ChainStateVerified {
			t.Fatalf("got %q: %s", r.State, r.Message)
		}
	})

	t.Run("ChainHead reads a final record over 1 MB", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainedLog(t, p, oldEvents()[:2])
		lines := readLines(t, p)
		if got, want := ChainHead(p), rawChainedHash([]byte(lines[1])); got != want {
			t.Fatalf("ChainHead = %q, want the hash of the 1.1 MB last record", got)
		}
	})

	// The production shape of B04: one hook process per event. The process
	// after the large event re-reads the head; with the old 1 MB cap it read
	// "" and opened a fresh chain mid-file, which the verifier calls a break.
	t.Run("hook writers around a 1.1 MB event stay verified", func(t *testing.T) {
		smallRotation(t, 1<<30)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		for _, cmd := range []string{"a", big, "c"} {
			lg, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := lg.Log(AuditEvent{Timestamp: "t", Command: cmd, Decision: "ALLOW"}); err != nil {
				t.Fatal(err)
			}
			_ = lg.Close()
		}
		if r := VerifyChain(p); r.State != ChainStateVerified || r.Entries != 3 {
			t.Fatalf("got %q (%d entries): %s", r.State, r.Entries, r.Message)
		}
	})

	tampers := map[string]func(lines []string) []string{
		"B01 R02 + junk at .1[0]": func(l []string) []string { return append([]string{junk}, dropLine(l, 2)...) },
		"B02 R02 + junk at .1[1]": func(l []string) []string {
			l = dropLine(l, 2)
			return append([]string{l[0], junk}, l[1:]...)
		},
		"B03 alter .1[3] + junk at .1[1]": func(l []string) []string {
			l[3] = strings.Replace(l[3], `"command":"old-"`, `"command":"FORGED-"`, 1)
			return append([]string{l[0], junk}, l[1:]...)
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
			writeLines(t, rotated, tamper(readLines(t, rotated)))
			r := VerifyChain(live)
			if r.State != ChainStateBroken || r.BrokenIn != "audit.jsonl.1" || r.Protected() {
				t.Fatalf("got %q in %q: %s", r.State, r.BrokenIn, r.Message)
			}
			if !strings.Contains(r.Message, "invalid JSON") {
				t.Errorf("the junk line is the first bad entry, got %q", r.Message)
			}
		})
	}
}

// Opus 2 (second half) and Codex pass-2 finding 3: a predecessor that is
// present but cannot be read was not verified, so the live result is neither
// a tampering claim nor a pass: ChainStateUnreadable, Protected() false, and
// the message names the file. Round 1 kept the live state and only reworded
// the note, which left Protected() true. A directory at .1 opens but does
// not read, which is the only genuine mid-read error a test can stage.
func TestVerifyChain_UnreadablePredecessorIsNotClaimedLinked(t *testing.T) {
	live, rotated := rotatedPair(t, t.TempDir(), 3, 2)
	if err := os.Remove(rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rotated, 0700); err != nil {
		t.Fatal(err)
	}
	r := VerifyChain(live)
	if r.State != ChainStateUnreadable || r.Protected() {
		t.Fatalf("an unreadable predecessor is neither a tampering claim nor a pass, got %q: %s", r.State, r.Message)
	}
	if r.BrokenAt != -1 || r.Entries != 2 {
		t.Errorf("BrokenAt %d, Entries %d: the live file's figures with no break", r.BrokenAt, r.Entries)
	}
	if strings.Contains(r.Note, "linked") || !strings.HasPrefix(r.Message, "audit.jsonl.1 unreadable, not verified: ") {
		t.Errorf("must name the predecessor as unreadable and never as linked, got %q / note %q", r.Message, r.Note)
	}
}

// relateToPredecessor is pure, so the compositions no on-disk layout can
// stage on demand are pinned here: a read error after a linked first entry
// in the live log, a predecessor read error after a matching head, and the
// legacy count carried through (Opus mutants M5 and M9).
func TestRelateToPredecessor_Compositions(t *testing.T) {
	clean := fileScan{result: ChainVerifyResult{State: ChainStateVerified, Entries: 4, BrokenAt: -1}, head: "H"}
	linked := fileScan{result: ChainVerifyResult{State: ChainStateVerified, Entries: 2, BrokenAt: -1}, continuedFrom: "H"}

	t.Run("live unreadable after a linked entry is returned as is", func(t *testing.T) {
		live := fileScan{
			result:        ChainVerifyResult{State: ChainStateUnreadable, Entries: 1, BrokenAt: -1, Message: "read error after entry 1: boom"},
			continuedFrom: "H",
		}
		broken := fileScan{result: ChainVerifyResult{State: ChainStateBroken, BrokenAt: 0}}
		if r := relateToPredecessor(live, broken, "audit.jsonl.1"); r != live.result {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("live broken after a linked entry is returned as is", func(t *testing.T) {
		live := fileScan{result: ChainVerifyResult{State: ChainStateBroken, Entries: 1, BrokenAt: 1}, continuedFrom: "H"}
		if r := relateToPredecessor(live, clean, "audit.jsonl.1"); r != live.result {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("predecessor read error after a matching head is unreadable, not linked", func(t *testing.T) {
		pred := fileScan{
			result:        ChainVerifyResult{State: ChainStateUnreadable, Entries: 3, BrokenAt: -1, Message: "read error after entry 3: input/output error"},
			continuedFrom: "", head: "H",
		}
		r := relateToPredecessor(linked, pred, "audit.jsonl.1")
		want := ChainVerifyResult{State: ChainStateUnreadable, Entries: 2, BrokenAt: -1,
			Message: "audit.jsonl.1 unreadable, not verified: read error after entry 3: input/output error"}
		if r != want || r.Protected() {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("partial predecessor behind a matching head is partial, linked, not protected", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStatePartial, Entries: 6, LegacyEntries: 4, BrokenAt: -1}, head: "H"}
		r := relateToPredecessor(linked, pred, "audit.jsonl.1")
		want := ChainVerifyResult{State: ChainStatePartial, Entries: 2, BrokenAt: -1,
			Message: "audit.jsonl.1 holds 4 pre-chain entries", Note: "linked to audit.jsonl.1"}
		if r != want || r.Protected() {
			t.Errorf("got %+v", r)
		}
		// The boundary still wins: a partial .1 whose head does not match
		// is a break, not a softer partial.
		if m := relateToPredecessor(linked, fileScan{result: pred.result, head: "other"}, "audit.jsonl.1"); m.State != ChainStateBroken || m.BrokenAt != 0 {
			t.Errorf("boundary break beats partial: got %+v", m)
		}
	})
	t.Run("legacy count of the live log is carried into a predecessor break", func(t *testing.T) {
		live := fileScan{result: ChainVerifyResult{State: ChainStatePartial, Entries: 5, LegacyEntries: 3, BrokenAt: -1}, continuedFrom: "H", firstChainedIdx: 3}
		pred := fileScan{result: ChainVerifyResult{State: ChainStateBroken, Entries: 2, BrokenAt: 1, Message: "entry 1: entry hash mismatch"}}
		r := relateToPredecessor(live, pred, "audit.jsonl.1")
		if r.State != ChainStateBroken || r.BrokenIn != "audit.jsonl.1" || r.BrokenAt != 1 || r.Entries != 5 || r.LegacyEntries != 3 {
			t.Errorf("got %+v", r)
		}
		mismatch := relateToPredecessor(live, fileScan{result: clean.result, head: "other"}, "audit.jsonl.1")
		if mismatch.State != ChainStateBroken || mismatch.BrokenAt != 3 || mismatch.LegacyEntries != 3 {
			t.Errorf("boundary break: got %+v", mismatch)
		}
	})
	t.Run("a predecessor with no chain cannot honour the link", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStateUnprotected, Entries: 3, LegacyEntries: 3, BrokenAt: -1}}
		r := relateToPredecessor(linked, pred, "audit.jsonl.1")
		if r.State != ChainStateBroken || r.BrokenIn != "" || r.BrokenAt != 0 || !strings.Contains(r.Message, "head of audit.jsonl.1") {
			t.Errorf("got %+v", r)
		}
	})
}

// Opus 3: the lock-race hint is read from the parsed notes, never from the
// raw bytes, so agent command text cannot plant it. Both neighbours count
// (Opus mutants M2 and M3), and the state is broken in every case.
func TestVerifyChain_LockHintFromStructuredNoteOnly(t *testing.T) {
	build := func(t *testing.T, at int, spoof bool) string {
		t.Helper()
		dir := t.TempDir()
		live := filepath.Join(dir, "audit.jsonl")
		rotated := live + rotatedSuffix
		events := []AuditEvent{
			{Timestamp: "t", Command: "old-0", Decision: "ALLOW"},
			{Timestamp: "t", Command: "old-1", Decision: "ALLOW"},
			{Timestamp: "t", Command: "old-2", Decision: "ALLOW"},
			{Timestamp: "t", Command: "old-3", Decision: "ALLOW"},
			{Timestamp: "t", Command: "old-4", Decision: "ALLOW"},
		}
		if at >= 0 {
			if spoof {
				// The bare kind as command text: the JSON line then contains
				// the exact bytes `"audit_lock_unavailable"` a substring match
				// looked for (Opus's shape, `echo "audit_lock_unavailable`,
				// produced the same bytes through the closing quote).
				events[at].Command = "audit_lock_unavailable"
			} else {
				events[at].Notes = []Note{{Kind: lockUnavailableNoteKind, Detail: "flock: EAGAIN"}}
			}
		}
		writeChainedLog(t, rotated, events)
		writeChainedLogFrom(t, live, ChainHead(rotated), []AuditEvent{{Timestamp: "t", Command: "new", Decision: "ALLOW"}})
		// Delete entry 2: old entry 3 becomes index 2 and is the broken
		// entry (its prev_hash names the deleted one); old entry 1 is its
		// previous neighbour and old entry 4 its next.
		writeLines(t, rotated, dropLine(readLines(t, rotated), 2))
		return live
	}
	cases := []struct {
		name  string
		at    int
		spoof bool
		hint  bool
	}{
		{"no note anywhere", -1, false, false},
		{"command text spoof on the previous neighbour", 1, true, false},
		{"command text spoof on the broken entry", 3, true, false},
		{"command text spoof on the next neighbour", 4, true, false},
		{"note on the previous neighbour", 1, false, true},
		{"note on the broken entry", 3, false, true},
		{"note on the next neighbour", 4, false, true},
		{"note on the deleted entry itself is gone with it", 2, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := VerifyChain(build(t, c.at, c.spoof))
			assertBrokenInPredecessor(t, r, 2)
			if got := strings.Contains(r.Message, "lost lock race"); got != c.hint {
				t.Errorf("hint present = %v, want %v: %q", got, c.hint, r.Message)
			}
		})
	}
}

// Opus known gap, closed: stripping chain fields from .1[0..k] turned .1
// into "partial" and left the live log verified and linked (A09/A09b). A
// healthy upgrade's partial file always opens its chain at genesis — the
// writer reads an empty head off an unchained tail — so a chain that
// continues an earlier generation behind unchained entries is a break.
func TestVerifyChain_PartialPredecessorContinuingEarlierChainIsBroken(t *testing.T) {
	strip := func(lines []string, upto int) []string {
		for i := 0; i <= upto; i++ {
			lines[i] = stripChain(t, lines[i])
		}
		return lines
	}
	t.Run("A09 strip 0..2 then alter [2]", func(t *testing.T) {
		live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
		lines := strip(readLines(t, rotated), 2)
		lines[2] = strings.Replace(lines[2], `"command":"old-"`, `"command":"FORGED-"`, 1)
		writeLines(t, rotated, lines)
		r := VerifyChain(live)
		assertBrokenInPredecessor(t, r, 3)
		if !strings.Contains(r.Message, "continues an earlier generation behind 3 unchained entries") {
			t.Errorf("message = %q", r.Message)
		}
	})
	t.Run("A09b strip 0..2 then delete [3]", func(t *testing.T) {
		live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
		writeLines(t, rotated, dropLine(strip(readLines(t, rotated), 2), 3))
		assertBrokenInPredecessor(t, VerifyChain(live), 3)
	})
	t.Run("standalone: the same file verifies as broken on its own", func(t *testing.T) {
		_, rotated := rotatedPair(t, t.TempDir(), 5, 2)
		writeLines(t, rotated, strip(readLines(t, rotated), 1))
		if r := VerifyChain(rotated); r.State != ChainStateBroken || r.BrokenAt != 2 {
			t.Errorf("got %q at %d: %s", r.State, r.BrokenAt, r.Message)
		}
	})
	// Codex pass-2 finding 2 / Opus mutant MX5: one stripped line is enough
	// for the attack (strip .1[0], delete .1[1]) and must read broken, not
	// partial — a `legacy > 1` mutant let it through as verified.
	t.Run("E5 strip .1[0] then delete .1[1]", func(t *testing.T) {
		live, rotated := rotatedPair(t, t.TempDir(), 5, 2)
		r := VerifyChain(live)
		if r.State != ChainStateVerified {
			t.Fatalf("control: %q", r.State)
		}
		writeLines(t, rotated, dropLine(strip(readLines(t, rotated), 0), 1))
		r = VerifyChain(live)
		assertBrokenInPredecessor(t, r, 1)
		if !strings.Contains(r.Message, "behind 1 unchained entries") {
			t.Errorf("message = %q", r.Message)
		}
	})
	// Control (Opus mutant M6): a partial .1 whose chain starts at genesis
	// is the shape a real upgrade leaves behind. It is not broken — a
	// treat-every-non-verified-.1-as-broken rule would be a false alarm here
	// — but neither is it protected: the legacy prefix carries no hash, so
	// the live log reads partial and linked (Codex pass-2 finding 2; round 1
	// left it verified).
	t.Run("partial .1 from genesis is partial and linked, not protected", func(t *testing.T) {
		dir := t.TempDir()
		live := filepath.Join(dir, "audit.jsonl")
		rotated := live + rotatedSuffix
		writeUnchainedLog(t, rotated, []AuditEvent{
			{Timestamp: "t", Command: "legacy-0", Decision: "ALLOW"},
			{Timestamp: "t", Command: "legacy-1", Decision: "ALLOW"},
		})
		lg, err := New(rotated)
		if err != nil {
			t.Fatal(err)
		}
		logEvents(t, lg, 3, "upgraded")
		_ = lg.Close()
		writeChainedLogFrom(t, live, ChainHead(rotated), []AuditEvent{{Timestamp: "t", Command: "new", Decision: "ALLOW"}})

		if one := VerifyChain(rotated); one.State != ChainStatePartial || one.LegacyEntries != 2 {
			t.Fatalf("control: .1 alone should be partial with 2 legacy entries, got %q: %s", one.State, one.Message)
		}
		assertPartialBehindPredecessor := func(t *testing.T, legacy int) {
			t.Helper()
			r := VerifyChain(live)
			if r.State != ChainStatePartial || r.Protected() || r.Note != "linked to audit.jsonl.1" {
				t.Fatalf("got %q note %q: %s", r.State, r.Note, r.Message)
			}
			if want := fmt.Sprintf("audit.jsonl.1 holds %d pre-chain entries", legacy); r.Message != want {
				t.Errorf("message %q, want %q", r.Message, want)
			}
		}
		assertPartialBehindPredecessor(t, 2)

		// What "not protected" means, stated as the two tampers the hash
		// cannot see: unchained events prepended to the legacy prefix, and
		// a genuine legacy entry edited. Both stay partial — never verified,
		// which is the claim round 1 made about them.
		lines := readLines(t, rotated)
		writeLines(t, rotated, append([]string{`{"timestamp":"t","command":"prepended","decision":"ALLOW"}`}, lines...))
		assertPartialBehindPredecessor(t, 3)
		lines = readLines(t, rotated)
		lines[1] = strings.Replace(lines[1], `"command":"legacy-0"`, `"command":"EDITED"`, 1)
		writeLines(t, rotated, lines)
		assertPartialBehindPredecessor(t, 3)
	})
}

// The production upgrade path end to end (Opus mutant M6 on real files): a
// pre-chain log, then hook-style writers through several rotations. No
// verification along the way may report broken. Two phases are pinned: while
// the legacy prefix is on disk — in the live file, then in .1 after the first
// rotation — the verdict is partial (⚠, honest: those entries are not
// protected); once the legacy generation has rotated out, verified.
func TestVerifyChain_UpgradeFromPreChainLogThroughRotations(t *testing.T) {
	for _, legacy := range []int{3, 12} {
		t.Run(fmt.Sprintf("%d legacy lines", legacy), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			events := make([]AuditEvent, legacy)
			for i := range events {
				events[i] = AuditEvent{Timestamp: "t", Command: fmt.Sprintf("legacy-%d", i), Decision: "ALLOW"}
			}
			writeUnchainedLog(t, p, events)
			smallRotation(t, 2500)
			rotations := 0
			for i := 0; i < 60; i++ {
				before, _ := os.Stat(p + rotatedSuffix)
				lg, err := New(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := lg.Log(AuditEvent{Timestamp: "t", Command: fmt.Sprintf("new-%d", i), Decision: "ALLOW", Mode: "enforce"}); err != nil {
					t.Fatal(err)
				}
				_ = lg.Close()
				if after, err := os.Stat(p + rotatedSuffix); err == nil && (before == nil || !os.SameFile(before, after)) {
					rotations++
				}
				r := VerifyChain(p)
				want := ChainStateVerified
				if rotations < 2 {
					want = ChainStatePartial
				}
				if r.State != want || r.Protected() != (want == ChainStateVerified) {
					t.Fatalf("write %d after %d rotations: %q, want %q: %s", i, rotations, r.State, want, r.Message)
				}
				if rotations == 1 && r.Message != fmt.Sprintf("audit.jsonl.1 holds %d pre-chain entries", legacy) {
					t.Fatalf("write %d: the legacy prefix is in .1 now, got %q", i, r.Message)
				}
			}
			if rotations < 2 {
				t.Fatalf("only %d rotations; the fixture did not exercise the boundary", rotations)
			}
		})
	}
}

// Codex F3: a rotation between the live scan and the predecessor read makes
// the two reads describe different generations, which looked like a break
// at the boundary on an untampered log. VerifyChain re-checks the live
// file's identity and retries.
func TestVerifyChain_RotationDuringVerificationRetries(t *testing.T) {
	rotate := func(t *testing.T, live string) {
		t.Helper()
		rotated := live + rotatedSuffix
		_ = os.Remove(rotated)
		if err := os.Rename(live, rotated); err != nil {
			t.Fatal(err)
		}
		writeChainedLogFrom(t, live, ChainHead(rotated), []AuditEvent{{Timestamp: "t", Command: "after-rotation", Decision: "ALLOW"}})
	}
	t.Cleanup(func() { verifyChainBetweenFiles = nil })

	t.Run("one rotation mid-verification: retried, verified", func(t *testing.T) {
		live, _ := rotatedPair(t, t.TempDir(), 3, 2)
		calls := 0
		verifyChainBetweenFiles = func() {
			calls++
			if calls == 1 {
				rotate(t, live)
			}
		}
		r := VerifyChain(live)
		if r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1" {
			t.Fatalf("got %q note %q: %s", r.State, r.Note, r.Message)
		}
		if calls != 2 {
			t.Errorf("expected exactly one retry, seam ran %d times", calls)
		}
	})

	// Codex pass-2 finding 1: round 1 returned the last attempt's verdict
	// with a caveat, and under continuous rotation every attempt compares
	// mismatched generations, so that verdict was a false BROKEN. A log that
	// moved during every attempt was not verified: unreadable, never broken.
	assertNotVerifiedMoving := func(t *testing.T, r ChainVerifyResult) {
		t.Helper()
		if r.State != ChainStateUnreadable || r.Protected() || r.BrokenAt != -1 || r.BrokenIn != "" {
			t.Fatalf("a result taken off a moving log is unreadable, got %q at %d in %q: %s", r.State, r.BrokenAt, r.BrokenIn, r.Message)
		}
		if r.Message != "cannot verify: the log rotated during every verification attempt; re-run" {
			t.Errorf("message = %q", r.Message)
		}
	}
	t.Run("a log that keeps rotating: bounded, unreadable, never broken", func(t *testing.T) {
		live, _ := rotatedPair(t, t.TempDir(), 3, 2)
		calls := 0
		verifyChainBetweenFiles = func() {
			calls++
			rotate(t, live)
		}
		assertNotVerifiedMoving(t, VerifyChain(live))
		if calls != verifyAttempts {
			t.Errorf("seam ran %d times, want %d", calls, verifyAttempts)
		}
	})

	// Opus mutant MX1: the last attempt can also come out clean while the
	// identity still moved (here: the live file replaced by a byte-identical
	// copy). That is still not a verification of the file now on disk.
	t.Run("identity moved on every attempt with a clean last pass: still unreadable", func(t *testing.T) {
		live, _ := rotatedPair(t, t.TempDir(), 3, 2)
		calls := 0
		verifyChainBetweenFiles = func() {
			calls++
			if calls < verifyAttempts {
				rotate(t, live)
				return
			}
			raw, err := os.ReadFile(live)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(live+".tmp", raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(live+".tmp", live); err != nil {
				t.Fatal(err)
			}
		}
		assertNotVerifiedMoving(t, VerifyChain(live))
	})

	// Opus mutant MX2: the bound is three attempts, so a rotation during
	// exactly two of them still ends in a verified third.
	t.Run("rotation during the first two attempts: the third verifies", func(t *testing.T) {
		live, _ := rotatedPair(t, t.TempDir(), 3, 2)
		calls := 0
		verifyChainBetweenFiles = func() {
			calls++
			if calls <= 2 {
				rotate(t, live)
			}
		}
		r := VerifyChain(live)
		if r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1" || calls != 3 {
			t.Fatalf("got %q note %q after %d passes: %s", r.State, r.Note, calls, r.Message)
		}
	})

	// Opus mutant MX9: between the rename and the create the live path is
	// briefly gone. A live file that vanished by the after-stat moved, so the
	// mismatched pass must not be returned as broken. The retry finds no
	// live file yet and (round 3) still reads the intact .1 beside it.
	t.Run("live file gone at the after-stat: retried, not broken", func(t *testing.T) {
		live, _ := rotatedPair(t, t.TempDir(), 3, 2)
		calls := 0
		verifyChainBetweenFiles = func() {
			calls++
			if calls > 1 {
				return
			}
			_ = os.Remove(live + rotatedSuffix)
			if err := os.Rename(live, live+rotatedSuffix); err != nil {
				t.Fatal(err)
			}
		}
		r := VerifyChain(live)
		if r.State == ChainStateBroken || r.Protected() {
			t.Fatalf("a mid-rename snapshot is not a break, got %q: %s", r.State, r.Message)
		}
		if calls != 2 || r.State != ChainStateEmpty || r.Note != "audit.jsonl.1 verified (not linked)" {
			t.Errorf("the retry finds no live file yet beside a verified .1: %d passes, %q note %q", calls, r.State, r.Note)
		}
	})

	// Opus mutant MX4: an absent log is the same absence before and after,
	// not a log that moved: one pass (which, since round 3, still looks for
	// a .1 beside the absent live file).
	t.Run("absent log: empty, single pass", func(t *testing.T) {
		calls := 0
		verifyChainBetweenFiles = func() { calls++ }
		r := VerifyChain(filepath.Join(t.TempDir(), "audit.jsonl"))
		if r.State != ChainStateEmpty || r.Message != "no audit log yet" || r.Note != "" || calls != 1 {
			t.Errorf("got %+v after %d passes", r, calls)
		}
	})

	t.Run("no rotation: a single pass", func(t *testing.T) {
		live, _ := rotatedPair(t, t.TempDir(), 3, 2)
		calls := 0
		verifyChainBetweenFiles = func() { calls++ }
		if r := VerifyChain(live); r.State != ChainStateVerified || calls != 1 {
			t.Errorf("got %q after %d passes", r.State, calls)
		}
	})
}

// Codex pass-2 finding 4 (pre-existing on main): lastRecord trimmed only LF,
// so a whitespace-only trailing line — the "\r" of a CRLF blank line, spaces
// — became the last record, ChainHead read "", and a healthy writer opened a
// fresh chain at genesis mid-file: a false BROKEN. lastRecord now skips
// blank lines with the verifier's own test, so a real AuditLogger appending
// after each tail shape links to the last record.
func TestChainHead_SkipsWhitespaceOnlyTail(t *testing.T) {
	// An unterminated whitespace fragment ("...}\n  " with no final LF) is
	// deliberately absent: lastRecord skips it too, but the writer then
	// appends its record on the same line and the verifier hashes that line
	// with the leading blanks. Fixing that is a write-path change (the
	// writer would have to start on a fresh line), not this PR's.
	tails := map[string]string{
		"CRLF blank line":                     "\r\n",
		"two CRLF blank lines":                "\r\n\r\n",
		"spaces line":                         "   \n",
		"tab line":                            "\t\n",
		"blank line then CRLF blank line":     "\n  \n\r\n",
		"extra LF (already tolerated)":        "\n",
		"non-breaking space line (TrimSpace)": " \n",
	}
	for name, tail := range tails {
		t.Run(name, func(t *testing.T) {
			smallRotation(t, 1<<30)
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			lg, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			logEvents(t, lg, 3, "before")
			_ = lg.Close()
			lines := readLines(t, p)
			appendRaw(t, p, tail)

			if got, want := ChainHead(p), rawChainedHash([]byte(lines[2])); got != want {
				t.Fatalf("ChainHead after tail %q = %q, want the hash of the last record", tail, got)
			}
			lg, err = New(p)
			if err != nil {
				t.Fatal(err)
			}
			logEvents(t, lg, 2, "after")
			_ = lg.Close()
			r := VerifyChain(p)
			if r.State != ChainStateVerified || r.Entries != 5 {
				t.Fatalf("after tail %q: %q (%d entries): %s", tail, r.State, r.Entries, r.Message)
			}
		})
	}
}

// Opus mutant MX3 / pass-2 finding 4: lastRecord has no cap at all — a
// 2 MB cap would survive the 1.1 MB tests — and it reads O(record), not
// O(file): a record over 4 MB at the end of a file of filler is found in a
// window that doubles until it holds the record.
func TestChainHead_NoCapAndReadsOnlyTheTail(t *testing.T) {
	big := strings.Repeat("B", 4200*1024)
	t.Run("ChainHead reads a final record over 4 MB", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainedLog(t, p, []AuditEvent{
			{Timestamp: "t", Command: "small", Decision: "ALLOW"},
			{Timestamp: "t", Command: big, Decision: "ALLOW"},
		})
		lines := readLines(t, p)
		if got, want := ChainHead(p), rawChainedHash([]byte(lines[1])); got != want {
			t.Fatalf("ChainHead = %q, want the hash of the 4.2 MB last record", got)
		}
	})
	t.Run("hook writers around a 4.2 MB event stay verified", func(t *testing.T) {
		smallRotation(t, 1<<30)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		for _, cmd := range []string{"a", big, "c"} {
			lg, err := New(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := lg.Log(AuditEvent{Timestamp: "t", Command: cmd, Decision: "ALLOW"}); err != nil {
				t.Fatal(err)
			}
			_ = lg.Close()
		}
		if r := VerifyChain(p); r.State != ChainStateVerified || r.Entries != 3 {
			t.Fatalf("got %q (%d entries): %s", r.State, r.Entries, r.Message)
		}
	})
	t.Run("lastRecordIn widens only until the record is complete", func(t *testing.T) {
		if _, ok := lastRecordIn([]byte("tail-of-a-longer-line\n"), false); ok {
			t.Error("a line cut by the window front is not a record yet")
		}
		if _, ok := lastRecordIn([]byte("tail-of-a-longer-line\n  \n\r\n"), false); ok {
			t.Error("blank lines behind a cut line do not make it complete")
		}
		if got, ok := lastRecordIn([]byte("whole\n"), true); !ok || string(got) != "whole" {
			t.Errorf("whole file: %q %v", got, ok)
		}
		if got, ok := lastRecordIn([]byte("a\nb\r\n  \n"), false); !ok || string(got) != "b" {
			t.Errorf("last non-blank complete line: %q %v", got, ok)
		}
		if _, ok := lastRecordIn([]byte("\n \n"), true); ok {
			t.Error("an all-blank file has no record")
		}
	})
}
