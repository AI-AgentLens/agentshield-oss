package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #4133 round 3 (Opus pass 3 C1/C2, Codex pass 3 lead 1): a present,
// non-empty audit.jsonl.1 is verified whether or not the live log links to
// it. Until round 2 a live file whose chain opened at genesis never consulted
// .1, and three shapes read ✅ over a .1 that was broken or wholly
// unprotected. Every fixture here is produced by the real writer where the
// shape can be reached through it.

// hookWrite is one IDE-hook invocation: open, one entry, close.
func hookWrite(t *testing.T, path, cmd string) {
	t.Helper()
	lg, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Log(AuditEvent{Timestamp: "2026-09-30T00:00:00Z", Command: cmd, Decision: "BLOCK"}); err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()
}

// padToThreshold appends one unchained JSON line that takes the file to
// maxLogBytes, so the next hook write rotates — and, because the tail is
// unchained, ChainHead(.1) is "" and the fresh file opens at genesis.
func padToThreshold(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	n := int(maxLogBytes - info.Size())
	if n < 0 {
		n = 0
	}
	appendRaw(t, path, `{"pad":"`+strings.Repeat("x", n)+`"}`+"\n")
}

func assertVerifiedNotLinked(t *testing.T, r ChainVerifyResult, wantEntries int) {
	t.Helper()
	if r.State != ChainStateVerified || !r.Protected() || r.Entries != wantEntries {
		t.Fatalf("got %q (%d entries, protected=%v): %s", r.State, r.Entries, r.Protected(), r.Message)
	}
	if r.Note != "audit.jsonl.1 verified (not linked)" {
		t.Errorf("note = %q, want the unlinked-but-verified note", r.Note)
	}
}

// Opus pass 3 C1. Delete a middle live entry (❌ while it is in the live
// file), then append one unchained padding line that reaches the rotation
// threshold. The next hook write rotates; ChainHead(.1) is "" because the
// tail is unchained, so the fresh live file opens at genesis and — before
// this round — never looked back at the .1 that holds the deletion: ✅,
// Protected()=true, while .1 alone read broken@4.
func TestVerifyChain_ForcedGenesisRotationDoesNotHideTamper(t *testing.T) {
	t.Run("deleted live entry followed by unchained padding", func(t *testing.T) {
		smallRotation(t, 5000)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		for i := 0; i < 10; i++ {
			hookWrite(t, p, fmt.Sprintf("real-%d", i))
		}
		writeLines(t, p, dropLine(readLines(t, p), 4))
		if r := VerifyChain(p); r.State != ChainStateBroken || r.BrokenAt != 4 || r.BrokenIn != "" {
			t.Fatalf("the deletion is visible while it is in the live file: got %q at %d in %q", r.State, r.BrokenAt, r.BrokenIn)
		}

		padToThreshold(t, p)
		hookWrite(t, p, "next hook rotates")

		// The shape the bypass needs, staged by the real writer.
		if fe := firstEntry(t, p); fe.PrevHash != "" {
			t.Fatalf("fixture: the fresh live file should open at genesis, got prev_hash %q", fe.PrevHash)
		}
		if r := VerifyChain(p + rotatedSuffix); r.State != ChainStateBroken || r.BrokenAt != 4 {
			t.Fatalf("fixture: .1 alone should be broken at 4, got %q at %d", r.State, r.BrokenAt)
		}

		assertBrokenInPredecessor(t, VerifyChain(p), 4)
	})

	// The same mechanism on an untampered MCP-proxy install (#4044): the
	// proxy's unchained line is .1's tail, the fresh live file opens at
	// genesis, and .1 reads "unchained entry after a chained entry". Known
	// and release-noted; the fix is the #4044 writer. Pinned so the
	// trade-off is deliberate, not accidental.
	t.Run("#4044 proxy line as the rotated tail reads broken in .1", func(t *testing.T) {
		smallRotation(t, 5000)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		for i := 0; i < 10; i++ {
			hookWrite(t, p, fmt.Sprintf("real-%d", i))
		}
		padToThreshold(t, p) // stands in for the proxy's unchained descriptor write
		hookWrite(t, p, "next hook rotates")

		r := VerifyChain(p)
		assertBrokenInPredecessor(t, r, 10)
		if !strings.Contains(r.Message, "unchained entry after a chained entry") {
			t.Errorf("message = %q", r.Message)
		}
	})
}

// Codex pass 3 lead 1. The entry hash excludes the chain fields, so a live
// file holding exactly one entry (right after a rotation) can lose its
// prev_hash and still verify on its own; later writers chain onto the
// stripped line. Before this round .1 was then never consulted.
func TestVerifyChain_StrippedLinkStillVerifiesPredecessor(t *testing.T) {
	stage := func(t *testing.T) (live, rotated string) {
		t.Helper()
		live, rotated = rotatedPair(t, t.TempDir(), 5, 1)
		lines := readLines(t, live)
		stripped, err := stripJSONKeys([]byte(lines[0]), "prev_hash")
		if err != nil {
			t.Fatal(err)
		}
		writeLines(t, live, []string{string(stripped)})
		hookWrite(t, live, "chains onto the stripped line")
		if fs := verifyFile(live); fs.result.State != ChainStateVerified || fs.continuedFrom != "" || fs.result.Entries != 2 {
			t.Fatalf("fixture: the stripped live file must verify on its own at genesis, got %+v", fs.result)
		}
		return live, rotated
	}

	t.Run("intact .1: verified, noted not linked — same capability as deleting .1 (#4132 item 1)", func(t *testing.T) {
		live, _ := stage(t)
		assertVerifiedNotLinked(t, VerifyChain(live), 2)
	})
	t.Run("tampered .1: broken in .1", func(t *testing.T) {
		live, rotated := stage(t)
		writeLines(t, rotated, dropLine(readLines(t, rotated), 2))
		assertBrokenInPredecessor(t, VerifyChain(live), 2)
	})
	t.Run("tampered .1 tail: broken at the last surviving entry's successor", func(t *testing.T) {
		live, rotated := stage(t)
		lines := readLines(t, rotated)
		lines[4] = strings.Replace(lines[4], `"command":"old-xxxx"`, `"command":"EDITED"`, 1)
		writeLines(t, rotated, lines)
		assertBrokenInPredecessor(t, VerifyChain(live), 4)
	})
}

// Opus pass 3 C2. A legacy (pre-chain) log already at or over the rotation
// threshold rotates on the first write after the upgrade: .1 is 100% legacy,
// the live file opens at genesis, and the install read ✅ at once — the
// release note's "⚠ partial until the legacy generation rotates out" was
// false for exactly the largest, longest-running installs. Now: partial,
// naming .1's pre-chain entries, until the legacy generation rotates out.
func TestVerifyChain_UpgradeFromLegacyLogAtRotationThreshold(t *testing.T) {
	for _, tc := range []struct {
		name string
		over int64
	}{{"at the threshold", 0}, {"over the threshold", 4000}} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			legacy := 0
			for {
				writeUnchainedLog(t, p, []AuditEvent{{Timestamp: "t", Command: fmt.Sprintf("legacy-%d", legacy), Decision: "ALLOW"}})
				legacy++
				if info, err := os.Stat(p); err == nil && info.Size() >= 2500+tc.over {
					break
				}
			}
			smallRotation(t, 2500)

			hookWrite(t, p, "first write after the upgrade")

			// The shape: everything legacy is in .1, the live file is one
			// genesis entry.
			if r := VerifyChain(p + rotatedSuffix); r.State != ChainStateUnprotected || r.Entries != legacy {
				t.Fatalf("fixture: .1 should be wholly unprotected with %d entries, got %q (%d)", legacy, r.State, r.Entries)
			}
			if fe := firstEntry(t, p); fe.PrevHash != "" {
				t.Fatalf("fixture: the live file should open at genesis, got prev_hash %q", fe.PrevHash)
			}

			r := VerifyChain(p)
			if r.State != ChainStatePartial || r.Protected() {
				t.Fatalf("after the first write: got %q (protected=%v): %s", r.State, r.Protected(), r.Message)
			}
			if want := fmt.Sprintf("audit.jsonl.1 holds %d pre-chain entries", legacy); r.Message != want {
				t.Fatalf("message = %q, want %q", r.Message, want)
			}

			// Partial until the legacy generation rotates out, verified
			// (and linked) from then on.
			rotations := 0
			for i := 0; i < 80; i++ {
				before, _ := os.Stat(p + rotatedSuffix)
				hookWrite(t, p, fmt.Sprintf("new-%d", i))
				if after, err := os.Stat(p + rotatedSuffix); err == nil && !os.SameFile(before, after) {
					rotations++
				}
				r := VerifyChain(p)
				switch {
				case rotations == 0 && r.State != ChainStatePartial:
					t.Fatalf("write %d before the legacy generation rotated out: %q: %s", i, r.State, r.Message)
				case rotations > 0 && (r.State != ChainStateVerified || r.Note != "linked to audit.jsonl.1"):
					t.Fatalf("write %d after %d rotations: %q note %q: %s", i, rotations, r.State, r.Note, r.Message)
				}
			}
			if rotations < 1 {
				t.Fatal("the fixture never rotated the legacy generation out")
			}
		})
	}
}

// No false alarm. A genesis live chain beside an intact .1 is what clean
// operation can leave behind, so it verifies (with a note that says the
// link is absent) — the verdict turns on .1's own integrity, never on the
// missing link.
func TestVerifyChain_GenesisLiveBesideIntactPredecessorVerifies(t *testing.T) {
	t.Run("clean rotations by the real writer stay linked and verified", func(t *testing.T) {
		smallRotation(t, 2000)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		rotations := 0
		for i := 0; i < 60; i++ {
			before, _ := os.Stat(p + rotatedSuffix)
			hookWrite(t, p, fmt.Sprintf("hook-%d", i))
			if after, err := os.Stat(p + rotatedSuffix); err == nil && (before == nil || !os.SameFile(before, after)) {
				rotations++
			}
			r := VerifyChain(p)
			if r.State != ChainStateVerified || !r.Protected() {
				t.Fatalf("write %d (%d rotations): %q: %s", i, rotations, r.State, r.Message)
			}
			if rotations > 0 && r.Note != "linked to audit.jsonl.1" {
				t.Fatalf("write %d: note %q", i, r.Note)
			}
		}
		if rotations < 2 {
			t.Fatalf("only %d rotations", rotations)
		}
	})

	// `mv audit.jsonl audit.jsonl.1; touch audit.jsonl` by an external
	// rotation tool, and — byte for byte the same layout — a writer that
	// lost the lock race inside the rotation window (#4131): it reopens the
	// fresh, still-empty live file, reads no head, writes a genesis line,
	// and the rotator's own entry then chains onto it (its resync sees the
	// size change). Neither is tampering.
	t.Run("external rotation or a lock-race follower's genesis line", func(t *testing.T) {
		smallRotation(t, 1<<30)
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		for i := 0; i < 6; i++ {
			hookWrite(t, p, fmt.Sprintf("before-%d", i))
		}
		if err := os.Rename(p, p+rotatedSuffix); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0600); err != nil {
			t.Fatal(err)
		}
		// Between the rename and the first write: nothing to verify in the
		// live file, and nothing wrong either.
		if r := VerifyChain(p); r.State != ChainStateEmpty || r.Protected() {
			t.Fatalf("empty live beside an intact .1: got %q: %s", r.State, r.Message)
		}
		// Since #4057 a writer that finds the live file empty links it to .1
		// (resyncHead reads .1's head), so external rotation verifies linked.
		for i := 0; i < 3; i++ {
			hookWrite(t, p, fmt.Sprintf("after-%d", i))
			if r := VerifyChain(p); r.State != ChainStateVerified || !r.Protected() || r.Note != "linked to audit.jsonl.1" {
				t.Fatalf("after external rotation, write %d: %q note=%q: %s", i, r.State, r.Note, r.Message)
			}
		}
		if fe := firstEntry(t, p); fe.PrevHash == "" {
			t.Fatalf("fixture: the first writer after the rotation should link to .1")
		}
		// The genesis layout a lock-race follower (#4131) can still leave,
		// built directly: verified, noted not linked.
		writeChainedLogFrom(t, p, "", []AuditEvent{{Timestamp: "2026-09-30T00:00:00Z", Command: "follower genesis", Decision: "ALLOW"}})
		assertVerifiedNotLinked(t, VerifyChain(p), 1)
		// ...and the same layout with .1 tampered is caught.
		rotated := p + rotatedSuffix
		writeLines(t, rotated, dropLine(readLines(t, rotated), 3))
		assertBrokenInPredecessor(t, VerifyChain(p), 3)
	})
}

// An unlinked live file beside a .1 that cannot be read: not verified, not
// a tampering claim — the same ⚠ a linked live file gets (round 2), now on
// real files for the genesis shape.
func TestVerifyChain_GenesisLiveBesideUnreadablePredecessorIsUnreadable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	hookWrite(t, p, "genesis")
	if err := os.Mkdir(p+rotatedSuffix, 0700); err != nil {
		t.Fatal(err)
	}
	r := VerifyChain(p)
	if r.State != ChainStateUnreadable || r.Protected() || !strings.HasPrefix(r.Message, "audit.jsonl.1 unreadable, not verified: ") {
		t.Fatalf("got %q (protected=%v): %s", r.State, r.Protected(), r.Message)
	}
}

// relateToPredecessor with an unlinked live scan: every predecessor state,
// and the live states a genesis chain can be in.
func TestRelateToPredecessor_UnlinkedCompositions(t *testing.T) {
	genesis := fileScan{result: ChainVerifyResult{State: ChainStateVerified, Entries: 2, BrokenAt: -1, Message: "chain verified"}, head: "G"}
	const base = "audit.jsonl.1"

	t.Run("verified .1 → live verdict, noted not linked", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStateVerified, Entries: 4, BrokenAt: -1}, head: "H"}
		r := relateToPredecessor(genesis, pred, base)
		want := genesis.result
		want.Note = "audit.jsonl.1 verified (not linked)"
		if r != want || !r.Protected() {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("partial .1 → partial naming its pre-chain entries", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStatePartial, Entries: 6, LegacyEntries: 4, BrokenAt: -1}, head: "H"}
		r := relateToPredecessor(genesis, pred, base)
		want := ChainVerifyResult{State: ChainStatePartial, Entries: 2, BrokenAt: -1, Message: "audit.jsonl.1 holds 4 pre-chain entries"}
		if r != want || r.Protected() {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("unprotected .1 → partial naming every entry", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStateUnprotected, Entries: 3, LegacyEntries: 3, BrokenAt: -1}}
		r := relateToPredecessor(genesis, pred, base)
		want := ChainVerifyResult{State: ChainStatePartial, Entries: 2, BrokenAt: -1, Message: "audit.jsonl.1 holds 3 pre-chain entries"}
		if r != want || r.Protected() {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("unreadable .1 → unreadable", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStateUnreadable, BrokenAt: -1, Message: "read error after entry 0: is a directory"}}
		r := relateToPredecessor(genesis, pred, base)
		want := ChainVerifyResult{State: ChainStateUnreadable, Entries: 2, BrokenAt: -1, Message: "audit.jsonl.1 unreadable, not verified: read error after entry 0: is a directory"}
		if r != want || r.Protected() {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("broken .1 → broken in .1", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStateBroken, Entries: 1, BrokenAt: 1, Message: "entry 1: entry hash mismatch"}}
		r := relateToPredecessor(genesis, pred, base)
		want := ChainVerifyResult{State: ChainStateBroken, Entries: 2, BrokenAt: 1, BrokenIn: base, Message: "audit.jsonl.1 entry 1: entry hash mismatch"}
		if r != want || r.Protected() {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("absent or empty .1 → live verdict, no note", func(t *testing.T) {
		pred := fileScan{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1}}
		if r := relateToPredecessor(genesis, pred, base); r != genesis.result {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("a partial or unprotected live file keeps its own verdict and message", func(t *testing.T) {
		unprotectedPred := fileScan{result: ChainVerifyResult{State: ChainStateUnprotected, Entries: 3, LegacyEntries: 3, BrokenAt: -1}}
		partialLive := fileScan{result: ChainVerifyResult{State: ChainStatePartial, Entries: 5, LegacyEntries: 3, BrokenAt: -1, Message: "3 of 5 entries predate the chain"}, head: "G"}
		if r := relateToPredecessor(partialLive, unprotectedPred, base); r != partialLive.result {
			t.Errorf("partial live: got %+v", r)
		}
		unprotectedLive := fileScan{result: ChainVerifyResult{State: ChainStateUnprotected, Entries: 2, LegacyEntries: 2, BrokenAt: -1, Message: "no chain fields written"}}
		if r := relateToPredecessor(unprotectedLive, unprotectedPred, base); r != unprotectedLive.result {
			t.Errorf("unprotected live: got %+v", r)
		}
		// ...but a broken .1 still wins over both. Both are asserted: with
		// only the partial case pinned, a mutant that skipped .1 for an
		// unprotected live file survived the suite (#4133 Opus pass 4 R12).
		broken := fileScan{result: ChainVerifyResult{State: ChainStateBroken, BrokenAt: 0, Message: "entry 0: invalid JSON: x"}}
		if r := relateToPredecessor(partialLive, broken, base); r.State != ChainStateBroken || r.BrokenIn != base || r.LegacyEntries != 3 {
			t.Errorf("partial live beside a broken .1: got %+v", r)
		}
		if r := relateToPredecessor(unprotectedLive, broken, base); r.State != ChainStateBroken || r.BrokenIn != base || r.BrokenAt != 0 || r.Entries != 2 || r.LegacyEntries != 2 {
			t.Errorf("unprotected live beside a broken .1: got %+v", r)
		}
		unreadable := fileScan{result: ChainVerifyResult{State: ChainStateUnreadable, BrokenAt: -1, Message: "not a regular file (p---------)"}}
		if r := relateToPredecessor(unprotectedLive, unreadable, base); r.State != ChainStateUnreadable || r.Entries != 2 {
			t.Errorf("unprotected live beside an unreadable .1: got %+v", r)
		}
	})
	t.Run("an empty live file beside a broken .1 is broken in .1", func(t *testing.T) {
		empty := fileScan{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "empty log"}}
		broken := fileScan{result: ChainVerifyResult{State: ChainStateBroken, BrokenAt: 2, Message: "entry 2: prev_hash mismatch (chain broken)"}}
		r := relateToPredecessor(empty, broken, base)
		if r.State != ChainStateBroken || r.BrokenIn != base || r.BrokenAt != 2 || r.Entries != 0 {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("a broken or unreadable live file is returned as is", func(t *testing.T) {
		clean := fileScan{result: ChainVerifyResult{State: ChainStateVerified, Entries: 4, BrokenAt: -1}, head: "H"}
		for _, live := range []fileScan{
			{result: ChainVerifyResult{State: ChainStateBroken, Entries: 1, BrokenAt: 1}},
			{result: ChainVerifyResult{State: ChainStateUnreadable, Entries: 1, BrokenAt: -1, Message: "read error after entry 1: boom"}},
		} {
			if r := relateToPredecessor(live, clean, base); r != live.result {
				t.Errorf("got %+v", r)
			}
		}
	})
}

// syntheticLog is a random-access log of the given size whose last bytes
// are tail and whose body is filler lines, so a test can hand lastRecordAt a
// 256 MiB file without writing or allocating one.
type syntheticLog struct {
	size int64
	tail []byte
}

func (s *syntheticLog) ReadAt(p []byte, off int64) (int, error) {
	tailStart := s.size - int64(len(s.tail))
	for i := range p {
		pos := off + int64(i)
		if pos >= s.size {
			return i, io.EOF
		}
		switch {
		case pos >= tailStart:
			p[i] = s.tail[pos-tailStart]
		case pos%1000 == 999:
			p[i] = '\n'
		default:
			p[i] = 'f'
		}
	}
	return len(p), nil
}

// countingReaderAt records what lastRecordAt actually read.
type countingReaderAt struct {
	io.ReaderAt
	bytes int64
	reads int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	c.bytes += int64(len(p))
	return c.ReaderAt.ReadAt(p, off)
}

// Opus pass 3 survivors N12 and N2: "read the whole file as the second
// window" and a window that grows by 64 KiB a step both return the right
// record and both pass every other test. The claim is O(record), so pin the
// cost: bytes read bounded by a small multiple of the record, reads
// logarithmic in it. A doubling window's total is under 2× its final
// window, and the final window is under 2× the record, hence the 4× bound.
func TestLastRecordAt_ReadsOnlyTheTail(t *testing.T) {
	const size = 256 << 20
	for _, tc := range []struct {
		name      string
		record    int
		wantBytes int64
		wantReads int
	}{
		{"small last record in a 256 MiB file", 200, tailReadBytes, 1},
		{"3 MiB last record in a 256 MiB file", 3 << 20, 4*(3<<20) + tailReadBytes, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := []byte(`{"command":"` + strings.Repeat("r", tc.record) + `"}`)
			src := &countingReaderAt{ReaderAt: &syntheticLog{size: size, tail: append(append([]byte{'\n'}, record...), '\n')}}
			got, ok, _ := lastRecordAt(src, size)
			if !ok || string(got) != string(record) {
				t.Fatalf("wrong record: ok=%v len=%d", ok, len(got))
			}
			if src.bytes > tc.wantBytes {
				t.Errorf("read %d bytes for a %d-byte record, want at most %d (O(record), not O(file))", src.bytes, len(record), tc.wantBytes)
			}
			if src.reads > tc.wantReads {
				t.Errorf("%d reads, want at most %d (a doubling window)", src.reads, tc.wantReads)
			}
			t.Logf("%d-byte record: %d bytes in %d reads", len(record), src.bytes, src.reads)
		})
	}
	t.Run("a file under one window is read once, whole", func(t *testing.T) {
		src := &countingReaderAt{ReaderAt: strings.NewReader("a\nb\n")}
		if got, ok, _ := lastRecordAt(src, 4); !ok || string(got) != "b" || src.reads != 1 || src.bytes != 4 {
			t.Errorf("got %q ok=%v reads=%d bytes=%d", got, ok, src.reads, src.bytes)
		}
	})
}
