package logger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// tailReadBytes is the first tail-read window. The chain head is recovered by
// reading the end of the log rather than the whole file, so the cost grows
// with the size of the final record, not of the log — this runs on every
// agentshield process start. lastRecord doubles the window until it holds a
// complete record; there is no upper bound (see lastRecord).
const tailReadBytes = 64 * 1024

// ChainedEvent extends AuditEvent with hash chain fields for tamper detection.
//
// Verification (entryHashFromRaw / rawChainedHash, #4008) hashes the raw JSON
// line as read from disk, structurally stripping only the two wrapper keys
// below — it never unmarshals into AuditEvent and re-marshals. So a field
// added to AuditEvent later needs no special handling to verify correctly
// across a version boundary: an older binary's struct not declaring the field
// no longer matters, because verification never goes through that struct.
// (Before #4008, verification DID re-marshal the parsed struct, and any field
// missing `omitempty` — or simply absent from an older reader's struct at
// all — made every historical entry report a false "entry hash mismatch".)
type ChainedEvent struct {
	AuditEvent
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}

// ComputeEntryHash computes the SHA-256 hash of a ChainedEvent (excluding hash fields).
func ComputeEntryHash(event ChainedEvent) string {
	// Hash the base event without chain fields
	plain := event.AuditEvent
	data, err := json.Marshal(plain)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ComputeChainedHash computes the SHA-256 hash of the full ChainedEvent JSON
// (including PrevHash and EntryHash) for use as the next entry's PrevHash.
func ComputeChainedHash(event ChainedEvent) string {
	data, err := json.Marshal(event)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// stripJSONKeys returns raw (a single JSON object) with the given top-level
// keys removed, preserving the exact bytes and order of every remaining
// key/value pair. It walks the token stream rather than doing a text search,
// so attacker-controlled field content (Command, Args) that happens to
// contain the literal text of a skipped key cannot smuggle a false strip.
func stripJSONKeys(raw []byte, skip ...string) ([]byte, error) {
	skipSet := make(map[string]bool, len(skip))
	for _, k := range skip {
		skipSet[k] = true
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("not a JSON object")
	}

	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T", keyTok)
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		if skipSet[key] {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		keyBytes, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')
		buf.Write(val)
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return nil, err
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// entryHashFromRaw computes the entry hash directly from the raw JSON line on
// disk, structurally stripping the chain-only "prev_hash"/"entry_hash" keys
// instead of unmarshalling into (and re-marshalling from) a versioned Go
// struct (#4008). A struct round trip silently drops any field the verifying
// binary's AuditEvent does not declare — e.g. an older binary reading an
// entry a newer binary wrote with `notes` set re-marshals without it and
// reports a false tamper alarm. This only assumes ChainedEvent always names
// its own two wrapper keys "prev_hash" and "entry_hash", which is independent
// of whatever fields AuditEvent gains or loses over time.
func entryHashFromRaw(raw []byte) (string, error) {
	stripped, err := stripJSONKeys(raw, "prev_hash", "entry_hash")
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(stripped)
	return hex.EncodeToString(h[:]), nil
}

// rawChainedHash hashes a record as stored (see recordBytes): no
// parse/re-marshal round trip, so (unlike ComputeChainedHash on a re-parsed
// struct) it agrees with any writer regardless of which AuditEvent fields
// that writer's binary knows about (#4008).
func rawChainedHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// recordBytes is the one normalization VerifyChain and ChainHead both apply
// to a line before hashing it: drop the line terminator (a trailing \r left
// by CRLF endings) and nothing else. They used to differ (TrimSpace vs
// "\n" only), so a log converted to CRLF verified on read but a writer
// resyncing its head produced a link no verifier accepted. Unicode TrimSpace
// also hid a trailing U+00A0/U+0085/U+2028 from the hash while
// `agentshield log` rejected the same line (#4026 Opus review).
func recordBytes(line []byte) []byte {
	return bytes.TrimRight(line, "\r")
}

// ChainState is the outcome of verifying an audit log's hash chain.
//
// It replaces the old `Valid bool`, which conflated "nothing detected" with
// "protected" — a log with no chain fields at all reported Valid and `scan`
// printed a green tick on it (issue #3112). Callers must distinguish the
// states; there is deliberately no boolean that a caller can render as a pass.
type ChainState string

const (
	// ChainStateEmpty means there are no entries to protect (fresh install).
	ChainStateEmpty ChainState = "empty"
	// ChainStateUnprotected means entries exist but none carry chain fields —
	// written by a build that predates chaining, or by nothing at all.
	ChainStateUnprotected ChainState = "unprotected"
	// ChainStatePartial means a prefix of unchained (pre-upgrade) entries is
	// followed by a verified chain. The prefix is not tamper-evident.
	ChainStatePartial ChainState = "partial"
	// ChainStateVerified means every entry is chained and the chain verifies.
	ChainStateVerified ChainState = "verified"
	// ChainStateBroken means an entry hash, a link, or the record structure
	// does not match — evidence of an edit, a deletion, or a truncated write.
	ChainStateBroken ChainState = "broken"
	// ChainStateUnreadable means the log could not be read (permissions, I/O).
	// Not a tampering claim.
	ChainStateUnreadable ChainState = "unreadable"
)

// ChainVerifyResult holds the result of an audit chain verification.
type ChainVerifyResult struct {
	State ChainState
	// Entries is the total number of records read, chained or not.
	Entries int
	// LegacyEntries is how many of them predate the hash chain.
	LegacyEntries int
	// BrokenAt is -1 unless State is ChainStateBroken, in which case it is the
	// 0-based index of the first bad entry — in BrokenIn when that is set,
	// otherwise in the verified path itself.
	BrokenAt int
	// BrokenIn names the file BrokenAt indexes when the break was found in
	// the rotated predecessor beside the verified path (#4132 item 2),
	// whether or not the live log links to it. Empty when the break is in
	// the verified path itself.
	BrokenIn string
	Message  string
	// Note carries secondary detail that does not change the state, currently
	// only the rotation-boundary finding.
	Note string
}

// Protected reports whether every entry in the log is covered by an intact
// chain. This is the only question a "verified" badge may be rendered from.
//
// It says nothing about who could have produced the chain: the digest is an
// unkeyed SHA-256 over a file the agent can write, so a process running as the
// same user can rewrite history and recompute a chain that reports Protected.
// Binding the chain to a key or an external anchor is issue #3112 stage 3.
func (r ChainVerifyResult) Protected() bool { return r.State == ChainStateVerified }

// VerifyChain reads an audit.jsonl file and verifies the hash chain integrity.
//
// Two tolerated discontinuities, both of which occur in normal operation:
//
//   - A prefix of unchained entries (a log that existed before the customer
//     upgraded to a chaining build). Reported as ChainStatePartial, never as
//     verified. An unchained entry *after* a chained one is not tolerated —
//     that is an edit, a downgraded writer, or an MCP proxy line (#4044).
//     Nor is a chain that starts behind that prefix with a non-empty
//     prev_hash: every AuditLogger opens the chain of an upgraded log at
//     genesis, so on a hook-only install that shape means chain fields were
//     stripped from earlier entries (#4133 Opus pass 1). An MCP proxy that
//     opens the fresh live file inside the rotation window can leave the
//     same [unchained][linked] shape on an untampered log; that is #4044's
//     writer defect, and it reads broken here until #4044 lands.
//   - A first entry whose prev_hash points at an entry this file does not
//     contain (the log was rotated). Cross-checked against <path>.1 when that
//     predecessor is still on disk.
//
// A present, non-empty <path>.1 is verified in full whether or not the live
// file links to it (#4132 item 2, Gary 2026-09-30; #4133 passes 1–3). The
// only time it is left unread is when the live file is broken or unreadable
// on its own: that verdict is reported as-is, whatever <path>.1 holds. The
// two verdicts compose:
//
//   - a break inside <path>.1 → ChainStateBroken with BrokenIn set, reported
//     before the boundary (linked or not);
//   - <path>.1 exists but cannot be read → ChainStateUnreadable: a read error
//     is not evidence of tampering, and neither is it a verification;
//   - <path>.1 absent or empty → the live verdict; when the live file links,
//     with the note "predecessor unavailable" (only one rotated generation
//     is kept).
//
// When the live file links (its first chained entry carries a prev_hash):
//
//   - the boundary (that prev_hash against <path>.1's head) does not match →
//     ChainStateBroken at the live entry;
//   - <path>.1 is partial (an upgraded install whose legacy generation has
//     not rotated out yet) → ChainStatePartial: the legacy entries really are
//     unprotected, and Protected() must not say otherwise;
//   - <path>.1 verified → the live verdict, noted "linked to <path>.1".
//
// When the live file does NOT link (its chain opens at genesis) there is no
// boundary to check, but <path>.1 still has to hold up: a verified <path>.1
// → the live verdict, noted "not linked"; a partial or unprotected <path>.1
// → ChainStatePartial naming its pre-chain entries. Three shapes made this
// necessary (#4133 pass 3): a deleted live entry followed by an unchained
// padding line that forces the next rotation to open the fresh file at
// genesis (ChainHead of an unchained tail is "") hid a broken <path>.1
// behind a ✅; stripping prev_hash from a one-entry live file (the entry
// hash excludes the chain fields) did the same; and an upgrade from a
// legacy log already at the rotation threshold rotated on its first write
// and read ✅ with every legacy entry unprotected in <path>.1. A genesis
// live file beside an intact <path>.1 is not itself a finding: a writer
// that lost the lock race inside the rotation window (#4131) produces it,
// and so does external rotation (`mv audit.jsonl audit.jsonl.1`) once
// writers read the head from the held descriptor (#4057) — before that, a
// write racing the external rename resyncs its head from the new empty file
// and lands a genesis entry at <path>.1's tail through the held descriptor,
// which reads as a break in <path>.1 (#4133 Opus pass 4 C1). The verdict
// turns on <path>.1's own integrity; the missing link only adds a note.
//
// <path>.1 is opened only when it is a regular file: a FIFO there blocked
// the verifier on open, and a symlink was followed. Anything else reads
// ChainStateUnreadable (scanPredecessor).
//
// Before this only the tail hash of <path>.1 was compared, so an entry
// deleted or mis-linked in the middle of the retained predecessor sat behind
// a live log that reported Protected() — and a stray byte appended to
// <path>.1 switched even the tail comparison off (#4133 Codex F1). The
// predecessor's *own* first entry may link to a generation that no longer
// exists, and that is accepted, as it is for the live file.
//
// A rotation that lands between the two reads makes the live scan and the
// predecessor read describe different generations, which reads as a break
// at the boundary on an untampered log (measured at about 11% of calls
// during a rotation storm, #4133 Codex F3). The live file's identity is
// therefore snapshotted before and re-checked after each attempt, and the
// verification is retried, bounded by verifyAttempts, while it keeps moving.
// A log that moved during every attempt was not verified: the result is
// ChainStateUnreadable, never broken (every attempt compared mismatched
// generations) and never verified (#4133 Codex pass 2).
func VerifyChain(path string) ChainVerifyResult {
	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		before, _ := os.Stat(path)
		result := verifyChainOnce(path)
		after, _ := os.Stat(path)
		if sameIdentity(before, after) {
			return result
		}
	}
	return ChainVerifyResult{
		State:    ChainStateUnreadable,
		BrokenAt: -1,
		Message:  "cannot verify: the log rotated during every verification attempt; re-run",
	}
}

// verifyAttempts bounds VerifyChain's retry when the live log is rotated
// underneath it. One rotation per 10 MB written makes a second collision in
// the same call implausible; three keeps a rotation storm from spinning.
const verifyAttempts = 3

// verifyChainBetweenFiles is a test seam, nil in production: when set it runs
// after the live log has been scanned and before its predecessor is read —
// the window a rotation has to land in to produce the false boundary break
// VerifyChain's retry exists for.
var verifyChainBetweenFiles func()

// sameIdentity reports whether two stats (either may be nil for "no file")
// describe the same file.
func sameIdentity(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b)
}

// verifyChainOnce is one pass of VerifyChain: scan the live log and, unless
// that already settled the verdict, the rotated predecessor too, and compose.
func verifyChainOnce(path string) ChainVerifyResult {
	live := verifyFile(path)
	if !live.consultsPredecessor() {
		return live.result
	}
	if verifyChainBetweenFiles != nil {
		verifyChainBetweenFiles()
	}
	rotated := path + rotatedSuffix
	return relateToPredecessor(live, scanPredecessor(rotated), filepath.Base(rotated))
}

// scanPredecessor is verifyFile for the rotated predecessor, guarded so that
// only a regular file is ever opened there. The writer creates <path>.1 by
// renaming its own regular file; anything else at that name was put there by
// someone else. A FIFO hung VerifyChain — and so `scan` — indefinitely on
// open (#4133 Opus pass 4), a directory read as an I/O error, and a symlink
// was followed wherever it pointed. All read Unreadable now: not a tampering
// claim, not a verification. (A symlink at <path>.1 used to be verified
// through; that is deliberately no longer the case.)
func scanPredecessor(path string) fileScan {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fileScan{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "no audit log yet"}}
	case err != nil:
		return fileScan{result: ChainVerifyResult{State: ChainStateUnreadable, BrokenAt: -1, Message: fmt.Sprintf("cannot stat: %v", err)}}
	case !info.Mode().IsRegular():
		return fileScan{result: ChainVerifyResult{State: ChainStateUnreadable, BrokenAt: -1, Message: fmt.Sprintf("not a regular file (%s)", info.Mode().Type())}}
	}
	return verifyFile(path)
}

// relateToPredecessor composes the live log's own verdict with its rotated
// predecessor's. It is a pure function of the two scans so that every
// combination of states — including the ones no file layout can produce on
// demand, such as a read error after a linked first entry — is testable.
func relateToPredecessor(live, pred fileScan, base string) ChainVerifyResult {
	if !live.consultsPredecessor() {
		return live.result
	}
	out := live.result
	switch pred.result.State {
	case ChainStateEmpty:
		if live.linksToPredecessor() {
			out.Note = "continues a rotated log (predecessor unavailable)"
		}
		return out
	case ChainStateUnreadable:
		// A present predecessor that could not be read was not verified, so
		// the live log's link to it cannot be honoured either way: not a
		// tampering claim (a read error is not evidence), and not a pass
		// (#4133 Codex pass 2 finding 3 — a directory at <path>.1 kept
		// Protected() true).
		return ChainVerifyResult{
			State:         ChainStateUnreadable,
			Entries:       out.Entries,
			LegacyEntries: out.LegacyEntries,
			BrokenAt:      -1,
			Message:       fmt.Sprintf("%s unreadable, not verified: %s", base, pred.result.Message),
		}
	case ChainStateBroken:
		msg := base + " " + pred.result.Message
		if pred.degradedNearBreak {
			msg += "; adjacent to a degraded (lockless) write, may be a lost lock race"
		}
		return ChainVerifyResult{
			State:         ChainStateBroken,
			Entries:       out.Entries,
			LegacyEntries: out.LegacyEntries,
			BrokenAt:      pred.result.BrokenAt,
			BrokenIn:      base,
			Message:       msg,
		}
	}
	// The predecessor holds up on its own (verified, partial from genesis, or
	// carrying no chain at all). Its own continuedFrom is deliberately not
	// chased: <path>.2 is never retained, so a linked first entry there is
	// the accepted "predecessor unavailable" case one generation further back.
	if !live.linksToPredecessor() {
		// No boundary to check: the live chain opened at genesis. That is
		// what external rotation and a lost lock race in the rotation
		// window (#4131) leave behind, so it is not a finding by itself —
		// but it is also exactly what a forced-genesis rotation behind a
		// tampered <path>.1, a stripped prev_hash, and an upgrade that
		// rotated on its first write leave behind (#4133 Opus pass 3 C1/C2,
		// Codex pass 3 lead 1), so <path>.1 still has to hold up on its own.
		switch pred.result.State {
		case ChainStateVerified:
			out.Note = base + " verified (not linked)"
		case ChainStatePartial, ChainStateUnprotected:
			if out.State == ChainStateVerified || out.State == ChainStateEmpty {
				// Same verdict a linked partial predecessor gets: the
				// pre-chain entries in <path>.1 are not covered by any hash.
				// A live file that is itself partial or unprotected already
				// says so and keeps its own message. An empty or absent live
				// file (an external `mv` of a legacy log, before the next
				// write) asserts nothing, so <path>.1's verdict stands —
				// Empty would have `scan` print "no entries yet" over
				// unprotected history (#4133 Codex pass 4 finding 2). A
				// verified <path>.1 leaves Empty as is: no ✅ is minted
				// from a file that holds nothing (#3112).
				out.State = ChainStatePartial
				out.Message = fmt.Sprintf("%s holds %d pre-chain entries", base, pred.result.LegacyEntries)
			}
		}
		return out
	}
	// Now the boundary. A predecessor carrying no chain at all has an empty
	// head, so the live file's claim to continue it cannot be honoured.
	if pred.head != live.continuedFrom {
		return ChainVerifyResult{
			State:         ChainStateBroken,
			Entries:       out.Entries,
			LegacyEntries: out.LegacyEntries,
			BrokenAt:      live.firstChainedIdx,
			Message: fmt.Sprintf("entry %d: prev_hash does not match the head of %s",
				live.firstChainedIdx, base),
		}
	}
	out.Note = "linked to " + base
	if pred.result.State == ChainStatePartial {
		// The link holds, but the predecessor's legacy prefix is not covered
		// by any hash: the same verdict a partial live file gets. An upgraded
		// install reads partial until its legacy generation rotates out;
		// entries prepended to or edited inside that prefix are not detected,
		// and Protected() must not claim they are (#4133 Codex pass 2
		// finding 2). Entries and LegacyEntries still describe the live file.
		out.State = ChainStatePartial
		out.Message = fmt.Sprintf("%s holds %d pre-chain entries", base, pred.result.LegacyEntries)
	}
	return out
}

// lockUnavailableNoteKind is the note kind a writer that could not take the
// audit lock attaches to its entry (#4057). It is read from the parsed Notes
// field, never matched against the raw line: command text is agent-written,
// so a substring match let `echo "audit_lock_unavailable"` plant the hint
// beside a real deletion (#4133 Opus pass 1). Either way it only ever adds
// words to a BROKEN message; a note can never turn a break into a pass.
const lockUnavailableNoteKind = "audit_lock_unavailable"

func hasLockUnavailableNote(e ChainedEvent) bool {
	for _, n := range e.Notes {
		if n.Kind == lockUnavailableNoteKind {
			return true
		}
	}
	return false
}

// fileScan is the outcome of verifying one file on its own, plus what
// VerifyChain needs to relate it to its rotated predecessor.
type fileScan struct {
	// result is the standalone verdict. Note is left empty; VerifyChain fills
	// it once the rotation link has been examined.
	result ChainVerifyResult
	// continuedFrom is the prev_hash of the first chained entry when it is
	// non-empty (the file claims to continue an earlier generation).
	continuedFrom string
	// firstChainedIdx is the index of the entry that carries continuedFrom.
	firstChainedIdx int
	// head is the hash the next entry appended to this file must carry as
	// its prev_hash: the chained hash of the last record when the scan
	// completed without a break, "" when the file carries no chain.
	head string
	// degradedNearBreak is set when result is broken and the bad entry or one
	// of its neighbours carries lockUnavailableNoteKind.
	degradedNearBreak bool
}

// consultsPredecessor reports whether the rotated generation before this
// file still has a say in the verdict: nothing found in the file itself
// already settles it. A break or a read error in the live file is reported
// as-is, whatever <path>.1 holds.
func (s fileScan) consultsPredecessor() bool {
	switch s.result.State {
	case ChainStateBroken, ChainStateUnreadable:
		return false
	}
	return true
}

// linksToPredecessor reports whether this file claims to continue the
// rotated generation before it (its first chained entry carries a
// prev_hash) and the verdict still depends on that claim.
func (s fileScan) linksToPredecessor() bool {
	return s.continuedFrom != "" && s.consultsPredecessor()
}

// recordReader yields the non-blank records of a log, one per line, with no
// upper bound on line length: bufio.Scanner's token limit made a legitimate
// 1.1 MB entry (an MCP call with a large argument payload) report the whole
// file unreadable, which for a rotated predecessor silently skipped its
// verification (#4133 Opus pass 1).
type recordReader struct {
	r   *bufio.Reader
	err error
}

func (rr *recordReader) next() ([]byte, bool) {
	for {
		line, err := rr.r.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			rr.err = err
			return nil, false
		}
		line = recordBytes(bytes.TrimSuffix(line, []byte("\n")))
		if !blankRecord(line) {
			return line, true
		}
		if err != nil {
			return nil, false
		}
	}
}

// blankRecord reports whether a line (terminator already removed) holds no
// record. The verifier skips such lines, so lastRecord must skip them too:
// a whitespace-only tail — the "\r" of a CRLF blank line, spaces — is not
// the head, and a writer that took it for one opened a fresh chain at
// genesis mid-file, which the verifier then called broken (#4133 Codex pass
// 2 finding 4).
func blankRecord(line []byte) bool {
	return len(bytes.TrimSpace(recordBytes(line))) == 0
}

// verifyFile walks one log file and verifies its chain without consulting any
// other file. VerifyChain composes it for the live log and its predecessor.
func verifyFile(path string) fileScan {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileScan{result: ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "no audit log yet"}}
		}
		return fileScan{result: ChainVerifyResult{State: ChainStateUnreadable, BrokenAt: -1, Message: fmt.Sprintf("cannot open file: %v", err)}}
	}
	defer func() { _ = f.Close() }()

	rr := &recordReader{r: bufio.NewReaderSize(f, tailReadBytes)}

	var (
		prevHash        string
		idx             int
		legacy          int
		chained         int
		continuedFrom   string
		firstChainedIdx int
		prevNoted       bool
	)

	broken := func(at int, msg string, noted bool) fileScan {
		if !noted {
			if next, ok := rr.next(); ok {
				var neighbour ChainedEvent
				noted = json.Unmarshal(next, &neighbour) == nil && hasLockUnavailableNote(neighbour)
			}
		}
		return fileScan{
			result: ChainVerifyResult{
				State:         ChainStateBroken,
				Entries:       idx,
				LegacyEntries: legacy,
				BrokenAt:      at,
				Message:       msg,
			},
			continuedFrom:     continuedFrom,
			firstChainedIdx:   firstChainedIdx,
			degradedNearBreak: noted,
		}
	}

	for {
		line, ok := rr.next()
		if !ok {
			break
		}

		var entry ChainedEvent
		if err := json.Unmarshal(line, &entry); err != nil {
			return broken(idx, fmt.Sprintf("entry %d: invalid JSON: %v", idx, err), prevNoted)
		}
		noted := hasLockUnavailableNote(entry)

		if entry.EntryHash == "" {
			if entry.PrevHash != "" {
				// No build ever wrote this: pre-chain writers wrote neither
				// field, chaining writers write both. It is a chained record
				// with its proof removed, wherever it sits — counting it as
				// legacy let a .1 stripped of every entry_hash read as
				// "pre-chain entries" (⚠) instead of a break (#4133 Codex
				// pass 4 finding 1).
				return broken(idx, fmt.Sprintf("entry %d: prev_hash without entry_hash (chain fields stripped)", idx), prevNoted || noted)
			}
			if chained > 0 {
				return broken(idx, fmt.Sprintf("entry %d: unchained entry after a chained entry", idx), prevNoted || noted)
			}
			legacy++
			idx++
			prevNoted = noted
			continue
		}

		if chained == 0 && entry.PrevHash != "" {
			if legacy > 0 {
				// A writer appending the first chained entry to a pre-chain
				// log reads an empty head and starts at genesis; a chain
				// that instead continues an earlier one behind unchained
				// entries had its own prefix stripped of chain fields.
				return broken(idx, fmt.Sprintf("entry %d: chain continues an earlier generation behind %d unchained entries", idx, legacy), prevNoted || noted)
			}
			// Chain continues from a rotated predecessor: adopt the claimed
			// head here; VerifyChain cross-checks it against <path>.1.
			continuedFrom = entry.PrevHash
			prevHash = entry.PrevHash
			firstChainedIdx = idx
		}

		if got, err := entryHashFromRaw(line); err != nil || entry.EntryHash != got {
			return broken(idx, fmt.Sprintf("entry %d: entry hash mismatch", idx), prevNoted || noted)
		}
		if entry.PrevHash != prevHash {
			return broken(idx, fmt.Sprintf("entry %d: prev_hash mismatch (chain broken)", idx), prevNoted || noted)
		}

		prevHash = rawChainedHash(line)
		chained++
		idx++
		prevNoted = noted
	}
	if rr.err != nil {
		return fileScan{
			result: ChainVerifyResult{
				State:         ChainStateUnreadable,
				Entries:       idx,
				LegacyEntries: legacy,
				BrokenAt:      -1,
				Message:       fmt.Sprintf("read error after entry %d: %v", idx, rr.err),
			},
			continuedFrom:   continuedFrom,
			firstChainedIdx: firstChainedIdx,
		}
	}

	scan := fileScan{continuedFrom: continuedFrom, firstChainedIdx: firstChainedIdx, head: prevHash}
	switch {
	case idx == 0:
		scan.result = ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "empty log"}
	case chained == 0:
		scan.result = ChainVerifyResult{
			State:         ChainStateUnprotected,
			Entries:       idx,
			LegacyEntries: legacy,
			BrokenAt:      -1,
			Message:       "no chain fields written",
		}
	case legacy > 0:
		scan.result = ChainVerifyResult{
			State:         ChainStatePartial,
			Entries:       idx,
			LegacyEntries: legacy,
			BrokenAt:      -1,
			Message:       fmt.Sprintf("%d of %d entries predate the chain", legacy, idx),
		}
	default:
		scan.result = ChainVerifyResult{
			State:    ChainStateVerified,
			Entries:  idx,
			BrokenAt: -1,
			Message:  "chain verified",
		}
	}
	return scan
}

// ChainHead returns the hash that the next entry appended to path must carry as
// its prev_hash. It reads only the tail of the file.
//
// Returns "" when the log is absent, empty, ends in an unchained (pre-upgrade)
// entry, or ends in a partially written record — in all of those cases the next
// entry starts a fresh chain rather than claiming a link it cannot prove.
func ChainHead(path string) string {
	line, ok := lastRecord(path)
	return chainHeadOf(line, ok)
}

// chainHeadFile is ChainHead for an already-open descriptor: the head of
// the inode f names, whatever name (or none) it has in the directory right
// now. A writer that derives its prev_hash from the path while its bytes go
// to the held descriptor links to the wrong file whenever a sibling's
// rotation has the two naming different inodes (#4057 Codex pass 2); the
// writer's own descriptor is the one source that cannot disagree with its
// append. readable is false when the descriptor itself cannot be read
// (opened write-only, see openLog); the head is then unknown, not "".
func chainHeadFile(f *os.File) (head string, readable bool) {
	line, ok, err := lastRecordFile(f)
	if err != nil {
		return "", false
	}
	return chainHeadOf(line, ok), true
}

func chainHeadOf(line []byte, ok bool) string {
	if !ok {
		return ""
	}
	line = recordBytes(line)
	var entry ChainedEvent
	if err := json.Unmarshal(line, &entry); err != nil {
		return ""
	}
	if entry.EntryHash == "" {
		return ""
	}
	return rawChainedHash(line)
}

// lastRecord returns the last non-blank line of path — the record the
// verifier will treat as the file's last — with its line terminator removed.
// Blank lines (see blankRecord) and an unterminated whitespace-only fragment
// are skipped exactly as the verifier skips them; an unterminated partial
// record is returned as-is and fails ChainHead's parse, which is the "start a
// fresh chain" outcome for a torn write.
//
// It reads the tail in a window that doubles until the window holds the
// whole last record, so the cost is O(size of that record), never O(file).
// There is no upper bound: capping at 1 MB made a legitimate larger final
// record read as "no head", and the writer then opened a fresh chain at
// genesis mid-file, which is exactly the shape the verifier calls a break
// (#4133 Opus pass 1, B04). The writer and the verifier must agree on the
// head, so both read without a line cap. The earlier "read the whole file as
// the last window" fallback was O(file) — 102 MB read and allocated for one
// 2 MB record — and a file that large is not hypothetical: the degraded
// mode (#4057) suspends rotation (#4133 Opus pass 2).
//
// Only a regular file has a head. The open never blocks (openTail) and the
// kind is taken from the open descriptor: a FIFO at <path>.1 made a writer
// with an empty live file hang in resyncHead before it had printed its
// decision (#4057 Codex pass 6), the harness timed out, and the hook's
// verdict was never delivered — the outcome #4052 exists to prevent. A
// non-regular file reads as "no head": the next entry is a genesis line.
func lastRecord(path string) ([]byte, bool) {
	f, err := openTail(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	line, ok, _ := lastRecordAt(f, info.Size())
	return line, ok
}

// lastRecordFile returns the last complete newline-terminated record of the
// open file f, read with pread so the descriptor's own offset (the append
// position of a writer's handle) is left alone. err is set only when the
// descriptor could not be stat'ed or read; an empty or truncated file is
// (nil, false, nil).
func lastRecordFile(f *os.File) (line []byte, ok bool, err error) {
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	return lastRecordAt(f, info.Size())
}

// lastRecordAt is lastRecord over any random-access source of the given
// size; lastRecord hands it the open file. The seam exists so a test can
// count the bytes and the reads: "whole file as the second window" and a
// window that grows linearly both return the right record and both cost
// O(file) (#4133 Opus pass 3 survivors N12, N2).
func lastRecordAt(r io.ReaderAt, size int64) ([]byte, bool, error) {
	if size == 0 {
		return nil, false, nil
	}
	for window := int64(tailReadBytes); ; window *= 2 {
		if window > size {
			window = size
		}
		buf := make([]byte, window)
		if _, err := r.ReadAt(buf, size-window); err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		if line, ok := lastRecordIn(buf, window == size); ok {
			return line, true, nil
		}
		if window == size {
			return nil, false, nil
		}
	}
}

// lastRecordIn finds the last non-blank line in buf, the tail of a file.
// wholeFile says buf starts at offset 0; otherwise a line that runs off the
// front of buf may be incomplete and the caller must widen the window. The
// second result is false when no complete non-blank line is in buf.
func lastRecordIn(buf []byte, wholeFile bool) ([]byte, bool) {
	end := len(buf)
	for {
		start := bytes.LastIndexByte(buf[:end], '\n') + 1
		if start == 0 && !wholeFile {
			return nil, false
		}
		if line := buf[start:end]; !blankRecord(line) {
			return recordBytes(line), true
		}
		if start == 0 {
			return nil, false
		}
		end = start - 1
	}
}
