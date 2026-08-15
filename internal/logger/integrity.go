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

// Tail-read window sizes. The chain head is recovered by reading the end of the
// log rather than the whole file, so the cost does not grow with log size —
// this runs on every agentshield process start.
const (
	tailReadBytes    = 64 * 1024
	maxTailReadBytes = 1024 * 1024
)

// ChainedEvent extends AuditEvent with hash chain fields for tamper detection.
//
// Forward-compatibility contract: verification re-marshals the parsed struct and
// compares the digest, so the JSON round trip must be lossless. Any field added
// to AuditEvent later MUST carry `omitempty` — otherwise entries written by an
// older build re-marshal with the new key present and every historical entry
// starts reporting "entry hash mismatch".
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
	// 0-based index of the first bad entry.
	BrokenAt int
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
//     that is an edit or a downgraded writer.
//   - A first entry whose prev_hash points at an entry this file does not
//     contain (the log was rotated). Cross-checked against <path>.1 when that
//     predecessor is still on disk.
func VerifyChain(path string) ChainVerifyResult {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "no audit log yet"}
		}
		return ChainVerifyResult{State: ChainStateUnreadable, BrokenAt: -1, Message: fmt.Sprintf("cannot open file: %v", err)}
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, maxTailReadBytes), maxTailReadBytes)

	var (
		prevHash        string
		idx             int
		legacy          int
		chained         int
		continuedFrom   string
		firstChainedIdx int
	)

	broken := func(at int, msg string) ChainVerifyResult {
		return ChainVerifyResult{
			State:         ChainStateBroken,
			Entries:       idx,
			LegacyEntries: legacy,
			BrokenAt:      at,
			Message:       msg,
		}
	}

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var entry ChainedEvent
		if err := json.Unmarshal(line, &entry); err != nil {
			return broken(idx, fmt.Sprintf("entry %d: invalid JSON: %v", idx, err))
		}

		if entry.EntryHash == "" {
			if chained > 0 {
				return broken(idx, fmt.Sprintf("entry %d: unchained entry after a chained entry", idx))
			}
			legacy++
			idx++
			continue
		}

		if chained == 0 && entry.PrevHash != "" {
			// Chain continues from a rotated predecessor: adopt the claimed
			// head here and cross-check it against <path>.1 after the loop.
			continuedFrom = entry.PrevHash
			prevHash = entry.PrevHash
			firstChainedIdx = idx
		}

		if got := ComputeEntryHash(entry); entry.EntryHash != got {
			return broken(idx, fmt.Sprintf("entry %d: entry hash mismatch", idx))
		}
		if entry.PrevHash != prevHash {
			return broken(idx, fmt.Sprintf("entry %d: prev_hash mismatch (chain broken)", idx))
		}

		prevHash = ComputeChainedHash(entry)
		chained++
		idx++
	}
	if err := scanner.Err(); err != nil {
		return ChainVerifyResult{
			State:         ChainStateUnreadable,
			Entries:       idx,
			LegacyEntries: legacy,
			BrokenAt:      -1,
			Message:       fmt.Sprintf("read error after entry %d: %v", idx, err),
		}
	}

	note := ""
	if continuedFrom != "" {
		rotated := path + rotatedSuffix
		switch head := ChainHead(rotated); {
		case head == "":
			note = "continues a rotated log (predecessor unavailable)"
		case head != continuedFrom:
			return ChainVerifyResult{
				State:         ChainStateBroken,
				Entries:       idx,
				LegacyEntries: legacy,
				BrokenAt:      firstChainedIdx,
				Message: fmt.Sprintf("entry %d: prev_hash does not match the head of %s",
					firstChainedIdx, filepath.Base(rotated)),
			}
		default:
			note = fmt.Sprintf("linked to %s", filepath.Base(rotated))
		}
	}

	switch {
	case idx == 0:
		return ChainVerifyResult{State: ChainStateEmpty, BrokenAt: -1, Message: "empty log"}
	case chained == 0:
		return ChainVerifyResult{
			State:         ChainStateUnprotected,
			Entries:       idx,
			LegacyEntries: legacy,
			BrokenAt:      -1,
			Message:       "no chain fields written",
		}
	case legacy > 0:
		return ChainVerifyResult{
			State:         ChainStatePartial,
			Entries:       idx,
			LegacyEntries: legacy,
			BrokenAt:      -1,
			Message:       fmt.Sprintf("%d of %d entries predate the chain", legacy, idx),
			Note:          note,
		}
	default:
		return ChainVerifyResult{
			State:    ChainStateVerified,
			Entries:  idx,
			BrokenAt: -1,
			Message:  "chain verified",
			Note:     note,
		}
	}
}

// ChainHead returns the hash that the next entry appended to path must carry as
// its prev_hash. It reads only the tail of the file.
//
// Returns "" when the log is absent, empty, ends in an unchained (pre-upgrade)
// entry, or ends in a partially written record — in all of those cases the next
// entry starts a fresh chain rather than claiming a link it cannot prove.
func ChainHead(path string) string {
	line, ok := lastRecord(path)
	if !ok {
		return ""
	}
	var entry ChainedEvent
	if err := json.Unmarshal(line, &entry); err != nil {
		return ""
	}
	if entry.EntryHash == "" {
		return ""
	}
	return ComputeChainedHash(entry)
}

// lastRecord returns the last complete newline-terminated record in path.
func lastRecord(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return nil, false
	}
	size := info.Size()

	// Start with a small window; escalate only if the final record is larger
	// than it (an MCP call with a big argument payload).
	for _, window := range []int64{tailReadBytes, maxTailReadBytes} {
		if window > size {
			window = size
		}
		buf := make([]byte, window)
		if _, err := f.ReadAt(buf, size-window); err != nil && !errors.Is(err, io.EOF) {
			return nil, false
		}
		trimmed := bytes.TrimRight(buf, "\n")
		if len(trimmed) == 0 {
			return nil, false
		}
		if idx := bytes.LastIndexByte(trimmed, '\n'); idx >= 0 {
			return trimmed[idx+1:], true
		}
		if window == size {
			// The whole file is a single record.
			return trimmed, true
		}
	}
	return nil, false
}
