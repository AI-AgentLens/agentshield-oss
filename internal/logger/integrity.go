package logger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// ChainedEvent extends AuditEvent with hash chain fields for tamper detection.
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

// ChainVerifyResult holds the result of an audit chain verification.
type ChainVerifyResult struct {
	Valid    bool
	Entries int
	BrokenAt int // -1 if valid, otherwise the 0-based index of the first broken entry
	Message  string
}

// VerifyChain reads an audit.jsonl file and verifies the hash chain integrity.
func VerifyChain(path string) ChainVerifyResult {
	f, err := os.Open(path)
	if err != nil {
		return ChainVerifyResult{Valid: false, BrokenAt: -1, Message: fmt.Sprintf("cannot open file: %v", err)}
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer

	var prevHash string
	idx := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry ChainedEvent
		if err := json.Unmarshal(line, &entry); err != nil {
			return ChainVerifyResult{
				Valid:    false,
				Entries:  idx,
				BrokenAt: idx,
				Message:  fmt.Sprintf("entry %d: invalid JSON: %v", idx, err),
			}
		}

		// If this file has no chain fields, it's a legacy log — treat as valid
		if entry.EntryHash == "" && entry.PrevHash == "" && idx == 0 {
			// Count remaining entries
			count := 1
			for scanner.Scan() {
				if len(scanner.Bytes()) > 0 {
					count++
				}
			}
			return ChainVerifyResult{Valid: true, Entries: count, BrokenAt: -1, Message: "legacy log (no chain)"}
		}

		// Verify entry hash
		expectedEntryHash := ComputeEntryHash(entry)
		if entry.EntryHash != expectedEntryHash {
			return ChainVerifyResult{
				Valid:    false,
				Entries:  idx,
				BrokenAt: idx,
				Message:  fmt.Sprintf("entry %d: entry hash mismatch", idx),
			}
		}

		// Verify previous hash link
		if entry.PrevHash != prevHash {
			return ChainVerifyResult{
				Valid:    false,
				Entries:  idx,
				BrokenAt: idx,
				Message:  fmt.Sprintf("entry %d: prev_hash mismatch (chain broken)", idx),
			}
		}

		prevHash = ComputeChainedHash(entry)
		idx++
	}

	if idx == 0 {
		return ChainVerifyResult{Valid: true, Entries: 0, BrokenAt: -1, Message: "empty log"}
	}

	return ChainVerifyResult{Valid: true, Entries: idx, BrokenAt: -1, Message: "chain verified"}
}
