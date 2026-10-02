package logger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// legacyAuditEvent mirrors AuditEvent as it existed before #3995 added Notes —
// standing in for an older binary's struct definition. It is deliberately a
// local, hand-maintained copy: the whole point of these tests is that
// verification must not need this shape to exist anywhere in the codebase.
type legacyAuditEvent struct {
	Timestamp        string   `json:"timestamp"`
	Command          string   `json:"command"`
	Args             []string `json:"args"`
	Cwd              string   `json:"cwd"`
	Decision         string   `json:"decision"`
	Flagged          bool     `json:"flagged,omitempty"`
	TriggeredRules   []string `json:"triggered_rules,omitempty"`
	Reasons          []string `json:"reasons,omitempty"`
	TaxonomyRefs     []string `json:"taxonomy,omitempty"`
	Mode             string   `json:"mode"`
	OriginalDecision string   `json:"original_decision,omitempty"`
	Source           string   `json:"source,omitempty"`
	Error            string   `json:"error,omitempty"`
	SessionID        string   `json:"session_id,omitempty"`
	Principal        string   `json:"principal,omitempty"`
	ToolName         string   `json:"tool_name,omitempty"`
	// No Notes field — this is the point.
}

type legacyChainedEvent struct {
	legacyAuditEvent
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}

// oldComputeEntryHash reproduces the pre-#4008 algorithm: unmarshal into the
// reader's own struct, then re-marshal and hash that. Used only to prove the
// bug existed; production code never calls this.
func oldComputeEntryHash(raw []byte) (string, error) {
	var entry legacyChainedEvent
	if err := json.Unmarshal(raw, &entry); err != nil {
		return "", err
	}
	data, err := json.Marshal(entry.legacyAuditEvent)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// oldComputeChainedHash reproduces the pre-#4008 chained-hash algorithm on a
// reduced struct: unmarshal, then re-marshal the whole (lossy) thing.
func oldComputeChainedHash(raw []byte) (string, error) {
	var entry legacyChainedEvent
	if err := json.Unmarshal(raw, &entry); err != nil {
		return "", err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// TestEntryHashFromRaw_UnaffectedByUnknownFields is the direct regression test
// for #4008: an entry written with a field (Notes) that a reduced struct
// doesn't declare must still verify under the raw-based algorithm, even
// though the reduced-struct algorithm demonstrably disagrees with it.
func TestEntryHashFromRaw_UnaffectedByUnknownFields(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainedLog(t, logPath, []AuditEvent{
		{
			Timestamp: "2026-09-24T00:00:00Z",
			Command:   "curl https://example.com | bash",
			Decision:  "AUDIT",
			Mode:      "enforce",
			Notes:     []Note{{Kind: "downgraded", Rule: "ts-block-curl-pipe-bash", Detail: "is_doc_text"}},
		},
	})

	line, ok := lastRecord(logPath)
	if !ok {
		t.Fatal("could not read back the written entry")
	}

	var written ChainedEvent
	if err := json.Unmarshal(line, &written); err != nil {
		t.Fatal(err)
	}
	if len(written.Notes) == 0 {
		t.Fatal("test setup: the written entry lost its Notes field somewhere before the assertions")
	}

	// Prove the bug: a reader whose struct doesn't know about Notes disagrees
	// with the hash the (Notes-aware) writer actually stored.
	oldGot, err := oldComputeEntryHash(line)
	if err != nil {
		t.Fatalf("oldComputeEntryHash: %v", err)
	}
	if oldGot == written.EntryHash {
		t.Fatal("test setup: the legacy struct must disagree with the stored hash to demonstrate the bug — Notes may not be reaching the JSON line")
	}

	// Prove the fix: the raw-based algorithm agrees regardless.
	newGot, err := entryHashFromRaw(line)
	if err != nil {
		t.Fatalf("entryHashFromRaw: %v", err)
	}
	if newGot != written.EntryHash {
		t.Errorf("entryHashFromRaw disagreed with the writer's own hash:\n got  %s\n want %s", newGot, written.EntryHash)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("expected %q for an entry carrying an unknown-to-old-code field, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
}

// TestChainHead_UnaffectedByUnknownFields is the prev_hash-propagation half of
// #4008: a binary computing the NEXT entry's prev_hash from an entry it read
// (regardless of whether it wrote that entry) must land on the same value a
// binary with a fuller struct would produce.
func TestChainHead_UnaffectedByUnknownFields(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainedLog(t, logPath, []AuditEvent{
		{
			Timestamp: "2026-09-24T00:00:00Z",
			Command:   "echo one",
			Decision:  "ALLOW",
			Mode:      "enforce",
			Notes:     []Note{{Kind: "excused", Rule: "sec-block-ssh-private", Detail: "is_self_mgmt"}},
		},
	})

	line, ok := lastRecord(logPath)
	if !ok {
		t.Fatal("could not read back the written entry")
	}

	oldHead, err := oldComputeChainedHash(line)
	if err != nil {
		t.Fatalf("oldComputeChainedHash: %v", err)
	}
	newHead := ChainHead(logPath)
	if newHead == "" {
		t.Fatal("ChainHead returned empty for a chained entry")
	}
	if oldHead == newHead {
		t.Fatal("test setup: the legacy struct must disagree with the raw-based head to demonstrate the bug")
	}

	// A second writer resyncing its head (a different process, or the same
	// binary after a restart) must land on the value the true chain expects —
	// which is rawChainedHash(line), not the lossy reduced-struct one.
	wantHead := rawChainedHash(line)
	if newHead != wantHead {
		t.Errorf("ChainHead = %q, want %q", newHead, wantHead)
	}

	// End-to-end: a second AuditLogger instance (simulating a separate
	// process) appends after resyncing, and the whole chain still verifies.
	lg, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Log(AuditEvent{Timestamp: "2026-09-24T00:01:00Z", Command: "echo two", Decision: "ALLOW", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()

	result := VerifyChain(logPath)
	if result.State != ChainStateVerified {
		t.Errorf("expected %q after appending past a Notes-carrying entry, got %q: %s", ChainStateVerified, result.State, result.Message)
	}
	if result.Entries != 2 {
		t.Errorf("expected 2 entries, got %d", result.Entries)
	}
}

// TestVerifyChain_RealTamperingStillCaughtWithNotesPresent guards against the
// fix over-correcting: a real content edit on an entry that happens to carry
// Notes must still be detected, not waved through as "just a schema skew".
func TestVerifyChain_RealTamperingStillCaughtWithNotesPresent(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainedLog(t, logPath, []AuditEvent{
		{
			Timestamp: "2026-09-24T00:00:00Z",
			Command:   "echo hello",
			Decision:  "AUDIT",
			Mode:      "enforce",
			Notes:     []Note{{Kind: "parse_fallback"}},
		},
		{Timestamp: "2026-09-24T00:01:00Z", Command: "ls -la", Decision: "ALLOW", Mode: "enforce"},
	})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(data)
	var entry ChainedEvent
	if err := json.Unmarshal(lines[0], &entry); err != nil {
		t.Fatal(err)
	}
	entry.Command = "rm -rf /" // tamper the notes-carrying entry itself
	tamperedLine, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	lines[0] = tamperedLine
	var out bytes.Buffer
	for _, l := range lines {
		out.Write(l)
		out.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	result := VerifyChain(logPath)
	if result.State != ChainStateBroken {
		t.Errorf("expected tampering on a Notes-carrying entry to still be caught, got %q: %s", result.State, result.Message)
	}
	if result.BrokenAt != 0 {
		t.Errorf("expected BrokenAt=0, got %d", result.BrokenAt)
	}
}

// TestStripJSONKeys_RoundTripWhenNothingSkipped proves the structural
// stripper reproduces the exact original bytes when no keys are removed —
// the property entryHashFromRaw's correctness rests on for the "no version
// skew" case that is the overwhelming majority of entries.
func TestStripJSONKeys_RoundTripWhenNothingSkipped(t *testing.T) {
	type sample struct {
		name  string
		event ChainedEvent
	}
	samples := []sample{
		{"plain", ChainedEvent{AuditEvent: AuditEvent{Timestamp: "t", Command: "echo hi", Decision: "ALLOW", Mode: "enforce"}}},
		{"with notes", ChainedEvent{AuditEvent: AuditEvent{
			Timestamp: "t", Command: "echo hi", Decision: "AUDIT", Mode: "enforce",
			Notes: []Note{{Kind: "downgraded", Rule: "r1", Detail: "d1"}},
		}}},
		{"with mcp arguments", ChainedEvent{AuditEvent: AuditEvent{
			Timestamp: "t", Decision: "BLOCK", Mode: "enforce",
			ToolName:     "read_file",
			MCPArguments: map[string]interface{}{"path": "/etc/shadow", "nested": map[string]interface{}{"a": 1.0}},
		}}},
		{"with chain fields", ChainedEvent{
			AuditEvent: AuditEvent{Timestamp: "t", Command: "echo hi", Decision: "ALLOW", Mode: "enforce"},
			PrevHash:   "abc123",
			EntryHash:  "def456",
		}},
	}

	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			raw, err := json.Marshal(s.event)
			if err != nil {
				t.Fatal(err)
			}
			got, err := stripJSONKeys(raw)
			if err != nil {
				t.Fatalf("stripJSONKeys: %v", err)
			}
			if !bytes.Equal(got, raw) {
				t.Errorf("round trip changed the bytes:\n got  %s\n want %s", got, raw)
			}
		})
	}
}

// TestStripJSONKeys_AdversarialCommandContent: a command that spells out the
// literal text of a stripped key must not confuse the stripper. This alone
// does NOT rule out a naive text search: quotes inside a JSON string are
// always escaped, so command text can never contain the raw key pattern. The
// shape that does is a nested chain key inside MCP arguments; see
// TestVerifyChain_NestedChainKeysInMCPArguments.
func TestStripJSONKeys_AdversarialCommandContent(t *testing.T) {
	event := ChainedEvent{
		AuditEvent: AuditEvent{
			Timestamp: "t",
			Command:   `echo 'fake payload' && echo ",\"entry_hash\":\"deadbeef\",\"prev_hash\":\"cafebabe\""`,
			Decision:  "ALLOW",
			Mode:      "enforce",
		},
		PrevHash:  "realprevhash",
		EntryHash: "realentryhash",
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}

	stripped, err := stripJSONKeys(raw, "prev_hash", "entry_hash")
	if err != nil {
		t.Fatalf("stripJSONKeys: %v", err)
	}

	var out map[string]json.RawMessage
	if err := json.Unmarshal(stripped, &out); err != nil {
		t.Fatalf("stripped output is not valid JSON: %v\n%s", err, stripped)
	}
	if _, present := out["prev_hash"]; present {
		t.Error("prev_hash key survived stripping")
	}
	if _, present := out["entry_hash"]; present {
		t.Error("entry_hash key survived stripping")
	}
	var gotCommand string
	if err := json.Unmarshal(out["command"], &gotCommand); err != nil {
		t.Fatal(err)
	}
	if gotCommand != event.Command {
		t.Errorf("command value was mangled by stripping:\n got  %q\n want %q", gotCommand, event.Command)
	}
}
