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

// These tests drive the PRODUCTION VerifyChain / ChainHead / AuditLogger on
// logs the current binary did not write. The Opus review of #4026 found that
// reverting all three call sites to the old struct round trip left the
// logger suite green: the version-skew tests only ever verified fields the
// current AuditEvent already declares.

// futureAuditEvent is what a NEWER binary would write: today's fields plus
// one this binary does not know.
type futureAuditEvent struct {
	AuditEvent
	ZZFuture string `json:"zz_future"`
}

type futureChainedEvent struct {
	futureAuditEvent
	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// writeFutureLog writes a chain the way a newer writer would: entry_hash over
// its own event, prev_hash over the previous full line. future[i] marks which
// entries carry the unknown field.
func writeFutureLog(t *testing.T, path string, future []bool) {
	t.Helper()
	var out bytes.Buffer
	prev := ""
	for i, f := range future {
		ev := futureAuditEvent{AuditEvent: AuditEvent{
			Timestamp: "2026-09-26T00:00:0" + string(rune('0'+i)) + "Z",
			Command:   "echo " + string(rune('a'+i)),
			Decision:  "ALLOW",
			Mode:      "enforce",
		}}
		var entry []byte
		var err error
		if f {
			ev.ZZFuture = "set-by-a-newer-binary"
			entry, err = json.Marshal(ev)
		} else {
			entry, err = json.Marshal(ev.AuditEvent)
		}
		if err != nil {
			t.Fatal(err)
		}
		var line []byte
		if f {
			line, err = json.Marshal(futureChainedEvent{futureAuditEvent: ev, PrevHash: prev, EntryHash: sha(entry)})
		} else {
			line, err = json.Marshal(ChainedEvent{AuditEvent: ev.AuditEvent, PrevHash: prev, EntryHash: sha(entry)})
		}
		if err != nil {
			t.Fatal(err)
		}
		out.Write(line)
		out.WriteByte('\n')
		prev = sha(line)
	}
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func appendWithLogger(t *testing.T, path string) {
	t.Helper()
	lg, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Log(AuditEvent{Timestamp: "2026-09-26T00:01:00Z", Command: "echo appended", Decision: "ALLOW", Mode: "enforce"}); err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()
}

// An entry carrying a field this binary does not declare must verify, both
// mid-chain (the entry check and the link out of it) and as the last entry
// (ChainHead, which the next writer resyncs from). #4008.
func TestVerifyChain_ProductionPath_UnknownTopLevelField(t *testing.T) {
	for name, future := range map[string][]bool{
		"mid-chain":  {false, true, false},
		"last entry": {false, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			writeFutureLog(t, path, future)
			if r := VerifyChain(path); r.State != ChainStateVerified {
				t.Fatalf("before append: got %q: %s", r.State, r.Message)
			}
			appendWithLogger(t, path)
			r := VerifyChain(path)
			if r.State != ChainStateVerified {
				t.Errorf("after a real append: got %q: %s", r.State, r.Message)
			}
			if r.Entries != len(future)+1 {
				t.Errorf("entries = %d, want %d", r.Entries, len(future)+1)
			}
		})
	}
}

// Keys named prev_hash / entry_hash NESTED inside MCP arguments are content,
// not chain fields: they must be hashed, and editing them is a tamper. A naive
// text-search stripper removes them and breaks this.
func TestVerifyChain_NestedChainKeysInMCPArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainedLog(t, path, []AuditEvent{
		{Timestamp: "2026-09-26T00:00:00Z", Command: "echo one", Decision: "ALLOW", Mode: "enforce"},
		{
			Timestamp: "2026-09-26T00:00:01Z", Decision: "BLOCK", Mode: "enforce",
			MCPArguments: map[string]interface{}{"prev_hash": "p", "entry_hash": "e", "path": "/tmp/x"},
		},
		{Timestamp: "2026-09-26T00:00:02Z", Command: "echo three", Decision: "ALLOW", Mode: "enforce"},
	})
	if r := VerifyChain(path); r.State != ChainStateVerified {
		t.Fatalf("untouched log with nested chain-named keys: got %q: %s", r.State, r.Message)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(`"entry_hash":"e"`), []byte(`"entry_hash":"E"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("test setup: nested key not found in the written log")
	}
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if r := VerifyChain(path); r.State != ChainStateBroken {
		t.Errorf("editing a nested chain-named key must be caught, got %q: %s", r.State, r.Message)
	}
}

// A log converted to CRLF, then appended to by a real writer, must verify:
// VerifyChain and ChainHead must normalize a line the same way.
func TestVerifyChain_CRLFLogThenAppendVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainedLog(t, path, []AuditEvent{
		{Timestamp: "2026-09-26T00:00:00Z", Command: "echo one", Decision: "ALLOW", Mode: "enforce"},
		{Timestamp: "2026-09-26T00:00:01Z", Command: "echo two", Decision: "ALLOW", Mode: "enforce"},
	})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n")), 0600); err != nil {
		t.Fatal(err)
	}
	appendWithLogger(t, path)
	if r := VerifyChain(path); r.State != ChainStateVerified {
		t.Errorf("CRLF log after a real append: got %q: %s", r.State, r.Message)
	}
}

// Trailing Unicode whitespace is not a line terminator. Unicode TrimSpace used
// to hide it from the hash while `agentshield log` rejected the same line, so
// an entry could vanish from the log view with the chain still "verified".
func TestVerifyChain_TrailingUnicodeSpaceIsTamper(t *testing.T) {
	for _, suffix := range []string{" ", "\u0085", " "} {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainedLog(t, path, []AuditEvent{
			{Timestamp: "2026-09-26T00:00:00Z", Command: "echo one", Decision: "BLOCK", Mode: "enforce"},
			{Timestamp: "2026-09-26T00:00:01Z", Command: "echo two", Decision: "ALLOW", Mode: "enforce"},
		})
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		first := bytes.IndexByte(data, '\n')
		tampered := append(append(append([]byte{}, data[:first]...), suffix...), data[first:]...)
		if err := os.WriteFile(path, tampered, 0600); err != nil {
			t.Fatal(err)
		}
		if r := VerifyChain(path); r.State != ChainStateBroken {
			t.Errorf("suffix %q on entry 0: got %q, want %q", suffix, r.State, ChainStateBroken)
		}
	}
}
