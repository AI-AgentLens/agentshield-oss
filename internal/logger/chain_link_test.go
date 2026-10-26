package logger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The link LogLinked returns is what the hook sends to /api/audit as
// local_chain (#4208): the SaaS decides "a local line never arrived" from
// it, so it has to be the line on disk, byte for byte, and nothing else.
// These tests compare every link against the file, never against another
// computation in this package.

// diskLines returns the records of path exactly as written: each line's
// bytes without its "\n", which is what VerifyChain and ChainHead hash.
func diskLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out [][]byte
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) > 0 {
			out = append(out, line)
		}
	}
	return out
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// diskPrevHash is the prev_hash field of one record as it sits on disk.
func diskPrevHash(t *testing.T, line []byte) string {
	t.Helper()
	var rec struct {
		PrevHash string `json:"prev_hash"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("decode record %s: %v", line, err)
	}
	return rec.PrevHash
}

func mustLogLinked(t *testing.T, lg *AuditLogger, ev AuditEvent) *ChainLink {
	t.Helper()
	link, err := lg.LogLinked(ev)
	if err != nil {
		t.Fatalf("LogLinked(%q): %v", ev.Command, err)
	}
	if link == nil {
		t.Fatalf("LogLinked(%q) wrote the line and returned no link", ev.Command)
	}
	return link
}

// TestLogLinked_LinksAreTheLinesOnDisk is the contract: two events through
// a real logger, and each link equals what the file holds. The second
// event carries a secret, so its line is the redacted one; a link computed
// from the event as handed in would not match the disk.
func TestLogLinked_LinksAreTheLinesOnDisk(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lg, err := New(logPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = lg.Close() }()

	cmd, secret := backendSecretCommand()
	link1 := mustLogLinked(t, lg, windowEvent("echo first"))
	link2 := mustLogLinked(t, lg, AuditEvent{Timestamp: "2026-10-21T00:00:00Z", Command: cmd, Decision: "AUDIT", Mode: "enforce"})

	lines := diskLines(t, logPath)
	if len(lines) != 2 {
		t.Fatalf("log holds %d lines, want 2", len(lines))
	}
	if strings.Contains(string(lines[1]), secret) {
		t.Fatalf("control: line 2 carries the secret, so it does not show the link covers the redacted bytes: %s", lines[1])
	}

	if link1.PrevHash != "" {
		t.Errorf("first line's link prev_hash = %q, want \"\" (genesis)", link1.PrevHash)
	}
	if want := sha256Hex(lines[0]); link1.LineHash != want {
		t.Errorf("link1.line_hash = %s, want SHA-256 of line 1 as written %s", link1.LineHash, want)
	}
	if link2.PrevHash != link1.LineHash {
		t.Errorf("link2.prev_hash = %s, want link1.line_hash %s: the receiver could not join them", link2.PrevHash, link1.LineHash)
	}
	if got := diskPrevHash(t, lines[1]); link2.PrevHash != got {
		t.Errorf("link2.prev_hash = %s, but line 2 on disk says %s", link2.PrevHash, got)
	}
	if want := sha256Hex(lines[1]); link2.LineHash != want {
		t.Errorf("link2.line_hash = %s, want SHA-256 of line 2 as written %s", link2.LineHash, want)
	}
	// The head the next writer continues from is the same value, read back
	// from the file: the link is a real link in the verified chain.
	if head := ChainHead(logPath); head != link2.LineHash {
		t.Errorf("ChainHead = %s, want link2.line_hash %s", head, link2.LineHash)
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Errorf("VerifyChain = %s: %s", r.State, r.Message)
	}
}

// TestLogLinked_NewProcessContinuesTheLink: every hook call is a fresh
// process with a fresh logger. Its first link must name the previous
// process's last line, or every event would look like a chain restart.
func TestLogLinked_NewProcessContinuesTheLink(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	first, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	link1 := mustLogLinked(t, first, windowEvent("process one"))
	_ = first.Close()

	second, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	link2 := mustLogLinked(t, second, windowEvent("process two"))

	if link2.PrevHash == "" || link2.PrevHash != link1.LineHash {
		t.Errorf("second process's prev_hash = %q, want the first process's line_hash %q", link2.PrevHash, link1.LineHash)
	}
	if lines := diskLines(t, logPath); len(lines) != 2 || link2.LineHash != sha256Hex(lines[1]) {
		t.Errorf("second process's line_hash does not match its line on disk")
	}
}

// TestLogLinked_RotationLinksToPredecessorHead: the first line of a fresh
// file carries .1's head as its prev_hash (#4057), so its link names the
// last line of .1. The receiver sees one unbroken chain across rotation.
func TestLogLinked_RotationLinksToPredecessorHead(t *testing.T) {
	smallRotation(t, 600)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lg, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lg.Close() }()

	var last *ChainLink
	for i := 0; i < 50; i++ {
		if st, err := os.Stat(logPath); err == nil && st.Size() >= maxLogBytes {
			break
		}
		last = mustLogLinked(t, lg, windowEvent("fill"))
	}
	rotating := mustLogLinked(t, lg, windowEvent("first line after rotation"))

	rotated := diskLines(t, logPath+rotatedSuffix)
	live := diskLines(t, logPath)
	if len(live) != 1 {
		t.Fatalf("control: live file holds %d lines after the rotating write, want 1 (no rotation happened)", len(live))
	}
	predecessorHead := sha256Hex(rotated[len(rotated)-1])
	if last == nil || last.LineHash != predecessorHead {
		t.Fatalf("control: the last pre-rotation link does not name .1's last line")
	}
	if rotating.PrevHash != predecessorHead {
		t.Errorf("first post-rotation prev_hash = %q, want .1's last line hash %q", rotating.PrevHash, predecessorHead)
	}
	if got := diskPrevHash(t, live[0]); rotating.PrevHash != got {
		t.Errorf("link prev_hash = %s, but the live file's first line says %s", rotating.PrevHash, got)
	}
	if rotating.LineHash != sha256Hex(live[0]) {
		t.Errorf("first post-rotation line_hash does not match its line on disk")
	}
}

// TestLogLinked_AfterUnchainedLineIsAGenesisLink: the MCP proxies append
// unchained lines to the same log (#4044). The next chained line opens a
// fresh chain, and its link says so with prev_hash "": the SaaS reads that
// as a restart, the weaker signal, never as a break.
func TestLogLinked_AfterUnchainedLineIsAGenesisLink(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lg, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lg.Close() }()
	mustLogLinked(t, lg, windowEvent("chained before"))

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"timestamp":"2026-10-21T00:00:00Z","tool_name":"read_file","decision":"ALLOW"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	link := mustLogLinked(t, lg, windowEvent("chained after"))
	if link.PrevHash != "" {
		t.Errorf("prev_hash after an unchained line = %q, want \"\" (the writer opens a genesis line)", link.PrevHash)
	}
	lines := diskLines(t, logPath)
	if link.LineHash != sha256Hex(lines[len(lines)-1]) {
		t.Errorf("line_hash does not match the line on disk")
	}
}

// TestLogLinked_FailedWriteReturnsNoLink: a link claims the line is in the
// log. When the write fails there is no line, so there is no link; the
// hook then sends no local_chain ("not chain-reported") rather than a
// fabricated one the SaaS would read as a break.
func TestLogLinked_FailedWriteReturnsNoLink(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	lg, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	mustLogLinked(t, lg, windowEvent("written"))
	_ = lg.Close()

	var link *ChainLink
	silenceStderr(t, func() { link, err = lg.LogLinked(windowEvent("not written")) })
	if err == nil {
		t.Fatal("control: LogLinked on a closed logger succeeded; the write did not fail")
	}
	if link != nil {
		t.Errorf("failed write returned link %+v, want nil", *link)
	}
	if n := len(diskLines(t, logPath)); n != 1 {
		t.Fatalf("control: log holds %d lines, want 1", n)
	}
}

// TestLog_StillAppendsTheSameLine: Log is LogLinked with the link dropped,
// so the Logger interface and every caller that does not send the event
// (the MCP path through the watchdog, shield-server) write what they wrote.
func TestLog_StillAppendsTheSameLine(t *testing.T) {
	dir := t.TempDir()
	viaLog, viaLinked := filepath.Join(dir, "log.jsonl"), filepath.Join(dir, "linked.jsonl")
	a, err := New(viaLog)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(viaLinked)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"one", "two"} {
		if err := a.Log(windowEvent(cmd)); err != nil {
			t.Fatal(err)
		}
		mustLogLinked(t, b, windowEvent(cmd))
	}
	_ = a.Close()
	_ = b.Close()
	got, _ := os.ReadFile(viaLog)
	want, _ := os.ReadFile(viaLinked)
	if len(got) == 0 || !bytes.Equal(got, want) {
		t.Errorf("Log and LogLinked wrote different files:\nLog       %s\nLogLinked %s", got, want)
	}
}

// silenceStderr runs fn with the logger's expected warnings sent to
// os.DevNull (the unix-only captureStderr pipe is not needed here).
func silenceStderr(t *testing.T, fn func()) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		fn()
		return
	}
	old := os.Stderr
	os.Stderr = devnull
	defer func() {
		os.Stderr = old
		_ = devnull.Close()
	}()
	fn()
}
