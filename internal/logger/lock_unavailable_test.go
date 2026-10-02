package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unopenableLockFixture builds a <log>.lock that New cannot open. Each
// fixture also reports whether it depends on permission bits, which root
// ignores: the directory shape runs everywhere, so a root CI runner still
// exercises the fallback instead of skipping every case (Codex pass 1 on
// #4057, finding 2).
type unopenableLockFixture struct {
	name      string
	needsMode bool
	setup     func(t *testing.T, dir, logPath string)
}

var unopenableLockFixtures = []unopenableLockFixture{
	{
		// Root-independent: a directory where the lock file should be.
		// OpenFile(O_CREATE|O_RDWR) on a directory fails with EISDIR for
		// every user, root included.
		name: "lock path is a directory",
		setup: func(t *testing.T, dir, logPath string) {
			if err := os.Mkdir(logPath+lockSuffix, 0755); err != nil {
				t.Fatal(err)
			}
		},
	},
	{
		// Created by root or another user: exists, but not openable by us.
		name:      "lock file not openable",
		needsMode: true,
		setup: func(t *testing.T, dir, logPath string) {
			if err := os.WriteFile(logPath+lockSuffix, nil, 0000); err != nil {
				t.Fatal(err)
			}
		},
	},
	{
		// Admin-managed log path: log file writable, directory read-only,
		// so the lock file cannot be created. Logging worked before #4052.
		name:      "log dir read-only, log file writable",
		needsMode: true,
		setup: func(t *testing.T, dir, logPath string) {
			if err := os.WriteFile(logPath, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
		},
	},
}

// newDegradedLogger builds the fixture and opens a logger over it, asserting
// that the lock really was unopenable (the positive control: the same open
// New attempts fails for the test too) and that the logger recorded that.
// Without both assertions a filesystem that ignores modes would pass the
// test with a healthy, locking logger.
func newDegradedLogger(t *testing.T, fx unopenableLockFixture) (*AuditLogger, string) {
	t.Helper()
	if fx.needsMode && os.Geteuid() == 0 {
		t.Skip("root ignores file modes; the directory-at-lock fixture still runs")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	fx.setup(t, dir, logPath)

	if f, err := os.OpenFile(logPath+lockSuffix, os.O_CREATE|os.O_RDWR, 0600); err == nil {
		_ = f.Close()
		t.Fatalf("fixture %q did not make the lock file unopenable; the test would pass with normal locking", fx.name)
	}

	l, err := New(logPath)
	if err != nil {
		t.Fatalf("New must not fail on an unopenable lock file (the hook would skip evaluation): %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if l.lockFd != nil {
		t.Fatalf("lockFd = %v; want nil — New opened a lock the fixture was meant to deny", l.lockFd.Name())
	}
	if l.lockUnavailable == "" {
		t.Fatal("lockUnavailable is empty; the degraded state was not recorded, so no event would carry the note")
	}
	if strings.Contains(l.lockUnavailable, dir) {
		t.Errorf("lockUnavailable = %q carries the log path; want only the error class", l.lockUnavailable)
	}
	return l, logPath
}

// A lock file New cannot open must not fail New. The hook turns a logger that
// fails to open into "audit log init failed", which skips evaluation entirely,
// so after #4052 an unopenable <log>.lock made every BLOCK an unenforced AUDIT.
// The permission shapes reproduced that end to end against the #4052 binary.
func TestNewSurvivesUnopenableLockFile(t *testing.T) {
	for _, fx := range unopenableLockFixtures {
		t.Run(fx.name, func(t *testing.T) {
			l, logPath := newDegradedLogger(t, fx)

			if err := l.Log(AuditEvent{Command: "echo hi", Decision: "AUDIT"}); err != nil {
				t.Fatalf("Log without a lock must still append: %v", err)
			}
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 {
				t.Fatal("expected the entry to be appended")
			}
		})
	}
}

// readEvents parses every line of the log as a ChainedEvent.
func readEvents(t *testing.T, logPath string) []ChainedEvent {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []ChainedEvent
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev ChainedEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d is not an event: %v\n%s", i, err, line)
		}
		out = append(out, ev)
	}
	return out
}

func lockNote(ns []Note) *Note {
	for i := range ns {
		if ns[i].Kind == NoteAuditLockUnavailable {
			return &ns[i]
		}
	}
	return nil
}

// TestDegradedLogger_NeverRotatesAndNotesEveryEvent pins Gary's design for
// Codex pass 1 finding 1 on #4057: without the cross-process lock, rotation
// can delete the generation a sibling writer just rotated out, so a degraded
// logger appends past maxLogBytes rather than rotate, and every event it
// appends carries the audit_lock_unavailable note so a later prev_hash break
// beside it can be read as a possible lost lock race (the note records the
// state, it proves nothing, and VerifyChain still reports the break). The
// chain over a single degraded writer still verifies.
func TestDegradedLogger_NeverRotatesAndNotesEveryEvent(t *testing.T) {
	for _, fx := range unopenableLockFixtures {
		t.Run(fx.name, func(t *testing.T) {
			smallRotation(t, 600) // two or three entries; well past it by 10
			l, logPath := newDegradedLogger(t, fx)

			const n = 10
			logEvents(t, l, n, "degraded")

			if _, err := os.Stat(logPath + rotatedSuffix); err == nil {
				t.Fatalf("%s exists: a degraded logger rotated (lockless rotation can delete audit history)", logPath+rotatedSuffix)
			}
			info, err := os.Stat(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() <= maxLogBytes {
				t.Fatalf("log is %d bytes, under the %d-byte threshold; the test did not cross the rotation boundary", info.Size(), maxLogBytes)
			}

			events := readEvents(t, logPath)
			if len(events) != n {
				t.Fatalf("log holds %d events; want all %d (a rotation or truncation lost some)", len(events), n)
			}
			for i, ev := range events {
				note := lockNote(ev.Notes)
				if note == nil {
					t.Fatalf("event %d carries no %q note: %+v", i, NoteAuditLockUnavailable, ev.Notes)
				}
				if note.Detail == "" || !strings.Contains(note.Detail, "rotation suspended") {
					t.Errorf("event %d note Detail = %q; want the error class and that rotation was suspended", i, note.Detail)
				}
				if strings.Contains(note.Detail, filepath.Dir(logPath)) {
					t.Errorf("event %d note Detail = %q leaks the log path", i, note.Detail)
				}
			}

			if r := VerifyChain(logPath); r.State != ChainStateVerified || r.Entries != n {
				t.Fatalf("VerifyChain = %+v; want verified over %d entries from a single degraded writer", r, n)
			}
		})
	}
}

// TestDegradedLogger_NoteIsHashedIntoTheChain: the note has to be part of
// the bytes the entry hash covers, or an editor could strip it from a line
// without breaking verification and make a lost-lock break look like
// tampering — or the reverse.
func TestDegradedLogger_NoteIsHashedIntoTheChain(t *testing.T) {
	l, logPath := newDegradedLogger(t, unopenableLockFixtures[0])
	logEvents(t, l, 2, "hashed")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Replace(string(data), `"notes":[{"kind":"audit_lock_unavailable"`, `"notes":[{"kind":"audit_lock_removed"`, 1)
	if stripped == string(data) {
		t.Fatal("test setup: the note was not found in the raw line")
	}
	if err := os.WriteFile(logPath, []byte(stripped), 0600); err != nil {
		t.Fatal(err)
	}
	if r := VerifyChain(logPath); r.State != ChainStateBroken || r.BrokenAt != 0 {
		t.Fatalf("VerifyChain = %+v after editing the note; want broken at entry 0", r)
	}
}

// TestHealthyLogger_RotatesAndCarriesNoLockNote is the control: with the
// lock available, rotation is unchanged and no event carries the note — the
// line has no notes key at all, so it is byte-identical to before #4057.
func TestHealthyLogger_RotatesAndCarriesNoLockNote(t *testing.T) {
	smallRotation(t, 600)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.lockFd == nil || l.lockUnavailable != "" {
		t.Fatalf("healthy logger reports degraded: lockFd=%v lockUnavailable=%q", l.lockFd, l.lockUnavailable)
	}

	logEvents(t, l, 10, "healthy")

	if _, err := os.Stat(logPath + rotatedSuffix); err != nil {
		t.Fatalf("healthy logger did not rotate past the threshold: %v", err)
	}
	for _, p := range []string{logPath, logPath + rotatedSuffix} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"notes"`) {
			t.Fatalf("%s carries a notes key on a healthy write:\n%s", p, data)
		}
	}
	if r := VerifyChain(logPath); r.State != ChainStateVerified {
		t.Fatalf("VerifyChain = %+v; want verified across the rotation", r)
	}
}

// TestDegradedLogger_NoteDoesNotLeakIntoCallerEvent: Log takes the event by
// value but its Notes slice is shared; the note must not appear in the
// caller's copy through spare capacity, or a caller that reuses the event
// (the hook POSTs the same struct to the SaaS) would see a note it did not
// write, and a second Log of the same event would carry it twice.
func TestDegradedLogger_NoteDoesNotLeakIntoCallerEvent(t *testing.T) {
	l, logPath := newDegradedLogger(t, unopenableLockFixtures[0])
	notes := make([]Note, 1, 4)
	notes[0] = Note{Kind: "parse_fallback"}
	ev := AuditEvent{Command: "x", Decision: "AUDIT", Notes: notes}
	if err := l.Log(ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.Notes) != 1 || notes[:2][1].Kind != "" {
		t.Fatalf("caller's notes changed: %+v / spare=%+v", ev.Notes, notes[:2][1])
	}
	if err := l.Log(ev); err != nil {
		t.Fatal(err)
	}
	for i, got := range readEvents(t, logPath) {
		if len(got.Notes) != 2 || got.Notes[0].Kind != "parse_fallback" || got.Notes[1].Kind != NoteAuditLockUnavailable {
			t.Errorf("event %d notes = %+v; want the caller's note then exactly one lock note", i, got.Notes)
		}
	}
}

// TestLockUnavailableNote_NilReceiver (pass 3 mutation n10): the hook's
// noteLockUnavailable takes the logger through an interface, and a typed
// nil *AuditLogger inside that interface is not == nil there, so the call
// reaches this method on a nil receiver. It must report "not degraded"
// rather than dereference.
func TestLockUnavailableNote_NilReceiver(t *testing.T) {
	var l *AuditLogger
	note, degraded := l.LockUnavailableNote()
	if degraded || note != (Note{}) {
		t.Fatalf("nil receiver: got %+v degraded=%v; want an empty note and false", note, degraded)
	}
}
