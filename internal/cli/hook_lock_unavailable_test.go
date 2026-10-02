package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// These tests pin #4052 at the hook boundary: an audit-log lock file the hook
// cannot open must not become "audit log init failed", which skips
// evaluation entirely and turned every BLOCK into an unenforced AUDIT. The
// logger-level fallback is covered in internal/logger; this is the proof
// that a known-BLOCK command still BLOCKs through the real hook path, and
// that the persisted event says the logger ran without its lock (Codex
// pass 1 on #4057, finding 2). The directory fixture runs under root too.
type unopenableLockFixture struct {
	name      string
	needsMode bool
	make      func(t *testing.T, lockPath string)
}

var unopenableLockFixtures = []unopenableLockFixture{
	{"lock-path-is-a-directory", false, func(t *testing.T, lockPath string) {
		if err := os.Mkdir(lockPath, 0o755); err != nil {
			t.Fatalf("Mkdir lock: %v", err)
		}
	}},
	{"lock-file-mode-000", true, func(t *testing.T, lockPath string) {
		if err := os.WriteFile(lockPath, nil, 0o000); err != nil {
			t.Fatalf("WriteFile lock: %v", err)
		}
	}},
}

// newHomeWithUnopenableLock builds a non-managed HOME whose audit.jsonl.lock
// the fixture makes unopenable, and proves it (positive control): an open
// with the logger's own flags must fail, or the test is exercising a
// healthy, locking hook.
func newHomeWithUnopenableLock(t *testing.T, fx unopenableLockFixture) (home, configDir string) {
	t.Helper()
	if fx.needsMode && os.Geteuid() == 0 {
		t.Skip("root ignores file modes (the lock-path-is-a-directory fixture still runs)")
	}
	home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
	lockPath := filepath.Join(configDir, "audit.jsonl.lock")
	fx.make(t, lockPath)
	if f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		_ = f.Close()
		t.Fatalf("fixture %q left the lock openable; the hook would lock normally", fx.name)
	}
	return home, configDir
}

// TestHook_LockFileUnopenable_StillBlocks drives `rm -rf /` through
// evaluateCommand with the lock unopenable: the decision must be a real
// BLOCK from a rule, not a fail-safe sentinel and not the #4052 AUDIT.
func TestHook_LockFileUnopenable_StillBlocks(t *testing.T) {
	for _, fx := range unopenableLockFixtures {
		t.Run(fx.name, func(t *testing.T) {
			_, configDir := newHomeWithUnopenableLock(t, fx)
			posted := captureAuditPOSTs(t)

			result, event := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "sess-4052")

			if result.Decision != policy.DecisionBlock {
				t.Fatalf("Decision = %v; want BLOCK — an unopenable lock file skipped evaluation (#4052)", result.Decision)
			}
			if containsStr(result.TriggeredRules, failClosedRuleID) || containsStr(result.TriggeredRules, evalErrorRuleID) {
				t.Errorf("TriggeredRules = %v; want a real rule id, not a fail-safe boundary sentinel", result.TriggeredRules)
			}
			if event == nil || event.Decision != "BLOCK" {
				t.Fatalf("event = %+v; want a normal BLOCK audit event", event)
			}

			logged := lastLoggedEvent(t, configDir)
			if logged.Decision != "BLOCK" {
				t.Fatalf("persisted event decision = %q; want BLOCK", logged.Decision)
			}
			if !hasNoteKind(logged.Notes, logger.NoteAuditLockUnavailable) {
				t.Fatalf("persisted event notes = %+v; want %q so a later chain break beside it can be read as a possible lost lock race", logged.Notes, logger.NoteAuditLockUnavailable)
			}
			if n := countNoteKind(logged.Notes, logger.NoteAuditLockUnavailable); n != 1 {
				t.Errorf("persisted event carries the lock note %d times; want exactly 1 (the hook appends it and Log deduplicates)", n)
			}

			// The wire must match the disk line: Log stamps a copy, so the
			// hook has to put the note on the event it POSTs (the #4077
			// pass-2 class: a note on disk that never reached the SaaS).
			sent := posted()
			if len(sent) != 1 {
				t.Fatalf("captured %d /api/audit events; want exactly 1", len(sent))
			}
			if !hasNoteKind(sent[0], logger.NoteAuditLockUnavailable) {
				t.Errorf("POSTed /api/audit event notes = %+v; want %q on the wire", sent[0], logger.NoteAuditLockUnavailable)
			}
		})
	}
}

func countNoteKind(ns []logger.Note, kind string) int {
	n := 0
	for _, note := range ns {
		if note.Kind == kind {
			n++
		}
	}
	return n
}

// TestHook_LockFileUnopenable_ExitsTwo is the end-to-end reproduction from
// #4052 through the real Claude Code hook entry point in a child process:
// the harness must see exit 2 (BLOCK), with the logger's warning on stderr
// and no init failure.
func TestHook_LockFileUnopenable_ExitsTwo(t *testing.T) {
	for _, fx := range unopenableLockFixtures {
		t.Run(fx.name, func(t *testing.T) {
			home, _ := newHomeWithUnopenableLock(t, fx)

			code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)

			if code != 2 {
				t.Fatalf("hook exit code = %d; want 2 (BLOCK). stderr:\n%s", code, stderr)
			}
			// Exit 2 alone is not a BLOCK: a Go panic exits 2 as well (the
			// #4071 class; Opus pass 2 on #4057, C4). Require the banner
			// the harness user sees and rule out the panic.
			if !strings.Contains(stderr, "AgentShield BLOCKED this command") {
				t.Fatalf("stderr carries no BLOCK banner; exit 2 came from something else:\n%s", stderr)
			}
			if strings.Contains(stderr, "panic:") {
				t.Fatalf("hook panicked:\n%s", stderr)
			}
			if strings.Contains(stderr, "audit log init") {
				t.Fatalf("stderr reports an audit-log init failure; evaluation was skipped:\n%s", stderr)
			}
			if !strings.Contains(stderr, "audit-log lock unavailable") {
				t.Errorf("stderr does not warn that the lock was unavailable:\n%s", stderr)
			}
		})
	}
}

// TestHook_LockFileOpenable_CarriesNoLockNote is the control: a normal HOME
// blocks the same command and its persisted event carries no lock note.
func TestHook_LockFileOpenable_CarriesNoLockNote(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, failSafePolicyGood)

	result, _ := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "sess-4052")
	if result.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK", result.Decision)
	}
	if logged := lastLoggedEvent(t, configDir); hasNoteKind(logged.Notes, logger.NoteAuditLockUnavailable) {
		t.Fatalf("healthy hook persisted a %q note: %+v", logger.NoteAuditLockUnavailable, logged.Notes)
	}
}

// diskAndWireLockNotes returns how many times the lock note appears on the
// last persisted event and on the one event POSTed to /api/audit. It fails
// the test unless exactly one event was POSTed, so a path that never sends
// cannot pass as "0 on the wire".
func diskAndWireLockNotes(t *testing.T, configDir string, posted func() [][]logger.Note) (disk, wire int) {
	t.Helper()
	disk = countNoteKind(lastLoggedEvent(t, configDir).Notes, logger.NoteAuditLockUnavailable)
	sent := posted()
	if len(sent) != 1 {
		t.Fatalf("captured %d /api/audit events; want exactly 1", len(sent))
	}
	return disk, countNoteKind(sent[0], logger.NoteAuditLockUnavailable)
}

// TestHook_LockFileUnopenable_MCPAuditDiskMatchesWire: auditMCPCall is the
// second path that both persists and POSTs an event. Opus pass 2 on #4057
// (C2) found the disk line carrying the lock note while the wire had none.
func TestHook_LockFileUnopenable_MCPAuditDiskMatchesWire(t *testing.T) {
	blocked := mcp.MCPEvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"mcp-test-rule"}, Reasons: []string{"test"}}
	for _, fx := range unopenableLockFixtures {
		t.Run(fx.name, func(t *testing.T) {
			_, configDir := newHomeWithUnopenableLock(t, fx)
			posted := captureAuditPOSTs(t)

			auditMCPCall("read_file", map[string]interface{}{"path": "/etc/hosts"}, blocked, "claude-code-hook", "enforce", "sess-4052")

			if disk, wire := diskAndWireLockNotes(t, configDir, posted); disk != 1 || wire != 1 {
				t.Fatalf("MCP audit path: lock note on disk %d times, on the wire %d times; want exactly 1 and 1", disk, wire)
			}
		})
	}
	t.Run("healthy control", func(t *testing.T) {
		_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		posted := captureAuditPOSTs(t)

		auditMCPCall("read_file", map[string]interface{}{"path": "/etc/hosts"}, blocked, "claude-code-hook", "enforce", "sess-4052")

		if disk, wire := diskAndWireLockNotes(t, configDir, posted); disk != 0 || wire != 0 {
			t.Fatalf("healthy MCP audit path: lock note on disk %d times, on the wire %d times; want none", disk, wire)
		}
	})
}

// TestHook_LockFileUnopenable_FailSafeDiskMatchesWire: the fail-safe
// boundary (here an engine-init failure from a typo'd intent label,
// non-managed) is the third path that persists and POSTs. Same C2 finding.
// The eval-error sentinel proves the boundary, not the engine, produced the
// event.
func TestHook_LockFileUnopenable_FailSafeDiskMatchesWire(t *testing.T) {
	evaluate := func(t *testing.T) {
		t.Helper()
		result, _ := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "sess-4052")
		if result.Decision != policy.DecisionAudit || !containsStr(result.TriggeredRules, evalErrorRuleID) {
			t.Fatalf("Decision = %v rules = %v; want the fail-safe AUDIT with %q (the boundary did not run)", result.Decision, result.TriggeredRules, evalErrorRuleID)
		}
	}
	for _, fx := range unopenableLockFixtures {
		t.Run(fx.name, func(t *testing.T) {
			_, configDir := newHomeWithUnopenableLock(t, fx)
			if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(failSafePolicyBadLabel), 0o600); err != nil {
				t.Fatal(err)
			}
			posted := captureAuditPOSTs(t)

			evaluate(t)

			if disk, wire := diskAndWireLockNotes(t, configDir, posted); disk != 1 || wire != 1 {
				t.Fatalf("fail-safe path: lock note on disk %d times, on the wire %d times; want exactly 1 and 1", disk, wire)
			}
		})
	}
	t.Run("healthy control", func(t *testing.T) {
		_, configDir := newFailSafeHome(t, false, failSafePolicyBadLabel)
		posted := captureAuditPOSTs(t)

		evaluate(t)

		if disk, wire := diskAndWireLockNotes(t, configDir, posted); disk != 0 || wire != 0 {
			t.Fatalf("healthy fail-safe path: lock note on disk %d times, on the wire %d times; want none", disk, wire)
		}
	})
}

// TestNoteLockUnavailable_NilLoggers (Opus pass 3 on #4057, mutation n10):
// the fail-safe boundary may hold no logger at all. Both nil shapes must be
// a no-op: an untyped nil interface, which the helper's own guard catches,
// and a typed nil *logger.AuditLogger, which is != nil as an interface and
// so reaches the method — the receiver guard in LockUnavailableNote is what
// keeps that from panicking. A healthy logger stays a no-op too.
func TestNoteLockUnavailable_NilLoggers(t *testing.T) {
	healthy, err := logger.New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	for _, tc := range []struct {
		name string
		l    lockNoteSource
	}{
		{"untyped nil", nil},
		{"typed nil", (*logger.AuditLogger)(nil)},
		{"healthy logger", healthy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := logger.AuditEvent{Command: "x", Decision: "AUDIT"}
			noteLockUnavailable(&ev, tc.l)
			if len(ev.Notes) != 0 {
				t.Fatalf("notes = %+v; want none", ev.Notes)
			}
		})
	}
}
