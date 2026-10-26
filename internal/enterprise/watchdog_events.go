package enterprise

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// What the watchdog loop logs and alerts on (#4292 PR B).
//
// Every check except the Claude Code managed-scope check keeps its behaviour
// from before #4292 PR B: a failing check is a tamper event, logged and
// alerted on every tick.
//
// The managed-scope check (hook-claude-code-managed) is different in two ways:
//
//  1. Tamper or configuration gap. A host whose managed settings have never
//     carried AgentShield's hook was most likely never deployed, which is a
//     configuration gap, not tamper. It is tamper when the hook was seen in
//     managed settings and is gone now, or when managed settings set
//     "disableAllHooks": true.
//  2. Dedupe. An event (and its webhook alert) is emitted only when the
//     check's state changes: pass to fail, fail to pass, or a different
//     failure. Before this, a host that had not deployed the managed hook
//     logged a tamper event on every tick: with the default 60 s interval
//     and a webhook, 1,440 alerts a day per host.
//
// "Was seen" must survive a restart, or an attacker who removes the hook
// while the watchdog is down would read as never deployed on the next start.
// So the last-seen state of the managed hook (present, absent, never-seen)
// is persisted in watchdogStateFile under the AgentShield config directory,
// which managed mode's self-protection covers. A missing or corrupt state
// file reads as never-seen; if the hook is present now, present is recorded.
// The dedupe memory itself is in-process: after a restart, a check that is
// still failing is reported once more.

// watchdogStateFile holds the watchdog's persisted state, under configDir.
const watchdogStateFile = "watchdog-state.json"

// Last-seen states of AgentShield's hook in Claude Code managed settings.
const (
	managedHookPresent   = "present"
	managedHookAbsent    = "absent" // was present, then went away
	managedHookNeverSeen = "never-seen"
)

// watchdogState is what the watchdog persists across restarts.
type watchdogState struct {
	ClaudeManagedHook string `json:"claude_managed_hook"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

// eventKind classifies one watchdog event.
type eventKind int

const (
	kindTamper eventKind = iota
	kindConfigGap
	kindRecovered
)

// Webhook alert "type" values. tamper_detected is the type every alert had
// before #4292 PR B.
const (
	alertTamper    = "tamper_detected"
	alertConfigGap = "config_gap"
	alertRecovered = "check_recovered"
)

func (k eventKind) alertType() string {
	switch k {
	case kindConfigGap:
		return alertConfigGap
	case kindRecovered:
		return alertRecovered
	default:
		return alertTamper
	}
}

// auditCommand is the audit-log "command" of the event.
func (k eventKind) auditCommand() string {
	switch k {
	case kindConfigGap:
		return "watchdog-config-gap"
	case kindRecovered:
		return "watchdog-check-recovered"
	default:
		return "watchdog-tamper-detected"
	}
}

// watchdogEvent is one event the loop logs and alerts on.
type watchdogEvent struct {
	kind  eventKind
	check WatchdogCheck
	// message is the alert's message and, after "<check>: ", the audit
	// event's error text.
	message string
}

// auditEvent is the audit-log record for the event. A tamper event is the
// record the watchdog always wrote; a configuration gap is AUDIT but not
// flagged, and a recovery is ALLOW.
func (ev watchdogEvent) auditEvent() logger.AuditEvent {
	e := logger.AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Command:   ev.kind.auditCommand(),
		Decision:  "AUDIT",
		Mode:      "watchdog",
		Source:    "watchdog",
		Error:     fmt.Sprintf("%s: %s", ev.check.Name, ev.message),
	}
	switch ev.kind {
	case kindTamper:
		e.Flagged = true
	case kindRecovered:
		e.Decision = "ALLOW"
	}
	return e
}

// watchdogTracker carries what the loop remembers between ticks.
type watchdogTracker struct {
	statePath string
	state     watchdogState
	// stateNote says why the persisted state could not be used, if it could
	// not; it is carried into the events it affects.
	stateNote string
	// last is, per check, the signature of the state last reported.
	last map[string]string
}

// newWatchdogTracker loads the persisted state from configDir.
func newWatchdogTracker(configDir string) *watchdogTracker {
	t := &watchdogTracker{
		statePath: filepath.Join(configDir, watchdogStateFile),
		state:     watchdogState{ClaudeManagedHook: managedHookNeverSeen},
		last:      map[string]string{},
	}
	data, err := os.ReadFile(t.statePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		t.stateNote = fmt.Sprintf("watchdog state %s is unreadable (%v), so the hook's earlier state is unknown", t.statePath, err)
	default:
		var s watchdogState
		if json.Unmarshal(data, &s) != nil || !validManagedHookState(s.ClaudeManagedHook) {
			t.stateNote = fmt.Sprintf("watchdog state %s is corrupt, so the hook's earlier state is unknown", t.statePath)
		} else {
			t.state = s
		}
	}
	return t
}

func validManagedHookState(s string) bool {
	return s == managedHookPresent || s == managedHookAbsent || s == managedHookNeverSeen
}

// evaluate turns one tick's checks into the events to log and alert on.
func (t *watchdogTracker) evaluate(checks []WatchdogCheck) []watchdogEvent {
	var events []watchdogEvent
	for _, c := range checks {
		if c.Name == ClaudeManagedHookCheckName && c.scope != nil {
			if ev, ok := t.evaluateManaged(c); ok {
				events = append(events, ev)
			}
			continue
		}
		// Unchanged from before #4292 PR B: every failing check, every tick.
		if !c.Passed {
			events = append(events, watchdogEvent{kind: kindTamper, check: c, message: c.Message})
		}
	}
	return events
}

// evaluateManaged classifies the managed-scope check, records the hook's
// last-seen state, and returns an event only when the reported state changed.
func (t *watchdogTracker) evaluateManaged(c WatchdogCheck) (watchdogEvent, bool) {
	prev := t.state.ClaudeManagedHook
	next := prev
	switch {
	case c.scope.hookInFile:
		next = managedHookPresent
	case prev == managedHookPresent:
		next = managedHookAbsent
	}
	t.persist(next)

	var ev watchdogEvent
	failing := !c.Passed
	if failing {
		switch {
		case c.scope.disablesAll:
			ev = watchdogEvent{kind: kindTamper, check: c, message: "tamper: Claude Code managed settings set " +
				"disableAllHooks: true, which turns off every hook, AgentShield's included. " + c.Message}
		case next == managedHookAbsent:
			ev = watchdogEvent{kind: kindTamper, check: c, message: "tamper: AgentShield's hook was present in " +
				"Claude Code managed settings and is gone. " + c.Message}
		default:
			msg := "config gap, not tamper: AgentShield's hook has not been recorded in Claude Code managed " +
				"settings on this host, so it has most likely not been deployed. " + c.Message
			if t.stateNote != "" {
				msg += " (" + t.stateNote + ")"
			}
			ev = watchdogEvent{kind: kindConfigGap, check: c, message: msg}
		}
	}

	sig := "pass"
	if failing {
		sig = fmt.Sprintf("%d\x00%s", ev.kind, ev.message)
	}
	prevSig, seen := t.last[c.Name]
	t.last[c.Name] = sig
	switch {
	case sig == prevSig:
		return watchdogEvent{}, false
	case !failing && !seen:
		// Passing on the first tick: nothing changed that anyone needs to hear.
		return watchdogEvent{}, false
	case !failing:
		return watchdogEvent{kind: kindRecovered, check: c, message: "recovered: " + c.Message}, true
	}
	return ev, true
}

// persist records the managed hook's last-seen state when it changed, and
// re-records it when the file on disk no longer holds what memory does (it was
// deleted or rewritten mid-run, #4434). A write failure is reported on stderr
// and carried in stateNote, so the events it affects say the state could not
// be recorded; the in-memory state is kept, so this run still classifies
// correctly.
func (t *watchdogTracker) persist(next string) {
	changed := next != t.state.ClaudeManagedHook
	// never-seen is the absence of a record: it is not written, and a corrupt
	// file stays in place so its note keeps reaching the events.
	if !changed && (t.state.ClaudeManagedHook == managedHookNeverSeen || t.stateOnDiskMatches()) {
		return
	}
	if changed {
		t.state = watchdogState{ClaudeManagedHook: next, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	if err := writeWatchdogState(t.statePath, t.state); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] watchdog: cannot record state in %s: %v\n", t.statePath, err)
		t.stateNote = fmt.Sprintf("watchdog state %s could not be written (%v), so the hook's state is not recorded across a restart", t.statePath, err)
		return
	}
	t.stateNote = ""
}

// stateOnDiskMatches reports whether the state file holds the hook state that
// memory holds. One small read per tick.
func (t *watchdogTracker) stateOnDiskMatches() bool {
	data, err := os.ReadFile(t.statePath)
	if err != nil {
		return false
	}
	var s watchdogState
	return json.Unmarshal(data, &s) == nil && s.ClaudeManagedHook == t.state.ClaudeManagedHook
}

// writeWatchdogState writes the state file through a temp file and a rename.
func writeWatchdogState(path string, s watchdogState) (err error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchdog-state-*.json")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
