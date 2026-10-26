package enterprise

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// Tests for how the watchdog loop reports the Claude Code managed-scope check
// (#4292 PR B fix round): tamper vs configuration gap, dedupe on state
// change, and the last-seen hook state persisted across restarts. A
// "restart" is a fresh tracker built from the same config directory, which
// is all RunWatchdog keeps between runs.

const disableAllWithHook = `{"disableAllHooks":true,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`

// healthyManagedHost is a managed host whose other checks all pass, so the
// only events a tick logs are the managed-scope check's.
func healthyManagedHost(t *testing.T) scopeFixture {
	t.Helper()
	f := newScopeFixture(t)
	t.Setenv("AGENTSHIELD_BYPASS", "")
	f.managedJSON(t, `{"managed":true}`)
	f.userSettings(t, execHookSettings)
	writeFixtureFile(t, filepath.Join(f.configDir, "policy.yaml"), "version: '0.1'\n")
	return f
}

// setManaged writes the managed settings file, or removes it for nil.
func (f scopeFixture) setManaged(t *testing.T, content *string) {
	t.Helper()
	if content == nil {
		if err := os.Remove(f.managedPath); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return
	}
	f.managedSettings(t, *content)
}

type tickResult struct {
	logged []logger.AuditEvent // excluding the heartbeat
	alerts []watchdogEvent
}

func (f scopeFixture) tick(tr *watchdogTracker) tickResult {
	var r tickResult
	watchdogTick(f.configDir, tr,
		func(e logger.AuditEvent) error {
			if e.Command != "watchdog-heartbeat" {
				r.logged = append(r.logged, e)
			}
			return nil
		},
		func(ev watchdogEvent) { r.alerts = append(r.alerts, ev) })
	return r
}

func (f scopeFixture) persistedHookState(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.configDir, watchdogStateFile))
	if os.IsNotExist(err) {
		return "(no file)"
	}
	if err != nil {
		t.Fatal(err)
	}
	var s watchdogState
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("state file does not parse: %v\n%s", err, data)
	}
	return s.ClaudeManagedHook
}

// wantEvent asserts a tick logged and alerted exactly one managed-scope event
// of the given kind ("" = none at all).
func wantEvent(t *testing.T, step string, r tickResult, kind string) {
	t.Helper()
	if kind == "" {
		if len(r.logged) != 0 || len(r.alerts) != 0 {
			t.Errorf("%s: want no event, got logged=%+v alerts=%d", step, r.logged, len(r.alerts))
		}
		return
	}
	if len(r.logged) != 1 || len(r.alerts) != 1 {
		t.Fatalf("%s: want one %s event and one alert, got logged=%+v alerts=%d", step, kind, r.logged, len(r.alerts))
	}
	e, a := r.logged[0], r.alerts[0]
	if !strings.HasPrefix(e.Error, ClaudeManagedHookCheckName+": ") || a.check.Name != ClaudeManagedHookCheckName {
		t.Errorf("%s: event is not the managed-scope check's: %q", step, e.Error)
	}
	want := map[string]struct {
		command, decision, alert, text string
		flagged                        bool
	}{
		"tamper":     {"watchdog-tamper-detected", "AUDIT", alertTamper, "tamper: ", true},
		"config_gap": {"watchdog-config-gap", "AUDIT", alertConfigGap, "config gap, not tamper", false},
		"recovered":  {"watchdog-check-recovered", "ALLOW", alertRecovered, "recovered: ", false},
	}[kind]
	if e.Command != want.command || e.Decision != want.decision || e.Flagged != want.flagged {
		t.Errorf("%s: event = {command %q, decision %q, flagged %v}; want {%q, %q, %v}", step, e.Command, e.Decision, e.Flagged, want.command, want.decision, want.flagged)
	}
	if got := a.kind.alertType(); got != want.alert {
		t.Errorf("%s: alert type %q; want %q", step, got, want.alert)
	}
	if !strings.Contains(e.Error, want.text) || !strings.Contains(a.message, want.text) {
		t.Errorf("%s: event text does not say %q:\n%s", step, want.text, e.Error)
	}
}

// One host through every transition, on one running watchdog.
func TestWatchdogEvents_Transitions(t *testing.T) {
	f := healthyManagedHost(t)
	tr := newWatchdogTracker(f.configDir)
	noHook := `{"model":"opus"}`
	empty := ""
	hook := execHookSettings
	disabled := disableAllWithHook
	steps := []struct {
		name    string
		managed *string
		want    string // event kind, "" = none
		state   string // persisted last-seen state after the tick
	}{
		{"never deployed: config gap", nil, "config_gap", "(no file)"},
		{"same, next tick: deduped", nil, "", "(no file)"},
		{"same, third tick: deduped", nil, "", "(no file)"},
		{"empty file: a different gap, reported", &empty, "config_gap", "(no file)"},
		{"file without our hook: a different gap, reported", &noHook, "config_gap", "(no file)"},
		{"hook deployed: recovered", &hook, "recovered", managedHookPresent},
		{"still present: nothing", &hook, "", managedHookPresent},
		{"hook removed: tamper", &noHook, "tamper", managedHookAbsent},
		{"still removed: deduped", &noHook, "", managedHookAbsent},
		{"whole file removed after removal: a different tamper", nil, "tamper", managedHookAbsent},
		{"hook restored: recovered", &hook, "recovered", managedHookPresent},
		{"managed disableAllHooks: tamper", &disabled, "tamper", managedHookPresent},
		{"still disabled: deduped", &disabled, "", managedHookPresent},
		{"disableAllHooks removed: recovered", &hook, "recovered", managedHookPresent},
		{"file deleted: tamper", nil, "tamper", managedHookAbsent},
	}
	for _, s := range steps {
		f.setManaged(t, s.managed)
		r := f.tick(tr)
		wantEvent(t, s.name, r, s.want)
		if got := f.persistedHookState(t); got != s.state {
			t.Errorf("%s: persisted state %q; want %q", s.name, got, s.state)
		}
	}
}

// The attack the persisted state exists for: the hook is removed while the
// watchdog is not running. The next start must read it as tamper.
func TestWatchdogEvents_RemovalAcrossRestartIsTamper(t *testing.T) {
	for _, tc := range []struct {
		name    string
		removed *string
	}{
		{"hook entry removed", strPtrE(`{"model":"opus"}`)},
		{"file deleted", nil},
		{"file emptied", strPtrE("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := healthyManagedHost(t)
			f.managedSettings(t, execHookSettings)
			wantEvent(t, "first run, hook present", f.tick(newWatchdogTracker(f.configDir)), "")
			if got := f.persistedHookState(t); got != managedHookPresent {
				t.Fatalf("after a run that saw the hook, persisted state = %q; want present", got)
			}

			// Watchdog down; the hook goes.
			f.setManaged(t, tc.removed)

			restarted := newWatchdogTracker(f.configDir)
			wantEvent(t, "restart after removal", f.tick(restarted), "tamper")
			wantEvent(t, "next tick", f.tick(restarted), "")

			// A second restart with the hook still gone: still tamper, once.
			again := newWatchdogTracker(f.configDir)
			wantEvent(t, "second restart, still removed", f.tick(again), "tamper")
			wantEvent(t, "second restart, next tick", f.tick(again), "")
		})
	}
}

// A host that never had the hook stays a configuration gap across restarts.
func TestWatchdogEvents_NeverDeployedAcrossRestartIsConfigGap(t *testing.T) {
	f := healthyManagedHost(t)
	wantEvent(t, "first run", f.tick(newWatchdogTracker(f.configDir)), "config_gap")
	wantEvent(t, "restart", f.tick(newWatchdogTracker(f.configDir)), "config_gap")
	if got := f.persistedHookState(t); got != "(no file)" && got != managedHookNeverSeen {
		t.Errorf("persisted state %q; want never-seen", got)
	}
}

// A state file deleted or rewritten mid-run, with the hook still in place, is
// written back on the next tick (#4434 item 1). Otherwise removing the hook
// while the watchdog is down would read as a configuration gap.
func TestWatchdogEvents_StateFileSelfHeals(t *testing.T) {
	for _, tc := range []struct {
		name string
		harm func(t *testing.T, path string)
	}{
		{"deleted", func(t *testing.T, p string) {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}},
		{"rewritten as never-seen", func(t *testing.T, p string) {
			writeFixtureFile(t, p, `{"claude_managed_hook":"never-seen"}`)
		}},
		{"rewritten as garbage", func(t *testing.T, p string) { writeFixtureFile(t, p, "{garbage") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := healthyManagedHost(t)
			f.managedSettings(t, execHookSettings)
			tr := newWatchdogTracker(f.configDir)
			wantEvent(t, "hook present", f.tick(tr), "")
			tc.harm(t, filepath.Join(f.configDir, watchdogStateFile))

			wantEvent(t, "next tick", f.tick(tr), "")
			if got := f.persistedHookState(t); got != managedHookPresent {
				t.Fatalf("after the harm and one more tick, persisted state = %q; want present", got)
			}

			// The hook goes while the watchdog is down: still tamper.
			f.setManaged(t, nil)
			wantEvent(t, "restart after removal", f.tick(newWatchdogTracker(f.configDir)), "tamper")
		})
	}
}

// A state write that fails is named in stateNote (#4434 item 2), and the next
// successful write clears it.
func TestWatchdogEvents_StateWriteFailureIsNamed(t *testing.T) {
	f := healthyManagedHost(t)
	f.managedSettings(t, execHookSettings)
	tr := newWatchdogTracker(f.configDir)

	// A directory at the state path makes the final rename fail.
	statePath := filepath.Join(f.configDir, watchdogStateFile)
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	wantEvent(t, "hook present, write fails", f.tick(tr), "")
	if !strings.Contains(tr.stateNote, "could not be written") {
		t.Fatalf("stateNote after a failed write = %q; want it to say the write failed", tr.stateNote)
	}

	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	f.tick(tr)
	if tr.stateNote != "" {
		t.Errorf("stateNote after a successful write = %q; want empty", tr.stateNote)
	}
	if got := f.persistedHookState(t); got != managedHookPresent {
		t.Errorf("persisted state %q; want present", got)
	}
}

// A missing or corrupt state file reads as never-seen when the hook is
// absent now, and records present when it is present now.
func TestWatchdogEvents_StateFileMissingOrCorrupt(t *testing.T) {
	for _, tc := range []struct{ name, stateFile string }{
		{"missing", ""},
		{"not JSON", "{garbage"},
		{"unknown value", `{"claude_managed_hook":"maybe"}`},
		{"empty", " "},
	} {
		t.Run(tc.name+", hook absent: config gap", func(t *testing.T) {
			f := healthyManagedHost(t)
			if tc.stateFile != "" {
				writeFixtureFile(t, filepath.Join(f.configDir, watchdogStateFile), tc.stateFile)
			}
			r := f.tick(newWatchdogTracker(f.configDir))
			wantEvent(t, "absent", r, "config_gap")
			if tc.stateFile != "" && len(r.logged) == 1 && !strings.Contains(r.logged[0].Error, "earlier state is unknown") {
				t.Errorf("a corrupt state file must be named in the event: %s", r.logged[0].Error)
			}
		})
		t.Run(tc.name+", hook present: records present", func(t *testing.T) {
			f := healthyManagedHost(t)
			if tc.stateFile != "" {
				writeFixtureFile(t, filepath.Join(f.configDir, watchdogStateFile), tc.stateFile)
			}
			f.managedSettings(t, execHookSettings)
			wantEvent(t, "present", f.tick(newWatchdogTracker(f.configDir)), "")
			if got := f.persistedHookState(t); got != managedHookPresent {
				t.Fatalf("persisted state %q; want present", got)
			}
			f.setManaged(t, nil)
			wantEvent(t, "restart after removal", f.tick(newWatchdogTracker(f.configDir)), "tamper")
		})
	}
}

// Managed disableAllHooks is tamper even on a host that never had our hook.
func TestWatchdogEvents_ManagedDisableAllHooksIsTamper(t *testing.T) {
	f := healthyManagedHost(t)
	f.managedSettings(t, `{"disableAllHooks":true}`)
	tr := newWatchdogTracker(f.configDir)
	r := f.tick(tr)
	wantEvent(t, "never seen, disableAllHooks", r, "tamper")
	if len(r.logged) == 1 && !strings.Contains(r.logged[0].Error, "disableAllHooks: true") {
		t.Errorf("tamper event must name disableAllHooks: %s", r.logged[0].Error)
	}
	wantEvent(t, "next tick", f.tick(tr), "")
}

// The state file is private to the user.
func TestWatchdogEvents_StateFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	f := healthyManagedHost(t)
	f.managedSettings(t, execHookSettings)
	f.tick(newWatchdogTracker(f.configDir))
	fi, err := os.Stat(filepath.Join(f.configDir, watchdogStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %#o; want 0600", fi.Mode().Perm())
	}
}

// Every other check keeps its old behaviour: a failure is tamper, logged and
// alerted on every tick. That includes the user-scope Claude Code check.
func TestWatchdogEvents_OtherChecksUnchanged(t *testing.T) {
	f := healthyManagedHost(t)
	f.managedSettings(t, execHookSettings)
	if err := os.Remove(filepath.Join(f.configDir, "policy.yaml")); err != nil {
		t.Fatal(err)
	}
	f.userSettings(t, `{"hooks":{"PreToolUse":[]}}`)
	tr := newWatchdogTracker(f.configDir)
	for tick := 1; tick <= 3; tick++ {
		r := f.tick(tr)
		got := map[string]logger.AuditEvent{}
		for _, e := range r.logged {
			got[strings.SplitN(e.Error, ":", 2)[0]] = e
		}
		for _, name := range []string{"policy-file", "hook-claude-code"} {
			e, ok := got[name]
			if !ok {
				t.Errorf("tick %d: no event for failing %s; want one every tick", tick, name)
				continue
			}
			if e.Command != "watchdog-tamper-detected" || !e.Flagged || e.Decision != "AUDIT" {
				t.Errorf("tick %d: %s event = %+v; want the flagged tamper event", tick, name, e)
			}
		}
		if len(r.logged) != 2 || len(r.alerts) != 2 {
			t.Errorf("tick %d: logged %d, alerted %d; want 2 and 2", tick, len(r.logged), len(r.alerts))
		}
		for _, a := range r.alerts {
			if a.kind.alertType() != alertTamper {
				t.Errorf("tick %d: %s alert type %q; want %q", tick, a.check.Name, a.kind.alertType(), alertTamper)
			}
		}
	}
}

// The webhook payload keeps its shape; "type" says which kind of event it is.
func TestWatchdogAlert_TypePerKind(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(body, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}))
	defer srv.Close()
	c := WatchdogCheck{Name: ClaudeManagedHookCheckName}
	for _, k := range []eventKind{kindTamper, kindConfigGap, kindRecovered} {
		sendWatchdogAlertEvent(srv.URL, watchdogEvent{kind: k, check: c, message: "m"})
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{alertTamper, alertConfigGap, alertRecovered}
	if len(got) != len(want) {
		t.Fatalf("alerts = %d; want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i]["type"] != w || got[i]["check"] != ClaudeManagedHookCheckName || got[i]["message"] != "m" || got[i]["timestamp"] == nil {
			t.Errorf("alert %d = %v; want type %q with check, message and timestamp", i, got[i], w)
		}
	}
}

func strPtrE(s string) *string { return &s }
