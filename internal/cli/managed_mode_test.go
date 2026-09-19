package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// These tests pin #3620 end to end through evaluateCommand and the real hook
// entry point. Helpers (newFailSafeHome, runHookInChildProcess,
// claudeCodePayloadDestructive) live in fail_safe_test.go.

// TestManagedConfigLoaders_Agree pins the two managed.json loaders — the
// config package's and the enterprise package's — to the same verdict on the
// same bytes. Two definitions of "managed" drifting apart is exactly how a
// hint and an enforcement decision fall out of step (see policy/remediation).
func TestManagedConfigLoaders_Agree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "managed.json")

	type verdict struct{ present, managed, failClosed bool }
	read := func() (a, b verdict) {
		if c := config.LoadManaged(dir); c != nil {
			a = verdict{true, c.Managed, c.FailClosed}
		}
		if e := enterprise.LoadManagedConfigFrom(path); e != nil {
			b = verdict{true, e.Managed, e.FailClosed}
		}
		return
	}

	cases := []struct {
		name  string
		bytes *string
		want  verdict
	}{
		{"absent", nil, verdict{}},
		{"valid managed", ptr(`{"managed": true, "fail_closed": true}`), verdict{true, true, true}},
		{"valid unmanaged", ptr(`{"managed": false}`), verdict{true, false, false}},
		{"corrupt", ptr(`{not json`), verdict{true, true, true}},
		{"empty", ptr(``), verdict{true, true, true}},
	}
	for _, tc := range cases {
		_ = os.Remove(path)
		if tc.bytes != nil {
			if err := os.WriteFile(path, []byte(*tc.bytes), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		a, b := read()
		if a != tc.want || b != tc.want {
			t.Errorf("%s: config=%+v enterprise=%+v; want both %+v", tc.name, a, b, tc.want)
		}
	}
}

func ptr(s string) *string { return &s }

const policyDisablingRootDelete = `version: "0.1"
defaults:
  decision: "AUDIT"
disable_rules: [block-rm-root, ts-block-rm-root, st-block-rm-recursive-root, ts-struct-block-rm-system]
rules: []
`

// TestManagedMode_IgnoresLocalDisableRules: a policy.yaml that disables the
// four rules firing on `rm -rf /` must have no effect on a managed host. The
// unmanaged control shows the same file does take effect there, so the test
// is measuring the guard and not a rule that happens to fire anyway.
func TestManagedMode_IgnoresLocalDisableRules(t *testing.T) {
	newFailSafeHome(t, true, policyDisablingRootDelete)
	managed, _ := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "")
	if managed.Decision != policy.DecisionBlock {
		t.Fatalf("managed: Decision = %v; want BLOCK", managed.Decision)
	}
	if !containsStr(managed.TriggeredRules, "block-rm-root") {
		t.Errorf("managed: TriggeredRules = %v; want block-rm-root to fire although the local policy disabled it", managed.TriggeredRules)
	}

	newFailSafeHome(t, false, policyDisablingRootDelete)
	unmanaged, _ := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "")
	if containsStr(unmanaged.TriggeredRules, "block-rm-root") {
		t.Errorf("unmanaged control: block-rm-root fired although disable_rules lists it — the control is not measuring the guard: %v", unmanaged.TriggeredRules)
	}
}

// TestManagedMode_InterpreterWriteToPolicyIsBlocked is the reproduction
// through evaluateCommand: the Python one-liner used to come back AUDIT.
func TestManagedMode_InterpreterWriteToPolicyIsBlocked(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	cmd := `python3 -c "open('` + home + `/.agentshield/policy.yaml','w').write('disable_rules: [block-rm-root]')"`

	res, event := evaluateCommand(cmd, home, "claude-code-hook", "")

	if res.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK — an interpreter write to policy.yaml passed on a managed host", res.Decision)
	}
	if !containsStr(res.TriggeredRules, "enterprise-self-protect") {
		t.Errorf("TriggeredRules = %v; want enterprise-self-protect", res.TriggeredRules)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "sp-block-config-touch") {
		t.Errorf("Reasons = %v; want the default-deny rule id for attribution", res.Reasons)
	}
	if event == nil || event.Decision != "BLOCK" {
		t.Errorf("event = %+v; want a BLOCK audit event", event)
	}

	// A plain read of the same file is not tampering.
	read, _ := evaluateCommand("cat "+home+"/.agentshield/policy.yaml", home, "claude-code-hook", "")
	if read.Decision == policy.DecisionBlock {
		t.Errorf("plain read blocked on a managed host: %v", read.Reasons)
	}
}

// TestHook_CorruptManagedJSON_PauseIsIgnored is the other reproduction: with
// `{not json` in managed.json and a live paused.json, `rm -rf /` exited 0
// because the host was read as unmanaged. Now a corrupt enrollment fails
// closed, so the pause is ignored and the command is blocked.
func TestHook_CorruptManagedJSON_PauseIsIgnored(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	paused, _ := json.Marshal(pauseState{Paused: true, PausedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err := os.WriteFile(filepath.Join(configDir, "paused.json"), paused, 0o600); err != nil {
		t.Fatal(err)
	}

	code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)
	if code != 2 {
		t.Fatalf("hook exit code = %d; want 2 — a corrupt managed.json must not let a pause through. stderr:\n%s", code, stderr)
	}

	// Control: the same pause on a genuinely unmanaged host is honored.
	if err := os.Remove(filepath.Join(configDir, "managed.json")); err != nil {
		t.Fatal(err)
	}
	code, stderr = runHookInChildProcess(t, home, claudeCodePayloadDestructive)
	if code != 0 {
		t.Fatalf("unmanaged control: exit code = %d; want 0 (pause honored). stderr:\n%s", code, stderr)
	}
}
