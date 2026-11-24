package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// TestHook_NestedRepoRuleReadsThePayloadCwd_4850: through the real hook on a
// premium install, ts-audit-git-cd-nested-repo-hook-detonation attests its
// node only when git runs in a directory under the PAYLOAD's cwd. The hook
// process runs from another directory, and each row decides differently
// depending on which of the two the gate reads.
func TestHook_NestedRepoRuleReadsThePayloadCwd_4850(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	const rule = "ts-audit-git-cd-nested-repo-hook-detonation"
	const node = "supply-chain/config-tampering/embedded-bare-repository-hook-execution"
	process := t.TempDir()
	if err := os.MkdirAll(filepath.Join(process, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cmd   func(session string) string
		fires bool
		why   string
		// gap5068: on Windows the cwd gate cannot resolve `~`, so the rule
		// over-fires (an AUDIT receipt citing the node; no decision is
		// lowered). Pinned so the fix for #5068 flips it on purpose.
		gap5068 bool
	}{
		{func(string) string { return "cd sub && git commit -m x" }, true, "relative subdirectory of the session", false},
		{func(s string) string { return "cd " + s + "/sub && git commit -m x" }, true, "absolute under the payload cwd, not under the process dir", false},
		{func(s string) string { return "git -C " + s + "/sub checkout main" }, true, "git -C under the payload cwd", false},
		{func(s string) string { return "cd " + s + " && cd sub 2>/dev/null && git commit -m x" }, true, "cwd itself, then a cd git follows", false},
		{func(string) string { return "cd " + process + "/sub && git commit -m x" }, false, "under the process dir only", false},
		{func(string) string { return "cd ~/dev/other && git commit -m x" }, false, "another repository under home", true},
		{func(string) string { return "cd ../other && git pull" }, false, "a sibling of the session", false},
	} {
		home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		installTreePremiumPacks(t, configDir)
		// The session is a repository under home, as on a real Mac: ~ and
		// $HOME resolve only when the cwd is inside the engine's home.
		session := filepath.Join(home, "dev", "app")
		if err := os.MkdirAll(filepath.Join(session, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := shellTextPaths(tc.cmd(session))
		payload := claudeToolPayloadAt(t, session, "Bash", map[string]interface{}{"command": cmd})
		code, _, stderr := runHookFrom(t, process, home, payload)
		if code != 0 {
			t.Fatalf("%s: exit %d, want 0. stderr:\n%s", tc.why, code, stderr)
		}
		ev := lastHarnessHookEvent(t, configDir)
		fires := tc.fires
		if runtime.GOOS == "windows" && tc.gap5068 {
			fires = true // #5068, pinned
		}
		if ev.Decision != "AUDIT" {
			t.Errorf("%s: %q decided %s, want AUDIT either way", tc.why, cmd, ev.Decision)
		}
		if got := containsString(ev.TriggeredRules, rule); got != fires {
			t.Errorf("%s: %q fired=%v, want %v (rules %v)", tc.why, cmd, got, fires, ev.TriggeredRules)
		}
		if got := containsString(ev.Taxonomy, node); got != fires {
			t.Errorf("%s: %q cites the node=%v, want %v (taxonomy %v)", tc.why, cmd, got, fires, ev.Taxonomy)
		}
	}
}
