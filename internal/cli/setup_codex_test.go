package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// codexPreToolUse parses a hooks.json body the way setup reads it from disk,
// so numbers come back as float64 exactly as they do for a real install.
func codexPreToolUse(t *testing.T, body string) []interface{} {
	t.Helper()
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(body), &settings); err != nil {
		t.Fatal(err)
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	pre, _ := hooks["PreToolUse"].([]interface{})
	return pre
}

func codexMatchers(entries []interface{}) []string {
	var out []string
	for _, e := range entries {
		m, _ := e.(map[string]interface{})
		matcher, _ := m["matcher"].(string)
		out = append(out, matcher)
	}
	return out
}

// withAgentShieldOnPath makes setup resolve a binary named agentshield, as on
// a real install. Without it, a machine with no agentshield installed (CI)
// falls back to the test binary's own path, and isAgentShieldCodexHookEntry
// rightly does not recognise "<path>/cli.test hook" as ours.
func withAgentShieldOnPath(t *testing.T) {
	t.Helper()
	prev := agentShieldPathCandidates
	agentShieldPathCandidates = nil
	t.Cleanup(func() { agentShieldPathCandidates = prev })
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "agentshield"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// An install made before the MCP group: the user's own hook, then the shell
// group Codex has already trusted, keyed pre_tool_use:1:0.
const codexShellOnlyHooks = `{"hooks":{"PreToolUse":[
  {"matcher":"^apply_patch$","hooks":[{"type":"command","command":"/opt/lint-hook","timeout":5}]},
  {"matcher":"^Bash$","hooks":[{"type":"command","command":"/usr/local/bin/agentshield hook","timeout":10}]}
]}}`

func TestEnsureCodexHookEntries_FreshInstallAddsShellThenMCP(t *testing.T) {
	withAgentShieldOnPath(t)
	got, added := ensureCodexHookEntries(nil)
	if !reflect.DeepEqual(added, []string{"shell", "MCP"}) {
		t.Fatalf("added %v, want [shell MCP]", added)
	}
	if want := []string{codexShellMatcher, codexMCPMatcher}; !reflect.DeepEqual(codexMatchers(got), want) {
		t.Fatalf("matchers %v, want %v", codexMatchers(got), want)
	}
	for i, e := range got {
		if !isAgentShieldCodexHookEntry(e) {
			t.Errorf("entry %d does not route to agentshield hook: %v", i, e)
		}
	}
	// Codex titles each entry in /hooks by its statusMessage.
	for i, want := range []string{codexShellHookName, codexMCPHookName} {
		handler := got[i].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
		if handler["statusMessage"] != want {
			t.Errorf("entry %d statusMessage %v, want %q", i, handler["statusMessage"], want)
		}
	}
}

// The whole command against a real file, so CI (which does not run the Docker
// setup suite) fails if setup stops writing the upgrade, rewrites PreToolUse,
// or touches the groups Codex already trusts.
func TestSetupCodexCommand_UpgradeOnDiskKeepsTrustedGroups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withAgentShieldOnPath(t)
	prev := disableFlag
	disableFlag = false
	t.Cleanup(func() { disableFlag = prev })

	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, []byte(codexShellOnlyHooks), 0o600); err != nil {
		t.Fatal(err)
	}
	pristine := codexPreToolUse(t, codexShellOnlyHooks)

	if err := setupCodexCommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	upgraded, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	got := codexPreToolUse(t, string(upgraded))
	if len(got) != len(pristine)+1 {
		t.Fatalf("got %d groups after upgrade, want %d: %s", len(got), len(pristine)+1, upgraded)
	}
	for i := range pristine {
		if !reflect.DeepEqual(got[i], pristine[i]) {
			t.Errorf("group %d changed on disk:\n got  %v\n want %v", i, got[i], pristine[i])
		}
	}
	if m := codexMatchers(got)[len(pristine)]; m != codexMCPMatcher {
		t.Errorf("appended matcher %q, want %q", m, codexMCPMatcher)
	}

	if err := setupCodexCommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(upgraded) {
		t.Errorf("second run rewrote hooks.json:\n%s\nwant\n%s", again, upgraded)
	}
}

// The trusted shell group must come out byte-for-byte as it went in and at the
// same index. Codex hashes event + matcher + handler under a positional key,
// so any edit or shift switches shell checking off until the user re-reviews.
func TestEnsureCodexHookEntries_UpgradeAppendsMCPAndLeavesTrustedGroupsAlone(t *testing.T) {
	withAgentShieldOnPath(t)
	before := codexPreToolUse(t, codexShellOnlyHooks)
	pristine := codexPreToolUse(t, codexShellOnlyHooks)

	got, added := ensureCodexHookEntries(before)
	if !reflect.DeepEqual(added, []string{"MCP"}) {
		t.Fatalf("added %v, want [MCP]", added)
	}
	if len(got) != 3 {
		t.Fatalf("got %d groups, want 3: %v", len(got), got)
	}
	for i := range pristine {
		if !reflect.DeepEqual(got[i], pristine[i]) {
			t.Errorf("group %d changed:\n got  %v\n want %v", i, got[i], pristine[i])
		}
	}
	if m := codexMatchers(got)[2]; m != codexMCPMatcher {
		t.Errorf("appended matcher %q, want %q", m, codexMCPMatcher)
	}

	again, added := ensureCodexHookEntries(got)
	if len(added) != 0 || len(again) != 3 {
		t.Errorf("second run added %v (len %d), want nothing", added, len(again))
	}
}

// If only the MCP group is left, the shell group goes on the end too: putting
// it first would shift the MCP group's key and un-trust it.
func TestEnsureCodexHookEntries_MissingShellIsAppendedNotPrepended(t *testing.T) {
	withAgentShieldOnPath(t)
	pre := codexPreToolUse(t, `{"hooks":{"PreToolUse":[
	  {"matcher":"^mcp__.*","hooks":[{"type":"command","command":"/usr/local/bin/agentshield hook","timeout":10}]}
	]}}`)
	got, added := ensureCodexHookEntries(pre)
	if !reflect.DeepEqual(added, []string{"shell"}) {
		t.Fatalf("added %v, want [shell]", added)
	}
	if want := []string{codexMCPMatcher, codexShellMatcher}; !reflect.DeepEqual(codexMatchers(got), want) {
		t.Errorf("matchers %v, want %v", codexMatchers(got), want)
	}
}

// Codex treats a matcher with no regex characters as an exact tool name, so
// "mcp__" would match no MCP tool at all. Pin the pattern against the names
// Codex sends (mcp__<server>__<tool>) and the tools it must not catch.
func TestCodexMCPMatcher_IsARegexThatCatchesOnlyMCPTools(t *testing.T) {
	if !strings.ContainsAny(codexMCPMatcher, `^$.*+?()[]{}|\`) {
		t.Fatalf("%q has no regex characters; Codex would match it exactly", codexMCPMatcher)
	}
	re := regexp.MustCompile(codexMCPMatcher)
	for _, name := range []string{"mcp__open_brain__stats", "mcp__filesystem__read_file", "mcp__memory__create_entities"} {
		if !re.MatchString(name) {
			t.Errorf("%q should match %s", codexMCPMatcher, name)
		}
	}
	for _, name := range []string{"Bash", "apply_patch", "web_search", "xmcp__a__b"} {
		if re.MatchString(name) {
			t.Errorf("%q should not match %s", codexMCPMatcher, name)
		}
	}
}

func TestDisableCodexHook_RemovesShellAndMCPGroupsKeepsOthers(t *testing.T) {
	withAgentShieldOnPath(t)
	path := filepath.Join(t.TempDir(), "hooks.json")
	pre, _ := ensureCodexHookEntries(codexPreToolUse(t, codexShellOnlyHooks))
	body, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": pre}})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := disableCodexHook(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	left := codexPreToolUse(t, string(data))
	if want := []string{"^apply_patch$"}; !reflect.DeepEqual(codexMatchers(left), want) {
		t.Errorf("after disable matchers %v, want %v", codexMatchers(left), want)
	}
}

func TestCodexHooksMissingMCP(t *testing.T) {
	withAgentShieldOnPath(t)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	both, _ := ensureCodexHookEntries(nil)
	bothBody, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": both}})

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"shell only (pre-MCP install)", write("old.json", codexShellOnlyHooks), true},
		{"shell and MCP", write("new.json", string(bothBody)), false},
		{"no AgentShield hook", write("none.json", `{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":"/opt/other"}]}]}}`), false},
		{"no file", filepath.Join(dir, "missing.json"), false},
		{"not JSON", write("bad.json", "{"), false},
	}
	for _, c := range cases {
		if got := codexHooksMissingMCP(c.path); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
