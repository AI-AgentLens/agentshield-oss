package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
)

// Tests for `agentshield setup claude-code --managed` and --write-managed
// (#4292 PR B). Every managed-settings path here is a temp file:
// enterprise.ClaudeManagedSettingsPath is pointed at it, and nothing reads or
// writes the real /Library, /etc or C:\Program Files location.

// pinManagedSettingsPath points the managed settings path setup and the
// watchdog use at a file in a fresh temp directory and returns it.
func pinManagedSettingsPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.json")
	prev := enterprise.ClaudeManagedSettingsPath
	enterprise.ClaudeManagedSettingsPath = func() string { return path }
	t.Cleanup(func() { enterprise.ClaudeManagedSettingsPath = prev })
	return path
}

// resetManagedFlags restores the package-level flag variables a test sets.
func resetManagedFlags(t *testing.T) {
	t.Helper()
	pm, pw, pd := managedFlag, writeManagedFlag, disableFlag
	t.Cleanup(func() { managedFlag, writeManagedFlag, disableFlag = pm, pw, pd })
}

// decodeJSON parses data as one JSON object.
func decodeJSON(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, data)
	}
	return m
}

func preToolUseGroups(settings map[string]interface{}) []interface{} {
	hooks, _ := settings["hooks"].(map[string]interface{})
	groups, _ := hooks["PreToolUse"].([]interface{})
	return groups
}

// The snippet is exactly one PreToolUse group holding the exec-form hook,
// with no matcher (every tool call), and nothing else.
func TestManagedSnippet_ExecFormEntry(t *testing.T) {
	bin := "/opt/homebrew/bin/agentshield"
	out, res, err := managedSettingsSnippet(bin, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Form != hookentry.Exec || !res.Added {
		t.Fatalf("snippet result = %+v; want an added exec-form entry", res)
	}
	want := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"hooks": []interface{}{
						map[string]interface{}{"type": "command", "command": bin, "args": []interface{}{"hook"}},
					},
				},
			},
		},
	}
	got := decodeJSON(t, out)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("snippet =\n%s\nwant the single exec-form PreToolUse group", out)
	}
	ok, err := hookentry.SettingsHasPreToolUseHook(out)
	if err != nil || !ok {
		t.Errorf("the watchdog's recognizer does not accept the snippet: ok=%v err=%v", ok, err)
	}
	g := preToolUseGroups(got)[0].(map[string]interface{})
	if _, hasMatcher := g["matcher"]; hasMatcher {
		t.Error("the group must carry no matcher, so it fires on every tool call like the user-scope entry")
	}

	// Without exec-form clearance the snippet falls back to shell form, as
	// the user-scope install does.
	shell, res, err := managedSettingsSnippet(bin, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Form != hookentry.Shell {
		t.Errorf("execOK=false: form = %v; want shell form", res.Form)
	}
	h := preToolUseGroups(decodeJSON(t, shell))[0].(map[string]interface{})["hooks"].([]interface{})[0]
	if hookentry.Classify(h) != hookentry.Shell {
		t.Errorf("execOK=false: hook %v is not shell form", h)
	}
}

// The managed entry is the user-scope entry: `setup claude-code` into an
// empty HOME writes the same PreToolUse list the snippet holds.
func TestManagedSnippet_IsTheUserScopeEntry(t *testing.T) {
	settingsPath := setupClaudeHome(t)
	resetManagedFlags(t)
	managedFlag, writeManagedFlag = false, false
	runSetupClaudeCode(t, false)
	user := readSettingsFile(t, settingsPath)

	hookPath := resolveAgentShieldPath()
	blocker := execFormBlocker(hookPath)
	if blocker != "" {
		t.Fatalf("fixture: exec form should be allowed for the stand-in install: %s", blocker)
	}
	snippet, _, err := managedSettingsSnippet(hookPath, blocker == "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := preToolUseGroups(decodeJSON(t, snippet)), preToolUseGroups(user); !reflect.DeepEqual(got, want) {
		t.Errorf("managed snippet PreToolUse = %v\nuser-scope PreToolUse = %v\nthey must be the same entry", got, want)
	}
}

// --managed prints the snippet on stdout and the paths on stderr, and writes
// nothing: not the managed file, not ~/.claude, not ~/.agentshield.
func TestSetupManaged_PrintsAndWritesNothing(t *testing.T) {
	settingsPath := setupClaudeHome(t)
	home := filepath.Dir(filepath.Dir(settingsPath))
	managedPath := pinManagedSettingsPath(t)
	resetManagedFlags(t)
	managedFlag, writeManagedFlag, disableFlag = true, false, false

	var stdout, stderr bytes.Buffer
	setupClaudeCodeCmd.SetOut(&stdout)
	setupClaudeCodeCmd.SetErr(&stderr)
	t.Cleanup(func() { setupClaudeCodeCmd.SetOut(nil); setupClaudeCodeCmd.SetErr(nil) })
	if err := setupClaudeCodeCommand(setupClaudeCodeCmd, nil); err != nil {
		t.Fatalf("setup claude-code --managed: %v", err)
	}

	ok, err := hookentry.SettingsHasPreToolUseHook(stdout.Bytes())
	if err != nil || !ok {
		t.Fatalf("stdout must be the managed-settings JSON alone; ok=%v err=%v\n%s", ok, err, stdout.String())
	}
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if p := hookentry.ManagedSettingsPath(goos); !strings.Contains(stderr.String(), p) {
			t.Errorf("stderr does not name the %s managed settings path %q:\n%s", goos, p, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), managedPath) {
		t.Errorf("stderr does not name this machine's path %q", managedPath)
	}
	if _, err := os.Stat(managedPath); !os.IsNotExist(err) {
		t.Errorf("--managed wrote %s (stat err=%v); it must write nothing", managedPath, err)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("--managed wrote into HOME: %v", entries)
	}
}

// The setup pre-run writes the new-install default for an install run, but
// not for --managed (writes nothing) or --write-managed (runs under sudo).
func TestSetupPreRun_SkipsManagedRuns(t *testing.T) {
	for _, flag := range []string{"managed", "write-managed", ""} {
		t.Run("flag="+flag, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			resetManagedFlags(t)
			if flag != "" {
				if err := setupClaudeCodeCmd.Flags().Set(flag, "true"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = setupClaudeCodeCmd.Flags().Set(flag, "false") })
			}
			_ = captureStdout(t, func() { _ = setupPreRun(setupClaudeCodeCmd, nil) })
			_, wrote := readConfigFile(t, home)
			if flag == "" && !wrote {
				t.Error("control: a plain setup run on a new machine must write the new-install default")
			}
			if flag != "" && wrote {
				t.Errorf("--%s must not write ~/.agentshield/agentshield.yaml", flag)
			}
		})
	}
}

// The three flags exclude each other.
func TestSetupClaudeCode_ManagedFlagsMutuallyExclusive(t *testing.T) {
	for _, args := range [][]string{
		{"--managed", "--write-managed"},
		{"--managed", "--disable"},
		{"--write-managed", "--disable"},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSetupProcess$")
		cmd.Env = append(os.Environ(),
			"AGENTSHIELD_SETUP_HELPER=1",
			"AGENTSHIELD_SETUP_ARGS=setup claude-code "+strings.Join(args, " "),
			"HOME="+t.TempDir(),
			"COPILOT_HOME=",
		)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("setup claude-code %v succeeded; want a flag error\n%s", args, out)
			continue
		}
		if !strings.Contains(string(out), "if any flags in the group") {
			t.Errorf("setup claude-code %v: want cobra's mutually-exclusive error, got:\n%s", args, out)
		}
	}
}

// End to end through the real command tree in a child process: --managed on
// a fresh HOME prints parseable JSON on stdout and leaves HOME empty.
func TestSetupManaged_ChildProcess_WritesNothing(t *testing.T) {
	home := newSetupHome(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSetupProcess$")
	cmd.Env = append(os.Environ(),
		"AGENTSHIELD_SETUP_HELPER=1",
		"AGENTSHIELD_SETUP_ARGS=setup claude-code --managed",
		"HOME="+home,
		"COPILOT_HOME=",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("setup claude-code --managed: %v\n%s", err, stderr.String())
	}
	// The child process does not run `go test`'s PASS line through stdout
	// when it exits from inside the test, so stdout is the snippet alone.
	ok, err := hookentry.SettingsHasPreToolUseHook(stdout.Bytes())
	if err != nil || !ok {
		t.Fatalf("stdout is not the managed-settings JSON: ok=%v err=%v\n%s", ok, err, stdout.String())
	}
	if !strings.Contains(stderr.String(), hookentry.ManagedSettingsPath(runtime.GOOS)) {
		t.Errorf("stderr does not name this OS's managed settings path:\n%s", stderr.String())
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("--managed wrote into HOME: %v", entries)
	}
}

// writeManaged runs the merge into a managed file holding content ("" means
// no file) and returns the result and the file's bytes afterwards.
func writeManaged(t *testing.T, content *string) (string, managedWrite, []byte, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.json")
	if content != nil {
		writeSettingsFile(t, path, *content)
	}
	res, err := writeManagedClaudeHook(path, "/opt/homebrew/bin/agentshield", true)
	data, _ := os.ReadFile(path)
	return path, res, data, err
}

func strPtr(s string) *string { return &s }

const orgPolicy = `{
  "permissions": {
    "deny": ["Read(./.env)", "Read(./secrets/**)"],
    "disableBypassPermissionsMode": "disable"
  },
  "allowManagedPermissionRulesOnly": true,
  "env": {"CLAUDE_CODE_ENABLE_TELEMETRY": "1"},
  "model": "opus",
  "cleanupPeriodDays": 30,
  "orgTicket": 12345678901234567890123,
  "ratio": 1.50,
  "banner": "<b>R&D</b> only",
  "futureKeyNobodyKnows": {"nested": [1, 2, {"x": null}]}
}`

// decodeJSONNumbers parses data as one JSON object, keeping numbers as
// written, so a comparison sees a precision loss float64 would hide.
func decodeJSONNumbers(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]interface{}
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, data)
	}
	return m
}

// mergeCases are the managed files --write-managed must merge into. want
// gives the AgentShield entry count after the merge.
func TestWriteManaged_Merge(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		_, res, data, err := writeManaged(t, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Added || !res.Created {
			t.Errorf("result = %+v; want a created file with the entry added", res)
		}
		snippet, _, _ := managedSettingsSnippet("/opt/homebrew/bin/agentshield", true)
		if !reflect.DeepEqual(decodeJSON(t, data), decodeJSON(t, snippet)) {
			t.Errorf("new file =\n%s\nwant the snippet", data)
		}
		if runtime.GOOS != "windows" && res.Mode != 0o644 {
			t.Errorf("new file mode = %#o; want 0644, readable by the user Claude Code runs as", res.Mode)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		_, res, data, err := writeManaged(t, strPtr(""))
		if err != nil {
			t.Fatal(err)
		}
		if !res.Added || res.Created {
			t.Errorf("result = %+v; want the entry added to the existing file", res)
		}
		if len(agentShieldHooks(decodeJSON(t, data))) != 1 {
			t.Errorf("empty file: want one AgentShield entry, got\n%s", data)
		}
	})

	t.Run("whitespace-only file", func(t *testing.T) {
		_, _, data, err := writeManaged(t, strPtr("  \n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(agentShieldHooks(decodeJSON(t, data))) != 1 {
			t.Errorf("want one AgentShield entry, got\n%s", data)
		}
	})

	t.Run("unrelated org keys are preserved", func(t *testing.T) {
		_, res, data, err := writeManaged(t, strPtr(orgPolicy))
		if err != nil {
			t.Fatal(err)
		}
		if !res.Added {
			t.Fatalf("result = %+v; want the entry added", res)
		}
		got := decodeJSONNumbers(t, data)
		hooks := got["hooks"]
		delete(got, "hooks")
		if want := decodeJSONNumbers(t, []byte(orgPolicy)); !reflect.DeepEqual(got, want) {
			t.Errorf("org keys changed in meaning:\n got %v\nwant %v", got, want)
		}
		if !bytes.Contains(data, []byte("12345678901234567890123")) {
			t.Errorf("a large integer was rewritten:\n%s", data)
		}
		if len(agentShieldHooks(map[string]interface{}{"hooks": hooks})) != 1 {
			t.Errorf("want one AgentShield entry, got %v", hooks)
		}
	})

	t.Run("already ours: idempotent, file untouched", func(t *testing.T) {
		snippet, _, _ := managedSettingsSnippet("/opt/homebrew/bin/agentshield", true)
		withOrg := decodeJSON(t, []byte(orgPolicy))
		withOrg["hooks"] = decodeJSON(t, snippet)["hooks"]
		raw, _ := json.Marshal(withOrg) // compact: a rewrite would re-indent it
		path, res, data, err := writeManaged(t, strPtr(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		if res.changed() {
			t.Errorf("result = %+v; want no change", res)
		}
		if !bytes.Equal(data, raw) {
			t.Errorf("file rewritten:\n%s\nwant it byte-for-byte unchanged:\n%s", data, raw)
		}
		// And a second full run on the merged output still gives one entry.
		if _, err := writeManagedClaudeHook(path, "/opt/homebrew/bin/agentshield", true); err != nil {
			t.Fatal(err)
		}
		again, _ := os.ReadFile(path)
		if n := len(agentShieldHooks(decodeJSON(t, again))); n != 1 {
			t.Errorf("after a second run: %d AgentShield entries; want 1", n)
		}
	})

	t.Run("twice from empty gives one entry", func(t *testing.T) {
		path, _, _, err := writeManaged(t, nil)
		if err != nil {
			t.Fatal(err)
		}
		first, _ := os.ReadFile(path)
		res, err := writeManagedClaudeHook(path, "/opt/homebrew/bin/agentshield", true)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := os.ReadFile(path)
		if res.changed() || !bytes.Equal(first, second) {
			t.Errorf("second run changed the file (res=%+v)", res)
		}
		if n := len(agentShieldHooks(decodeJSON(t, second))); n != 1 {
			t.Errorf("%d AgentShield entries; want 1", n)
		}
	})

	t.Run("a different hook entry is kept", func(t *testing.T) {
		other := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/org-audit","timeout":5}]}],` +
			`"SessionStart":[{"hooks":[{"type":"command","command":"/usr/local/bin/org-banner"}]}]}}`
		_, res, data, err := writeManaged(t, strPtr(other))
		if err != nil {
			t.Fatal(err)
		}
		if !res.Added {
			t.Fatalf("result = %+v; want the entry added", res)
		}
		got := decodeJSON(t, data)
		if !reflect.DeepEqual(otherHooks(got), otherHooks(decodeJSON(t, []byte(other)))) {
			t.Errorf("other hooks changed:\n%s", data)
		}
		groups := preToolUseGroups(got)
		if len(groups) != 2 {
			t.Fatalf("PreToolUse groups = %d; want the org's group plus ours", len(groups))
		}
		if !reflect.DeepEqual(groups[0], preToolUseGroups(decodeJSON(t, []byte(other)))[0]) {
			t.Errorf("the org's group was modified: %v", groups[0])
		}
		if len(agentShieldHooks(got)) != 1 {
			t.Errorf("want one AgentShield entry:\n%s", data)
		}
	})

	t.Run("shell-form entry migrates in place, keeping its keys", func(t *testing.T) {
		old := `{"model":"opus","hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook","timeout":10}]}]}}`
		_, res, data, err := writeManaged(t, strPtr(old))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Migrated) != 1 || res.Form != hookentry.Exec {
			t.Fatalf("result = %+v; want one migration to exec form", res)
		}
		h := agentShieldHooks(decodeJSON(t, data))
		if len(h) != 1 || h[0]["timeout"] != float64(10) || hookentry.Classify(h[0]) != hookentry.Exec {
			t.Errorf("migrated entry = %v; want exec form with timeout kept", h)
		}
	})

	t.Run("UTF-8 BOM is read", func(t *testing.T) {
		_, res, data, err := writeManaged(t, strPtr("\xef\xbb\xbf"+orgPolicy))
		if err != nil {
			t.Fatal(err)
		}
		if !res.Added || len(agentShieldHooks(decodeJSON(t, data))) != 1 {
			t.Errorf("BOM file: res=%+v\n%s", res, data)
		}
	})

	t.Run("disableAllHooks in the file is reported", func(t *testing.T) {
		_, res, _, err := writeManaged(t, strPtr(`{"disableAllHooks":true}`))
		if err != nil {
			t.Fatal(err)
		}
		if !res.DisablesAllHooks {
			t.Error("DisablesAllHooks = false; setup must warn that the managed hook will not run")
		}
	})

	t.Run("existing mode is kept", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX permission bits")
		}
		path := filepath.Join(t.TempDir(), "managed-settings.json")
		writeSettingsFile(t, path, orgPolicy)
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
		res, err := writeManagedClaudeHook(path, "/opt/homebrew/bin/agentshield", true)
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o640 || res.Mode != 0o640 {
			t.Errorf("mode = %#o (res %#o); want 0640 kept", fi.Mode().Perm(), res.Mode)
		}
	})

	t.Run("symlink: the target is written, the link kept", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real.json")
		writeSettingsFile(t, target, orgPolicy)
		link := filepath.Join(dir, "managed-settings.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("symlinks unavailable:", err)
		}
		if _, err := writeManagedClaudeHook(link, "/opt/homebrew/bin/agentshield", true); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the symlink was replaced (err=%v)", err)
		}
		data, _ := os.ReadFile(target)
		if len(agentShieldHooks(decodeJSON(t, data))) != 1 {
			t.Errorf("target not merged:\n%s", data)
		}
	})
}

// A file the merge cannot read as an object, or whose hooks it would have to
// replace, is refused and left byte-for-byte as it was.
func TestWriteManaged_RefusesMalformed(t *testing.T) {
	for _, tc := range []struct{ name, content, why string }{
		{"not JSON", `{"permissions": {"deny": [`, "does not parse"},
		{"trailing garbage", `{"model":"opus"} x`, "does not parse"},
		{"top level is an array", `[{"model":"opus"}]`, "not a JSON object"},
		{"top level is null", `null`, "not a JSON object"},
		{"top level is a string", `"agentshield"`, "not a JSON object"},
		{"hooks is a string", `{"hooks":"none"}`, `"hooks" is not a JSON object`},
		{"hooks is an array", `{"hooks":[]}`, `"hooks" is not a JSON object`},
		{"PreToolUse is an object", `{"hooks":{"PreToolUse":{"matcher":"Bash"}}}`, `"hooks.PreToolUse" is not a JSON array`},
		{"PreToolUse is null", `{"hooks":{"PreToolUse":null}}`, `"hooks.PreToolUse" is not a JSON array`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, data, err := writeManaged(t, strPtr(tc.content))
			if err == nil {
				t.Fatalf("merge into %q succeeded; want a refusal", tc.content)
			}
			if !strings.Contains(err.Error(), tc.why) || !strings.Contains(err.Error(), "not modified") {
				t.Errorf("error %q; want it to say %q and that the file was not modified", err, tc.why)
			}
			if string(data) != tc.content {
				t.Errorf("file changed to %q; want it left as %q", data, tc.content)
			}
		})
	}
}

// Without write access, --write-managed fails with the elevated-rights
// message and changes nothing. It never escalates.
func TestWriteManaged_PermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	t.Run("directory not writable", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "ClaudeCode")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "managed-settings.json")
		writeSettingsFile(t, path, orgPolicy)
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		_, err := writeManagedClaudeHook(path, "/opt/homebrew/bin/agentshield", true)
		assertElevationError(t, err)
		if data, _ := os.ReadFile(path); string(data) != orgPolicy {
			t.Errorf("file changed:\n%s", data)
		}
		if left, _ := filepath.Glob(filepath.Join(dir, ".agentshield-managed-settings-*")); len(left) != 0 {
			t.Errorf("temp files left behind: %v", left)
		}
	})
	t.Run("parent directory missing and not creatable", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
		_, err := writeManagedClaudeHook(filepath.Join(parent, "ClaudeCode", "managed-settings.json"), "/opt/homebrew/bin/agentshield", true)
		assertElevationError(t, err)
	})
	t.Run("file not readable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "managed-settings.json")
		writeSettingsFile(t, path, orgPolicy)
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
		_, err := writeManagedClaudeHook(path, "/opt/homebrew/bin/agentshield", true)
		assertElevationError(t, err)
	})
}

func assertElevationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("write succeeded without permission")
	}
	msg := err.Error()
	if !strings.Contains(msg, "administrator rights") || !strings.Contains(msg, elevatedWriteManagedCommand()) || !strings.Contains(msg, "does not elevate itself") {
		t.Errorf("error does not tell the user to re-run elevated:\n%s", msg)
	}
}

// --write-managed through the command writes the managed file and leaves
// ~/.claude alone (it usually runs under sudo).
func TestSetupWriteManaged_WritesManagedOnly(t *testing.T) {
	settingsPath := setupClaudeHome(t)
	home := filepath.Dir(filepath.Dir(settingsPath))
	managedPath := pinManagedSettingsPath(t)
	resetManagedFlags(t)
	managedFlag, writeManagedFlag, disableFlag = false, true, false

	var stdout bytes.Buffer
	setupClaudeCodeCmd.SetOut(&stdout)
	t.Cleanup(func() { setupClaudeCodeCmd.SetOut(nil) })
	if err := setupClaudeCodeCommand(setupClaudeCodeCmd, nil); err != nil {
		t.Fatalf("setup claude-code --write-managed: %v", err)
	}
	data, err := os.ReadFile(managedPath)
	if err != nil {
		t.Fatalf("managed file not written: %v", err)
	}
	h := agentShieldHooks(decodeJSON(t, data))
	if len(h) != 1 || hookentry.Classify(h[0]) != hookentry.Exec {
		t.Errorf("managed file hooks = %v; want one exec-form entry", h)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Errorf("--write-managed wrote into HOME: %v", entries)
	}
	if !strings.Contains(stdout.String(), managedPath) || !strings.Contains(stdout.String(), "/status") {
		t.Errorf("output does not name the file and the /status check:\n%s", stdout.String())
	}

	// The watchdog, reading the same path, now passes the managed scope.
	configDir := filepath.Join(home, ".agentshield")
	writeSettingsFile(t, filepath.Join(configDir, "managed.json"), `{"managed":true}`)
	var managedCheck *enterprise.WatchdogCheck
	for _, c := range enterprise.RunWatchdogOnce(configDir) {
		if c.Name == enterprise.ClaudeManagedHookCheckName {
			c := c
			managedCheck = &c
		}
	}
	if managedCheck == nil || !managedCheck.Passed {
		t.Errorf("after --write-managed the watchdog's managed-scope check = %+v; want passed", managedCheck)
	}
}
