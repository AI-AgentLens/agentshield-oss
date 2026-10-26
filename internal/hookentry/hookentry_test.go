package hookentry

import (
	"encoding/json"
	"testing"
)

// decode turns a JSON hook object into the shape callers hold after
// json.Unmarshal into map[string]interface{}, so the table exercises exactly
// what a settings file on disk produces.
func decode(t *testing.T, s string) interface{} {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("bad fixture %s: %v", s, err)
	}
	return v
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		hook string
		want Form
	}{
		// Accepted.
		{"shell form, absolute path", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}`, Shell},
		{"shell form, bare", `{"type":"command","command":"agentshield hook"}`, Shell},
		{"exec form, absolute path", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}`, Exec},
		{"exec form, bare program name", `{"type":"command","command":"agentshield","args":["hook"]}`, Exec},
		{"exec form, path with a space", `{"type":"command","command":"/Users/a b/bin/agentshield","args":["hook"]}`, Exec},

		// Rejected: not our command at all.
		{"echo mentioning agentshield", `{"type":"command","command":"echo \"agentshield was here\""}`, None},
		{"command merely contains agentshield", `{"type":"command","command":"/usr/bin/true agentshield"}`, None},
		{"agentshield hook not at the end", `{"type":"command","command":"agentshield hook --help"}`, None},
		// #4326: the suffix alone is not an invocation. Each of these ends
		// with "agentshield hook" and runs no hook.
		{"echo wrapper (watchdog false-healthy)", `{"type":"command","command":"echo agentshield hook"}`, None},
		{"printf wrapper", `{"type":"command","command":"printf %s agentshield hook"}`, None},
		{"compound, other command first", `{"type":"command","command":"true; agentshield hook"}`, None},
		{"compound, && chain", `{"type":"command","command":"false && agentshield hook"}`, None},
		{"or-list masks the verdict", `{"type":"command","command":"agentshield hook || true"}`, None},
		{"backgrounded", `{"type":"command","command":"agentshield hook &"}`, None},
		{"negated", `{"type":"command","command":"! agentshield hook"}`, None},
		{"assignment prefix", `{"type":"command","command":"PATH=/tmp agentshield hook"}`, None},
		{"redirected away", `{"type":"command","command":"agentshield hook >/dev/null"}`, None},
		{"lookalike program", `{"type":"command","command":"/tmp/xagentshield hook"}`, None},
		{"expansion decides the program", `{"type":"command","command":"$P agentshield hook"}`, None},
		{"expansion in the program path", `{"type":"command","command":"$HOME/bin/agentshield hook"}`, None},
		{"command substitution", `{"type":"command","command":"$(echo x)agentshield hook"}`, None},
		{"wrapper program", `{"type":"command","command":"env agentshield hook"}`, None},
		{"unparseable", `{"type":"command","command":"'agentshield hook"}`, None},
		{"subshell", `{"type":"command","command":"(agentshield hook)"}`, None},
		{"quoted program path with a space", `{"type":"command","command":"\"/Users/a b/bin/agentshield\" hook"}`, Shell},
		{"single-quoted program", `{"type":"command","command":"'/opt/bin/agentshield' hook"}`, Shell},
		// #4330 pass 1: shapes mvdan/sh accepts that a real shell does not run as
		// `agentshield hook`. Main rejected each; none may read as installed.
		{"trailing CR (bash passes hook\\r)", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook\r"}`, None},
		{"CRLF line ending", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook\r\n"}`, None},
		{"CR as the separator", `{"type":"command","command":"/opt/homebrew/bin/agentshield\rhook"}`, None},
		{"trailing NUL", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook\u0000"}`, None},
		{"brace expansion in the program path", `{"type":"command","command":"/opt/homebrew/bin{,}/agentshield 'hook'"}`, None},
		{"glob in the program path", `{"type":"command","command":"/x/*/agentshield 'hook'"}`, None},
		{"leading tilde expands", `{"type":"command","command":"~/bin/agentshield hook"}`, None},
		{"question-mark glob in the program path", `{"type":"command","command":"/x/?/agentshield 'hook'"}`, None},
		{"bracket glob in the program path", `{"type":"command","command":"/opt/homebrew/bi[n]/agentshield 'hook'"}`, None},
		// #4330 pass 2: mvdan/sh ends a comment at a backslash-newline; a real
		// shell runs `agentshield` with no argument, then `hook` (exit 127).
		{"comment ended by a line continuation", `{"type":"command","command":"/opt/homebrew/bin/agentshield #x\\\nhook"}`, None},
		{"bare, comment ended by a line continuation", `{"type":"command","command":"agentshield #\\\nhook"}`, None},
		// Mutation gaps from the same pass: each row kills one surviving mutant.
		{"second statement masks the exit code", `{"type":"command","command":"agentshield hook; true"}`, None},
		{"substitution inside double quotes", `{"type":"command","command":"\"$(x)/agentshield\" hook"}`, None},
		{"wrong subcommand", `{"type":"command","command":"/opt/homebrew/bin/agentshield version"}`, None},
		{"no command", `{"type":"command"}`, None},
		{"command not a string", `{"type":"command","command":["agentshield","hook"]}`, None},
		{"not an object", `"agentshield hook"`, None},

		// Rejected: exec form whose args do not run the hook.
		{"exec form, args null", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":null}`, None},
		{"exec form, args empty", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":[]}`, None},
		{"exec form, hook plus --help", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook","--help"]}`, None},
		{"exec form, --help only", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["--help"]}`, None},
		{"exec form, args a string", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":"hook"}`, None},
		{"exec form, args not strings", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":[1]}`, None},
		{"exec form, args uppercased", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["HOOK"]}`, None},
		{"exec form, hook prefix only", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hookx"]}`, None},
		{"exec form, flags before hook (downgrade tamper)", `{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["--mode","audit-only","hook"]}`, None},

		// Rejected: exec form naming another program.
		{"exec form, lookalike agentshield-evil", `{"type":"command","command":"/tmp/agentshield-evil","args":["hook"]}`, None},
		{"exec form, lookalike xagentshield", `{"type":"command","command":"/tmp/xagentshield","args":["hook"]}`, None},
		{"exec form, agentshield is a directory", `{"type":"command","command":"/tmp/agentshield/","args":["hook"]}`, None},
		{"exec form, trailing space", `{"type":"command","command":"/opt/homebrew/bin/agentshield ","args":["hook"]}`, None},
		{"exec form, leading space", `{"type":"command","command":" /opt/homebrew/bin/agentshield","args":["hook"]}`, None},
		{"exec form, other program", `{"type":"command","command":"/bin/echo","args":["hook"]}`, None},

		// Rejected: a shell-form string that also carries args is spawned as a
		// program named "/…/agentshield hook", which does not exist.
		{"shell string with args", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook","args":["hook"]}`, None},
		{"shell string with empty args", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook","args":[]}`, None},
		{"shell string with null args", `{"type":"command","command":"/opt/homebrew/bin/agentshield hook","args":null}`, None},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(decode(t, tc.hook)); got != tc.want {
				t.Errorf("Classify(%s) = %v; want %v", tc.hook, got, tc.want)
			}
			if got, want := IsAgentShieldHook(decode(t, tc.hook)), tc.want != None; got != want {
				t.Errorf("IsAgentShieldHook(%s) = %v; want %v", tc.hook, got, want)
			}
		})
	}
}

// TestBuildersRoundTrip pins that what setup writes is what every reader
// recognises, after the trip through a settings file on disk.
func TestBuildersRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		hook map[string]interface{}
		want Form
	}{
		{ExecHook("/opt/homebrew/bin/agentshield"), Exec},
		{ShellHook("/opt/homebrew/bin/agentshield"), Shell},
		{ShellHook("agentshield"), Shell},
	} {
		if got := Classify(tc.hook); got != tc.want {
			t.Errorf("Classify(%v) in memory = %v; want %v", tc.hook, got, tc.want)
		}
		raw, err := json.Marshal(tc.hook)
		if err != nil {
			t.Fatal(err)
		}
		if got := Classify(decode(t, string(raw))); got != tc.want {
			t.Errorf("Classify(%s) after a JSON round trip = %v; want %v", raw, got, tc.want)
		}
	}
	// Go callers may build args as []string; it means the same thing.
	if got := Classify(map[string]interface{}{"command": "/x/agentshield", "args": []string{"hook"}}); got != Exec {
		t.Errorf("[]string args: Classify = %v; want exec form", got)
	}
	if got := Classify(map[string]interface{}{"command": "/x/agentshield", "args": []string{"hook", "--help"}}); got != None {
		t.Errorf("[]string args with --help: Classify = %v; want none", got)
	}
}

func TestSettingsHasPreToolUseHook(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		want     bool
		wantErr  bool
	}{
		{"exec form", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, true, false},
		{"shell form", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, true, false},
		{"ours beside another hook in the same group", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/other"},{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, true, false},
		{"exec form with args removed", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield"}]}]}}`, false, false},
		{"echo replacing the hook", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo \"agentshield was here\""}]}]}}`, false, false},
		{"our command under another event only", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, false, false},
		{"our command as free text outside hooks", `{"note":"/opt/homebrew/bin/agentshield hook","hooks":{"PreToolUse":[]}}`, false, false},
		{"no hooks", `{}`, false, false},
		{"hooks is not an object", `{"hooks":"agentshield hook"}`, false, false},
		{"not JSON", `agentshield hook`, false, true},
		{"UTF-8 BOM, exec form", "\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, true, false},
		{"UTF-8 BOM, shell form", "\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, true, false},
		{"UTF-8 BOM, no hook", "\xef\xbb\xbf" + `{"hooks":{}}`, false, false},
		// Exactly one leading BOM is skipped. Claude Code rejects a double BOM
		// (#4314 pass 2), so these must not parse.
		{"double BOM", "\xef\xbb\xbf\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, false, true},
		{"triple BOM", "\xef\xbb\xbf\xef\xbb\xbf\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, false, true},
		{"BOM only", "\xef\xbb\xbf", false, true},
		{"partial BOM", "\xef\xbb" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, false, true},
		{"BOM bytes reordered", "\xbb\xef\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SettingsHasPreToolUseHook([]byte(tc.settings))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v; wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("SettingsHasPreToolUseHook = %v; want %v", got, tc.want)
			}
		})
	}
}

// The managed settings paths are the ones Claude Code documents
// (https://code.claude.com/docs/en/managed-settings, read 2026-10-19). The
// Windows path is under Program Files: Claude Code no longer reads the legacy
// C:\ProgramData location (#4292 PR B).
func TestManagedSettingsPath(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  "/Library/Application Support/ClaudeCode/managed-settings.json",
		"linux":   "/etc/claude-code/managed-settings.json",
		"windows": `C:\Program Files\ClaudeCode\managed-settings.json`,
		"freebsd": "/etc/claude-code/managed-settings.json",
	} {
		if got := ManagedSettingsPath(goos); got != want {
			t.Errorf("ManagedSettingsPath(%q) = %q; want %q", goos, got, want)
		}
	}
}
