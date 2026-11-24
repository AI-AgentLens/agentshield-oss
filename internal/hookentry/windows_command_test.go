package hookentry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The three recognisers #5066 widens, each called for a given GOOS, so one
// table pins them on every OS from any OS.
//
//   - shell: Claude Code's shell form (Classify), which setup, scan and the
//     watchdog's Claude Code checks use.
//   - match: MatchesHookCommand, the Codex, Gemini CLI and Copilot CLI
//     command test in setup and scan.
//   - text: HookFile, the whole-file test the watchdog, status and setup use
//     for the five non-Claude hook files, here with Codex's shape. The
//     command is put in a hook file the way setup writes it, through
//     encoding/json, so on Windows its backslashes are doubled on disk.
type recognised struct{ shell, match, text bool }

// codexFile is a Codex hooks.json holding cmd where setup puts its command.
func codexFile(cmd string) []byte {
	file, err := json.MarshalIndent(map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{map[string]interface{}{
				"hooks": []interface{}{map[string]interface{}{"type": "command", "command": cmd}},
			}},
		},
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	return file
}

// recogniseOn is what setup's recognisers make of cmd: words only.
func recogniseOn(goos, cmd string) recognised {
	return recognised{
		shell: classifyOn(goos, map[string]interface{}{"type": "command", "command": cmd}) == Shell,
		match: matchesHookCommandOn(goos, anyProgram, cmd),
		text:  CodexHookFile.hasOn(goos, anyProgram, codexFile(cmd)),
	}
}

// reportOn is what the reporters (Present, CommandPresent,
// HookFile.Present) make of cmd when isFile says whether a program exists.
func reportOn(goos string, isFile func(string) bool, cmd string) recognised {
	return recognised{
		shell: presentOn(goos, isFile, map[string]interface{}{"type": "command", "command": cmd}),
		match: matchesHookCommandOn(goos, isFile, cmd),
		text:  CodexHookFile.hasOn(goos, isFile, codexFile(cmd)),
	}
}

// onMain is what main's tests, before #5066, made of cmd on every OS: the
// POSIX shell-form parse, the suffix and the substring.
func onMain(cmd string) recognised {
	return recognised{
		shell: isShellInvocation(cmd),
		match: strings.HasSuffix(cmd, "agentshield hook"),
		text:  bytes.Contains(codexFile(cmd), []byte("agentshield hook")),
	}
}

func noFile(string) bool { return false }

var (
	none = recognised{}
	all  = recognised{shell: true, match: true, text: true}
	// loose: the suffix and substring tests the non-Claude surfaces always
	// had accept it; Claude Code's structural test does not. Pre-existing on
	// every OS, and unchanged here.
	loose = recognised{match: true, text: true}
	// noShell: on Windows, the backslash command setup writes for Codex,
	// Gemini CLI and Copilot CLI. MatchesHookCommand and
	// HookFile accept it; Claude Code's shell form does not,
	// because Claude Code runs it through Git Bash, which drops the unquoted
	// backslashes, so the hook never starts (#5072 review). The same value
	// as loose, named for its reason.
	noShell = recognised{match: true, text: true}
)

// setupWindowsPath is what exec.LookPath returns on Windows for the
// installer's location (scripts/install.ps1: %LOCALAPPDATA%\Programs\AgentShield).
const setupWindowsPath = `C:\Users\u\AppData\Local\Programs\AgentShield\agentshield.exe`

// setupWindowsShellPath is setupWindowsPath as setup writes it into Claude
// Code's shell form on Windows: with forward slashes (ShellHook).
var setupWindowsShellPath = strings.ReplaceAll(setupWindowsPath, `\`, "/")

// commandRow is one command and what the three recognisers make of it off
// Windows (posix) and on Windows.
type commandRow struct {
	name           string
	cmd            string
	posix, windows recognised
}

func TestRecognisers_WindowsCommandTable(t *testing.T) {
	cases := []commandRow{
		// Accepted on Windows only: what setup writes there (#5066). On
		// macOS and Linux nothing changes. Claude Code's shell form takes
		// the forward-slash spelling only (#5072 review); the backslash
		// one, which setup writes for Codex, Gemini CLI and Copilot CLI, is
		// MatchesHookCommand's and HookFile's.
		{"setup's Claude Code shell form on Windows", setupWindowsShellPath + " hook", none, all},
		{"setup's Codex, Gemini and Copilot command on Windows", setupWindowsPath + " hook", none, noShell},
		{"mixed separators", `C:\Users\u/AppData\Local/agentshield.exe hook`, none, noShell},
		{"backslash only after the drive", `C:\Users/u/agentshield.exe hook`, none, noShell},
		{"backslash only before the name", `C:/Users/u\agentshield.exe hook`, none, noShell},
		{"upper-case name and extension", `C:\Tools\AGENTSHIELD.EXE hook`, none, noShell},
		{"upper-case name and extension, forward slashes", `C:/Tools/AGENTSHIELD.EXE hook`, none, all},
		{"lower-case drive, mixed-case name", `c:\tools\AgentShield.Exe hook`, none, noShell},
		{"lower-case drive, mixed-case name, forward slashes", `c:/tools/AgentShield.Exe hook`, none, all},
		{"non-ASCII letters in a directory", `C:\Users\José\AppData\Local\Programs\AgentShield\agentshield.exe hook`, none, noShell},
		{"non-ASCII letters in a directory, forward slashes", `C:/Users/José/AppData/Local/Programs/AgentShield/agentshield.exe hook`, none, all},
		{"8.3 short directory name", `C:\PROGRA~1\AgentShield\agentshield.exe hook`, none, noShell},
		{"8.3 short directory name, forward slashes", `C:/PROGRA~1/AgentShield/agentshield.exe hook`, none, all},
		{"dash in a directory", `C:\Users\u\my-tools\agentshield.exe hook`, none, noShell},
		{"dash in a directory, forward slashes", `C:/Users/u/my-tools/agentshield.exe hook`, none, all},
		{"go test temp dir", `C:\Users\u\AppData\Local\Temp\TestSetup_X123\001\agentshield.exe hook`, none, noShell},
		{"go test temp dir, forward slashes", `C:/Users/u/AppData/Local/Temp/TestSetup_X123/001/agentshield.exe hook`, none, all},
		{"mixed-case name, no extension, forward slashes", `C:/Tools/AgentShield hook`, none, all},
		// The suffix test already matched these everywhere, and the POSIX
		// parse already took the forward-slash one as shell form.
		{"no extension, backslashes", `C:\Tools\agentshield hook`, loose, loose},
		{"no extension, forward slashes", `C:/Tools/agentshield hook`, all, all},

		// Accepted everywhere, unchanged.
		{"bare", "agentshield hook", all, all},
		{"POSIX absolute", "/opt/homebrew/bin/agentshield hook", all, all},

		// Rejected everywhere: another program's name.
		{"lookalike agentshield-helper", `C:\Tools\agentshield-helper.exe hook`, none, none},
		{"lookalike notagentshield", `C:\Tools\notagentshield.exe hook`, none, none},
		{"lookalike, second extension", `C:\Tools\agentshield.exe.bat hook`, none, none},
		{"lookalike, long s folds to s", `C:\Tools\agentſhield.exe hook`, none, none},
		{"lookalike, Cyrillic a", `C:\Tools\аgentshield.exe hook`, none, none},
		{"directory named agentshield.exe", `C:\Tools\agentshield.exe\ hook`, none, none},
		{"alternate data stream", `C:\Tools\notes.txt:agentshield.exe hook`, none, none},

		// Rejected everywhere: agentshield as an argument to another program.
		{"echo", `echo C:\Tools\agentshield.exe hook`, none, none},
		{"cmd /c", `cmd /c C:\Tools\agentshield.exe hook`, none, none},
		{"cmd.exe by path", `C:\Windows\System32\cmd.exe /c C:\Tools\agentshield.exe hook`, none, none},
		{"powershell -c", `powershell -c C:\Tools\agentshield.exe hook`, none, none},
		{"start", `start C:\Tools\agentshield.exe hook`, none, none},
		{"chained after another command", `C:\x\a.exe & C:\Tools\agentshield.exe hook`, none, none},
		{"two hooks chained", `C:\Tools\agentshield.exe hook && C:\Tools\agentshield.exe hook`, none, none},

		// Rejected everywhere: not exactly `<path> hook`.
		{"extra argument", `C:\Tools\agentshield.exe hook --help`, none, none},
		{"flag before hook", `C:\Tools\agentshield.exe --mode audit-only hook`, none, none},
		{"two spaces", `C:\Tools\agentshield.exe  hook`, none, none},
		{"tab", "C:\\Tools\\agentshield.exe\thook", none, none},
		{"trailing space", `C:\Tools\agentshield.exe hook `, none, none},
		{"trailing CR", "C:\\Tools\\agentshield.exe hook\r", none, none},
		{"leading space", ` C:\Tools\agentshield.exe hook`, none, none},
		{"HOOK", `C:\Tools\agentshield.exe HOOK`, none, none},
		{"hookx", `C:\Tools\agentshield.exe hookx`, none, none},
		{"wrong subcommand", `C:\Tools\agentshield.exe version`, none, none},
		{"program only, no hook", `C:\Tools\agentshield.exe`, none, none},

		// Rejected everywhere: not an absolute drive-letter path. setup never
		// writes these on Windows, so recognising them is not needed.
		{"bare with .exe", "agentshield.exe hook", none, none},
		{"relative", `..\bin\agentshield.exe hook`, none, none},
		{"drive-relative", `C:agentshield.exe hook`, none, none},
		{"drive-relative with a directory", `C:x\agentshield.exe hook`, none, none},
		{"colon past the drive", `C:\a:b\agentshield.exe hook`, none, none},
		{"UNC", `\\server\share\agentshield.exe hook`, none, none},
		{"digit drive", `1:\Tools\agentshield.exe hook`, none, none},
		{"no colon after the letter", `ab\agentshield.exe hook`, none, none},
		{"drive only", `C: hook`, none, none},
		{"drive root only", `C:\ hook`, none, none},
		{"leading dash", `-C:\Tools\agentshield.exe hook`, none, none},

		// Rejected everywhere: a character some shell splits, expands, escapes
		// or quotes on. A path with a space is a residual: setup writes it
		// unquoted, and no shell runs it as one program.
		{"space (Program Files)", `C:\Program Files\AgentShield\agentshield.exe hook`, none, none},
		{"double-quoted path", `"C:\Program Files\AgentShield\agentshield.exe" hook`, none, none},
		{"single-quoted path", `'C:\Tools\agentshield.exe' hook`, none, none},
		{"ampersand", `C:\a&b\agentshield.exe hook`, none, none},
		{"pipe", `C:\a|b\agentshield.exe hook`, none, none},
		{"redirect", `C:\a>b\agentshield.exe hook`, none, none},
		{"semicolon", `C:\a;b\agentshield.exe hook`, none, none},
		{"comma", `C:\a,b\agentshield.exe hook`, none, none},
		{"equals", `C:\a=b\agentshield.exe hook`, none, none},
		{"percent variable", `C:\%TEMP%\agentshield.exe hook`, none, none},
		{"delayed expansion", `C:\!X!\agentshield.exe hook`, none, none},
		{"caret escape", `C:\a^&b\agentshield.exe hook`, none, none},
		{"dollar", `C:\$env:TEMP\agentshield.exe hook`, none, none},
		{"backquote", "C:\\a`nb\\agentshield.exe hook", none, none},
		{"parentheses", `C:\a(b)\agentshield.exe hook`, none, none},
		{"braces", `C:\{a,b}\agentshield.exe hook`, none, none},
		{"glob", `C:\*\agentshield.exe hook`, none, none},
		{"brackets", `C:\[a]\agentshield.exe hook`, none, none},
		{"hash", `C:\#\agentshield.exe hook`, none, none},
		{"at", `C:\@a\agentshield.exe hook`, none, none},
		{"plus", `C:\a+b\agentshield.exe hook`, none, none},
		{"no-break space", "C:\\a\u00a0b\\agentshield.exe hook", none, none},
		{"en dash (PowerShell reads it as -)", "C:\\a\u2013b\\agentshield.exe hook", none, none},
		{"curly quote (PowerShell reads it as ')", "C:\\a\u2019b\\agentshield.exe hook", none, none},
		{"NUL", "C:\\a\x00\\agentshield.exe hook", none, none},
		// Residual, pinned: a combining mark (a decomposed é) is not a
		// letter, so a directory spelled with one is refused. No shell
		// splits on it; refusing it is a false negative, as before.
		{"combining mark in a directory", "C:/Users/Jose\u0301/agentshield.exe hook", none, none},

		// Pre-existing and unchanged: the suffix and substring tests are
		// loose on every OS (#4326 tightened only Claude Code). Pinned so a
		// change is deliberate.
		{"gap: echo before the suffix", "echo agentshield hook", loose, loose},
		{"substring, not the suffix", "agentshield hook --help", recognised{text: true}, recognised{text: true}},
		{"gap: suffix of a lookalike", "/tmp/notagentshield hook", loose, loose},
		{"gap: Windows lookalike without .exe", `C:\Tools\notagentshield hook`, loose, loose},
	}
	// Every row rejected everywhere is rejected with forward slashes too, so
	// no rejection above rests on the shell form's backslash test alone.
	for _, tc := range cases {
		if tc.posix == none && tc.windows == none && strings.Contains(tc.cmd, `\`) {
			cases = append(cases, commandRow{tc.name + ", forward slashes", strings.ReplaceAll(tc.cmd, `\`, "/"), none, none})
		}
	}
	// One character at a time inside a directory, with either separator:
	// each splits, expands, escapes or quotes in at least one of sh,
	// cmd.exe and PowerShell, so no recogniser accepts it (#5072 review: no
	// row isolated these).
	for _, c := range []string{"?", "<", `"`, "'", "$", "^", "(", ")", "[", "]", "{", "}", "\t"} {
		for _, sep := range []string{`\`, "/"} {
			cmd := "C:" + sep + "a" + c + "b" + sep + "agentshield.exe hook"
			cases = append(cases, commandRow{fmt.Sprintf("%q in a directory, separator %s", c, sep), cmd, none, none})
		}
	}
	for _, tc := range cases {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			want := tc.posix
			if goos == "windows" {
				want = tc.windows
			}
			if got := recogniseOn(goos, tc.cmd); got != want {
				t.Errorf("%s on %s: %q recognised %+v, want %+v", tc.name, goos, tc.cmd, got, want)
			}
			// The reporters agree with setup while the program is a file,
			// and with no file accept exactly what main accepted
			// (#5072 pass 2).
			if got := reportOn(goos, anyProgram, tc.cmd); got != want {
				t.Errorf("%s on %s, program a file: %q reported %+v, want %+v", tc.name, goos, tc.cmd, got, want)
			}
			if got, was := reportOn(goos, noFile, tc.cmd), onMain(tc.cmd); got != was {
				t.Errorf("%s on %s, no program file: %q reported %+v, main reported %+v", tc.name, goos, tc.cmd, got, was)
			}
		}
	}
}

// classifyOn judges exec form for the GOOS it is given, as Classify does for
// runtime.GOOS (#4717); #5066 only threads the GOOS through.
func TestClassifyOn_ExecFormFollowsGOOS(t *testing.T) {
	hook := map[string]interface{}{"type": "command", "command": setupWindowsPath, "args": []interface{}{"hook"}}
	for goos, want := range map[string]Form{"windows": Exec, "linux": None, "darwin": None} {
		if got := classifyOn(goos, hook); got != want {
			t.Errorf("classifyOn(%s, exec form %s) = %v, want %v", goos, setupWindowsPath, got, want)
		}
	}
}

// HookFile's Windows test reads the file as JSON and wants the command, whole,
// where the integration keeps it: the Field of a hook under the Event setup
// writes. A copy anywhere else in the file does not count (#5072 pass 2):
// the harness never runs it. Off Windows these files are judged by the
// substring alone, as before, and so is the substring on Windows.
func TestHookFile_WindowsFileShapes(t *testing.T) {
	q, _ := json.Marshal(setupWindowsPath + " hook")
	cmd := string(q)
	other := `"C:\\Tools\\other.exe"`
	codex := `{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":` + cmd + `,"timeout":10,"statusMessage":"AgentShield: shell commands"}]}]}}`
	cases := []struct {
		name           string
		file           HookFile
		data           string
		posix, windows bool
	}{
		// The shape each setup writes, holding the Windows command.
		{"codex", CodexHookFile, codex, false, true},
		{"gemini-cli", GeminiCLIHookFile, `{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":` + cmd + `,"name":"agentshield","timeout":10000}]}]}}`, false, true},
		{"copilot-cli, bash key", CopilotCLIHookFile, `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":` + cmd + `,"env":{"AGENTSHIELD_AGENT_ID":"copilot-cli"},"timeoutSec":30}]}}`, false, true},
		{"windsurf", WindsurfHookFile, `{"hooks":{"pre_run_command":[{"command":` + cmd + `,"show_output":true}]}}`, false, true},
		{"cursor", CursorHookFile, `{"version":1,"hooks":{"beforeShellExecution":[{"command":` + cmd + `}]}}`, false, true},
		{"one UTF-8 BOM", CodexHookFile, "\xef\xbb\xbf" + codex, false, true},
		{"\\u escapes for the backslashes", CodexHookFile, `{"hooks":{"PreToolUse":[{"hooks":[{"command":"C:\u005cTools\u005cagentshield.exe hook"}]}]}}`, false, true},
		{"ours after another group and hook", CodexHookFile, `{"hooks":{"PreToolUse":[{"hooks":[{"command":` + other + `}]},{"hooks":[{"command":` + other + `},{"command":` + cmd + `}]}]}}`, false, true},
		{"elements of other types are skipped", CodexHookFile, `{"hooks":{"PreToolUse":[1,"x",null,[],{"hooks":"x"},{"hooks":[7,{"command":1},{"command":` + cmd + `}]}]}}`, false, true},

		// #5072 pass 2, finding 1: the command survives only in metadata,
		// and the hook the harness runs is another program.
		{"metadata: codex statusMessage", CodexHookFile, `{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"type":"command","command":` + other + `,"statusMessage":` + cmd + `}]}]}}`, false, false},
		{"metadata: gemini name", GeminiCLIHookFile, `{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":` + other + `,"name":` + cmd + `}]}]}}`, false, false},
		{"metadata: copilot env value", CopilotCLIHookFile, `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":` + other + `,"env":{"OLD":` + cmd + `}}]}}`, false, false},
		{"metadata: copilot powershell key, not bash", CopilotCLIHookFile, `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":` + other + `,"powershell":` + cmd + `}]}}`, false, false},
		{"metadata: windsurf note", WindsurfHookFile, `{"hooks":{"pre_run_command":[{"command":` + other + `,"note":` + cmd + `}]}}`, false, false},
		{"metadata: cursor top-level note", CursorHookFile, `{"note":` + cmd + `,"version":1,"hooks":{"beforeShellExecution":[{"command":` + other + `}]}}`, false, false},
		{"metadata: the matcher", CodexHookFile, `{"hooks":{"PreToolUse":[{"matcher":` + cmd + `,"hooks":[{"command":` + other + `}]}]}}`, false, false},
		// Reverse control: the command where it belongs, and metadata that
		// is something else.
		{"control: command right, statusMessage other", CodexHookFile, `{"hooks":{"PreToolUse":[{"hooks":[{"command":` + cmd + `,"statusMessage":` + other + `}]}]}}`, false, true},

		// The right field under another event, or at another depth.
		{"codex PostToolUse only", CodexHookFile, `{"hooks":{"PostToolUse":[{"hooks":[{"command":` + cmd + `}]}],"PreToolUse":[{"hooks":[{"command":` + other + `}]}]}}`, false, false},
		{"gemini file judged as codex (BeforeTool is not PreToolUse)", CodexHookFile, `{"hooks":{"BeforeTool":[{"hooks":[{"command":` + cmd + `}]}]}}`, false, false},
		{"codex hook not nested in a group", CodexHookFile, `{"hooks":{"PreToolUse":[{"command":` + cmd + `}]}}`, false, false},
		{"windsurf hook nested in a group", WindsurfHookFile, `{"hooks":{"pre_run_command":[{"hooks":[{"command":` + cmd + `}]}]}}`, false, false},
		{"event at the top level, not under hooks", WindsurfHookFile, `{"pre_run_command":[{"command":` + cmd + `}]}`, false, false},
		{"hooks is not an object", CodexHookFile, `{"hooks":[` + cmd + `]}`, false, false},
		{"event is not an array", CodexHookFile, `{"hooks":{"PreToolUse":{"hooks":[{"command":` + cmd + `}]}}}`, false, false},
		{"bare string document", CodexHookFile, cmd, false, false},
		{"only as an object key", CodexHookFile, `{"hooks":{` + cmd + `:true}}`, false, false},
		{"inside a longer command", CodexHookFile, `{"hooks":{"PreToolUse":[{"hooks":[{"command":"echo ` + strings.Trim(cmd, `"`) + `"}]}]}}`, false, false},
		{"double BOM does not parse", CodexHookFile, "\xef\xbb\xbf\xef\xbb\xbf" + codex, false, false},
		{"not JSON", CodexHookFile, setupWindowsPath + " hook", false, false},
		{"truncated JSON", CodexHookFile, codex[:len(codex)-2], false, false},
		{"empty", CodexHookFile, ``, false, false},

		// The substring, unchanged on every OS, and as loose as it was:
		// anywhere in the bytes counts. Pinned so a change is deliberate.
		{"substring, unchanged", CodexHookFile, `{"command":"agentshield hook"}`, true, true},
		{"gap, unchanged: substring in metadata", CodexHookFile, `{"hooks":{"PreToolUse":[{"hooks":[{"command":` + other + `,"statusMessage":"agentshield hook"}]}]}}`, true, true},
		{"substring in free text, unchanged", WindsurfHookFile, `# agentshield hook`, true, true},
		// The substring reads raw bytes, so an escaped space hides it on
		// every OS; the Windows test does not fall back to the suffix.
		{"escaped space, everywhere", CodexHookFile, `{"hooks":{"PreToolUse":[{"hooks":[{"command":"agentshield\u0020hook"}]}]}}`, false, false},
	}
	for _, tc := range cases {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			want := tc.posix
			if goos == "windows" {
				want = tc.windows
			}
			if got := tc.file.hasOn(goos, anyProgram, []byte(tc.data)); got != want {
				t.Errorf("%s on %s: Has = %v, want %v", tc.name, goos, got, want)
			}
			// With the program a file, Present agrees with Has; with none,
			// it is main's substring.
			if got := tc.file.hasOn(goos, func(string) bool { return true }, []byte(tc.data)); got != want {
				t.Errorf("%s on %s: Present (program a file) = %v, want %v", tc.name, goos, got, want)
			}
			if got, was := tc.file.hasOn(goos, noFile, []byte(tc.data)), strings.Contains(tc.data, "agentshield hook"); got != was {
				t.Errorf("%s on %s: Present (no program file) = %v, main's substring %v", tc.name, goos, got, was)
			}
		}
	}
}

// The layouts are the shapes setup writes, by name; the cli test
// TestHookFile_LayoutsAreWhatSetupWrites pins each against its writer.
func TestHookFile_Layouts(t *testing.T) {
	for _, c := range []struct {
		name string
		got  HookFile
		want HookFile
	}{
		{"windsurf", WindsurfHookFile, HookFile{Event: "pre_run_command", Field: "command"}},
		{"cursor", CursorHookFile, HookFile{Event: "beforeShellExecution", Field: "command"}},
		{"gemini-cli", GeminiCLIHookFile, HookFile{Event: "BeforeTool", Nested: true, Field: "command"}},
		{"codex", CodexHookFile, HookFile{Event: "PreToolUse", Nested: true, Field: "command"}},
		{"copilot-cli", CopilotCLIHookFile, HookFile{Event: "PreToolUse", Field: "bash"}},
	} {
		if c.got != c.want {
			t.Errorf("%s layout = %+v, want %+v", c.name, c.got, c.want)
		}
	}
}

// The reporters ask about the program, not the command: everything before
// " hook", as written, with either separator (#5072 pass 2).
func TestReporters_AskAboutTheProgramAsWritten(t *testing.T) {
	for _, cmd := range []string{
		setupWindowsPath + " hook",
		setupWindowsShellPath + " hook",
		`c:\tools\AgentShield.Exe hook`,
		`C:/Tools/AgentShield hook`,
	} {
		want := strings.TrimSuffix(cmd, " hook")
		var asked []string
		isFile := func(p string) bool { asked = append(asked, p); return p == want }
		got := reportOn("windows", isFile, cmd)
		if exp := recogniseOn("windows", cmd); got != exp {
			t.Errorf("%q with its program a file: reported %+v, want %+v", cmd, got, exp)
		}
		for _, p := range asked {
			if p != want {
				t.Errorf("%q: the reporters asked about %q, want %q", cmd, p, want)
			}
		}
		if len(asked) == 0 {
			t.Errorf("%q: no reporter asked about the program", cmd)
		}
	}
}

// programIsFile on the real file system: a regular file with at least one
// byte, following a symbolic link. Not a directory (one named
// agentshield.exe, say), not an empty file, not a missing path.
func TestProgramIsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "agentshield.exe")
	if err := os.WriteFile(file, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty", "agentshield.exe")
	asDir := filepath.Join(dir, "asdir", "agentshield.exe")
	if err := os.MkdirAll(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(empty), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path string
		want       bool
	}{
		{"regular file", file, true},
		{"regular file, forward slashes", filepath.ToSlash(file), true},
		{"empty file", empty, false},
		{"directory named agentshield.exe", asDir, false},
		{"missing", filepath.Join(dir, "gone", "agentshield.exe"), false},
		{"a file's path with a trailing separator", file + string(filepath.Separator), false},
	}
	link := filepath.Join(dir, "link", "agentshield.exe")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err == nil {
		dangling := filepath.Join(dir, "link", "dangling.exe")
		_ = os.Symlink(filepath.Join(dir, "nowhere"), dangling)
		dirLink := filepath.Join(dir, "link", "dir.exe")
		_ = os.Symlink(asDir, dirLink)
		cases = append(cases,
			struct {
				name, path string
				want       bool
			}{"symbolic link to the file", link, true},
			struct {
				name, path string
				want       bool
			}{"dangling symbolic link", dangling, false},
			struct {
				name, path string
				want       bool
			}{"symbolic link to a directory", dirLink, false},
		)
	} else {
		t.Logf("no symbolic link rows: %v", err)
	}
	for _, tc := range cases {
		if got := programIsFile(tc.path); got != tc.want {
			t.Errorf("%s (%s): programIsFile = %v, want %v", tc.name, tc.path, got, tc.want)
		}
	}
}

// The exported functions on the real OS and file system. setup's own Windows
// entries, named by a binary that exists: setup's recognisers and the
// reporters accept them on Windows only. Once the binary is gone, or is a
// directory or an empty file, setup still finds them (to rewrite or remove
// them) and the reporters do not. main's spellings are judged by their
// words on every OS, binary or not.
func TestRecognisers_RuntimeGOOS(t *testing.T) {
	onWindows := runtime.GOOS == "windows"
	dir := t.TempDir()
	bin := filepath.Join(dir, "agentshield.exe")

	hook := ShellHook(setupWindowsPath)
	if want := map[bool]string{true: setupWindowsShellPath + " hook", false: setupWindowsPath + " hook"}[onWindows]; hook["command"] != want {
		t.Errorf("ShellHook(%q) wrote %q on %s, want %q", setupWindowsPath, hook["command"], runtime.GOOS, want)
	}
	backslash := setupWindowsPath + " hook"
	if f := Classify(map[string]interface{}{"type": "command", "command": backslash}); f != None {
		t.Errorf("Classify(shell form %q) = %v on %s, want %v", backslash, f, runtime.GOOS, None)
	}

	// exported runs every exported test on the entries setup writes for bin
	// on this OS: Claude Code's shell form, and the command Codex, Gemini
	// CLI and Copilot CLI get. Each reporter is its own element, so one
	// cannot mask another.
	type verdicts struct {
		setup  [4]bool // Classify, MatchesHookCommand, CodexHookFile.Has, CopilotCLIHookFile.Has
		report [5]bool // Present, SettingsHasPreToolUseHook, CommandPresent, CodexHookFile.Present, CopilotCLIHookFile.Present
	}
	exported := func() verdicts {
		shell := ShellHook(bin)
		cmd := bin + " hook"
		settings, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{"hooks": []interface{}{shell}}}}})
		inSettings, err := SettingsHasPreToolUseHook(settings)
		if err != nil {
			t.Fatal(err)
		}
		codex := codexFile(cmd)
		copilot, _ := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{map[string]interface{}{"bash": cmd}}}})
		return verdicts{
			setup:  [4]bool{Classify(shell) == Shell, MatchesHookCommand(cmd), CodexHookFile.Has(codex), CopilotCLIHookFile.Has(copilot)},
			report: [5]bool{Present(shell), inSettings, CommandPresent(cmd), CodexHookFile.Present(codex), CopilotCLIHookFile.Present(copilot)},
		}
	}
	all4, all5 := [4]bool{true, true, true, true}, [5]bool{true, true, true, true, true}
	var none4 [4]bool
	var none5 [5]bool
	setupOnWindows := map[bool][4]bool{true: all4, false: none4}[onWindows]
	reportOnWindows := map[bool][5]bool{true: all5, false: none5}[onWindows]
	check := func(state string, want verdicts) {
		t.Helper()
		if got := exported(); got != want {
			t.Errorf("%s on %s: setup %v, reporters %v; want setup %v, reporters %v", state, runtime.GOOS, got.setup, got.report, want.setup, want.report)
		}
	}

	if err := os.WriteFile(bin, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	check("binary present", verdicts{setupOnWindows, reportOnWindows})
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	check("binary deleted", verdicts{setupOnWindows, none5})
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	check("binary an empty file", verdicts{setupOnWindows, none5})
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	check("a directory named agentshield.exe", verdicts{setupOnWindows, none5})

	// main's spellings: the extension-less path, with forward slashes for
	// Claude Code's shell form. No file is ever created for it, and every
	// test accepts it on every OS, as before #5066.
	plain := filepath.Join(dir, "missing", "agentshield")
	shell := map[string]interface{}{"type": "command", "command": filepath.ToSlash(plain) + " hook"}
	cmd := plain + " hook"
	for _, c := range []struct {
		name string
		got  bool
	}{
		{"Classify", Classify(shell) == Shell},
		{"Present", Present(shell)},
		{"MatchesHookCommand", MatchesHookCommand(cmd)},
		{"CommandPresent", CommandPresent(cmd)},
		{"CodexHookFile.Has", CodexHookFile.Has(codexFile(cmd))},
		{"CodexHookFile.Present", CodexHookFile.Present(codexFile(cmd))},
	} {
		if !c.got {
			t.Errorf("%s rejected main's spelling %q on %s, with no file behind it", c.name, cmd, runtime.GOOS)
		}
	}
}

// shellHookOn writes the shell form with forward slashes on Windows, and
// what it writes is what Classify accepts there (#5072 review). Off Windows
// it writes binPath as given, as before.
func TestShellHookOn_WritesTheFormClassifyAccepts(t *testing.T) {
	cases := []struct {
		goos, bin, want string
		form            Form
	}{
		{"windows", setupWindowsPath, `C:/Users/u/AppData/Local/Programs/AgentShield/agentshield.exe hook`, Shell},
		{"windows", `C:\Users\u/mixed\agentshield.exe`, `C:/Users/u/mixed/agentshield.exe hook`, Shell},
		{"windows", `C:/already/forward/agentshield.exe`, `C:/already/forward/agentshield.exe hook`, Shell},
		{"windows", "agentshield", "agentshield hook", Shell},
		// Residual, as before: a space splits the unquoted path under every
		// shell, so the entry is written but not recognised and never runs.
		{"windows", `C:\Users\John Smith\AppData\Local\Programs\AgentShield\agentshield.exe`, `C:/Users/John Smith/AppData/Local/Programs/AgentShield/agentshield.exe hook`, None},
		{"linux", "/usr/local/bin/agentshield", "/usr/local/bin/agentshield hook", Shell},
		{"darwin", "/opt/homebrew/bin/agentshield", "/opt/homebrew/bin/agentshield hook", Shell},
		// Off Windows a backslash is a file-name byte: left as it is, and
		// refused by the shell-form parse, as before.
		{"linux", `/odd\dir/agentshield`, `/odd\dir/agentshield hook`, None},
		{"darwin", setupWindowsPath, setupWindowsPath + " hook", None},
	}
	for _, tc := range cases {
		h := shellHookOn(tc.goos, tc.bin)
		if h["command"] != tc.want || h["type"] != "command" || len(h) != 2 {
			t.Errorf("shellHookOn(%s, %q) = %v, want command %q", tc.goos, tc.bin, h, tc.want)
		}
		if got := classifyOn(tc.goos, h); got != tc.form {
			t.Errorf("classifyOn(%s, shellHookOn(%q)) = %v, want %v", tc.goos, tc.bin, got, tc.form)
		}
	}
}

// FuzzRecognisers_POSIXUnchanged is the "byte-identical off Windows" claim as
// a property: on linux and darwin each widened recogniser, and each
// reporter, equals the test it replaced, for any input and whatever the file
// system holds. On every OS a reporter with no program file is exactly main's
// test, so the Windows-only acceptance needs a file (#5072 pass 2). On
// Windows, anything newly accepted is exactly `X:<sep><path> hook` whose path
// holds no shell metacharacter and ends in an agentshield binary name,
// checked here with an independent spelling of those rules.
func FuzzRecognisers_POSIXUnchanged(f *testing.F) {
	for _, s := range []string{
		"agentshield hook", "/opt/homebrew/bin/agentshield hook", "echo agentshield hook",
		setupWindowsPath + " hook", `C:/x/agentshield.exe hook`, `C:\x\agentshield hook`,
		`"C:\x\agentshield.exe" hook`, `C:\x\notagentshield.exe hook`, `{"command":"C:\\x\\agentshield.exe hook"}`,
		`C:\x y\agentshield.exe hook`, "C:\\x\\agentshield.exe hook\r", "",
	} {
		f.Add(s)
	}
	const metachars = " \t\r\n\x00\"'`$%!^&|;,=()<>[]{}*?#@+:"
	f.Fuzz(func(t *testing.T, s string) {
		files := []HookFile{WindsurfHookFile, CursorHookFile, GeminiCLIHookFile, CodexHookFile, CopilotCLIHookFile}
		always := func(string) bool { return true }
		hook := map[string]interface{}{"type": "command", "command": s}
		for _, goos := range []string{"linux", "darwin"} {
			if got, was := isShellInvocationOn(goos, s), isShellInvocation(s); got != was {
				t.Fatalf("%s shell form changed for %q: %v, was %v", goos, s, got, was)
			}
			for _, isFile := range []func(string) bool{always, noFile} {
				if got, was := presentOn(goos, isFile, hook), isShellInvocation(s); got != was {
					t.Fatalf("%s Present changed for %q: %v, was %v", goos, s, got, was)
				}
				if got, was := matchesHookCommandOn(goos, isFile, s), strings.HasSuffix(s, "agentshield hook"); got != was {
					t.Fatalf("%s MatchesHookCommand changed for %q: %v, was %v", goos, s, got, was)
				}
				for _, f := range files {
					for _, data := range [][]byte{[]byte(s), codexFile(s)} {
						if got, was := f.hasOn(goos, isFile, data), bytes.Contains(data, []byte("agentshield hook")); got != was {
							t.Fatalf("%s %+v changed for %q: %v, was %v", goos, f, data, got, was)
						}
					}
				}
			}
		}
		// With no program file, the reporters are main's tests on Windows
		// too, so everything the Windows branch adds to them needs a file.
		if got, was := presentOn("windows", noFile, hook), isShellInvocation(s); got != was {
			t.Fatalf("windows Present with no file = %v for %q, main %v", got, s, was)
		}
		if got, was := matchesHookCommandOn("windows", noFile, s), strings.HasSuffix(s, "agentshield hook"); got != was {
			t.Fatalf("windows CommandPresent with no file = %v for %q, main %v", got, s, was)
		}
		for _, f := range files {
			for _, data := range [][]byte{[]byte(s), codexFile(s)} {
				if got, was := f.hasOn("windows", noFile, data), bytes.Contains(data, []byte("agentshield hook")); got != was {
					t.Fatalf("windows %+v Present with no file = %v for %q, main %v", f, got, data, was)
				}
			}
		}
		for _, goos := range []string{"linux", "darwin"} {
			if got := shellHookOn(goos, s)["command"]; got != s+" hook" {
				t.Fatalf("%s ShellHook changed for %q: %q", goos, s, got)
			}
		}
		// Claude Code's shell form never takes a backslash on Windows: Git
		// Bash drops it and the hook does not start (#5072 review).
		if isShellInvocationOn("windows", s) && !isShellInvocation(s) && strings.Contains(s, `\`) {
			t.Fatalf("Windows shell form accepted %q, which holds a backslash", s)
		}
		if !isWindowsHookCommand(s) {
			return
		}
		prog, arg, ok := strings.Cut(s, " ")
		if !ok || arg != "hook" {
			t.Fatalf("Windows accepted %q: not exactly <program> hook", s)
		}
		drive := prog[0] | 0x20
		if len(prog) < 3 || drive < 'a' || drive > 'z' || prog[1] != ':' || (prog[2] != '\\' && prog[2] != '/') {
			t.Fatalf("Windows accepted %q: program is not an absolute drive path", s)
		}
		if i := strings.IndexAny(prog[2:], metachars); i >= 0 {
			t.Fatalf("Windows accepted %q: program holds %q", s, prog[2+i])
		}
		base := strings.ToLower(prog[strings.LastIndexAny(prog, `\/`)+1:])
		if base != "agentshield" && base != "agentshield.exe" {
			t.Fatalf("Windows accepted %q: program base %q is not the agentshield binary", s, base)
		}
	})
}

// settingsHasPreToolUseHookOn, the watchdog's Claude Code reader, asks
// Present: on Windows the forward-slash shell form counts only while its
// program is a file, exec form and main's shell forms count as before, and a
// file that does not parse is still an error (#5072 pass 2).
func TestSettingsHasPreToolUseHookOn_ProgramMustBeAFile(t *testing.T) {
	settings := func(hook string) []byte {
		return []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/bin/other"},` + hook + `]}]}}`)
	}
	shell := settings(`{"type":"command","command":"` + setupWindowsShellPath + ` hook"}`)
	exec := settings(`{"type":"command","command":"C:\\x\\agentshield.exe","args":["hook"]}`)
	plain := settings(`{"type":"command","command":"C:/x/agentshield hook"}`)
	always := func(string) bool { return true }
	for _, tc := range []struct {
		name   string
		goos   string
		isFile func(string) bool
		data   []byte
		want   bool
	}{
		{"Windows shell form, program a file", "windows", always, shell, true},
		{"Windows shell form, no program file", "windows", noFile, shell, false},
		{"exec form, no program file (main's, unchanged)", "windows", noFile, exec, true},
		{"main's shell form, no program file", "windows", noFile, plain, true},
		{"main's shell form, no program file, linux", "linux", noFile, plain, true},
		{"Windows shell form off Windows, program a file", "darwin", always, shell, false},
	} {
		got, err := settingsHasPreToolUseHookOn(tc.goos, tc.isFile, tc.data)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := settingsHasPreToolUseHookOn("windows", noFile, []byte(`{`)); err == nil {
		t.Error("a file that does not parse returned no error")
	}
}
