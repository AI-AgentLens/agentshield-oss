// Package hookentry is the one definition of "this Claude Code hook object is
// AgentShield's": the entry `agentshield setup claude-code` writes, `scan`
// reports, and the managed-mode watchdog requires. It lives in its own package
// because internal/enterprise (the watchdog) cannot import internal/cli.
//
// Two forms are recognised (#4292):
//
//   - Shell form, the historical one: {"command": "/abs/agentshield hook"}.
//     Claude Code hands the string to a shell, so a CLAUDE_CODE_SHELL_PREFIX
//     set from a committed project .claude/settings.json wraps it and decides
//     whether our hook runs.
//   - Exec form, Claude Code >= 2.1.139: {"command": "/abs/agentshield",
//     "args": ["hook"]}. Claude Code spawns the program directly, and the
//     shell prefix does not apply.
//
// Classify is Claude Code's check. The Windsurf, Cursor, Gemini, Codex and
// Copilot recognisers use MatchesHookCommand and HookFile, which keep the
// looser tests those surfaces always had and add only the Windows command
// (#5066). On Windows, Classify's shell form adds only the forward-slash
// spelling, the one Claude Code's Git Bash can start.
//
// Each test comes in two strengths. Classify, MatchesHookCommand and
// HookFile.Has are setup's: they find its own entry, to keep, rewrite or
// remove it, even when the binary it names has gone. Present,
// CommandPresent and HookFile.Present are the reporters' (the watchdog,
// status, scan): a spelling that only the Windows test accepts also needs
// the program it names to be a file (#5072 pass 2). Every spelling accepted
// before #5066 is judged the same way by both, as before.
package hookentry

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"unicode"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

const (
	// BinaryName is the program an exec-form entry must name.
	BinaryName = "agentshield"
	// Subcommand is the one argument an exec-form entry must pass.
	Subcommand = "hook"
	// HookCommand is the two-word command the Windsurf and Cursor templates
	// write, and the suffix of the one Codex, Gemini CLI and Copilot CLI get.
	HookCommand = BinaryName + " " + Subcommand
)

// Form says how a hook object invokes AgentShield, if it does.
type Form int

const (
	// None: the object does not invoke `agentshield hook`.
	None Form = iota
	// Shell: {"command": "... agentshield hook"} with no "args" key.
	Shell
	// Exec: {"command": ".../agentshield", "args": ["hook"]}.
	Exec
)

func (f Form) String() string {
	switch f {
	case Shell:
		return "shell form"
	case Exec:
		return "exec form"
	default:
		return "not AgentShield"
	}
}

// Classify reports whether one hook object (an element of
// hooks.<Event>[*].hooks in a Claude Code settings file) invokes
// `agentshield hook`, and in which form.
//
// Exec form requires the program's base name to be exactly "agentshield" and
// args to be exactly ["hook"]. Anything else is rejected: ["hook", "--help"]
// prints help and exits 0, which Claude Code reads as allow, and a lookalike
// such as agentshield-evil is some other program.
//
// An object with an "args" key is judged as exec form only. On Claude Code
// 2.1.296 a shell-form string such as "/abs/agentshield hook" carrying
// "args" of ["x"], [] or null never ran, while a plain shell-form and a plain
// exec-form hook in the same file did (measured 2026-10-12, #4292): the
// string is taken as the name of a program that does not exist.
func Classify(hook interface{}) Form { return classifyOn(runtime.GOOS, hook) }

// classifyOn is Classify for a given GOOS.
func classifyOn(goos string, hook interface{}) Form {
	m, ok := hook.(map[string]interface{})
	if !ok {
		return None
	}
	cmd, ok := m["command"].(string)
	if !ok {
		return None
	}
	if args, hasArgs := m["args"]; hasArgs {
		if isExecProgramOn(goos, cmd) && isExecArgs(args) {
			return Exec
		}
		return None
	}
	if isShellInvocationOn(goos, cmd) {
		return Shell
	}
	return None
}

// Present is Classify for a reporter: the watchdog's Claude Code checks
// (through SettingsHasPreToolUseHook) and scan. It differs from Classify for
// one spelling, the shell form only Windows accepts,
// `C:/.../agentshield.exe hook` (isWindowsShellHookCommand): that counts only
// when the program it names is a file (programIsFile). Before this check the
// watchdog reported such an entry healthy after its binary was deleted or
// moved, where Git Bash has nothing to start (#5072 pass 2). Exec form, and
// every shell form isShellInvocation accepts, are judged by their words, as
// before.
func Present(hook interface{}) bool { return presentOn(runtime.GOOS, programIsFile, hook) }

// presentOn is Present for a given GOOS and program test.
func presentOn(goos string, isFile func(string) bool, hook interface{}) bool {
	switch classifyOn(goos, hook) {
	case Exec:
		return true
	case Shell:
		cmd := hook.(map[string]interface{})["command"].(string)
		return isShellInvocation(cmd) || isFile(windowsProgram(cmd))
	}
	return false
}

// windowsProgram is the program of a command isWindowsHookCommand accepts:
// everything before " hook".
func windowsProgram(cmd string) string { return strings.TrimSuffix(cmd, " "+Subcommand) }

// programIsFile reports whether path names a regular file of at least one
// byte, following a symbolic link: the least a hook that names it needs in
// order to start. A missing path, a directory and an empty file fail, and so
// does a path the caller cannot stat. It does not check that the file is
// AgentShield, or that it is an executable at all.
func programIsFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Size() > 0
}

// anyProgram is the program test of setup's recognisers. They judge words
// only, so setup still finds, rewrites and removes an entry whose binary has
// gone.
func anyProgram(string) bool { return true }

// isShellInvocationOn is isShellInvocation for a given GOOS. Off Windows it
// is exactly isShellInvocation. On Windows it also accepts the shell-form
// command setup writes there, `C:/.../agentshield.exe hook`
// (isWindowsShellHookCommand), which isShellInvocation refuses for its .exe
// (#5066).
func isShellInvocationOn(goos, cmd string) bool {
	return isShellInvocation(cmd) || (goos == "windows" && isWindowsShellHookCommand(cmd))
}

// isWindowsShellHookCommand is isWindowsHookCommand with forward slashes
// only: the Claude Code shell-form command that runs on Windows.
//
// Claude Code on Windows runs a shell-form hook through Git Bash, which reads
// an unquoted backslash as an escape and drops it: `C:\x\agentshield.exe hook`
// runs `C:xagentshield.exe`, exits 127, and Claude Code treats that as a
// non-blocking error and runs the tool call. The forward-slash spelling ran
// under Git Bash, cmd.exe, Windows PowerShell 5.1 and pwsh 7 (Claude Code
// 2.1.302 on Windows 10, #5072 review). So a backslash command is not
// recognised here, as before #5066, and the watchdog keeps reporting such an
// entry as missing; ShellHook writes the forward-slash form on Windows.
func isWindowsShellHookCommand(cmd string) bool {
	return !strings.Contains(cmd, `\`) && isWindowsHookCommand(cmd)
}

// isWindowsHookCommand reports whether cmd is exactly the command setup
// writes on Windows, `<binPath> hook`, where binPath is the absolute path
// exec.LookPath or os.Executable returns there, with backslashes (Codex,
// Gemini CLI, Copilot CLI) or, for Claude Code's shell form, forward slashes
// (#5066). Claude Code's shell form accepts only the forward-slash spelling
// (isWindowsShellHookCommand).
//
// It is a structural test, not a wider suffix, so `echo C:\x\agentshield.exe
// hook` and `C:\x\notagentshield.exe hook` stay out. The program must be one
// plain word that no shell a harness might hand it to (sh, cmd.exe,
// PowerShell) reads as anything but a path:
//
//   - it starts with a drive letter, a colon and a separator (C:\ or C:/),
//     so a relative or bare name never matches here; the bare
//     `agentshield hook` is isShellInvocation's;
//   - the rest is Unicode letters and digits and `\ / . _ - ~` only: no
//     space, quote, `$`, `%`, `!`, `^`, `&`, `|`, `;`, `,`, `=`, `(`, `)`,
//     `[`, `]`, `{`, `}`, `*`, `?`, `#`, `@`, `+` or backquote, each of which
//     splits, expands, escapes or quotes in at least one of those shells;
//   - its last element is ASCII and names the binary as isExecProgramOn
//     reads it on Windows: agentshield or agentshield.exe, any case. ASCII,
//     so Unicode case folding (U+017F folds to s) cannot match another name.
//
// Exactly one space and "hook" follow, as setup writes them.
//
// A path with a space or one of those characters is not recognised, as on
// POSIX, where such a path is split by the shell. setup writes it unquoted
// all the same. Which shell runs it was measured for Claude Code only (Git
// Bash); for Codex, Gemini CLI and Copilot CLI it is not measured (#5066).
func isWindowsHookCommand(cmd string) bool {
	prog, ok := strings.CutSuffix(cmd, " "+Subcommand)
	if !ok || len(prog) < 3 {
		return false
	}
	if !isASCIILetter(prog[0]) || prog[1] != ':' || (prog[2] != '\\' && prog[2] != '/') {
		return false
	}
	for _, r := range prog[3:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(`\/._-~`, r) {
			return false
		}
	}
	base := prog[strings.LastIndexAny(prog, `/\`)+1:]
	for i := 0; i < len(base); i++ {
		if base[i] >= 0x80 {
			return false
		}
	}
	return isExecProgramOn("windows", prog)
}

func isASCIILetter(b byte) bool { return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' }

// MatchesHookCommand is the command test of the Codex, Gemini CLI and
// Copilot CLI recognisers in setup. Each applies it to the command field of
// its own event's hooks only.
//
// Off Windows it is the test those recognisers always had, unchanged: cmd
// ends with "agentshield hook". That test is loose. `echo agentshield hook`
// passes it; #4326 tightened only Claude Code's recogniser. On Windows it
// also accepts exactly the command setup writes there (isWindowsHookCommand),
// which the suffix misses because of the .exe (#5066).
func MatchesHookCommand(cmd string) bool { return matchesHookCommandOn(runtime.GOOS, anyProgram, cmd) }

// CommandPresent is MatchesHookCommand for a reporter (scan's Codex check):
// a command only the Windows test accepts counts only when the program it
// names is a file (programIsFile, #5072 pass 2). A command ending in
// "agentshield hook" is judged by its words, as before.
func CommandPresent(cmd string) bool { return matchesHookCommandOn(runtime.GOOS, programIsFile, cmd) }

func matchesHookCommandOn(goos string, isFile func(string) bool, cmd string) bool {
	if strings.HasSuffix(cmd, HookCommand) {
		return true
	}
	return goos == "windows" && isWindowsHookCommand(cmd) && isFile(windowsProgram(cmd))
}

// HookFile is where one integration's hook file keeps its hooks' commands:
// the Field of each element of hooks.<Event>, or with Nested, of each
// element of hooks.<Event>[*].hooks. The values below are the shapes setup
// writes; a cli test pins each one against its writer.
type HookFile struct {
	Event  string
	Nested bool
	Field  string
}

var (
	// WindsurfHookFile is ~/.codeium/windsurf/hooks.json (setup windsurf).
	WindsurfHookFile = HookFile{Event: "pre_run_command", Field: "command"}
	// CursorHookFile is ~/.cursor/hooks.json (setup cursor).
	CursorHookFile = HookFile{Event: "beforeShellExecution", Field: "command"}
	// GeminiCLIHookFile is ~/.gemini/settings.json (setup gemini-cli).
	GeminiCLIHookFile = HookFile{Event: "BeforeTool", Nested: true, Field: "command"}
	// CodexHookFile is ~/.codex/hooks.json (setup codex).
	CodexHookFile = HookFile{Event: "PreToolUse", Nested: true, Field: "command"}
	// CopilotCLIHookFile is AgentShield's file in Copilot CLI's hooks
	// directory (setup copilot-cli), which runs the "bash" command.
	CopilotCLIHookFile = HookFile{Event: "PreToolUse", Field: "bash"}
)

// Has reports whether a hook file holds AgentShield's hook, for setup: the
// Windsurf and Cursor "already configured" check and their --disable.
//
// Off Windows it is the test those surfaces always had, unchanged: the bytes
// contain "agentshield hook" anywhere. On Windows it also passes when one of
// the commands f locates (Commands) is exactly the command setup writes
// there (isWindowsHookCommand), which the substring misses twice over: JSON
// doubles its backslashes, and it ends in agentshield.exe hook (#5066).
//
// The Windows test reads those commands only. A copy of the command in a
// statusMessage, a note or another event does not count (#5072 pass 2): the
// harness never runs it, and --disable would otherwise set aside a file
// whose hooks are not AgentShield's. The substring is as loose as it always
// was, on every OS.
func (f HookFile) Has(data []byte) bool { return f.hasOn(runtime.GOOS, anyProgram, data) }

// Present is Has for a reporter: the watchdog and status. A command only the
// Windows test accepts counts only when the program it names is a file
// (programIsFile), so a hook whose binary was deleted or moved is reported
// missing (#5072 pass 2). The substring is judged as before.
func (f HookFile) Present(data []byte) bool { return f.hasOn(runtime.GOOS, programIsFile, data) }

func (f HookFile) hasOn(goos string, isFile func(string) bool, data []byte) bool {
	if bytes.Contains(data, []byte(HookCommand)) {
		return true
	}
	if goos != "windows" {
		return false
	}
	for _, cmd := range f.Commands(data) {
		if isWindowsHookCommand(cmd) && isFile(windowsProgram(cmd)) {
			return true
		}
	}
	return false
}

// Commands returns, in file order, the string value of Field in each hook
// f locates. A file that does not parse as JSON (after one UTF-8 BOM) has
// none, and so does an element of an unexpected type, which is skipped.
func (f HookFile) Commands(data []byte) []string {
	var doc map[string]interface{}
	if json.Unmarshal(bytes.TrimPrefix(data, utf8BOM), &doc) != nil {
		return nil
	}
	hooks, _ := doc["hooks"].(map[string]interface{})
	entries, _ := hooks[f.Event].([]interface{})
	var cmds []string
	for _, e := range entries {
		handlers := []interface{}{e}
		if f.Nested {
			group, _ := e.(map[string]interface{})
			handlers, _ = group["hooks"].([]interface{})
		}
		for _, h := range handlers {
			hook, _ := h.(map[string]interface{})
			if cmd, ok := hook[f.Field].(string); ok {
				cmds = append(cmds, cmd)
			}
		}
	}
	return cmds
}

// isShellInvocation reports whether a shell-form command is, parsed as shell,
// exactly one simple command whose program is the agentshield binary and whose
// only argument is "hook" (#4326). A suffix test let `echo agentshield hook`
// and `cmd; agentshield hook` through: the entry counted as installed while
// every tool call ran unevaluated.
// Every word must be literal, since an expansion decides at run time what runs;
// assignments, redirects and background are refused for the same reason.
func isShellInvocation(cmd string) bool {
	// mvdan/sh reads \r as a blank and stops at NUL; bash passes "hook\r" as the
	// argument and a spawn rejects NUL, so neither runs the hook. mvdan/sh also
	// ends a # comment at a backslash-newline and continues the command, where
	// every real shell ends it only at the newline: `agentshield #x\<NL>hook`
	// parses as `agentshield hook` but runs `agentshield` with no argument
	// (#4330 pass 2). setup never writes a continuation, so refuse them all.
	if strings.ContainsAny(cmd, "\r\x00") || strings.Contains(cmd, "\\\n") {
		return false
	}
	// A hook entry is "agentshield hook", so one past the chain bound (#4778)
	// is not it, and is not parsed.
	if shellparse.CheckChainBound(cmd) != nil {
		return false
	}
	f, err := shellparse.ParseText(cmd)
	if err != nil || len(f.Stmts) != 1 {
		return false
	}
	st := f.Stmts[0]
	if st.Background || st.Coprocess || st.Negated || len(st.Redirs) > 0 {
		return false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) != 2 {
		return false
	}
	prog, ok1 := literalWord(call.Args[0])
	arg, ok2 := literalWord(call.Args[1])
	if !ok1 || !ok2 || arg != Subcommand {
		return false
	}
	return prog == BinaryName || strings.HasSuffix(prog, "/"+BinaryName)
}

// literalWord returns the value of a word made only of literal text and quotes
// with no expansion in them.
func literalWord(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	for i, p := range w.Parts {
		switch n := p.(type) {
		case *syntax.Lit:
			// Unquoted glob and brace characters, and a leading tilde, expand at run time.
			if strings.ContainsAny(n.Value, "*?[{") || (i == 0 && strings.HasPrefix(n.Value, "~")) {
				return "", false
			}
			sb.WriteString(n.Value)
		case *syntax.SglQuoted:
			if n.Dollar {
				return "", false
			}
			sb.WriteString(n.Value)
		case *syntax.DblQuoted:
			if n.Dollar {
				return "", false
			}
			for _, q := range n.Parts {
				l, ok := q.(*syntax.Lit)
				if !ok {
					return "", false
				}
				sb.WriteString(l.Value)
			}
		default:
			return "", false
		}
	}
	v := sb.String()
	// A backslash in an unquoted Lit is an escape the parser leaves in place.
	if strings.Contains(v, `\`) {
		return "", false
	}
	return v, true
}

// IsAgentShieldHook reports whether one hook object invokes `agentshield hook`.
func IsAgentShieldHook(hook interface{}) bool {
	return Classify(hook) != None
}

// utf8BOM is the byte-order mark some Windows editors write at the start of a
// UTF-8 file.
var utf8BOM = []byte("\xef\xbb\xbf")

// SettingsHasPreToolUseHook parses a Claude Code settings file and reports
// whether hooks.PreToolUse[*].hooks[*] holds an AgentShield hook object that
// Present accepts. Its callers are the watchdog's reports, so the
// Windows-only shell form must name a program that is a file. A file that
// does not parse returns the parse error. A leading UTF-8 BOM is skipped:
// Claude Code loads such a file (measured on 2.1.296 and 2.1.138, #4292
// review pass 1, C2) and encoding/json rejects it.
func SettingsHasPreToolUseHook(data []byte) (bool, error) {
	return settingsHasPreToolUseHookOn(runtime.GOOS, programIsFile, data)
}

func settingsHasPreToolUseHookOn(goos string, isFile func(string) bool, data []byte) (bool, error) {
	data = bytes.TrimPrefix(data, utf8BOM)
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, err
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	for _, group := range preToolUse {
		m, _ := group.(map[string]interface{})
		subHooks, _ := m["hooks"].([]interface{})
		for _, h := range subHooks {
			if presentOn(goos, isFile, h) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ManagedSettingsPath is Claude Code's file-based managed settings path for
// the operating system goos (a runtime.GOOS value). A hook registered there
// survives a repository's committed .claude/settings.json setting
// "disableAllHooks": true; a user-scope hook does not. That was measured for a
// SessionStart hook on Claude Code 2.1.296 with the Linux path (2026-10-12,
// #4292); for PreToolUse, the event AgentShield registers, it is documented,
// not measured.
//
// Paths are from Claude Code's "Deploy managed settings" page,
// https://code.claude.com/docs/en/managed-settings ("Place the file on each
// machine" and "Where each mechanism stores the policy"), read 2026-10-19:
//
//   - macOS: /Library/Application Support/ClaudeCode/managed-settings.json
//   - Linux and WSL: /etc/claude-code/managed-settings.json
//   - Windows: C:\Program Files\ClaudeCode\managed-settings.json
//
// The same page says Claude Code doesn't read the legacy Windows path
// C:\ProgramData\ClaudeCode\managed-settings.json, which #4292's issue body
// still named. Only the Linux path has been measured; the macOS and Windows
// paths are documented, not measured.
//
// Any other goos gets the Linux path: Claude Code ships for macOS, Linux and
// Windows only, and WSL reports linux.
func ManagedSettingsPath(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	case "windows":
		return `C:\Program Files\ClaudeCode\managed-settings.json`
	default:
		return "/etc/claude-code/managed-settings.json"
	}
}

// ExecHook is the exec-form hook object for the binary at binPath.
func ExecHook(binPath string) map[string]interface{} {
	return map[string]interface{}{
		"type":    "command",
		"command": binPath,
		"args":    []interface{}{Subcommand},
	}
}

// ShellHook is the shell-form hook object for the binary at binPath. On
// Windows the path is written with forward slashes: Claude Code runs a
// shell-form hook through Git Bash there, which drops unquoted backslashes,
// so the backslash path never starts (isWindowsShellHookCommand, #5072
// review). Exec form keeps the native path, since no shell reads it.
func ShellHook(binPath string) map[string]interface{} { return shellHookOn(runtime.GOOS, binPath) }

// shellHookOn is ShellHook for a given GOOS. On Windows it is
// filepath.ToSlash(binPath).
func shellHookOn(goos, binPath string) map[string]interface{} {
	if goos == "windows" {
		binPath = strings.ReplaceAll(binPath, `\`, "/")
	}
	return map[string]interface{}{
		"type":    "command",
		"command": binPath + " " + Subcommand,
	}
}

// IsProgram reports whether a configured command names the agentshield
// binary, the way setup writes it: the bare name or a path ending in it, and
// on Windows agentshield.exe in any case. setup mcp and status use it to
// recognise a server they wrapped (#4717).
func IsProgram(cmd string) bool { return isExecProgram(cmd) }

// isExecProgram reports whether an exec-form command names the agentshield
// binary: "agentshield" itself or a path whose last element is exactly that.
// A trailing slash, a lookalike name or surrounding whitespace is rejected,
// because each names something Claude Code cannot spawn as our binary.
func isExecProgram(cmd string) bool {
	return isExecProgramOn(runtime.GOOS, cmd)
}

// isExecProgramOn is isExecProgram for a given GOOS. On Windows the binary
// setup writes is agentshield.exe, either separator ends the directory, and
// the file system ignores case, so C:\...\AgentShield.exe is the same
// program (#4717). Without this, setup could not see its own entry: every
// run appended another, and --disable found nothing to remove.
func isExecProgramOn(goos, cmd string) bool {
	if cmd != strings.TrimSpace(cmd) {
		return false
	}
	if goos != "windows" {
		return cmd == BinaryName || strings.HasSuffix(cmd, "/"+BinaryName)
	}
	base := cmd[strings.LastIndexAny(cmd, `/\`)+1:]
	return strings.EqualFold(base, BinaryName) || strings.EqualFold(base, BinaryName+".exe")
}

// isExecArgs reports whether args is exactly ["hook"].
func isExecArgs(args interface{}) bool {
	switch a := args.(type) {
	case []interface{}:
		if len(a) != 1 {
			return false
		}
		s, ok := a[0].(string)
		return ok && s == Subcommand
	case []string:
		return len(a) == 1 && a[0] == Subcommand
	default:
		return false
	}
}
