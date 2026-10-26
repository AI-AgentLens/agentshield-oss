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
// Only Claude Code settings use this. The Windsurf, Cursor, Gemini, Codex and
// Copilot detectors keep their own checks.
package hookentry

import (
	"bytes"
	"encoding/json"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	// BinaryName is the program an exec-form entry must name.
	BinaryName = "agentshield"
	// Subcommand is the one argument an exec-form entry must pass.
	Subcommand = "hook"
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
func Classify(hook interface{}) Form {
	m, ok := hook.(map[string]interface{})
	if !ok {
		return None
	}
	cmd, ok := m["command"].(string)
	if !ok {
		return None
	}
	if args, hasArgs := m["args"]; hasArgs {
		if isExecProgram(cmd) && isExecArgs(args) {
			return Exec
		}
		return None
	}
	if isShellInvocation(cmd) {
		return Shell
	}
	return None
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
	f, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
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

// GroupHasAgentShieldHook reports whether a matcher group (an element of
// hooks.<Event>) contains at least one AgentShield hook object.
func GroupHasAgentShieldHook(group interface{}) bool {
	m, ok := group.(map[string]interface{})
	if !ok {
		return false
	}
	subHooks, _ := m["hooks"].([]interface{})
	for _, h := range subHooks {
		if IsAgentShieldHook(h) {
			return true
		}
	}
	return false
}

// utf8BOM is the byte-order mark some Windows editors write at the start of a
// UTF-8 file.
var utf8BOM = []byte("\xef\xbb\xbf")

// SettingsHasPreToolUseHook parses a Claude Code settings file and reports
// whether hooks.PreToolUse[*].hooks[*] holds an AgentShield hook object. A
// file that does not parse returns the parse error. A leading UTF-8 BOM is
// skipped: Claude Code loads such a file (measured on 2.1.296 and 2.1.138,
// #4292 review pass 1, C2) and encoding/json rejects it.
func SettingsHasPreToolUseHook(data []byte) (bool, error) {
	data = bytes.TrimPrefix(data, utf8BOM)
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, err
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	for _, group := range preToolUse {
		if GroupHasAgentShieldHook(group) {
			return true, nil
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

// ShellHook is the shell-form hook object for the binary at binPath.
func ShellHook(binPath string) map[string]interface{} {
	return map[string]interface{}{
		"type":    "command",
		"command": binPath + " " + Subcommand,
	}
}

// isExecProgram reports whether an exec-form command names the agentshield
// binary: "agentshield" itself or a path whose last element is exactly that.
// A trailing slash, a lookalike name or surrounding whitespace is rejected,
// because each names something Claude Code cannot spawn as our binary.
func isExecProgram(cmd string) bool {
	if cmd != strings.TrimSpace(cmd) {
		return false
	}
	return cmd == BinaryName || strings.HasSuffix(cmd, "/"+BinaryName)
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
