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
)

const (
	// BinaryName is the program an exec-form entry must name.
	BinaryName = "agentshield"
	// Subcommand is the one argument an exec-form entry must pass.
	Subcommand = "hook"
	// shellSuffix is what a shell-form command must end with. It is the check
	// every caller used before #4292, kept as it was.
	shellSuffix = BinaryName + " " + Subcommand
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
	if strings.HasSuffix(cmd, shellSuffix) {
		return Shell
	}
	return None
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
