package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// The bare-invocation backstop (#4292).
//
// `agentshield setup claude-code` registers the hook in exec form,
// {"command": "/abs/agentshield", "args": ["hook"]}, so that a
// CLAUDE_CODE_SHELL_PREFIX set by a committed project settings file cannot
// wrap it. Claude Code 2.1.139 and later honour "args". Claude Code 2.1.138
// and earlier accept the file but drop "args" and run "command" alone
// (measured: the probe saw argc=0). That is a bare `agentshield` with the hook
// payload on stdin, which used to print help and exit 0, and Claude Code reads
// exit 0 as allow.
//
// A version gate cannot fix that: the VS Code extension and the desktop app
// can bundle their own Claude Code, which reads the same ~/.claude/settings.json.
// So the binary itself recognises the case. A bare `agentshield` whose stdin
// is a hook payload runs `agentshield hook` on those bytes; anything else
// prints help and exits 0, as before.

// hookStdin is where `agentshield hook` reads its payload: os.Stdin, unless a
// bare invocation already consumed stdin to recognise the payload, in which
// case it holds those buffered bytes.
var hookStdin io.Reader

func hookStdinReader() io.Reader {
	if hookStdin != nil {
		return hookStdin
	}
	return os.Stdin
}

// bareStdin is the part of *os.File the backstop needs.
type bareStdin interface {
	io.Reader
	Stat() (os.FileInfo, error)
}

// bareHookInput decides whether a bare `agentshield` was spawned as a hook.
// It returns the reader `agentshield hook` must consume and true, or false
// when the invocation should print help as it always has.
//
//   - stdin closed or not stat-able: help.
//   - stdin a character device (a terminal, or /dev/null): help, without
//     reading, so an interactive run never waits on the keyboard.
//   - stdin a pipe, socket or file: read it all, as `agentshield hook` does.
//     The bytes route to the hook when they are a JSON object whose
//     hook_event_name is a string; empty input, non-JSON, and JSON without
//     that field print help.
//   - a read error: the hook gets the bytes read so far and then the same
//     error, so it takes the same input-failure path (fail-safe AUDIT, or
//     BLOCK under managed fail_closed) that `agentshield hook` takes on a
//     failed read. Help would be exit 0, an allow.
func bareHookInput(stdin bareStdin) (io.Reader, bool) {
	fi, err := stdin.Stat()
	if err != nil {
		return nil, false
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return nil, false
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		return io.MultiReader(bytes.NewReader(data), errReader{err}), true
	}
	if !isHookPayload(data) {
		return nil, false
	}
	return bytes.NewReader(data), true
}

// isHookPayload reports whether data is a JSON object carrying a string
// hook_event_name: Claude Code sends one on every hook event, as do Codex,
// Gemini CLI and Cursor. The field is decoded the way hookInput decodes it,
// so the two agree on what counts.
func isHookPayload(data []byte) bool {
	var probe struct {
		HookEventName *string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.HookEventName != nil
}

// errReader returns err on every read.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }
