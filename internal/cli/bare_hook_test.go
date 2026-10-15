package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests pin the bare-invocation backstop (#4292). Claude Code 2.1.138
// and earlier drop an exec-form hook's "args" and run `agentshield` bare with
// the hook payload on stdin. That must decide exactly as `agentshield hook`
// does; every other bare invocation must still print help and exit 0.

// TestHelperBareInvocation is the re-exec target: it runs the real Execute()
// entry point with the argv in AGENTSHIELD_BARE_HELPER_ARGV (JSON) and exits
// as cmd/agentshield's main would.
func TestHelperBareInvocation(t *testing.T) {
	argvJSON := os.Getenv("AGENTSHIELD_BARE_HELPER_ARGV")
	if argvJSON == "" {
		return
	}
	var argv []string
	if err := json.Unmarshal([]byte(argvJSON), &argv); err != nil {
		os.Exit(99)
	}
	os.Args = argv
	if err := Execute(); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

type invocation struct {
	stdout, stderr string
	code           int
}

// stdinMode says what the child's stdin is.
type stdinMode int

const (
	stdinPipe    stdinMode = iota // a pipe carrying the given bytes, then EOF
	stdinDevNull                  // exec.Cmd's default for a nil Stdin
	stdinClosed                   // fd 0 not open at all
)

// invokeAgentshield runs Execute() in a child process with the given argv,
// HOME, and stdin, and returns what a harness would see.
func invokeAgentshield(t *testing.T, home string, argv []string, mode stdinMode, stdin string) invocation {
	t.Helper()
	argvJSON, _ := json.Marshal(argv)
	self := []string{os.Args[0], "-test.run=^TestHelperBareInvocation$"}
	var cmd *exec.Cmd
	if mode == stdinClosed {
		cmd = exec.Command("/bin/sh", append([]string{"-c", `exec "$0" "$@" <&-`}, self...)...)
	} else {
		cmd = exec.Command(self[0], self[1:]...)
	}
	env := []string{"AGENTSHIELD_BARE_HELPER_ARGV=" + string(argvJSON), "HOME=" + home}
	for _, kv := range os.Environ() {
		// The host's own bypass or harness identity must not leak into the child.
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "AGENTSHIELD_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	if mode == stdinPipe {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running %v: %v", argv, err)
		}
		code = ee.ExitCode()
	}
	return invocation{stdout: out.String(), stderr: errb.String(), code: code}
}

// freshHookHome is a HOME holding only a valid policy, so the embedded
// community rules decide. Each invocation gets its own, so session state one
// run leaves behind cannot change the next run's decision.
func freshHookHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(failSafePolicyGood), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

const claudeCodePayloadBenign = `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"exit-code-test","tool_input":{"command":"ls -la"}}`

// A bare invocation with a PreToolUse payload decides exactly as
// `agentshield hook` does on the same bytes: stdout, stderr and exit code.
// On main the bare run printed help and exited 0 — an allow of a command the
// hook blocks.
func TestBareInvocation_DecidesExactlyLikeHook(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payload  string
		wantCode int
	}{
		{"BLOCK", claudeCodePayloadDestructive, 2},
		{"ALLOW/AUDIT", claudeCodePayloadBenign, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := invokeAgentshield(t, freshHookHome(t), []string{"agentshield", "hook"}, stdinPipe, tc.payload)
			bare := invokeAgentshield(t, freshHookHome(t), []string{"agentshield"}, stdinPipe, tc.payload)

			// Control: the hook itself decided as expected, so the comparison
			// below is between two decisions, not two help screens.
			if hook.code != tc.wantCode || strings.Contains(hook.stdout, "Usage:") {
				t.Fatalf("control: `agentshield hook` exit=%d stdout=%q; want exit %d and no help", hook.code, hook.stdout, tc.wantCode)
			}
			if bare.code != hook.code {
				t.Errorf("exit code: bare=%d hook=%d", bare.code, hook.code)
			}
			if bare.stdout != hook.stdout {
				t.Errorf("stdout differs:\nbare %q\nhook %q", bare.stdout, hook.stdout)
			}
			if bare.stderr != hook.stderr {
				t.Errorf("stderr differs:\nbare %q\nhook %q", bare.stderr, hook.stderr)
			}
		})
	}
}

// Every bare invocation that is not a hook payload prints the same help as
// `agentshield --help` and exits 0, as on main.
func TestBareInvocation_NonHookStdinPrintsHelp(t *testing.T) {
	help := invokeAgentshield(t, t.TempDir(), []string{"agentshield", "--help"}, stdinDevNull, "")
	if help.code != 0 || !strings.Contains(help.stdout, "Usage:") {
		t.Fatalf("control: --help exit=%d stdout=%q", help.code, help.stdout)
	}
	for _, tc := range []struct {
		name  string
		mode  stdinMode
		stdin string
	}{
		{"no stdin (/dev/null)", stdinDevNull, ""},
		{"closed stdin", stdinClosed, ""},
		{"empty pipe", stdinPipe, ""},
		{"not JSON", stdinPipe, "hello\n"},
		{"JSON array", stdinPipe, `["hook_event_name"]`},
		{"JSON without hook_event_name", stdinPipe, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`},
		{"Cursor-shaped payload", stdinPipe, `{"command":"ls","cwd":"/tmp"}`},
		{"hook_event_name not a string", stdinPipe, `{"hook_event_name":1,"tool_name":"Bash"}`},
		{"hook_event_name null", stdinPipe, `{"hook_event_name":null,"tool_name":"Bash"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := invokeAgentshield(t, t.TempDir(), []string{"agentshield"}, tc.mode, tc.stdin)
			if got.code != 0 {
				t.Errorf("exit = %d; want 0", got.code)
			}
			if got.stdout != help.stdout {
				t.Errorf("stdout is not the --help text:\n%s", got.stdout)
			}
		})
	}
}

// fakeStdin is a bareStdin whose mode and contents a test controls. It
// records whether anything read it.
type fakeStdin struct {
	mode    fs.FileMode
	statErr error
	r       io.Reader
	reads   int
}

func (f *fakeStdin) Stat() (os.FileInfo, error) {
	if f.statErr != nil {
		return nil, f.statErr
	}
	return fakeInfo{mode: f.mode}, nil
}

func (f *fakeStdin) Read(p []byte) (int, error) {
	f.reads++
	return f.r.Read(p)
}

type fakeInfo struct{ mode fs.FileMode }

func (i fakeInfo) Name() string       { return "stdin" }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() interface{}   { return nil }

// A terminal on stdin is never read, even when it would carry a payload: an
// interactive `agentshield` must print help at once, not wait on the keyboard.
func TestBareHookInput_TerminalIsNeverRead(t *testing.T) {
	tty := &fakeStdin{mode: fs.ModeDevice | fs.ModeCharDevice | 0o620, r: strings.NewReader(claudeCodePayloadDestructive)}
	if _, ok := bareHookInput(tty); ok {
		t.Error("a terminal stdin was routed to the hook")
	}
	if tty.reads != 0 {
		t.Errorf("a terminal stdin was read %d time(s); want 0", tty.reads)
	}
}

func TestBareHookInput_Decisions(t *testing.T) {
	pipe := fs.ModeNamedPipe | 0o600
	socket := fs.ModeSocket | 0o600 // what Claude Code's spawn hands a child on Unix
	for _, tc := range []struct {
		name    string
		mode    fs.FileMode
		statErr error
		input   string
		want    bool
	}{
		{"pipe with PreToolUse payload", pipe, nil, claudeCodePayloadDestructive, true},
		{"socket with PreToolUse payload", socket, nil, claudeCodePayloadDestructive, true},
		{"regular file with payload", 0o600, nil, claudeCodePayloadBenign, true},
		{"empty hook_event_name is still a string", pipe, nil, `{"hook_event_name":""}`, true},
		{"stat fails (closed stdin)", 0, os.ErrClosed, claudeCodePayloadDestructive, false},
		{"empty", pipe, nil, "", false},
		{"not JSON", pipe, nil, "{", false},
		{"JSON without the field", pipe, nil, `{"tool_name":"Bash"}`, false},
		{"field not a string", pipe, nil, `{"hook_event_name":["PreToolUse"]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdin := &fakeStdin{mode: tc.mode, statErr: tc.statErr, r: strings.NewReader(tc.input)}
			in, ok := bareHookInput(stdin)
			if ok != tc.want {
				t.Fatalf("routed to hook = %v; want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			// The hook must see exactly the bytes the backstop consumed.
			got, err := io.ReadAll(in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.input {
				t.Errorf("hook reads %q; want the same bytes %q", got, tc.input)
			}
		})
	}
}

// A read that fails part-way goes to the hook, which sees the same bytes and
// then the same error, so it takes the input-failure path `agentshield hook`
// takes (BLOCK under managed fail_closed) instead of help's exit 0.
func TestBareHookInput_ReadErrorReachesTheHook(t *testing.T) {
	boom := errors.New("boom")
	stdin := &fakeStdin{mode: fs.ModeNamedPipe, r: io.MultiReader(strings.NewReader(`{"hook_event`), errReader{boom})}
	in, ok := bareHookInput(stdin)
	if !ok {
		t.Fatal("a failed read printed help (exit 0, an allow); want it routed to the hook")
	}
	got, err := io.ReadAll(in)
	if !errors.Is(err, boom) {
		t.Errorf("hook read error = %v; want %v", err, boom)
	}
	if string(got) != `{"hook_event` {
		t.Errorf("hook read %q before the error; want the bytes read so far", got)
	}
}

// The backstop is for a bare `agentshield` only. An invocation with a
// subcommand or a flag keeps its meaning even with a hook payload on stdin.
func TestBareInvocation_OnlyWithoutArguments(t *testing.T) {
	for _, argv := range [][]string{
		{"agentshield", "version"},
		{"agentshield", "--mode", "audit-only"},
	} {
		t.Run(strings.Join(argv[1:], " "), func(t *testing.T) {
			want := invokeAgentshield(t, t.TempDir(), argv, stdinDevNull, "")
			got := invokeAgentshield(t, freshHookHome(t), argv, stdinPipe, claudeCodePayloadDestructive)
			if got.code != want.code || got.stdout != want.stdout {
				t.Errorf("%v with a hook payload on stdin: exit=%d stdout=%q; want exit=%d stdout=%q (the same as without one)",
					argv, got.code, got.stdout, want.code, want.stdout)
			}
		})
	}
}

// managedFailClosedHome is a HOME with a valid policy and managed mode set to
// fail_closed, so `agentshield hook` BLOCKs input it cannot parse.
func managedFailClosedHome(t *testing.T) string {
	t.Helper()
	home := freshHookHome(t)
	managed := `{"managed": true, "organization_id": "test-4314", "fail_closed": true}`
	if err := os.WriteFile(filepath.Join(home, ".agentshield", "managed.json"), []byte(managed), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// ACCEPTED RESIDUAL (Gary, 2026-10-12; #4314 Codex F1). This test pins the gap;
// it does not endorse it.
//
// Under managed fail_closed, `agentshield hook` BLOCKs hook input it cannot
// parse (truncated, empty or closed stdin). A bare `agentshield` prints help
// and exits 0 on the same input, because the backstop only takes the hook path
// for a well-formed payload. So on an exec-form install read by Claude Code
// 2.1.138 or earlier (which drops "args" and runs the binary bare), degraded
// hook input is allowed where the shell-form install blocked it.
//
// Why it was accepted: it needs Claude Code <= 2.1.138 (being deprecated),
// opt-in managed fail_closed, AND malformed hook input, which Claude Code does
// not produce. Closing it later is deliberate: route every non-terminal bare
// invocation to the hook path, then flip the bare expectations below to the
// hook's exit 2.
func TestBareInvocation_FailClosedDegradedInputIsAcceptedResidual(t *testing.T) {
	help := invokeAgentshield(t, t.TempDir(), []string{"agentshield", "--help"}, stdinDevNull, "")
	for _, tc := range []struct {
		name  string
		mode  stdinMode
		stdin string
	}{
		{"truncated JSON", stdinPipe, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls`},
		{"empty pipe", stdinPipe, ""},
		{"no stdin (/dev/null)", stdinDevNull, ""},
		{"closed stdin", stdinClosed, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Control: the shell-form path blocks this input under fail_closed,
			// so the bare result below is a real difference, not two help screens.
			hook := invokeAgentshield(t, managedFailClosedHome(t), []string{"agentshield", "hook"}, tc.mode, tc.stdin)
			if hook.code != 2 {
				t.Fatalf("control: `agentshield hook` under fail_closed exit=%d stderr=%q; want 2 (BLOCK)", hook.code, hook.stderr)
			}
			bare := invokeAgentshield(t, managedFailClosedHome(t), []string{"agentshield"}, tc.mode, tc.stdin)
			if bare.code != 0 || bare.stdout != help.stdout {
				t.Errorf("bare `agentshield` under fail_closed: exit=%d; the accepted residual is help + exit 0. "+
					"If this changed on purpose, the residual is closed: update this test and the docs (#4314).", bare.code)
			}
		})
	}
}
