//go:build unix

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4474: the hook reads two files under ~/.agentshield on every call before
// it answers: paused.json (IsPaused, at hook entry) and credentials.json
// (auth.Load, in sendRemoteAudit). Both were plain os.ReadFile, so a FIFO at
// either path blocked open(2) with no writer and no verdict came back:
// measured on main, killed at 15 s, while Codex and Gemini time a hook out
// at 10 s and Copilot fails open. Any agent running as this user can plant
// one (#4393). The #4057 FIFO class, a third time after #4208's cache read.

// releaseFIFOAtCleanup gives a reader stuck in open(2) on path a writer, at
// cleanup, so a goroutine the unfixed code left blocked sees EOF and ends
// instead of outliving its test. With no reader waiting the open fails
// with ENXIO, which is the fixed code's case and is ignored.
func releaseFIFOAtCleanup(t *testing.T, path string) {
	t.Helper()
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

// destructiveCommand is assembled at runtime: the hook reads test sources.
var destructiveCommand = "rm " + "-rf /"

// TestRemoteAudit_FIFOAtCredentialsPath_VerdictStillReturns drives the
// verdict path with a FIFO at the credentials path. evaluateCommand must
// return BLOCK, inside a guard, and nothing is sent: a FIFO is "no
// credentials".
func TestRemoteAudit_FIFOAtCredentialsPath_VerdictStillReturns(t *testing.T) {
	newRedactionHome(t, "")
	path := auth.CredentialsPath()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	releaseFIFOAtCleanup(t, path)

	done := make(chan policy.Decision, 1)
	go func() {
		res, _ := evaluateCommand(destructiveCommand, "/workspace", "claude-code-hook", "sess-4474")
		done <- res.Decision
	}()
	select {
	case d := <-done:
		if d != policy.DecisionBlock {
			t.Fatalf("decision = %s, want BLOCK", d)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("evaluateCommand did not return in 20 s with a FIFO at the credentials path")
	}
}

// TestRemoteAudit_SymlinkedCredentialsStillSend is the positive control on
// the same path: credentials.json as a symlink to a regular file holding a
// real login still sends the event. Without it, a Load that returned nil for
// everything would pass every "reads as no credentials" test.
func TestRemoteAudit_SymlinkedCredentialsStillSend(t *testing.T) {
	srv, bodies := captureAudit(t)
	home := newRedactionHome(t, "")
	real := filepath.Join(home, "creds.real.json")
	data, err := json.Marshal(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, auth.CredentialsPath()); err != nil {
		t.Fatal(err)
	}
	useMachineIDSource(t, func() string { return testHardwareID })

	res, _ := evaluateCommand(destructiveCommand, "/workspace", "claude-code-hook", "sess-4474")
	if res.Decision != policy.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", res.Decision)
	}
	if got := bodies(); len(got) != 1 {
		t.Fatalf("captured %d /api/audit bodies through a symlinked credentials file, want 1", len(got))
	}
}

// pauseFile is IsPaused's path in the current HOME.
func pauseFile(t *testing.T) string {
	t.Helper()
	p, err := pauseFilePath()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// isPausedUnderGuard runs IsPaused and fails if it has not returned in 5 s.
func isPausedUnderGuard(t *testing.T) bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- IsPaused() }()
	select {
	case p := <-done:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("IsPaused did not return in 5 s")
		return false
	}
}

func validPauseState(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(pauseState{Paused: true, PausedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestIsPaused_NonRegularIsNotPaused: a FIFO, a directory, an endless
// device behind a symlink and an oversized file all read as "not paused",
// the same as no file, and none of them holds the read.
func TestIsPaused_NonRegularIsNotPaused(t *testing.T) {
	cases := map[string]func(t *testing.T, path string) error{
		"FIFO": func(t *testing.T, p string) error {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				return err
			}
			releaseFIFOAtCleanup(t, p)
			return nil
		},
		"directory": func(_ *testing.T, p string) error { return os.Mkdir(p, 0o700) },
		"symlink to /dev/zero": func(_ *testing.T, p string) error {
			if _, err := os.Stat("/dev/zero"); err != nil {
				return err
			}
			return os.Symlink("/dev/zero", p)
		},
		"over the cap": func(t *testing.T, p string) error {
			// A valid paused state padded past the cap with JSON whitespace:
			// it would parse, so only the cap can refuse it.
			body := validPauseState(t)
			pad := strings.Repeat(" ", 4<<10)
			return os.WriteFile(p, append(body, pad...), 0o600)
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			newRedactionHome(t, "")
			if err := plant(t, pauseFile(t)); err != nil {
				t.Skipf("cannot plant %s: %v", name, err)
			}
			if isPausedUnderGuard(t) {
				t.Errorf("IsPaused() = true (%s at paused.json); want false", name)
			}
		})
	}
}

// TestIsPaused_CapBoundary pins the 4 KiB cap from both sides: a valid
// state padded to exactly the cap is honoured, one byte more is not. The
// size is written out rather than taken from pauseFileMaxBytes, so that
// changing the cap is a visible decision here.
func TestIsPaused_CapBoundary(t *testing.T) {
	const capBytes = 4 << 10
	newRedactionHome(t, "")
	padded := func(n int) []byte {
		body := validPauseState(t)
		return append(body, strings.Repeat(" ", n-len(body))...)
	}
	if err := os.WriteFile(pauseFile(t), padded(capBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isPausedUnderGuard(t) {
		t.Errorf("IsPaused() = false for a valid state of exactly %d bytes; want true", capBytes)
	}
	if err := os.WriteFile(pauseFile(t), padded(capBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if isPausedUnderGuard(t) {
		t.Errorf("IsPaused() = true for a state of %d bytes; want false (over the cap)", capBytes+1)
	}
}

// TestIsPaused_RegularAndSymlinkedStateIsPaused is the positive control:
// a real pause state is honoured, as a file and behind a symlink.
func TestIsPaused_RegularAndSymlinkedStateIsPaused(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		newRedactionHome(t, "")
		if err := os.WriteFile(pauseFile(t), validPauseState(t), 0o600); err != nil {
			t.Fatal(err)
		}
		if !isPausedUnderGuard(t) {
			t.Error("IsPaused() = false for a valid pause state; want true")
		}
	})
	t.Run("symlink to a regular file", func(t *testing.T) {
		home := newRedactionHome(t, "")
		real := filepath.Join(home, "paused.real.json")
		if err := os.WriteFile(real, validPauseState(t), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, pauseFile(t)); err != nil {
			t.Fatal(err)
		}
		if !isPausedUnderGuard(t) {
			t.Error("IsPaused() = false for a symlinked valid pause state; want true")
		}
	})
}

// runHookWithDeadline runs the real hook entry point in a child process
// (TestHelperHookProcess) and kills it at deadline. timedOut reports the
// kill: the failure this test exists for is a hook that never answers.
func runHookWithDeadline(t *testing.T, home, payload string, deadline time.Duration) (code int, stderr string, timedOut bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperHookProcess$")
	cmd.Env = append(os.Environ(), "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home)
	cmd.Stdin = strings.NewReader(payload)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	cmd.WaitDelay = 2 * time.Second // do not wait on a pipe a killed child left open
	err := cmd.Run()
	if ctx.Err() != nil {
		return -1, errBuf.String(), true
	}
	if err == nil {
		return 0, errBuf.String(), false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), errBuf.String(), false
	}
	t.Fatalf("running hook helper: %v", err)
	return -1, "", false
}

// TestHook_FIFOUnderConfigDir_StillBlocks drives the hook entry point, the
// contract a harness sees, with a FIFO at each of the two paths: exit 2,
// inside the 10 s the Codex and Gemini harnesses allow a hook.
func TestHook_FIFOUnderConfigDir_StillBlocks(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"session_id":      "fifo-4474",
		"tool_input":      map[string]string{"command": destructiveCommand},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"credentials.json", "paused.json"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".agentshield")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "agentshield.yaml"), []byte("mode: enforce\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			start := time.Now()
			code, stderr, timedOut := runHookWithDeadline(t, home, string(payload), 10*time.Second)
			if timedOut {
				t.Fatalf("hook gave no verdict in 10 s with a FIFO at %s", name)
			}
			if code != 2 {
				t.Fatalf("hook exit code = %d, want 2 (BLOCK). stderr:\n%s", code, stderr)
			}
			t.Logf("exit 2 in %v", time.Since(start).Round(time.Millisecond))
		})
	}
}
