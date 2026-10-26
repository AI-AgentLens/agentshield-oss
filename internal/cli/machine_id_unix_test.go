//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4208 fix round 1, item 2 (the coordinator, reading 302d127c): the cache
// read ran synchronously inside once.Do, before within()'s timer, and
// sync.Once blocks every concurrent caller. A FIFO at the cache path blocks
// open(2) with no writer, so every hook call hung past the 250 ms bound;
// a device or a huge file did the same. An agent running as the same user
// can plant any of them (#4393). The #4057 FIFO class, Codex pass 6.

// withinUnderGuard runs src.within(d) and fails if it does not return
// inside guard: a hang must fail the test, not the package timeout.
func withinUnderGuard(t *testing.T, src *machineIDSource, d, guard time.Duration) (string, time.Duration) {
	t.Helper()
	type result struct {
		id   string
		took time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		id := src.within(d)
		done <- result{id, time.Since(start)}
	}()
	select {
	case r := <-done:
		return r.id, r.took
	case <-time.After(guard):
		t.Fatalf("within(%v) did not return in %v: the cache read is not bounded by the deadline", d, guard)
		return "", 0
	}
}

// plantAtCachePath makes the cache path whatever plant creates, in a HOME
// that has credentials (so the id is read at all).
func plantAtCachePath(t *testing.T, plant func(path string) error) string {
	t.Helper()
	newRedactionHome(t, "http://127.0.0.1:1")
	path := machineIDCachePath()
	if err := plant(path); err != nil {
		t.Skipf("cannot plant the cache path: %v", err)
	}
	return path
}

// TestMachineID_FIFOAtCachePathDoesNotHang: a FIFO with no writer at the
// cache path. within() returns inside its deadline (from the live read,
// since the FIFO is no cache), and the verdict path still returns BLOCK.
func TestMachineID_FIFOAtCachePathDoesNotHang(t *testing.T) {
	plantAtCachePath(t, func(p string) error { return syscall.Mkfifo(p, 0o600) })

	src := newMachineIDSource(func() string { return testHardwareID })
	id, took := withinUnderGuard(t, src, machineIDWait, 5*time.Second)
	if took > machineIDWait+500*time.Millisecond {
		t.Errorf("within took %v with a FIFO at the cache path; want at most the %v deadline", took, machineIDWait)
	}
	if id != testHardwareID {
		t.Errorf("id = %q, want the live read's %q (a FIFO is no cache)", id, testHardwareID)
	}
}

// TestMachineID_FIFOAtCachePath_VerdictStillReturns drives the verdict
// path itself with the FIFO planted and a capture server logged in.
func TestMachineID_FIFOAtCachePath_VerdictStillReturns(t *testing.T) {
	srv, bodies := captureAudit(t)
	newRedactionHome(t, srv.URL)
	if err := syscall.Mkfifo(machineIDCachePath(), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	read, _ := blockingMachineIDRead(t) // and the live read never returns either
	useMachineIDSource(t, read)

	done := make(chan policy.Decision, 1)
	go func() {
		res, _ := evaluateCommand("rm "+"-rf /", "/workspace", "claude-code-hook", "sess-4208")
		done <- res.Decision
	}()
	select {
	case d := <-done:
		if d != policy.DecisionBlock {
			t.Fatalf("decision = %s, want BLOCK", d)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("evaluateCommand did not return in 20 s with a FIFO at the machine-id cache path")
	}
	if got := bodies(); len(got) != 1 {
		t.Fatalf("captured %d bodies, want 1", len(got))
	} else if _, present := wireEntry(t, got[0])["machine_id"]; present {
		t.Error("machine_id sent although neither the cache nor the live read produced one")
	}
}

// TestMachineID_NonRegularCacheIsAMiss: a directory, a symlink to a device
// that never ends, and a symlink to an oversized regular file are all "no
// cache": the live read answers inside the deadline.
func TestMachineID_NonRegularCacheIsAMiss(t *testing.T) {
	cases := map[string]func(path string) error{
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
		"symlink to /dev/zero": func(p string) error {
			if _, err := os.Stat("/dev/zero"); err != nil {
				return err
			}
			return os.Symlink("/dev/zero", p)
		},
		"symlink to a large file": func(p string) error {
			big := filepath.Join(filepath.Dir(p), "big")
			if err := os.WriteFile(big, make([]byte, 4<<20), 0o600); err != nil {
				return err
			}
			return os.Symlink(big, p)
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			plantAtCachePath(t, plant)
			src := newMachineIDSource(func() string { return testHardwareID })
			id, took := withinUnderGuard(t, src, machineIDWait, 5*time.Second)
			if took > machineIDWait+500*time.Millisecond {
				t.Errorf("within took %v; want at most the %v deadline", took, machineIDWait)
			}
			if id != testHardwareID {
				t.Errorf("id = %q, want the live read's %q", id, testHardwareID)
			}
		})
	}
}

// TestMachineID_SymlinkToRegularCacheIsRead: the positive control for the
// fstat check. fstat follows the link, so a symlink to a regular file
// holding a hardware id is still a cache hit.
func TestMachineID_SymlinkToRegularCacheIsRead(t *testing.T) {
	plantAtCachePath(t, func(p string) error {
		real := filepath.Join(filepath.Dir(p), "machine_id.real")
		if err := os.WriteFile(real, []byte(testHardwareID+"\n"), 0o600); err != nil {
			return err
		}
		return os.Symlink(real, p)
	})
	src := newMachineIDSource(func() string { return "SHOULD-NOT-BE-READ" })
	if id, _ := withinUnderGuard(t, src, 5*time.Second, 10*time.Second); id != testHardwareID {
		t.Errorf("id = %q, want the cached %q through the symlink", id, testHardwareID)
	}
}
