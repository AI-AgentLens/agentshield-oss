package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4208 fix round 1 (Opus pass 1, B1): the machine id is sent with every
// /api/audit event, and that send runs before the hook returns its verdict.
// The live read execs ioreg on macOS. These tests pin that the verdict
// never waits on that read for longer than machineIDWait, that no read
// happens without credentials, and that the first hardware id is cached so
// later processes never exec at all.

// useMachineIDSource swaps the process's machine-id source for one whose
// live read is read, for the duration of the test.
func useMachineIDSource(t *testing.T, read func() string) *machineIDSource {
	t.Helper()
	prev := machineIDs
	src := newMachineIDSource(read)
	machineIDs = src
	t.Cleanup(func() { machineIDs = prev })
	return src
}

// blockingMachineIDRead stands in for an ioreg that never returns (the
// reviewer SIGSTOPped it). It is released at cleanup and then returns "",
// which is never cached, so a released read cannot write into a later
// test's HOME.
func blockingMachineIDRead(t *testing.T) (read func() string, called <-chan struct{}) {
	t.Helper()
	release := make(chan struct{})
	ch := make(chan struct{}, 1)
	t.Cleanup(func() { close(release) })
	return func() string {
		select {
		case ch <- struct{}{}:
		default:
		}
		<-release
		return ""
	}, ch
}

const testHardwareID = "4208ABCD-0000-4111-8222-333344445555"

// TestMachineIDWithin_GivesUpAtTheDeadline is the bound itself: a read that
// never returns costs the caller the deadline and an empty id, not a hang.
func TestMachineIDWithin_GivesUpAtTheDeadline(t *testing.T) {
	newRedactionHome(t, "")
	read, called := blockingMachineIDRead(t)
	src := newMachineIDSource(read)

	type result struct {
		id   string
		took time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		id := src.within(50 * time.Millisecond)
		done <- result{id, time.Since(start)}
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("within did not return in 5 s with a 50 ms deadline: the wait is unbounded")
	}
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("control: the live read never started")
	}
	if r.id != "" {
		t.Errorf("within = %q, want \"\" (the read had not finished)", r.id)
	}
	if r.took > time.Second {
		t.Errorf("within took %v with a 50 ms deadline", r.took)
	}
}

// TestMachineIDWithin_SlowCacheReadIsBoundedToo: the cache read runs in
// the background goroutine, never on the caller's path, so a cache read
// that stalls (a hung mount, whatever the file turns out to be) costs the
// caller the deadline and no more. With the read inside once.Do, within()
// would wait for it before its timer even started.
func TestMachineIDWithin_SlowCacheReadIsBoundedToo(t *testing.T) {
	newRedactionHome(t, "http://127.0.0.1:1")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	// The read returns "", never a hardware id: the stalled cache read is
	// released at cleanup and then falls through to this read, after HOME is
	// restored, so a cacheable id here was written into the developer's real
	// ~/.agentshield/machine_id (the blockingMachineIDRead rule, above).
	src := newMachineIDSource(func() string { return "" })
	src.cached = func() (string, bool) {
		<-release
		return "", false
	}
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_ = src.within(50 * time.Millisecond)
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		if took > time.Second {
			t.Errorf("within took %v with the cache read stalled and a 50 ms deadline", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("within did not return in 5 s with the cache read stalled: the cache read is on the caller's path")
	}
}

// TestMachineIDWait_StaysUnderTheVerdictBudget: the deadline is paid by the
// verdict whenever the id is not ready, and Copilot fails open on a hook
// timeout. Raising it past half a second is a decision for the PR that
// does it, not a constant edit.
func TestMachineIDWait_StaysUnderTheVerdictBudget(t *testing.T) {
	if machineIDWait <= 0 || machineIDWait > 500*time.Millisecond {
		t.Errorf("machineIDWait = %v; want (0, 500ms]", machineIDWait)
	}
}

// TestSendRemoteAudit_SlowMachineIDDoesNotHoldTheVerdict reproduces B1: the
// machine-id read never returns. The send must still go out within the
// deadline, without machine_id, and evaluateCommand must still return its
// BLOCK with the local link on the wire.
func TestSendRemoteAudit_SlowMachineIDDoesNotHoldTheVerdict(t *testing.T) {
	srv, bodies := captureAudit(t)
	newRedactionHome(t, srv.URL)
	read, _ := blockingMachineIDRead(t)
	useMachineIDSource(t, read)

	// The send alone: bounded by machineIDWait, plus a loopback POST.
	sent := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		sendRemoteAudit(&logger.AuditEvent{Command: "echo bounded", Decision: "AUDIT"}, nil)
		sent <- time.Since(start)
	}()
	select {
	case elapsed := <-sent:
		if elapsed > machineIDWait+time.Second {
			t.Fatalf("sendRemoteAudit took %v with the machine-id read hung; want at most machineIDWait (%v) plus the POST", elapsed, machineIDWait)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sendRemoteAudit did not return in 10 s with the machine-id read hung: the wait is unbounded (B1)")
	}

	// The verdict path: a BLOCK must come back, not hang with the read.
	type verdict struct {
		decision policy.Decision
		took     time.Duration
	}
	done := make(chan verdict, 1)
	go func() {
		start := time.Now()
		res, _ := evaluateCommand("rm "+"-rf /", "/workspace", "claude-code-hook", "sess-4208")
		done <- verdict{res.Decision, time.Since(start)}
	}()
	var v verdict
	select {
	case v = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("evaluateCommand did not return a verdict in 20 s with the machine-id read hung (B1)")
	}
	if v.decision != policy.DecisionBlock {
		t.Fatalf("control: decision = %s, want BLOCK", v.decision)
	}

	got := bodies()
	if len(got) != 2 {
		t.Fatalf("captured %d bodies, want 2 (the bare send and the BLOCK)", len(got))
	}
	for i, body := range got {
		entry := wireEntry(t, body)
		if _, present := entry["machine_id"]; present {
			t.Errorf("body %d carries machine_id %v although the read never finished", i, entry["machine_id"])
		}
	}
	if _, present := wireEntry(t, got[1])["local_chain"]; !present {
		t.Error("the BLOCK's event lost its local_chain: only machine_id may be dropped on timeout")
	}
}

// TestMachineID_NotReadWithoutCredentials: an install that reports nowhere
// never runs the read, through any of the three ways in.
func TestMachineID_NotReadWithoutCredentials(t *testing.T) {
	newRedactionHome(t, "")
	called := make(chan struct{}, 4)
	useMachineIDSource(t, func() string {
		called <- struct{}{}
		return testHardwareID
	})

	prefetchMachineID()
	sendRemoteAudit(&logger.AuditEvent{Command: "echo no-creds", Decision: "AUDIT"}, nil)
	evaluateCommand("ls", "/workspace", "claude-code-hook", "sess-4208")

	select {
	case <-called:
		t.Fatal("the machine id was read on an install with no credentials")
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := os.Stat(machineIDCachePath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache file exists without credentials: %v", err)
	}
}

// TestPrefetchMachineID_StartsTheReadWithCredentials is the positive control
// for the test above: with credentials the prefetch does start the read.
func TestPrefetchMachineID_StartsTheReadWithCredentials(t *testing.T) {
	newRedactionHome(t, "http://127.0.0.1:1")
	called := make(chan struct{}, 1)
	src := useMachineIDSource(t, func() string {
		called <- struct{}{}
		return testHardwareID
	})
	prefetchMachineID()
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("prefetchMachineID did not start the read with credentials present")
	}
	// Let the read finish (it caches into this test's HOME) before the
	// TempDir cleanup runs.
	select {
	case <-src.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the prefetched read did not complete")
	}
}

// TestMachineID_SecondProcessUsesTheCache: the first process caches the
// hardware id; a second process (a fresh source) reads it from the file and
// never runs the live read.
func TestMachineID_SecondProcessUsesTheCache(t *testing.T) {
	newRedactionHome(t, "http://127.0.0.1:1")
	first := newMachineIDSource(func() string { return testHardwareID })
	if got := first.within(5 * time.Second); got != testHardwareID {
		t.Fatalf("first process id = %q, want %q", got, testHardwareID)
	}
	path := machineIDCachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	if string(data) != testHardwareID+"\n" {
		t.Errorf("cache content = %q, want the id and a newline", data)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("cache mode = %v, want 0600", info.Mode().Perm())
	}
	if filepath.Base(filepath.Dir(path)) != ".agentshield" {
		t.Errorf("cache at %s, want it beside credentials.json in ~/.agentshield", path)
	}

	var reads atomic.Int32
	second := newMachineIDSource(func() string { reads.Add(1); return "SHOULD-NOT-BE-READ" })
	if got := second.within(5 * time.Second); got != testHardwareID {
		t.Errorf("second process id = %q, want the cached %q", got, testHardwareID)
	}
	if n := reads.Load(); n != 0 {
		t.Errorf("second process ran the live read %d times; the cache should have answered", n)
	}
}

// TestMachineID_FallbackIsNeverCached: a fallback id (the read failed) is
// sent as the heartbeat would send it, but not cached; the next process
// reads live again, and caches the hardware id it gets.
func TestMachineID_FallbackIsNeverCached(t *testing.T) {
	newRedactionHome(t, "http://127.0.0.1:1")
	const fallback = "fallback-0123456789abcdef"
	first := newMachineIDSource(func() string { return fallback })
	if got := first.within(5 * time.Second); got != fallback {
		t.Fatalf("id = %q, want the fallback %q (it is the heartbeat's value this time)", got, fallback)
	}
	if _, err := os.Stat(machineIDCachePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the fallback id was cached (stat err %v); one failed read would pin a second id", err)
	}

	var reads atomic.Int32
	second := newMachineIDSource(func() string { reads.Add(1); return testHardwareID })
	if got := second.within(5 * time.Second); got != testHardwareID || reads.Load() != 1 {
		t.Errorf("after a fallback: id = %q with %d live reads, want %q from one live read", got, reads.Load(), testHardwareID)
	}
	if data, _ := os.ReadFile(machineIDCachePath()); string(data) != testHardwareID+"\n" {
		t.Errorf("cache after a real read = %q, want the hardware id", data)
	}
}

// TestMachineID_BadCacheFallsBackToTheLiveRead: a cache file that is not one
// hardware id (garbage, a hand-written fallback, oversized) is a miss.
func TestMachineID_BadCacheFallsBackToTheLiveRead(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":   "not an id\x00\n",
		"fallback":  "fallback-0123456789abcdef\n",
		"two lines": testHardwareID + "\n" + testHardwareID + "\n",
		"oversized": strings.Repeat("A", 300) + "\n",
		"empty":     "",
	} {
		t.Run(name, func(t *testing.T) {
			newRedactionHome(t, "http://127.0.0.1:1")
			if err := os.WriteFile(machineIDCachePath(), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			var reads atomic.Int32
			src := newMachineIDSource(func() string { reads.Add(1); return testHardwareID })
			if got := src.within(5 * time.Second); got != testHardwareID || reads.Load() != 1 {
				t.Errorf("id = %q with %d live reads, want %q from one live read", got, reads.Load(), testHardwareID)
			}
		})
	}
}

// TestIsHardwareMachineID is the shape the cache accepts.
func TestIsHardwareMachineID(t *testing.T) {
	for id, want := range map[string]bool{
		testHardwareID:                      true, // IOPlatformUUID
		"0123456789abcdef0123456789abcdef":  true, // /etc/machine-id
		"":                                  false,
		"fallback-0123456789abcdef":         false,
		"has space":                         false,
		testHardwareID + "\n":               false,
		strings.Repeat("a", 129):            false,
		"4208ABCD-0000-4111-8222-33334444Ø": false,
	} {
		if got := isHardwareMachineID(id); got != want {
			t.Errorf("isHardwareMachineID(%q) = %v, want %v", id, got, want)
		}
	}
}

// TestMachineIDSource_ConcurrentCallersShareOneRead: the hook's prefetch and
// its send can race; the read runs once and both see the same id. Run with
// -race.
func TestMachineIDSource_ConcurrentCallersShareOneRead(t *testing.T) {
	newRedactionHome(t, "http://127.0.0.1:1")
	var reads atomic.Int32
	src := newMachineIDSource(func() string {
		reads.Add(1)
		time.Sleep(20 * time.Millisecond)
		return testHardwareID
	})
	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = src.within(5 * time.Second)
		}(i)
	}
	wg.Wait()
	for i, id := range got {
		if id != testHardwareID {
			t.Errorf("caller %d got %q", i, id)
		}
	}
	if n := reads.Load(); n != 1 {
		t.Errorf("live read ran %d times, want 1", n)
	}
}
