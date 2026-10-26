package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// End-to-end tests for #4467 through the real hook entry point in a child
// process, with the production detached spawn (TestMain, envAuditDetachedSpawn):
// the uploader is a separate process the hook never waits for.

const latencyPayload4467 = `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"lat-4467","tool_input":{"command":"ls -la"}}`

// timedSaaS answers /api/audit after hold and records when each request
// arrived and when it was answered.
type timedSaaS struct {
	srv      *httptest.Server
	mu       sync.Mutex
	ids      []string
	answered int
}

func newTimedSaaS(t *testing.T, hold time.Duration) *timedSaaS {
	t.Helper()
	s := &timedSaaS{}
	stop := make(chan struct{})
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/audit" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		ids := wireClientEventIDs(t, body)
		s.mu.Lock()
		s.ids = append(s.ids, ids...)
		s.mu.Unlock()
		select {
		case <-time.After(hold):
		case <-stop:
		}
		s.mu.Lock()
		s.answered++
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.srv.Close)
	t.Cleanup(func() { close(stop) }) // runs first: unblock handlers so Close returns
	return s
}

func (s *timedSaaS) snapshot() (ids []string, answered int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ids...), s.answered
}

// newE2EHome is a scratch HOME for a hook child, logged in to server unless
// it is "". The heartbeat the hook fires on every call is pointed at this
// test process (a live pid, a fresh stamp), so a logged-in child never tries
// to start a heartbeat daemon from the test binary.
func newE2EHome(t *testing.T, server string) (home, queueDir string) {
	t.Helper()
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	if server != "" {
		saveQueueCreds(t, server, "tok-e2e", 7)
	}
	for name, body := range map[string]string{
		"heartbeat.pid":  strconv.Itoa(os.Getpid()),
		"last_heartbeat": time.Now().UTC().Format(time.RFC3339),
	} {
		if err := os.WriteFile(filepath.Join(configDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, filepath.Join(configDir, auditQueueDirName)
}

// runHookDetached runs the hook the way a harness does: payload on stdin,
// stdout and stderr on pipes, and it returns only when the child has exited
// AND both pipes have closed (exec.Cmd.Run copies them to completion). An
// uploader that inherited either pipe would hold this call open for as long
// as the upload takes.
func runHookDetached(t *testing.T, home, payload string, extraEnv ...string) time.Duration {
	t.Helper()
	env := make([]string, 0, len(os.Environ())+5)
	gorace := "atexit_sleep_ms=0"
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, auditUploadEnv+"="):
		case strings.HasPrefix(kv, "GORACE="):
			gorace = strings.TrimPrefix(kv, "GORACE=") + " " + gorace
		default:
			env = append(env, kv)
		}
	}
	// Under -race a test binary sleeps 1 s at exit by default (GORACE
	// atexit_sleep_ms), after the hook has queued and spawned: that would
	// read as the hook waiting for the upload. Ignored without -race.
	env = append(env, "GORACE="+gorace)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHookProcess$")
	cmd.Env = append(append(env, "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home, envAuditDetachedSpawn+"=1"), extraEnv...)
	cmd.Stdin = strings.NewReader(payload)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	d := time.Since(start)
	if err != nil {
		t.Fatalf("hook child: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errb.String())
	}
	return d
}

func medianDuration(ds []time.Duration) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", within, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitIdle waits until no uploader holds the queue, so a test never ends
// with a detached child still writing into its temp HOME.
func waitIdle(t *testing.T, queueDir string) {
	t.Helper()
	waitFor(t, 30*time.Second, "the uploader to exit", func() bool { return !auditFlusherRunning(queueDir) })
}

// latencyMargin is how much slower than a logged-out call a logged-in hook
// call may be: enqueue, a state read, a lock probe and one fork/exec, with
// headroom for a loaded CI runner. It is well under the 500 ms the slowest
// SaaS below takes to answer, so a hook that waits for the upload fails.
const latencyMargin = 250 * time.Millisecond

// TestAuditFlusher_HookDoesNotWaitForUpload is #4467's fitness function. A
// logged-in hook call against a SaaS that answers in 500 ms, and one that
// holds every request for 3 s, returns within the logged-out time plus a
// small margin; at that moment the SaaS has not answered, so the upload is
// still in flight in the detached uploader; and every event arrives after.
//
// It also proves the uploader does not hold the hook's pipes: runHookDetached
// returns only when stdout and stderr close. With the uploader's Stderr set
// to os.Stderr (the inherited pipe) this test fails at ~3 s.
func TestAuditFlusher_HookDoesNotWaitForUpload(t *testing.T) {
	const runs = 3
	for _, hold := range []time.Duration{500 * time.Millisecond, 3 * time.Second} {
		t.Run(hold.String(), func(t *testing.T) {
			saas := newTimedSaaS(t, hold)
			home, queueDir := newE2EHome(t, saas.srv.URL)
			loHome, _ := newE2EHome(t, "")
			// Logged-out and logged-in runs alternate, so load that comes or
			// goes during the test lands on both sides of the comparison.
			var lo, in []time.Duration
			for i := 0; i < runs; i++ {
				lo = append(lo, runHookDetached(t, loHome, latencyPayload4467))
				in = append(in, runHookDetached(t, home, latencyPayload4467))
				if i == 0 {
					if _, answered := saas.snapshot(); answered != 0 {
						t.Fatalf("the SaaS had already answered when the hook returned: the hook waited for the upload")
					}
				}
			}
			budget := medianDuration(lo) + latencyMargin
			if m := medianDuration(in); m > budget {
				t.Fatalf("logged-in hook median %v (runs %v) exceeds the logged-out median %v + %v; SaaS holds %v",
					m, in, medianDuration(lo), latencyMargin, hold)
			}
			waitFor(t, 4*hold+20*time.Second, "every event to reach the SaaS", func() bool {
				ids, _ := saas.snapshot()
				return len(ids) >= runs
			})
			waitIdle(t, queueDir)
			ids, _ := saas.snapshot()
			seen := map[string]bool{}
			for _, id := range ids {
				if !eventIDRe.MatchString(id) || seen[id] {
					t.Errorf("SaaS received ids %v; want %d distinct 32-hex ids", ids, runs)
					break
				}
				seen[id] = true
			}
			t.Logf("hold %v: logged-out median %v, logged-in runs %v", hold, medianDuration(lo), in)
		})
	}
}

// TestAuditFlusher_ParallelHooksLoseNothing: parallel tool calls are real.
// N concurrent hooks, each appending and maybe starting an uploader, deliver
// exactly N distinct events; the queue ends empty.
func TestAuditFlusher_ParallelHooksLoseNothing(t *testing.T) {
	const n = 12
	saas := newTimedSaaS(t, 100*time.Millisecond)
	home, queueDir := newE2EHome(t, saas.srv.URL)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runHookDetached(t, home, latencyPayload4467)
		}()
	}
	wg.Wait()
	waitFor(t, 30*time.Second, "all events to reach the SaaS", func() bool {
		ids, _ := saas.snapshot()
		return len(ids) >= n
	})
	waitIdle(t, queueDir)

	ids, _ := saas.snapshot()
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if len(ids) != n || len(seen) != n {
		t.Fatalf("SaaS received %d events (%d distinct); want exactly %d distinct", len(ids), len(seen), n)
	}
	if size := queueSize(t, queueDir); size != 0 {
		t.Errorf("queue holds %d bytes after everything was delivered", size)
	}
}

// TestAuditFlusher_KilledMidUploadResendsSameIDs: the uploader process is
// killed after the SaaS received a batch but before it acknowledged. The
// kernel releases its lock, nothing was marked sent, and the next uploader
// re-sends the same client_event_ids.
func TestAuditFlusher_KilledMidUploadResendsSameIDs(t *testing.T) {
	var (
		mu       sync.Mutex
		reqs     [][]string
		received = make(chan struct{}, 1)
		release  = make(chan struct{})
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, wireClientEventIDs(t, body))
		first := len(reqs) == 1
		mu.Unlock()
		if first {
			received <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	home, queueDir := newE2EHome(t, srv.URL)
	stubFlusher(t, nil)
	for _, c := range []string{"ls a", "ls b", "ls c"} {
		sendRemoteAudit(queueEvent(c), nil)
	}
	queued := queuedIDs(t, queueDir)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe)
	child.Env = append(os.Environ(), "HOME="+home, envAuditFlushHelper+"=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-time.After(20 * time.Second):
		_ = child.Process.Kill()
		t.Fatal("the uploader never reached the SaaS")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatalf("kill uploader: %v", err)
	}
	_ = child.Wait()
	unblock()

	res := flushAuditQueue()
	mu.Lock()
	got := append([][]string(nil), reqs...)
	mu.Unlock()
	if res.Stopped != "queue drained" || res.Sent != 3 || len(got) != 2 {
		t.Fatalf("after the kill: flush %+v, requests %v; want the backlog re-sent in one request and drained", res, got)
	}
	if strings.Join(got[0], ",") != strings.Join(queued, ",") || strings.Join(got[1], ",") != strings.Join(queued, ",") {
		t.Fatalf("re-send changed the ids:\nqueued %v\nkilled %v\nresent %v", queued, got[0], got[1])
	}
}
