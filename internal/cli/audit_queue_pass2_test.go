package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
)

// Tests for the #4471 pass-2 round: runs of adjacent refusals, the probe that
// replaced "send the next event alone", and the follow-ups pass 2 found
// unpinned (the head's re-send, a 4xx probe, the synchronous paths' chain
// link, non-regular queue files).

// deadIDs is the client_event_id of every dead-lettered event, in order. A
// line that is not an event (malformed, say) reads as "".
func deadIDs(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, auditDeadFileName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read dead.jsonl: %v", err)
	}
	var ids []string
	for _, rec := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r struct {
			Line auditQueueLine `json:"line"`
		}
		_ = json.Unmarshal([]byte(rec), &r)
		var e map[string]any
		_ = json.Unmarshal(r.Line.Event, &e)
		id, _ := e["client_event_id"].(string)
		ids = append(ids, id)
	}
	return ids
}

// refusedAny reports whether a request carried one of the given ids; the
// SaaS refused every such request in these tests.
func refusedAny(ids []string) func([]string) bool {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	return func(r []string) bool {
		for _, id := range r {
			if set[id] {
				return true
			}
		}
		return false
	}
}

// TestAuditQueue_AdjacentRefusalsDoNotStallTheQueue: a run of adjacent events
// refused for their content (a 5xx or a reset) must not hold back the events
// behind it. Pass 2: with two adjacent, round 1 probed only the next event,
// read the refusal as an outage, and every later event stalled for good
// (waf2.py: 0/12 delivered, main 12/12). 40 is longer than the doubling's
// last power of two before the good events, so the probe of the last event
// has to find them.
func TestAuditQueue_AdjacentRefusalsDoNotStallTheQueue(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, -1} {
		for _, n := range []int{2, 3, 5, 40} {
			t.Run(fmt.Sprintf("%d refused, status %d", n, status), func(t *testing.T) {
				saas, _ := poisonSaaS(t, status)
				dir := newQueueHome(t, saas.srv.URL)
				stubFlusher(t, nil)
				advance := fakeClock(t)
				cmds := []string{"echo a"}
				for i := 0; i < n; i++ {
					cmds = append(cmds, "echo poison")
				}
				cmds = append(cmds, "echo b", "echo c", "echo d")
				for _, c := range cmds {
					sendRemoteAudit(queueEvent(c), nil)
				}
				ids := queuedIDs(t, dir)
				poisoned := ids[1 : 1+n]

				runs := runUntilDrained(t, advance, 20)
				if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
					t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
				}
				got := acceptedIDs(t, saas, refusedAny(poisoned))
				for i, id := range ids {
					if !strings.Contains(cmds[i], "poison") && got[id] == 0 {
						t.Errorf("event %d (%s) was never delivered", i, cmds[i])
					}
				}
				if dead := deadIDs(t, dir); strings.Join(dead, ",") != strings.Join(poisoned, ",") {
					t.Errorf("dead.jsonl holds %d events %v; want exactly the %d refused, in order", len(dead), dead, n)
				}
			})
		}
	}
}

// TestAuditQueue_ProbeWalksOnlyAsFarAsItMust: the walk sends events one at a
// time, so the accepted probe must be near the refusals, not at the end of a
// long queue. Two refusals in front of 200 events cost about 15 requests;
// probing only the next and the last event would walk all 200 alone.
func TestAuditQueue_ProbeWalksOnlyAsFarAsItMust(t *testing.T) {
	saas, _ := poisonSaaS(t, http.StatusServiceUnavailable)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	sendRemoteAudit(queueEvent("echo poison"), nil)
	sendRemoteAudit(queueEvent("echo poison"), nil)
	for i := 0; i < 200; i++ {
		sendRemoteAudit(queueEvent("ls"), nil)
	}
	runs := runUntilDrained(t, advance, 10)
	if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
		t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
	}
	if n := len(saas.requests()); n > 40 {
		t.Errorf("%d requests to get past 2 refused events; want at most 40", n)
	}
	if dead := deadIDs(t, dir); len(dead) != 2 {
		t.Errorf("dead.jsonl holds %d events; want the 2 refused", len(dead))
	}
}

// TestAuditQueue_RefusedHeadBeforeAnUnsendableLine: lines that can never be
// sent (malformed, another account's) right behind a refused head are stepped
// over by the probe and dead-lettered by the walk. Round 1 read them as an
// inconclusive probe and stalled (pass 2).
func TestAuditQueue_RefusedHeadBeforeAnUnsendableLine(t *testing.T) {
	saas, _ := poisonSaaS(t, http.StatusServiceUnavailable)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	sendRemoteAudit(queueEvent("echo poison"), nil)
	appendQueueRaw(t, dir, "not a queue line\n")
	appendQueueRaw(t, dir, `{"v":1,"acct":"another-account","event":{"client_event_id":"0123456789abcdef0123456789abcdef"}}`+"\n")
	sendRemoteAudit(queueEvent("echo b"), nil)
	sendRemoteAudit(queueEvent("echo c"), nil)
	ids := queuedIDs(t, dir)

	runs := runUntilDrained(t, advance, 10)
	if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
		t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
	}
	got := acceptedIDs(t, saas, refusedAny(ids[:1]))
	if got[ids[3]] == 0 || got[ids[4]] == 0 {
		t.Errorf("events behind the refused head and the unsendable lines were not delivered: %v", got)
	}
	if dead := deadIDs(t, dir); len(dead) != 3 || dead[0] != ids[0] {
		t.Errorf("dead.jsonl = %v; want the refused head, then the two unsendable lines", dead)
	}
}

// TestAuditQueue_OutageEndingAtTheProbeDeadLettersNothing: when an outage
// ends just as the probe goes out, the head is accepted when the walk sends
// it again, and nothing is dead-lettered. Dead-lettering the head as soon as
// a later event is accepted, without sending it again, loses it (pass 2, G8).
func TestAuditQueue_OutageEndingAtTheProbeDeadLettersNothing(t *testing.T) {
	var mu sync.Mutex
	down, probeID := true, ""
	saas := newFakeSaaS(t, func(ids []string, _ string) int {
		mu.Lock()
		defer mu.Unlock()
		if len(ids) == 1 && ids[0] == probeID {
			down = false
		}
		if down {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	for i := 0; i < 4; i++ {
		sendRemoteAudit(queueEvent("echo outage"), nil)
	}
	ids := queuedIDs(t, dir)
	mu.Lock()
	probeID = ids[1] // the first probe: the event right behind the head
	mu.Unlock()

	runs := runUntilDrained(t, advance, 10)
	if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
		t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
	}
	if dead := deadIDs(t, dir); len(dead) != 0 {
		t.Fatalf("an outage that ended at the probe dead-lettered %v", dead)
	}
	got := acceptedIDs(t, saas, func([]string) bool { return false })
	for i, id := range ids {
		if got[id] == 0 {
			t.Errorf("event %d was never accepted", i)
		}
	}
}

// TestAuditQueue_OutageStartingMidWalkDeadLettersNothingMore: on the walk to
// the accepted event, an event that keeps failing is dead-lettered only if
// the accepted event is accepted again right after. When the path goes down
// mid-walk, the walk stops, nothing more is dead-lettered, and the rest is
// delivered on recovery.
func TestAuditQueue_OutageStartingMidWalkDeadLettersNothingMore(t *testing.T) {
	var mu sync.Mutex
	down, hitID, hitSeen := false, "", 0
	saas := newFakeSaaS(t, func(ids []string, body string) int {
		mu.Lock()
		defer mu.Unlock()
		if len(ids) == 1 && ids[0] == hitID {
			// 1: the probe that finds it. 2: the check before the head is
			// dead-lettered. Then the path goes down.
			if hitSeen++; hitSeen == 2 {
				down = true
				return http.StatusOK
			}
		}
		if down || strings.Contains(body, "poison") {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	for _, c := range []string{"echo poison", "echo poison", "echo b", "echo c"} {
		sendRemoteAudit(queueEvent(c), nil)
	}
	ids := queuedIDs(t, dir)
	mu.Lock()
	hitID = ids[2] // probes: ids[1] (refused), then ids[2]
	mu.Unlock()

	for i := 0; i < 4 && deadIDs(t, dir) == nil; i++ {
		flushAuditQueue()
		advance(auditBackoffMax)
	}
	if dead := deadIDs(t, dir); len(dead) != 1 || dead[0] != ids[0] {
		t.Fatalf("dead.jsonl = %v; want only the head, dead-lettered before the path went down", dead)
	}

	mu.Lock()
	down = false
	mu.Unlock()
	runs := runUntilDrained(t, advance, 10)
	if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
		t.Fatalf("queue not drained after recovery: %+v", runs)
	}
	if dead := deadIDs(t, dir); len(dead) != 2 || dead[1] != ids[1] {
		t.Errorf("dead.jsonl = %v; want the two refused events, the second only after the recovery", dead)
	}
	got := acceptedIDs(t, saas, refusedAny(ids[:2]))
	if got[ids[2]] == 0 || got[ids[3]] == 0 {
		t.Errorf("events behind the refusals were not delivered: %v", got)
	}
}

// TestAuditQueue_WalkTriesAnEventTwiceBeforeDeadLettering: an event on the
// walk that fails once and is accepted on its second try is delivered, not
// dead-lettered.
func TestAuditQueue_WalkTriesAnEventTwiceBeforeDeadLettering(t *testing.T) {
	var mu sync.Mutex
	flakyID, flakySends := "", 0
	saas := newFakeSaaS(t, func(ids []string, body string) int {
		mu.Lock()
		defer mu.Unlock()
		if len(ids) == 1 && ids[0] == flakyID {
			// Sent alone as the first probe, then by the walk: both fail.
			if flakySends++; flakySends <= 2 {
				return http.StatusBadGateway
			}
		}
		if strings.Contains(body, "poison") {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	for _, c := range []string{"echo poison", "echo flaky", "echo c"} {
		sendRemoteAudit(queueEvent(c), nil)
	}
	ids := queuedIDs(t, dir)
	mu.Lock()
	flakyID = ids[1]
	mu.Unlock()

	runs := runUntilDrained(t, advance, 10)
	if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
		t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
	}
	if dead := deadIDs(t, dir); len(dead) != 1 || dead[0] != ids[0] {
		t.Errorf("dead.jsonl = %v; want only the refused head", dead)
	}
	if got := acceptedIDs(t, saas, refusedAny(ids[:1])); got[ids[1]] == 0 {
		t.Errorf("the event that failed once on the walk was not delivered (%d sends)", flakySends)
	}
}

// TestAuditQueue_ProbeRefusedWith4xxIsNotProofThePathWorks: a probe answered
// with a 4xx (that event's own content refused) does not count as the path
// working. Counting it made the walk check the path against an event that is
// never accepted, and the queue stalled (pass 2, G9).
func TestAuditQueue_ProbeRefusedWith4xxIsNotProofThePathWorks(t *testing.T) {
	saas := newFakeSaaS(t, func(_ []string, body string) int {
		switch {
		case strings.Contains(body, "badreq"):
			return http.StatusBadRequest
		case strings.Contains(body, "poison"):
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	for _, c := range []string{"echo poison", "echo badreq", "echo b", "echo c"} {
		sendRemoteAudit(queueEvent(c), nil)
	}
	ids := queuedIDs(t, dir)

	runs := runUntilDrained(t, advance, 10)
	if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
		t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
	}
	if dead := deadIDs(t, dir); strings.Join(dead, ",") != ids[0]+","+ids[1] {
		t.Errorf("dead.jsonl = %v; want the 503-refused head and the 400-refused event", dead)
	}
	got := acceptedIDs(t, saas, refusedAny(ids[:2]))
	if got[ids[2]] == 0 || got[ids[3]] == 0 {
		t.Errorf("events behind the refusals were not delivered: %v", got)
	}
}

// TestRemoteAudit_SyncPathsCarryTheLocalLink: sync mode, and the fallback
// when the queue cannot be used, send the entry the queue would have: the
// machine id, and a local_chain whose line_hash is the SHA-256 of the event's
// audit.jsonl line. Pass 2: rebuilding the entry on those paths without the
// link or the machine id survived every test (E3/E4).
func TestRemoteAudit_SyncPathsCarryTheLocalLink(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, home string)
	}{
		{"AGENTSHIELD_AUDIT_UPLOAD=sync", func(t *testing.T, _ string) { t.Setenv(auditUploadEnv, "sync") }},
		{"queue unusable", func(t *testing.T, home string) {
			// A file where the queue directory should be.
			if err := os.WriteFile(filepath.Join(home, ".agentshield", auditQueueDirName), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, bodies := captureAudit(t)
			home := newRedactionHome(t, srv.URL)
			warmRealMachineID(t)
			spawns := stubFlusher(t, nil)
			tc.setup(t, home)

			evaluateCommand("ls -la", "/workspace", "claude-code-hook", "sess-4471")

			got, lines := bodies(), auditLines(t, home)
			if len(got) != 1 || len(lines) != 1 || spawns() != 0 {
				t.Fatalf("%d bodies, %d audit lines, %d uploader starts; want 1, 1 and none (a direct upload)", len(got), len(lines), spawns())
			}
			entry := wireEntry(t, got[0])
			want := enterprise.MachineID()
			if want == "" {
				t.Fatal("control: enterprise.MachineID() is empty, so machine_id cannot be checked")
			}
			if m, _ := entry["machine_id"].(string); m != want {
				t.Errorf("machine_id = %q; want %q", m, want)
			}
			if _, line := wireLocalChain(t, entry); line != lineSHA256(lines[0]) {
				t.Errorf("line_hash = %s; want the SHA-256 of the audit.jsonl line, %s", line, lineSHA256(lines[0]))
			}
		})
	}
}

// TestAuditQueue_NonRegularQueueFilesFallBackToSync: a FIFO at queue.jsonl or
// at state.jsonl must neither swallow the event nor hang the hook; the hook
// uploads directly. Pass 2: without the state.jsonl kind check the hook hung
// reading the FIFO (killed at 10 s, against 76 ms), and the queue.jsonl
// regular-file check was unpinned (U1/U2/S2).
func TestAuditQueue_NonRegularQueueFilesFallBackToSync(t *testing.T) {
	for _, name := range []string{auditQueueFileName, auditStateFileName} {
		t.Run(name, func(t *testing.T) {
			saas := newFakeSaaS(t, nil)
			dir := newQueueHome(t, saas.srv.URL)
			spawns := stubFlusher(t, nil)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(dir, name)
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			// Release anything left blocked on the FIFO, so a failure ends.
			t.Cleanup(func() {
				if f, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
					_ = f.Close()
				}
			})

			done := make(chan struct{})
			go func() {
				defer close(done)
				sendRemoteAudit(queueEvent("echo past a fifo"), nil)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("the hook hung on a FIFO at %s", name)
			}
			if got := len(flatten(saas.requests())); got != 1 || spawns() != 0 {
				t.Fatalf("FIFO at %s: %d direct uploads, %d uploader starts; want 1 and 0", name, got, spawns())
			}
		})
	}
}
