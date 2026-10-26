package cli

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// Tests for the #4471 review round: head-of-line refusal, unrecordable
// progress, backoff escalation by parallel uploaders, cheap suppression of
// the uploader, and the mutants pass 1 left alive.

// TestClassifyUpload pins which answers keep a batch and which give up on it.
func TestClassifyUpload(t *testing.T) {
	for _, tc := range []struct {
		status int
		err    error
		want   uploadOutcome
	}{
		{200, nil, uploadOK}, {202, nil, uploadOK}, {204, nil, uploadOK},
		{401, nil, uploadRetry}, {408, nil, uploadRetry}, {429, nil, uploadRetry},
		{403, nil, uploadPermanent}, {400, nil, uploadPermanent}, {404, nil, uploadPermanent},
		{413, nil, uploadPermanent}, {422, nil, uploadPermanent},
		{500, nil, uploadRetry}, {502, nil, uploadRetry}, {503, nil, uploadRetry},
		{302, nil, uploadRetry}, {0, errors.New("connection reset by peer"), uploadRetry},
	} {
		if got := classifyUpload(tc.status, tc.err); got != tc.want {
			t.Errorf("classifyUpload(%d, %v) = %d; want %d", tc.status, tc.err, got, tc.want)
		}
	}
}

// poisonSaaS refuses, with status, any request whose body carries "poison",
// the way a WAF or DLP proxy in front of the SaaS refuses content; down makes
// it refuse everything (an outage). status -1 drops the connection.
func poisonSaaS(t *testing.T, status int) (*fakeSaaS, func(bool)) {
	var mu sync.Mutex
	down := false
	f := newFakeSaaS(t, func(_ []string, body string) int {
		mu.Lock()
		defer mu.Unlock()
		if down || strings.Contains(body, "poison") {
			return status
		}
		return 200
	})
	return f, func(d bool) { mu.Lock(); down = d; mu.Unlock() }
}

// acceptedIDs is every id the SaaS acknowledged: requests that returned 200.
func acceptedIDs(t *testing.T, f *fakeSaaS, refusedIfAny func([]string) bool) map[string]int {
	got := map[string]int{}
	for _, r := range f.requests() {
		if refusedIfAny(r) {
			continue
		}
		for _, id := range r {
			got[id]++
		}
	}
	return got
}

// runUntilDrained runs the uploader the way hooks would, one run per backoff
// window, until the queue drains or rounds run out.
func runUntilDrained(t *testing.T, advance func(time.Duration), rounds int) []flushResult {
	t.Helper()
	var out []flushResult
	for i := 0; i < rounds; i++ {
		r := flushAuditQueue()
		out = append(out, r)
		if r.Stopped == "queue drained" {
			return out
		}
		advance(auditBackoffMax)
	}
	return out
}

// TestAuditQueue_ContentRefusalDoesNotStallTheQueue: one event something in
// front of the SaaS refuses for its content (403, a 5xx, or a dropped
// connection) must not hold back the events behind it. Pass 1 found every
// later event stalled until the cap (waf.py: 0/12 delivered, main 12/12).
func TestAuditQueue_ContentRefusalDoesNotStallTheQueue(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantStatus int
	}{
		{"403", http.StatusForbidden, http.StatusForbidden},
		{"503", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{"connection reset", -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saas, _ := poisonSaaS(t, tc.status)
			dir := newQueueHome(t, saas.srv.URL)
			stubFlusher(t, nil)
			advance := fakeClock(t)
			for _, c := range []string{"echo a", "echo poison", "echo b", "echo c"} {
				sendRemoteAudit(queueEvent(c), nil)
			}
			ids := queuedIDs(t, dir)

			runs := runUntilDrained(t, advance, 10)
			if last := runs[len(runs)-1]; last.Stopped != "queue drained" {
				t.Fatalf("queue not drained after %d runs: %+v", len(runs), runs)
			}
			poisoned := map[string]bool{ids[1]: true}
			got := acceptedIDs(t, saas, func(r []string) bool {
				for _, id := range r {
					if poisoned[id] {
						return true
					}
				}
				return false
			})
			for _, i := range []int{0, 2, 3} {
				if got[ids[i]] == 0 {
					t.Errorf("event %d was never delivered (runs %+v)", i, runs)
				}
			}
			dead, _ := os.ReadFile(filepath.Join(dir, auditDeadFileName))
			if strings.Count(string(dead), "\n") != 1 || !strings.Contains(string(dead), ids[1]) {
				t.Fatalf("dead.jsonl = %s; want exactly the refused event", dead)
			}
			if tc.wantStatus != 0 && !strings.Contains(string(dead), `"status":`+strconv.Itoa(tc.wantStatus)) {
				t.Errorf("dead letter does not record status %d: %s", tc.wantStatus, dead)
			}
			if tc.wantStatus == 0 && !strings.Contains(string(dead), "EOF") && !strings.Contains(string(dead), "reset") {
				t.Errorf("dead letter does not record the connection error: %s", dead)
			}
		})
	}
}

// TestAuditQueue_OutageDeadLettersNothing: when everything fails, nothing is
// a poison event. However many runs, the queue keeps every event.
func TestAuditQueue_OutageDeadLettersNothing(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, -1} {
		saas, setDown := poisonSaaS(t, status)
		setDown(true)
		dir := newQueueHome(t, saas.srv.URL)
		stubFlusher(t, nil)
		advance := fakeClock(t)
		for i := 0; i < 6; i++ {
			sendRemoteAudit(queueEvent("echo outage"), nil)
		}
		runs := runUntilDrained(t, advance, 12)
		if _, err := os.Stat(filepath.Join(dir, auditDeadFileName)); !os.IsNotExist(err) {
			dead, _ := os.ReadFile(filepath.Join(dir, auditDeadFileName))
			t.Fatalf("status %d: an outage dead-lettered events: %s", status, dead)
		}
		if n := len(queuedIDs(t, dir)); n != 6 {
			t.Fatalf("status %d: queue holds %d events after the outage; want all 6", status, n)
		}
		if s := readAuditState(dir); s.Failures != 12 || s.HeadFailures != 12 {
			t.Fatalf("status %d: state %+v after 12 failed runs", status, s)
		}
		// The guard did probe (two requests per run once it engaged).
		if n := len(saas.requests()); n <= len(runs) {
			t.Fatalf("status %d: %d requests in %d runs; the head-of-line probe never ran", status, n, len(runs))
		}
		// And when the SaaS comes back, everything goes.
		setDown(false)
		if r := runUntilDrained(t, advance, 2); r[len(r)-1].Stopped != "queue drained" || r[len(r)-1].Sent != 6 {
			t.Fatalf("status %d: after recovery %+v; want all 6 delivered", status, r)
		}
	}
}

// TestAuditFlush_DoesNotEscalateBackoffFromParallelStarts: hooks that start
// uploaders in the same instant must not each count a failure. Pass 1: 30
// parallel hooks during a sub-second outage left failures=8 and 241 s of
// backoff.
func TestAuditFlush_DoesNotEscalateBackoffFromParallelStarts(t *testing.T) {
	saas, setDown := poisonSaaS(t, http.StatusServiceUnavailable)
	setDown(true)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	fakeClock(t)
	sendRemoteAudit(queueEvent("ls"), nil)
	for i := 0; i < 30; i++ { // 30 uploaders that all passed the hook's check
		flushAuditQueue()
	}
	if s := readAuditState(dir); s.Failures != 1 {
		t.Fatalf("failures = %d after 30 uploaders inside one window; want 1", s.Failures)
	}
	if n := len(saas.requests()); n != 1 {
		t.Fatalf("%d requests from 30 uploaders inside one backoff window; want 1", n)
	}

	// And a failure recorded inside an open window is not counted again.
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	s := auditQueueState{Failures: 1, RetryAfter: now.Add(time.Second).UnixMilli(), HeadFailures: 1}
	recordAuditFailure(&s, 0, now)
	if s.Failures != 1 || s.HeadFailures != 1 {
		t.Fatalf("failure inside an open window was counted: %+v", s)
	}
}

// TestAuditQueue_BackoffIsCapped pins the 5-minute ceiling.
func TestAuditQueue_BackoffIsCapped(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, prior := range []int{0, 1, 7, 8, 29, 40} {
		s := auditQueueState{Failures: prior}
		recordAuditFailure(&s, 0, now)
		want := auditBackoffMax // 2 s << 8 = 512 s is already past it
		if prior < 8 {
			want = auditBackoffBase << prior // 2 s, 4 s, ... 256 s
		}
		if got := time.Duration(s.RetryAfter-now.UnixMilli()) * time.Millisecond; got != want {
			t.Errorf("after %d prior failures the backoff is %v; want %v", prior, got, want)
		}
	}
}

// TestAuditFlush_StopsWhenProgressCannotBeRecorded: with the queue directory
// read-only the uploader cannot move its cursor. Pass 1 re-posted the same
// batch 10,086 times in 4 s. Now it posts once per run and stops, and the
// hook uploads directly instead of queueing.
func TestAuditFlush_StopsWhenProgressCannotBeRecorded(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	spawns := stubFlusher(t, nil)
	sendRemoteAudit(queueEvent("echo queued before the chmod"), nil)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	res := flushAuditQueue()
	if res.Requests != 1 || res.Stopped != "progress could not be recorded" {
		t.Fatalf("uploader with unrecordable progress: %+v; want 1 request then stop", res)
	}

	before := len(saas.requests())
	sendRemoteAudit(queueEvent("echo after the chmod"), nil)
	if got := len(saas.requests()) - before; got != 1 || spawns() != 1 {
		t.Fatalf("hook with an unrecordable queue: %d direct uploads, %d uploader starts; want 1 and none new", got, spawns()-1)
	}
	if n := len(queuedIDs(t, dir)); n != 1 {
		t.Fatalf("queue holds %d events; the hook must not queue what can never be marked sent", n)
	}
}

// TestAuditQueue_UnopenableFlushLockStillDelivers: chmod 000 on flush.lock
// stopped every upload (the uploader read it as "another uploader holds
// it"). It now runs unlocked.
func TestAuditQueue_UnopenableFlushLockStillDelivers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, func() { flushAuditQueue() })
	sendRemoteAudit(queueEvent("ls"), nil)
	lock := filepath.Join(dir, auditFlushLockName)
	if err := os.Chmod(lock, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lock, 0o600) })
	for i := 0; i < 3; i++ {
		sendRemoteAudit(queueEvent("ls"), nil)
	}
	if got := len(flatten(saas.requests())); got != 4 {
		t.Fatalf("SaaS received %d events with flush.lock unopenable; want 4", got)
	}
}

// TestAuditQueue_SymlinkedQueueFallsBackToSync: a queue.jsonl that is a
// symlink (to /dev/null, say) is never written through; the hook uploads
// directly.
func TestAuditQueue_SymlinkedQueueFallsBackToSync(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	spawns := stubFlusher(t, nil)
	sendRemoteAudit(queueEvent("ls"), nil) // creates the dir
	queue := filepath.Join(dir, auditQueueFileName)
	if err := os.Remove(queue); err != nil {
		t.Fatal(err)
	}
	sink := filepath.Join(t.TempDir(), "sink")
	if err := os.WriteFile(sink, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sink, queue); err != nil {
		t.Fatal(err)
	}
	before, startsBefore := len(saas.requests()), spawns()
	sendRemoteAudit(queueEvent("echo through a symlink"), nil)
	if got := len(saas.requests()) - before; got != 1 || spawns() != startsBefore {
		t.Fatalf("symlinked queue: %d direct uploads, %d new uploader starts; want 1 and 0", got, spawns()-startsBefore)
	}
	if data, _ := os.ReadFile(sink); len(data) != 0 {
		t.Fatalf("the event was written through the symlink: %s", data)
	}
}

// TestAuditQueue_AccountKeyCoversOrgAndServer: an event queued under one org
// or one server is never uploaded under another.
func TestAuditQueue_AccountKeyCoversOrgAndServer(t *testing.T) {
	org := func(n int64) *int64 { return &n }
	for _, tc := range []struct {
		name  string
		relog func(t *testing.T, a, b string)
	}{
		{"other org", func(t *testing.T, a, _ string) {
			c := &auth.Credentials{Server: a, Token: "tok-a"}
			c.User.ID, c.User.OrgID = 7, org(2)
			if err := auth.Save(c); err != nil {
				t.Fatal(err)
			}
		}},
		{"other server", func(t *testing.T, _, b string) {
			c := &auth.Credentials{Server: b, Token: "tok-a"} // same user and org
			c.User.ID, c.User.OrgID = 7, org(1)
			if err := auth.Save(c); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newFakeSaaS(t, nil), newFakeSaaS(t, nil)
			dir := newQueueHome(t, a.srv.URL)
			c := &auth.Credentials{Server: a.srv.URL, Token: "tok-a"}
			c.User.ID, c.User.OrgID = 7, org(1)
			if err := auth.Save(c); err != nil {
				t.Fatal(err)
			}
			stubFlusher(t, nil)
			sendRemoteAudit(queueEvent("echo recorded under the first login"), nil)
			tc.relog(t, a.srv.URL, b.srv.URL)
			res := flushAuditQueue()
			if n := len(a.requests()) + len(b.requests()); n != 0 || res.DeadLettered != 1 {
				t.Fatalf("after a re-login to %s: %d uploads, flush %+v; want 0 and 1 dead-lettered", tc.name, n, res)
			}
			if dead, _ := os.ReadFile(filepath.Join(dir, auditDeadFileName)); !strings.Contains(string(dead), "another account") {
				t.Fatalf("dead.jsonl does not say why: %s", dead)
			}
		})
	}
}

// TestAuditQueue_OversizedEventGoesAlone: an event larger than the batch byte
// budget is still sent, in a request of its own, and its neighbours are not
// held back.
func TestAuditQueue_OversizedEventGoesAlone(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	prev := auditBatchMaxBytes
	auditBatchMaxBytes = 600
	t.Cleanup(func() { auditBatchMaxBytes = prev })

	sendRemoteAudit(queueEvent("echo small one"), nil)
	sendRemoteAudit(queueEvent("echo "+strings.Repeat("x", 2000)), nil)
	sendRemoteAudit(queueEvent("echo small two"), nil)
	ids := queuedIDs(t, dir)
	if res := flushAuditQueue(); res.Sent != 3 {
		t.Fatalf("flush = %+v; want all 3 sent", res)
	}
	reqs := saas.requests()
	if len(reqs) != 3 || len(reqs[1]) != 1 || reqs[1][0] != ids[1] {
		t.Fatalf("requests = %v; want the oversized event alone in the second of three", reqs)
	}
}

// TestAuditQueue_RetryResendsTheSameBytes: the wire entry, with its #4208
// local chain link and its client_event_id, is fixed when the hook queues it.
// A retry after a lost response sends byte-identical events.
func TestAuditQueue_RetryResendsTheSameBytes(t *testing.T) {
	var first sync.Once
	saas := newFakeSaaS(t, func([]string, string) int {
		status := 200
		first.Do(func() { status = -1 })
		return status
	})
	newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	link := &logger.ChainLink{PrevHash: strings.Repeat("a", 64), LineHash: strings.Repeat("b", 64)}
	sendRemoteAudit(queueEvent("ls one"), link)
	sendRemoteAudit(queueEvent("ls two"), nil)

	flushAuditQueue()
	advance(auditBackoffBase)
	if res := flushAuditQueue(); res.Sent != 2 {
		t.Fatalf("retry = %+v; want both sent", res)
	}
	saas.mu.Lock()
	bodies := append([]string(nil), saas.bodies...)
	saas.mu.Unlock()
	if len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("retry body differs from the first send:\nfirst %s\nretry %s", bodies[0], bodies[len(bodies)-1])
	}
	if !strings.Contains(bodies[1], `"local_chain":{"line_hash":"`+link.LineHash+`","prev_hash":"`+link.PrevHash+`"}`) {
		t.Fatalf("the queued entry lost its local chain link: %s", bodies[1])
	}
}
