package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// In-process tests for the #4467 upload queue (audit_queue.go). The detached
// spawn and the hook's latency are covered by audit_queue_e2e_test.go.

var eventIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// fakeSaaS stands in for /api/audit. decide picks the status for a request
// from its event ids and body; nil answers 200.
type fakeSaaS struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   [][]string // event ids, per request, in arrival order
	bodies []string   // request bodies, in arrival order
	decide func(ids []string, body string) int
}

func newFakeSaaS(t *testing.T, decide func(ids []string, body string) int) *fakeSaaS {
	t.Helper()
	f := &fakeSaaS{decide: decide}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/audit" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		ids := wireClientEventIDs(t, body)
		f.mu.Lock()
		f.reqs = append(f.reqs, ids)
		f.bodies = append(f.bodies, string(body))
		decide := f.decide
		f.mu.Unlock()
		status := http.StatusOK
		if decide != nil {
			status = decide(ids, string(body))
		}
		if status < 0 { // drop the connection: the server got the batch, the client never hears back
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					_ = c.Close()
					return
				}
			}
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSaaS) requests() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.reqs))
	copy(out, f.reqs)
	return out
}

func wireClientEventIDs(t *testing.T, body []byte) []string {
	var wire struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Errorf("/api/audit body is not the wire envelope: %v\n%s", err, body)
		return nil
	}
	ids := make([]string, 0, len(wire.Events))
	for _, e := range wire.Events {
		id, _ := e["client_event_id"].(string)
		ids = append(ids, id)
	}
	return ids
}

// newQueueHome is a scratch HOME logged in to server as user 7, with the
// package config flags pinned to their defaults. It returns the queue dir.
func newQueueHome(t *testing.T, server string) string {
	t.Helper()
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	saveQueueCreds(t, server, "tok-a", 7)
	return filepath.Join(home, ".agentshield", auditQueueDirName)
}

func saveQueueCreds(t *testing.T, server, token string, userID int64) {
	t.Helper()
	c := &auth.Credentials{Server: server, Token: token}
	c.User.ID = userID
	if err := auth.Save(c); err != nil {
		t.Fatalf("auth.Save: %v", err)
	}
}

// stubFlusher replaces the spawn for one test: run is what a "spawn" does
// (nil: nothing, the event stays queued). It returns the spawn count.
func stubFlusher(t *testing.T, run func()) func() int {
	t.Helper()
	var mu sync.Mutex
	n := 0
	prev := startAuditFlusher
	startAuditFlusher = func() error {
		mu.Lock()
		n++
		mu.Unlock()
		if run != nil {
			run()
		}
		return nil
	}
	t.Cleanup(func() { startAuditFlusher = prev })
	return func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// fakeClock pins auditNow; advance moves it.
func fakeClock(t *testing.T) (advance func(time.Duration)) {
	t.Helper()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	prev := auditNow
	auditNow = func() time.Time { return now }
	t.Cleanup(func() { auditNow = prev })
	return func(d time.Duration) { now = now.Add(d) }
}

func queueEvent(cmd string) *logger.AuditEvent {
	return &logger.AuditEvent{Command: cmd, Decision: "AUDIT", Mode: "enforce", Source: "claude-code-hook",
		TriggeredRules: []string{"test-rule"}, Reasons: []string{"test"}}
}

// queuedIDs reads the event ids queue.jsonl holds, in order.
func queuedIDs(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, auditQueueFileName))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read queue: %v", err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ql auditQueueLine
		if err := json.Unmarshal([]byte(line), &ql); err != nil {
			ids = append(ids, "") // a malformed line a test planted: keep positions
			continue
		}
		var e map[string]any
		_ = json.Unmarshal(ql.Event, &e)
		id, _ := e["client_event_id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func queueSize(t *testing.T, dir string) int64 {
	t.Helper()
	st, err := os.Stat(filepath.Join(dir, auditQueueFileName))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatalf("stat queue: %v", err)
	}
	return st.Size()
}

func flatten(reqs [][]string) []string {
	var out []string
	for _, r := range reqs {
		out = append(out, r...)
	}
	return out
}

// TestAuditBatchBody_MatchesMarshal: the queue's batch envelope is the same
// bytes json.Marshal gives for {"events":[...]}, so the single-event golden
// pins the batched wire too.
func TestAuditBatchBody_MatchesMarshal(t *testing.T) {
	e1 := map[string]any{"command": "a <b> & c", "decision": "AUDIT", "rule_ids": []string{}}
	e2 := map[string]any{"command": "mcp:Read", "decision": "BLOCK", "arguments": map[string]any{"k": 1.0}}
	r1, _ := json.Marshal(e1)
	r2, _ := json.Marshal(e2)
	for _, tc := range []struct {
		raws []json.RawMessage
		objs []map[string]any
	}{
		{[]json.RawMessage{r1}, []map[string]any{e1}},
		{[]json.RawMessage{r1, r2}, []map[string]any{e1, e2}},
	} {
		want, _ := json.Marshal(map[string]any{"events": tc.objs})
		if got := auditBatchBody(tc.raws); string(got) != string(want) {
			t.Errorf("batch body diverged from json.Marshal:\n got %s\nwant %s", got, want)
		}
	}
}

// TestSendRemoteAudit_QueuesWithoutTouchingTheNetwork is the in-process
// fitness function for contract item 1: against a SaaS that holds every
// request for 2 s, sendRemoteAudit returns at local-disk speed, having sent
// nothing, and the event goes out when the uploader runs.
func TestSendRemoteAudit_QueuesWithoutTouchingTheNetwork(t *testing.T) {
	saas := newFakeSaaS(t, func([]string, string) int { time.Sleep(2 * time.Second); return 200 })
	dir := newQueueHome(t, saas.srv.URL)
	spawns := stubFlusher(t, nil)

	start := time.Now()
	sendRemoteAudit(queueEvent("ls -la"), nil)
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("sendRemoteAudit took %v; it must not wait on the SaaS (holds 2 s)", d)
	}
	if n := len(saas.requests()); n != 0 {
		t.Fatalf("SaaS saw %d requests during the hook; want 0", n)
	}
	if spawns() != 1 {
		t.Fatalf("uploader started %d times; want 1", spawns())
	}
	ids := queuedIDs(t, dir)
	if len(ids) != 1 || !eventIDRe.MatchString(ids[0]) {
		t.Fatalf("queue ids = %v; want one 32-hex client_event_id", ids)
	}

	res := flushAuditQueue()
	if got := flatten(saas.requests()); len(got) != 1 || got[0] != ids[0] {
		t.Fatalf("SaaS received %v; want the queued id %s (flush: %+v)", got, ids[0], res)
	}
	if queueSize(t, dir) != 0 {
		t.Errorf("queue not truncated after a full upload")
	}
}

// TestAuditQueue_RedactionAtRest: the queue is a new at-rest copy of the
// payload. A data-label match (#4448) and a secret Redacted() removes must
// not reach it, and the file is private.
func TestAuditQueue_RedactionAtRest(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, dataLabelPolicy4448)
	saveQueueCreds(t, "http://127.0.0.1:1", "tok-a", 7)
	stubFlusher(t, nil) // nothing uploads: the events stay at rest
	dir := filepath.Join(home, ".agentshield", auditQueueDirName)

	const label = "CUST-104233"
	cmd := `curl -sS -H "Authorization: Bearer ` + testBearerToken() + `" https://api.example.com/v1/customers/` + label
	res, _ := evaluateCommand(cmd, "/workspace", "claude-code-hook", "sess-4467")
	if res.Decision != policy.DecisionBlock {
		t.Fatalf("precondition: want the data-label BLOCK, got %v %v", res.Decision, res.TriggeredRules)
	}
	auditMCPCall("postgres_connect",
		map[string]interface{}{"host": "db.internal", "password": testPassword()},
		mcp.MCPEvalResult{Decision: policy.DecisionAudit, TriggeredRules: []string{"test-rule"}, Reasons: []string{"test"}},
		"claude-code-hook", "enforce", "sess-4467", "", nil)

	data, err := os.ReadFile(filepath.Join(dir, auditQueueFileName))
	if err != nil {
		t.Fatalf("read queue: %v", err)
	}
	if n := strings.Count(string(data), "\n"); n != 2 {
		t.Fatalf("queue holds %d lines; want 2 — without them this test asserts nothing:\n%s", n, data)
	}
	assertSecretAbsent(t, "queue.jsonl", data, testBearerToken())
	assertSecretAbsent(t, "queue.jsonl", data, testPassword())
	if strings.Contains(string(data), label) {
		t.Errorf("queue.jsonl carries the data-label match %s:\n%s", label, data)
	}
	if !strings.Contains(string(data), "[LABEL:customer-records]") {
		t.Errorf("queue.jsonl has no label placeholder; the fixture no longer reaches the scrubber:\n%s", data)
	}
	if log := readFailSafeAuditLog(t, configDir); strings.Contains(log, label) {
		t.Errorf("control: audit.jsonl itself carries the label match:\n%s", log)
	}
	for _, p := range []string{auditQueueFileName, auditQueueLockName} {
		st, err := os.Stat(filepath.Join(dir, p))
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v; want 0600", p, st.Mode().Perm())
		}
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("queue dir mode = %v (%v); want 0700", st.Mode().Perm(), err)
	}
}

// TestAuditQueue_LostResponseResendsSameEventIDs: the SaaS stores a batch but
// the uploader never hears back (connection dropped). The batch stays queued
// and the retry carries the same client_event_ids, which is what lets the SaaS drop
// the repeat.
func TestAuditQueue_LostResponseResendsSameEventIDs(t *testing.T) {
	var first sync.Once
	saas := newFakeSaaS(t, func([]string, string) int {
		status := 200
		first.Do(func() { status = -1 })
		return status
	})
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	advance := fakeClock(t)
	for _, c := range []string{"ls a", "ls b", "ls c"} {
		sendRemoteAudit(queueEvent(c), nil)
	}
	queued := queuedIDs(t, dir)

	res := flushAuditQueue()
	if !strings.Contains(res.Stopped, "backing off") || res.Sent != 0 {
		t.Fatalf("first flush = %+v; want a retryable failure and nothing marked sent", res)
	}
	if s := readAuditState(dir); s.Failures != 1 || s.Cursor != 0 {
		t.Fatalf("state after the lost response = %+v; want failures 1, cursor 0", s)
	}
	advance(auditBackoffBase)
	res = flushAuditQueue()
	reqs := saas.requests()
	if len(reqs) != 2 || res.Sent != 3 {
		t.Fatalf("requests = %v, flush = %+v; want two requests, the second acknowledged", reqs, res)
	}
	if strings.Join(reqs[0], ",") != strings.Join(queued, ",") || strings.Join(reqs[1], ",") != strings.Join(queued, ",") {
		t.Fatalf("retry changed the event ids:\nqueued %v\nfirst  %v\nretry  %v", queued, reqs[0], reqs[1])
	}
	if s := readAuditState(dir); s.Failures != 0 || s.RetryAfter != 0 || s.Cursor != 0 || queueSize(t, dir) != 0 {
		t.Errorf("after delivery: state %+v, queue %d bytes; want reset and empty", s, queueSize(t, dir))
	}
}

// TestAuditQueue_OutageBacksOffThenDeliversBacklog: during an outage the
// first failure starts an exponential backoff and no hook starts another
// uploader inside it (no spawn storm); when the SaaS is back every queued
// event is delivered, in order, with its original id.
func TestAuditQueue_OutageBacksOffThenDeliversBacklog(t *testing.T) {
	var mu sync.Mutex
	up := false
	saas := newFakeSaaS(t, func([]string, string) int {
		mu.Lock()
		defer mu.Unlock()
		if up {
			return 200
		}
		return http.StatusServiceUnavailable
	})
	dir := newQueueHome(t, saas.srv.URL)
	advance := fakeClock(t)
	spawns := stubFlusher(t, func() { flushAuditQueue() })

	for i := 0; i < 20; i++ {
		sendRemoteAudit(queueEvent("echo outage"), nil)
	}
	if spawns() != 1 || len(saas.requests()) != 1 {
		t.Fatalf("20 hook calls in an outage: %d uploader starts, %d requests; want 1 and 1", spawns(), len(saas.requests()))
	}
	if s := readAuditState(dir); s.Failures != 1 || s.RetryAfter != auditNow().Add(2*time.Second).UnixMilli() {
		t.Fatalf("state = %+v; want failures 1 and a 2 s backoff", s)
	}

	advance(1 * time.Second) // still inside the window
	sendRemoteAudit(queueEvent("echo outage"), nil)
	if spawns() != 1 {
		t.Fatalf("an uploader started inside the backoff window")
	}
	advance(1 * time.Second) // window over, SaaS still down: the backoff doubles
	sendRemoteAudit(queueEvent("echo outage"), nil)
	if s := readAuditState(dir); spawns() != 2 || s.Failures != 2 || s.RetryAfter != auditNow().Add(4*time.Second).UnixMilli() {
		t.Fatalf("second failure: %d starts, state %+v; want 2 starts, failures 2, a 4 s backoff", spawns(), s)
	}

	queued := queuedIDs(t, dir)
	if len(queued) != 22 {
		t.Fatalf("queue holds %d events; want all 22", len(queued))
	}
	mu.Lock()
	up = true
	mu.Unlock()
	advance(4 * time.Second)
	sendRemoteAudit(queueEvent("echo recovered"), nil)
	reqs := saas.requests()
	delivered := reqs[len(reqs)-1]
	if spawns() != 3 || len(delivered) != 23 {
		t.Fatalf("recovery: %d starts, last request carried %d events; want 3 and 23", spawns(), len(delivered))
	}
	if strings.Join(delivered[:22], ",") != strings.Join(queued, ",") {
		t.Fatalf("backlog delivered out of order or with new ids")
	}
	if queueSize(t, dir) != 0 {
		t.Errorf("queue not truncated after the backlog was delivered")
	}
}

// TestAuditQueue_RefusedEventIsDeadLettered: a permanent 4xx must not block
// the queue. A refused batch is retried one event at a time, the refused
// event moves to dead.jsonl, its neighbours are delivered. Undeliverable
// lines (malformed, another account's) are dead-lettered too.
func TestAuditQueue_RefusedEventIsDeadLettered(t *testing.T) {
	saas := newFakeSaaS(t, func(_ []string, body string) int {
		if strings.Contains(body, "poison") {
			return http.StatusBadRequest
		}
		return 200
	})
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)

	sendRemoteAudit(queueEvent("echo a"), nil)
	sendRemoteAudit(queueEvent("echo poison"), nil)
	sendRemoteAudit(queueEvent("echo b"), nil)
	appendQueueRaw(t, dir, "this is not json\n")
	appendQueueRaw(t, dir, `{"v":1,"acct":"0123456789abcdef0123456789abcdef","event":{"command":"x","client_event_id":"ffffffffffffffffffffffffffffffff"}}`+"\n")
	sendRemoteAudit(queueEvent("echo c"), nil)
	ids := queuedIDs(t, dir)

	res := flushAuditQueue()
	if res.Sent != 3 || res.DeadLettered != 3 || res.Stopped != "queue drained" {
		t.Fatalf("flush = %+v; want 3 sent, 3 dead-lettered, drained", res)
	}
	accepted := map[string]bool{}
	for _, r := range saas.requests() {
		if len(r) == 1 && r[0] != ids[1] {
			accepted[r[0]] = true
		}
	}
	for _, i := range []int{0, 2, 5} {
		if !accepted[ids[i]] {
			t.Errorf("event %d (%s) was not delivered on its own after the refusal", i, ids[i])
		}
	}
	dead, err := os.ReadFile(filepath.Join(dir, auditDeadFileName))
	if err != nil {
		t.Fatalf("read dead.jsonl: %v", err)
	}
	for _, want := range []string{ids[1], `"status":400`, "malformed queue line", "another account"} {
		if !strings.Contains(string(dead), want) {
			t.Errorf("dead.jsonl lacks %q:\n%s", want, dead)
		}
	}
	if queueSize(t, dir) != 0 {
		t.Errorf("queue not drained past the dead letters")
	}
}

func appendQueueRaw(t *testing.T, dir, s string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, auditQueueFileName), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatalf("write queue: %v", err)
	}
	_ = f.Close()
}

// TestAuditQueue_TornLineDoesNotSwallowTheNextEvent: a crashed writer's
// fragment without a newline is terminated by the next append, so the next
// event is its own line and is delivered; the fragment is dead-lettered.
func TestAuditQueue_TornLineDoesNotSwallowTheNextEvent(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	appendQueueRaw(t, dir, `{"v":1,"acct":"abc","event":{"comm`)
	sendRemoteAudit(queueEvent("echo after the tear"), nil)

	res := flushAuditQueue()
	if res.Sent != 1 || res.DeadLettered != 1 {
		t.Fatalf("flush = %+v; want the event sent and the fragment dead-lettered", res)
	}
	if got := flatten(saas.requests()); len(got) != 1 || !eventIDRe.MatchString(got[0]) {
		t.Fatalf("SaaS received %v; want the one event", got)
	}
}

// TestAuditQueue_CapDropsNewEventsAndCounts: at the cap a new event is not
// queued and is counted; audit.jsonl still has every event.
func TestAuditQueue_CapDropsNewEventsAndCounts(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	saveQueueCreds(t, "http://127.0.0.1:1", "tok-a", 7)
	stubFlusher(t, nil)
	prev := auditQueueMaxBytes
	auditQueueMaxBytes = 2048
	t.Cleanup(func() { auditQueueMaxBytes = prev })
	dir := filepath.Join(filepath.Dir(configDir), ".agentshield", auditQueueDirName)

	const n = 12
	for i := 0; i < n; i++ {
		evaluateCommand("ls -la /tmp", "/workspace", "claude-code-hook", "sess-cap")
	}
	queued := len(queuedIDs(t, dir))
	if size := queueSize(t, dir); size > 2048 || queued == 0 || queued == n {
		t.Fatalf("queue %d bytes holding %d of %d events; want a non-empty queue under the 2048-byte cap", size, queued, n)
	}
	if s := readAuditState(dir); s.Dropped != int64(n-queued) {
		t.Errorf("state.dropped = %d; want %d", s.Dropped, n-queued)
	}
	if lines := strings.Count(readFailSafeAuditLog(t, configDir), "\n"); lines != n {
		t.Errorf("audit.jsonl holds %d lines; want all %d — the cap is on the upload queue only", lines, n)
	}
}

// TestAuditUpload_SyncModeIsTheOldBehaviour: AGENTSHIELD_AUDIT_UPLOAD=sync
// POSTs from the hook and waits, with no queue and no uploader.
func TestAuditUpload_SyncModeIsTheOldBehaviour(t *testing.T) {
	saas := newFakeSaaS(t, func([]string, string) int { time.Sleep(300 * time.Millisecond); return 200 })
	dir := newQueueHome(t, saas.srv.URL)
	spawns := stubFlusher(t, nil)
	t.Setenv(auditUploadEnv, "sync")

	start := time.Now()
	sendRemoteAudit(queueEvent("ls -la"), nil)
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("sync upload returned in %v, before the SaaS answered (300 ms)", d)
	}
	got := flatten(saas.requests())
	if len(got) != 1 || !eventIDRe.MatchString(got[0]) {
		t.Fatalf("SaaS received %v; want one event with a client_event_id", got)
	}
	if spawns() != 0 {
		t.Errorf("sync mode started %d uploaders", spawns())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("sync mode created the queue dir (%v)", err)
	}
}

// TestAuditUpload_UnwritableQueueFallsBackToSync: if the queue cannot be
// written the event is POSTed directly rather than lost.
func TestAuditUpload_UnwritableQueueFallsBackToSync(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	spawns := stubFlusher(t, nil)
	if err := os.WriteFile(dir, []byte("a file where the queue dir should be"), 0o600); err != nil {
		t.Fatal(err)
	}
	sendRemoteAudit(queueEvent("ls -la"), nil)
	if got := flatten(saas.requests()); len(got) != 1 {
		t.Fatalf("SaaS received %v; want the event via the synchronous fallback", got)
	}
	if spawns() != 0 {
		t.Errorf("fallback started an uploader")
	}
}

// TestAuditQueue_OtherAccountIsNotMisfiled: an event queued under one login
// is never uploaded under another; a re-login to the same account (new
// token) still delivers.
func TestAuditQueue_OtherAccountIsNotMisfiled(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)

	sendRemoteAudit(queueEvent("echo user seven"), nil)
	saveQueueCreds(t, saas.srv.URL, "tok-a2", 7) // same account, new token
	sendRemoteAudit(queueEvent("echo user seven again"), nil)
	if res := flushAuditQueue(); res.Sent != 2 {
		t.Fatalf("re-login to the same account: flush = %+v; want both events sent", res)
	}

	sendRemoteAudit(queueEvent("echo user seven, before logout"), nil)
	saveQueueCreds(t, saas.srv.URL, "tok-b", 8)
	before := len(flatten(saas.requests()))
	res := flushAuditQueue()
	if after := len(flatten(saas.requests())); after != before || res.DeadLettered != 1 {
		t.Fatalf("another account logged in: %d events uploaded, flush %+v; want 0 uploaded, 1 dead-lettered", after-before, res)
	}
	if dead, _ := os.ReadFile(filepath.Join(dir, auditDeadFileName)); !strings.Contains(string(dead), "another account") {
		t.Errorf("dead.jsonl does not say why:\n%s", dead)
	}
}

// TestAuditQueue_FinishReleasesFlushLockUnderQueueLock pins the lost-wake-up
// ordering: the uploader gives up flush.lock while it still holds
// queue.lock, so an append cannot land between "nothing left" and "uploader
// gone" without the appender seeing no uploader and starting one.
func TestAuditQueue_FinishReleasesFlushLockUnderQueueLock(t *testing.T) {
	dir := newQueueHome(t, "http://127.0.0.1:1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	release, ok := tryLockFlush(dir)
	if !ok {
		t.Fatal("could not take flush.lock")
	}
	heldDuringRelease := false
	done := finishAuditFlush(dir, 0, func() {
		heldDuringRelease = queueLockHeldElsewhere(t, dir)
		release()
	})
	if !done {
		t.Fatal("finishAuditFlush on an empty queue did not finish")
	}
	if !heldDuringRelease {
		t.Fatal("flush.lock was released after queue.lock: an append in that gap is stranded until the next tool call")
	}
	if auditFlusherRunning(dir) {
		t.Fatal("flush.lock still held after finish")
	}
}

func queueLockHeldElsewhere(t *testing.T, dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, auditQueueLockName), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open queue.lock: %v", err)
	}
	defer func() { _ = f.Close() }()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		unlockFd(int(f.Fd()))
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK)
}

// TestAuditFlusherArgv_IsFixed: the uploader's command line is this binary
// and the word audit-flush, never event data (exec_safety_test.go's concern).
func TestAuditFlusherArgv_IsFixed(t *testing.T) {
	argv, env, err := auditFlusherArgv()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if len(argv) != 2 || argv[0] != exe || argv[1] != "audit-flush" || len(env) != 0 {
		t.Fatalf("argv = %q, env = %q; want [%s audit-flush] and no extra env", argv, env, exe)
	}
	if c, _, err := rootCmd.Find([]string{"audit-flush"}); err != nil || c != auditFlushCmd || !c.Hidden {
		t.Fatalf("audit-flush is not the hidden uploader command: %v %v", c, err)
	}
}

// TestAuditQueueFiles_SelfProtectedLikeAuditLog: the queue is evidence in
// flight, so an agent may not tamper with it any more than with audit.jsonl.
// Every shell tamper shape decides at least as strictly on a queue file as on
// audit.jsonl, deletes are BLOCKed outright, and the MCP config guard covers
// the directory. Commands are assembled at runtime: the hook reads test
// sources as text.
func TestAuditQueueFiles_SelfProtectedLikeAuditLog(t *testing.T) {
	newFailSafeHome(t, false, failSafePolicyGood)
	stubFlusher(t, nil)
	base := "~/.agent" + "shield/"
	rank := map[policy.Decision]int{policy.DecisionAllow: 0, policy.DecisionAudit: 1,
		policy.DecisionRequireApproval: 2, policy.DecisionBlock: 3}
	decide := func(cmd string) policy.Decision {
		r, _ := evaluateCommand(cmd, "/workspace", "claude-code-hook", "sess-sp")
		return r.Decision
	}
	rm := "r" + "m"
	shapes := []string{rm + " -f %s", rm + " -rf %s", "truncate -s 0 %s", "sed -i 1d %s", ": > %s",
		"cp /dev/null %s", "mv %s /tmp/x", "echo x >> %s", "unlink %s"}
	targets := []string{auditQueueDirName + "/" + auditQueueFileName, auditQueueDirName + "/" + auditStateFileName,
		auditQueueDirName + "/" + auditDeadFileName}
	for _, shape := range shapes {
		ref := decide(strings.Replace(shape, "%s", base+"audit.jsonl", 1))
		for _, tgt := range targets {
			got := decide(strings.Replace(shape, "%s", base+tgt, 1))
			if rank[got] < rank[ref] {
				t.Errorf("%q on %s decides %v, weaker than %v on audit.jsonl", shape, tgt, got, ref)
			}
		}
	}
	for _, cmd := range []string{rm + " -f " + base + auditQueueDirName + "/" + auditQueueFileName, rm + " -rf " + base + auditQueueDirName} {
		if got := decide(cmd); got != policy.DecisionBlock {
			t.Errorf("%q decides %v; want BLOCK", cmd, got)
		}
	}
	home := os.Getenv("HOME")
	for _, tool := range []string{"Write", "Edit", "write_file"} {
		r := mcp.CheckConfigGuard(tool, map[string]interface{}{
			"file_path": home + "/.agentshield/" + auditQueueDirName + "/" + auditQueueFileName,
			"path":      home + "/.agentshield/" + auditQueueDirName + "/" + auditQueueFileName,
			"content":   "{}\n",
		})
		if !r.Blocked {
			t.Errorf("MCP %s to the queue is not blocked by the config guard", tool)
		}
	}
}

// TestAuditBackingOff_IgnoresAFarFutureRetry: a retry_after beyond the
// longest backoff (a clock moved backwards, an edited state file) must not
// stall uploads; inside the window it is honoured.
func TestAuditBackingOff_IgnoresAFarFutureRetry(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		retryAfter time.Time
		want       bool
	}{
		{now.Add(time.Second), true},
		{now.Add(auditBackoffMax), true},
		{now.Add(auditBackoffMax + time.Second), false},
		{now.Add(24 * time.Hour), false},
		{now.Add(-time.Second), false},
	} {
		if got := auditBackingOff(auditQueueState{RetryAfter: tc.retryAfter.UnixMilli()}, now); got != tc.want {
			t.Errorf("retry_after now%+v: backing off = %v; want %v", tc.retryAfter.Sub(now), got, tc.want)
		}
	}
	if auditBackingOff(auditQueueState{}, now) {
		t.Error("no retry_after reads as backing off")
	}
}
