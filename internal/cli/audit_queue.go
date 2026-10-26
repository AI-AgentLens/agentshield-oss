package cli

// Local upload queue for SaaS audit events (#4467).
//
// Before this the hook POSTed every event to /api/audit and waited for the
// answer: one SaaS round trip on every tool call, 3 s whenever the SaaS hung,
// and the event was lost on any error. Now the hook appends the event to a
// queue file and starts a detached uploader (`agentshield audit-flush`) that
// it never waits for. The decision is final before any of this runs.
//
// # Files, all under ~/.agentshield/audit-queue/ (0700 dir, 0600 files)
//
//	queue.jsonl  one line per event: {"v":1,"acct":<account key>,"event":<wire entry>}
//	queue.lock   flock taken by every append and by the uploader's short
//	             bookkeeping steps; never held across network I/O
//	flush.lock   flock the one running uploader holds for its lifetime
//	state.jsonl  {cursor, failures, retry_after, head_cursor, head_failures,
//	             dropped, dead_dropped}
//	dead.jsonl   events the SaaS permanently refused, or that belong to an
//	             account other than the one now logged in
//
// The event stored is the wire entry auditWireEntry builds, from the
// event's Redacted() copy (data-label scrub included), so the queue never
// holds more than audit.jsonl does. audit.jsonl stays the source of truth;
// this queue is only the delivery buffer. The entry is built once, in the
// hook; the uploader and every retry send those bytes unchanged.
//
// queue.jsonl and dead.jsonl are opened with O_NOFOLLOW and must be regular
// files: a symlink to /dev/null would otherwise swallow every event. If the
// queue cannot be written, or its directory or state file cannot (progress
// could never be recorded), the hook uploads synchronously instead.
//
// # Delivery: at least once
//
// The uploader sends lines from the cursor in batches and advances the cursor
// only after a 2xx. A crash or a lost response after the SaaS stored a batch
// re-sends it with the same client_event_ids, and the SaaS drops the repeats
// (aiagentlens: unique (org_id, client_event_id)). A network error, a timeout,
// a 5xx or a 401/408/429 keeps the batch and backs off exponentially; no new
// uploader starts until the backoff window passes, and an uploader that finds
// itself inside one exits. Any other 4xx, 403 included, is a permanent
// refusal: a multi-event batch is re-sent one event at a time so one bad
// event cannot take its neighbours with it, and the refused event moves to
// dead.jsonl so it cannot block the queue.
//
// # Head of line
//
// Something between Shield and the SaaS (a WAF, a DLP proxy) can refuse one
// event for its content with what looks retryable: a 5xx, or a reset. Left
// alone that event would stall every event behind it until the cap. After
// auditHeadProbeAfter consecutive retryable failures at the same cursor, the
// uploader sends events one at a time. When the head fails alone, it probes
// further down the queue, sending the 1st, 2nd, 4th, 8th, ... event behind
// the head alone until one is accepted. Doubling reaches any run of adjacent
// refusals in a few requests (pass 2 found that probing only the next event
// stalled the queue for good on two). If no probe is accepted, it is an
// outage: nothing is dead-lettered and the queue backs off.
//
// An accepted probe proves the path to the SaaS works, so the uploader walks
// from the head to it one event at a time. An event that fails, and fails a
// second try, is dead-lettered with its status or error only if the accepted
// event is then accepted once more; if that fails too, the path went down
// mid-walk and the queue backs off without dead-lettering. That re-send is
// stored already, and the SaaS drops it as a repeat of its client_event_id.
//
// An event is queued under the account logged in when it happened (acct is a
// hash of server, user id and org id, never the token). If a different
// account is logged in at upload time the event goes to dead.jsonl instead of
// being filed under the wrong organisation.
//
// # Bounds
//
// The queue file is capped at auditQueueMaxBytes. At the cap a new event is
// not queued (state.dropped counts it); it is still in audit.jsonl. The
// uploader truncates the file whenever it has sent everything in it.
// dead.jsonl is capped at auditDeadMaxBytes the same way (dead_dropped). An
// uploader that cannot record its progress stops at once, so it re-sends at
// most one batch per run.
//
// # Lost wake-up
//
// An append that lands while an uploader is finishing must not be stranded
// until the next tool call. The uploader decides it is done only under
// queue.lock (file size == cursor), and releases flush.lock BEFORE releasing
// queue.lock. An append therefore either lands before that check (the
// uploader sees it and keeps going) or after flush.lock is free (the hook that
// appended sees no uploader running and starts one).

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
)

const (
	auditQueueDirName  = "audit-queue"
	auditQueueFileName = "queue.jsonl"
	auditQueueLockName = "queue.lock"
	auditFlushLockName = "flush.lock"
	// state.jsonl is one JSON object. The .jsonl name is deliberate: the
	// shell self-protection rules for ~/.agentshield key on .jsonl (truncate,
	// redirect, sed -i), so the cursor and backoff get the same protection as
	// the events (TestAuditQueueFiles_SelfProtectedLikeAuditLog).
	auditStateFileName = "state.jsonl"
	auditDeadFileName  = "dead.jsonl"

	// auditQueueLineVersion is the "v" of a queue line. A line with any
	// other version is not guessed at: it goes to dead.jsonl.
	auditQueueLineVersion = 1

	// auditUploadEnv selects the upload mode. "sync" restores the pre-#4467
	// synchronous POST; anything else (or unset) is the queue.
	auditUploadEnv = "AGENTSHIELD_AUDIT_UPLOAD"
)

// Tunables. Variables only so tests can shrink them.
var (
	// auditQueueMaxBytes caps queue.jsonl: about 16k typical shell events.
	auditQueueMaxBytes int64 = 16 << 20
	// auditDeadMaxBytes caps dead.jsonl.
	auditDeadMaxBytes int64 = 4 << 20
	// A batch is at most this many events and this many bytes of entries
	// (always at least one event). The SaaS ingest sets no body or event
	// count limit and its proxy allows far larger bodies; 512 KiB also stays
	// under nginx's 1 MiB default, for a deployment that sets none. One event
	// larger than a proxy's limit is refused (413) and dead-lettered.
	auditBatchMaxEvents       = 100
	auditBatchMaxBytes  int64 = 512 << 10
	// Backoff after a retryable failure: base, doubling, capped.
	auditBackoffBase = 2 * time.Second
	auditBackoffMax  = 5 * time.Minute
	// auditHeadProbeAfter is how many consecutive retryable failures at one
	// cursor switch the uploader to single events and the head-of-line probe.
	auditHeadProbeAfter = 3
	// auditFlushRequestTimeout bounds one POST; auditFlushBudget bounds one
	// uploader process. A backlog left at the budget is picked up by the
	// uploader the next hook call starts.
	auditFlushRequestTimeout = 15 * time.Second
	auditFlushBudget         = 2 * time.Minute
	// auditQueueLockWait bounds how long an append waits for queue.lock. The
	// lock is only ever held for local file bookkeeping, so the budget is
	// generous; past it the append goes ahead unlocked (O_APPEND keeps a
	// single write whole) rather than stall the hook.
	auditQueueLockWait = 200 * time.Millisecond

	auditNow = time.Now

	// startAuditFlusher starts the background uploader. Production spawns a
	// detached `agentshield audit-flush` (audit_flush.go); the package tests
	// replace it (audit_queue_main_test.go).
	startAuditFlusher = spawnDetachedFlusher
)

// errAuditQueueUnusable makes the hook upload synchronously: the queue file
// is not a regular file, or the queue's progress could not be recorded.
var errAuditQueueUnusable = errors.New("audit queue unusable")

// auditUploadSync reports whether the synchronous escape hatch is selected.
func auditUploadSync() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(auditUploadEnv)), "sync")
}

// newClientEventID returns 128 random bits as 32 lowercase hex characters.
// crypto/rand.Read does not fail on supported platforms (Go 1.24+ aborts the
// program instead), so there is no fallback id to get wrong.
func newClientEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// auditAccountKey identifies the account an event was recorded under, so a
// queued event is never uploaded under another login. It hashes the server,
// user id and org id; the token is deliberately not part of it (a re-login to
// the same account issues a new token and must still deliver the backlog).
func auditAccountKey(c *auth.Credentials) string {
	org := ""
	if c.User.OrgID != nil {
		org = strconv.FormatInt(*c.User.OrgID, 10)
	}
	sum := sha256.Sum256([]byte("aal.audit-queue.acct.v1\n" + strings.TrimRight(c.Server, "/") + "\n" +
		strconv.FormatInt(c.User.ID, 10) + "\n" + org))
	return hex.EncodeToString(sum[:16])
}

// auditQueueDir is ~/.agentshield/audit-queue, next to credentials.json.
func auditQueueDir() string {
	return filepath.Join(filepath.Dir(auth.CredentialsPath()), auditQueueDirName)
}

type auditQueueLine struct {
	V     int             `json:"v"`
	Acct  string          `json:"acct"`
	Event json.RawMessage `json:"event"`
}

// openRegularNoFollow opens path without following a symlink and refuses
// anything that is not a regular file (a FIFO, a device, a directory).
func openRegularNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w (not a regular file)", filepath.Base(path), errAuditQueueUnusable)
	}
	return f, nil
}

// auditQueueRecordable reports whether the uploader could record progress:
// the directory is writable (state.jsonl is replaced by rename) and
// state.jsonl, if present, is a writable regular file. Two syscalls.
func auditQueueRecordable(dir string) bool {
	if syscall.Access(dir, 2 /* W_OK */) != nil {
		return false
	}
	st, err := os.Lstat(filepath.Join(dir, auditStateFileName))
	if os.IsNotExist(err) {
		return true
	}
	return err == nil && st.Mode().IsRegular() && syscall.Access(filepath.Join(dir, auditStateFileName), 2) == nil
}

// enqueueAuditEntry appends one wire entry to the queue. It returns an error
// when the queue could not be used; the caller then uploads synchronously. An
// event refused at the size cap is not an error: it is counted in
// state.dropped and stays in audit.jsonl.
func enqueueAuditEntry(creds *auth.Credentials, entry json.RawMessage) error {
	line, err := json.Marshal(auditQueueLine{V: auditQueueLineVersion, Acct: auditAccountKey(creds), Event: entry})
	if err != nil {
		return err
	}
	line = append(line, '\n')

	dir := auditQueueDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Queueing an event the uploader could deliver but never mark delivered
	// would re-send it on every run (#4471 review: a chmod 500 of this
	// directory made 10,086 requests in 4 s). Upload it directly instead.
	if !auditQueueRecordable(dir) {
		return errAuditQueueUnusable
	}
	unlock := lockAuditQueue(dir, auditQueueLockWait)
	defer unlock()

	f, err := openRegularNoFollow(filepath.Join(dir, auditQueueFileName), os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if size+int64(len(line)) > auditQueueMaxBytes {
		s := readAuditState(dir)
		s.Dropped++
		_ = writeAuditState(dir, s)
		return nil
	}
	// A line a crashed writer left without its newline would swallow this
	// one into a single malformed line. Terminate it first; the uploader
	// dead-letters the fragment and this event survives.
	if size > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], size-1); err == nil && last[0] != '\n' {
			line = append([]byte{'\n'}, line...)
		}
	}
	_, err = f.Write(line)
	return err
}

// kickAuditFlusher starts an uploader unless one is running or the queue is
// backing off after a failure. Called after every enqueue.
func kickAuditFlusher() {
	dir := auditQueueDir()
	if auditBackingOff(readAuditState(dir), auditNow()) {
		return
	}
	if auditFlusherRunning(dir) {
		return
	}
	_ = startAuditFlusher()
}

// auditBackingOff reports whether now is inside the backoff window. A
// retry_after further ahead than the longest backoff is not honoured: it can
// only come from a clock that moved backwards or an edited state file, and
// either must not stall delivery for longer than auditBackoffMax.
func auditBackingOff(s auditQueueState, now time.Time) bool {
	if s.RetryAfter <= 0 {
		return false
	}
	wait := s.RetryAfter - now.UnixMilli()
	return wait > 0 && wait <= auditBackoffMax.Milliseconds()
}

// auditFlusherRunning probes flush.lock without waiting. A probe that cannot
// tell (the lock file will not open) answers "not running": the uploader it
// leads to starting runs unlocked in that case (tryLockFlush).
func auditFlusherRunning(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, auditFlushLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			unlockFd(int(f.Fd()))
			return false
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return true
		default:
			return false
		}
	}
}

// lockAuditQueue takes queue.lock, waiting at most wait. It always returns a
// release function; past the budget, or on a filesystem without flock, the
// release is a no-op and the caller proceeds unlocked.
func lockAuditQueue(dir string, wait time.Duration) func() {
	f, err := os.OpenFile(filepath.Join(dir, auditQueueLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	fd := int(f.Fd())
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return func() { unlockFd(fd); _ = f.Close() }
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK) && time.Now().Before(deadline):
			time.Sleep(2 * time.Millisecond)
		default:
			_ = f.Close()
			return func() {}
		}
	}
}

// tryLockFlush takes flush.lock without waiting; ok is false only when
// another uploader holds it. When the lock cannot be taken for any other
// reason (the file will not open, e.g. its mode was changed to 000, or the
// filesystem has no flock) it proceeds unlocked: a second uploader then costs
// repeats the SaaS drops, while refusing would leave the queue undelivered for
// good (#4471 review).
func tryLockFlush(dir string) (release func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, auditFlushLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, true
	}
	fd := int(f.Fd())
	released := false
	release = func() {
		if !released {
			released = true
			unlockFd(fd)
			_ = f.Close()
		}
	}
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return release, true
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			_ = f.Close()
			return nil, false
		default:
			return release, true
		}
	}
}

func unlockFd(fd int) {
	for i := 0; i < 5; i++ {
		if err := syscall.Flock(fd, syscall.LOCK_UN); !errors.Is(err, syscall.EINTR) {
			return
		}
	}
}

// auditQueueState is state.jsonl. RetryAfter is unix milliseconds.
// HeadCursor and HeadFailures count consecutive retryable failures of the
// batch starting at HeadCursor (the head-of-line guard).
type auditQueueState struct {
	Cursor       int64 `json:"cursor"`
	Failures     int   `json:"failures,omitempty"`
	RetryAfter   int64 `json:"retry_after,omitempty"`
	HeadCursor   int64 `json:"head_cursor,omitempty"`
	HeadFailures int   `json:"head_failures,omitempty"`
	Dropped      int64 `json:"dropped,omitempty"`
	DeadDropped  int64 `json:"dead_dropped,omitempty"`
}

// readAuditState reads state.jsonl; missing or unreadable reads as zero,
// which at worst re-sends events the SaaS then drops as repeats.
func readAuditState(dir string) auditQueueState {
	var s auditQueueState
	data, err := os.ReadFile(filepath.Join(dir, auditStateFileName))
	if err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

// writeAuditState replaces state.jsonl atomically (write + rename), so an
// unlocked reader sees the old state or the new one, never a torn one.
// Writers hold queue.lock.
func writeAuditState(dir string, s auditQueueState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, auditStateFileName+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, auditStateFileName)); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// updateAuditState applies fn to state.jsonl under queue.lock. Its error is
// the uploader's signal to stop: progress it cannot record would be repeated
// by the next loop iteration, endlessly.
func updateAuditState(dir string, fn func(*auditQueueState)) error {
	unlock := lockAuditQueue(dir, auditQueueLockWait)
	defer unlock()
	s := readAuditState(dir)
	fn(&s)
	return writeAuditState(dir, s)
}

// flushResult says what one uploader run did. Tests read it; the command
// ignores it.
type flushResult struct {
	Sent         int    // events acknowledged with a 2xx
	DeadLettered int    // events moved to dead.jsonl
	Requests     int    // POSTs made
	Stopped      string // why the run ended
}

// queuedEvent is one complete queue line read back.
type queuedEvent struct {
	line  []byte          // the whole line, newline included
	event json.RawMessage // the wire entry
}

// auditBatch is what readAuditBatch found from the cursor.
type auditBatch struct {
	events []queuedEvent
	// end is the offset just past the last line consumed (the events, or the
	// one bad line).
	end int64
	// bad is a line that can never be delivered (malformed, unknown version,
	// another account's event). Set only when events is empty, so the cursor
	// never jumps over an undelivered good event.
	bad    []byte
	badWhy string
}

// readAuditBatch reads complete lines from cursor: at most maxEvents events
// and maxBytes of entries (but always one event). A trailing line without its
// newline is an append in progress and is left alone.
func readAuditBatch(path string, cursor int64, acct string, maxEvents int, maxBytes int64) (auditBatch, error) {
	b := auditBatch{end: cursor}
	f, err := openRegularNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return b, nil
		}
		return b, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(cursor, io.SeekStart); err != nil {
		return b, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var bytesIn int64
	for len(b.events) < maxEvents {
		line, err := r.ReadBytes('\n')
		if len(line) == 0 || line[len(line)-1] != '\n' {
			return b, nil // EOF, or a partial line still being written
		}
		if err != nil && err != io.EOF {
			return b, err
		}
		body := bytes.TrimSpace(line)
		if len(body) == 0 { // an empty line carries nothing; step over it
			b.end += int64(len(line))
			continue
		}
		event, why := parseAuditQueueLine(body, acct)
		if why != "" {
			if len(b.events) == 0 {
				b.bad, b.badWhy = line, why
				b.end += int64(len(line))
			}
			return b, nil
		}
		if len(b.events) > 0 && bytesIn+int64(len(event)) > maxBytes {
			return b, nil
		}
		b.events = append(b.events, queuedEvent{line: line, event: event})
		bytesIn += int64(len(event))
		b.end += int64(len(line))
	}
	return b, nil
}

// parseAuditQueueLine returns the wire entry of one non-empty queue line, or
// why it can never be delivered by the account acct.
func parseAuditQueueLine(body []byte, acct string) (json.RawMessage, string) {
	var ql auditQueueLine
	switch {
	case json.Unmarshal(body, &ql) != nil:
		return nil, "malformed queue line"
	case ql.V != auditQueueLineVersion:
		return nil, fmt.Sprintf("unknown queue line version %d", ql.V)
	case len(ql.Event) == 0 || ql.Event[0] != '{':
		return nil, "queue line has no event"
	case ql.Acct != acct:
		return nil, "recorded under another account than the one logged in"
	}
	return ql.Event, ""
}

// validAuditCursor returns cursor if it points at a line start inside the
// file, else 0. A cursor that does not (state.jsonl from before a truncation
// that did not finish, or a hand edit) restarts from the top: the SaaS drops
// the repeats, which beats skipping events.
func validAuditCursor(path string, cursor int64) int64 {
	if cursor <= 0 {
		return 0
	}
	f, err := openRegularNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || cursor > st.Size() {
		return 0
	}
	var prev [1]byte
	if _, err := f.ReadAt(prev[:], cursor-1); err != nil || prev[0] != '\n' {
		return 0
	}
	return cursor
}

// uploadOutcome classifies one POST.
type uploadOutcome int

const (
	uploadOK        uploadOutcome = iota
	uploadRetry                   // keep the batch, back off
	uploadPermanent               // this batch will never be accepted
)

// classifyUpload: 401 (a token the user can renew by logging in again), 408
// and 429 are retryable, as are network errors, 3xx left unfollowed and 5xx.
// Every other 4xx is permanent. 403 is permanent too: the SaaS never answers
// 403 on /api/audit, so a 403 comes from something in between refusing this
// content, and waiting will not change its mind (#4471 review).
func classifyUpload(status int, err error) uploadOutcome {
	switch {
	case err != nil:
		return uploadRetry
	case status >= 200 && status < 300:
		return uploadOK
	case status == http.StatusUnauthorized, status == http.StatusRequestTimeout, status == http.StatusTooManyRequests:
		return uploadRetry
	case status >= 400 && status < 500:
		return uploadPermanent
	default:
		return uploadRetry
	}
}

func postAuditBatch(client *http.Client, creds *auth.Credentials, events []queuedEvent) (int, error) {
	entries := make([]json.RawMessage, len(events))
	for i, e := range events {
		entries[i] = e.event
	}
	return postAuditBody(client, creds, auditBatchBody(entries))
}

func postAuditBody(client *http.Client, creds *auth.Credentials, body []byte) (int, error) {
	req, err := http.NewRequest("POST", creds.Server+"/api/audit", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// uploadFailure describes a failed POST for state and dead.jsonl.
func uploadFailure(status int, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("HTTP %d", status)
}

// deadLetterAudit moves one queue line to dead.jsonl with the reason. Only
// the uploader writes this file, under flush.lock.
func deadLetterAudit(dir string, line []byte, why string, status int) {
	rec, err := json.Marshal(struct {
		At     string          `json:"at"`
		Reason string          `json:"reason"`
		Status int             `json:"status,omitempty"`
		Line   json.RawMessage `json:"line,omitempty"`
		Raw    string          `json:"raw,omitempty"`
	}{
		At:     auditNow().UTC().Format(time.RFC3339),
		Reason: why,
		Status: status,
		Line:   validJSONOrNil(bytes.TrimSpace(line)),
		Raw:    rawIfInvalid(bytes.TrimSpace(line)),
	})
	if err != nil {
		return
	}
	rec = append(rec, '\n')
	path := filepath.Join(dir, auditDeadFileName)
	f, err := openRegularNoFollow(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil && st.Size()+int64(len(rec)) > auditDeadMaxBytes {
		_ = updateAuditState(dir, func(s *auditQueueState) { s.DeadDropped++ })
		return
	}
	_, _ = f.Write(rec)
}

func validJSONOrNil(b []byte) json.RawMessage {
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	return nil
}

func rawIfInvalid(b []byte) string {
	if json.Valid(b) {
		return ""
	}
	return string(b)
}

// finishAuditFlush is the uploader's exit test, run under queue.lock. If the
// file holds nothing past cursor it resets the cursor, truncates the file and
// releases flush.lock while still holding queue.lock (see "Lost wake-up").
// It returns false when there is something left to send.
func finishAuditFlush(dir string, cursor int64, releaseFlush func()) bool {
	unlock := lockAuditQueue(dir, auditQueueLockWait)
	defer unlock()
	f, err := openRegularNoFollow(filepath.Join(dir, auditQueueFileName), os.O_RDWR, 0)
	if err != nil {
		releaseFlush()
		return true
	}
	defer func() { _ = f.Close() }()
	size := int64(0)
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	if size > cursor {
		tail := make([]byte, size-cursor)
		if _, err := f.ReadAt(tail, cursor); err == nil && bytes.IndexByte(tail, '\n') >= 0 {
			return false // an append landed since the last read: keep going
		}
		// Only a fragment without a newline: an append in progress, or one a
		// crashed writer left. The next append terminates it; leave it.
		releaseFlush()
		return true
	}
	// Everything is sent. Reset the cursor before truncating: a crash between
	// the two re-sends the file (dropped as repeats) instead of pointing the
	// cursor past the end of a file that later grows back.
	s := readAuditState(dir)
	s.Cursor = 0
	if err := writeAuditState(dir, s); err == nil {
		_ = f.Truncate(0)
	}
	releaseFlush()
	return true
}

// flushAuditQueue is one uploader run: `agentshield audit-flush`.
func flushAuditQueue() flushResult {
	var res flushResult
	dir := auditQueueDir()
	if _, err := os.Stat(dir); err != nil {
		res.Stopped = "no queue"
		return res
	}
	releaseFlush, ok := tryLockFlush(dir)
	if !ok {
		res.Stopped = "another uploader is running"
		return res
	}
	defer releaseFlush()

	// Several hooks can start uploaders in the same instant; the first to run
	// may have opened a backoff window since the others checked. Without this
	// re-check each of them failed once more and the window grew to minutes
	// on a blip of under a second (#4471 review: 30 hooks, failures=8).
	if auditBackingOff(readAuditState(dir), auditNow()) {
		res.Stopped = "backing off"
		return res
	}
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		res.Stopped = "not logged in"
		return res
	}
	acct := auditAccountKey(creds)
	path := filepath.Join(dir, auditQueueFileName)
	client := &http.Client{Timeout: auditFlushRequestTimeout}
	deadline := auditNow().Add(auditFlushBudget)
	isolate := 0            // events still to send one at a time
	probe := false          // isolate came from the head-of-line guard
	var walk *auditProbeHit // a later event accepted while the head kept failing
	stop := func(why string) flushResult { res.Stopped = why; return res }
	persist := func(fn func(*auditQueueState)) bool { return updateAuditState(dir, fn) == nil }
	delivered := func(end int64) func(*auditQueueState) {
		return func(s *auditQueueState) {
			s.Cursor, s.Failures, s.RetryAfter, s.HeadCursor, s.HeadFailures = end, 0, 0, 0, 0
		}
	}
	const unrecordable = "progress could not be recorded"

	for {
		if !auditNow().Before(deadline) {
			return stop("time budget spent")
		}
		st := readAuditState(dir)
		cursor := validAuditCursor(path, st.Cursor)
		if walk != nil && cursor >= walk.start {
			// The walk reached the accepted event, which is delivered already.
			if !persist(delivered(walk.end)) {
				return stop(unrecordable)
			}
			walk, probe, isolate = nil, false, 0
			continue
		}
		if !probe && st.HeadFailures >= auditHeadProbeAfter && st.HeadCursor == cursor {
			probe, isolate = true, auditBatchMaxEvents
		}
		maxEvents := auditBatchMaxEvents
		if isolate > 0 || walk != nil {
			maxEvents = 1
		} else {
			probe = false
		}
		b, err := readAuditBatch(path, cursor, acct, maxEvents, auditBatchMaxBytes)
		if err != nil {
			return stop("queue unreadable: " + err.Error())
		}
		if b.bad != nil {
			deadLetterAudit(dir, b.bad, b.badWhy, 0)
			res.DeadLettered++
			if !persist(func(s *auditQueueState) { s.Cursor = b.end }) {
				return stop(unrecordable)
			}
			continue
		}
		if len(b.events) == 0 && b.end > cursor {
			// Only empty lines were stepped over: record that, then look again.
			if !persist(func(s *auditQueueState) { s.Cursor = b.end }) {
				return stop(unrecordable)
			}
			continue
		}
		if len(b.events) == 0 {
			if finishAuditFlush(dir, cursor, releaseFlush) {
				return stop("queue drained")
			}
			continue
		}

		status, err := postAuditBatch(client, creds, b.events)
		res.Requests++
		switch classifyUpload(status, err) {
		case uploadOK:
			res.Sent += len(b.events)
			if isolate > 0 {
				isolate -= len(b.events)
			}
			if !persist(delivered(b.end)) {
				return stop(unrecordable)
			}
		case uploadPermanent:
			if len(b.events) > 1 {
				isolate = len(b.events)
				continue
			}
			deadLetterAudit(dir, b.events[0].line, "refused by the SaaS or a proxy in front of it", status)
			res.DeadLettered++
			if isolate > 0 {
				isolate--
			}
			if !persist(func(s *auditQueueState) { s.Cursor = b.end }) {
				return stop(unrecordable)
			}
		case uploadRetry:
			if walk != nil { // a single event between the head and the accepted one
				status, err = postAuditBatch(client, creds, b.events) // one more try
				res.Requests++
				if classifyUpload(status, err) == uploadOK {
					res.Sent++
					if !persist(delivered(b.end)) {
						return stop(unrecordable)
					}
					continue
				}
				cStatus, cErr := postAuditBatch(client, creds, []queuedEvent{walk.event})
				res.Requests++
				if classifyUpload(cStatus, cErr) == uploadOK {
					deadLetterAudit(dir, b.events[0].line,
						"refused by the SaaS or a proxy in front of it while a later event was accepted: "+uploadFailure(status, err), status)
					res.DeadLettered++
					if !persist(func(s *auditQueueState) { s.Cursor = b.end }) {
						return stop(unrecordable)
					}
					continue
				}
				// The accepted event fails now too: the path went down mid-walk.
			} else if probe && len(b.events) == 1 {
				if hit, ok := auditProbeAhead(client, creds, acct, path, b.end, deadline, &res); ok {
					walk = &hit
					continue
				}
			}
			if !persist(func(s *auditQueueState) { recordAuditFailure(s, cursor, auditNow()) }) {
				return stop(unrecordable)
			}
			return stop("upload failed, backing off: " + uploadFailure(status, err))
		}
	}
}

// auditProbeHit is an event behind the head that the SaaS accepted. The
// cursor stands at start when it is the next event, and moves to end once
// the walk reaches it.
type auditProbeHit struct {
	event      queuedEvent
	start, end int64
}

// auditProbeAhead runs when the event at the head keeps failing alone. From
// offset from (just past the head), it sends the 1st, 2nd, 4th, 8th, ...
// event this account can send, and then the last one, each alone, until one
// is accepted, and returns it. The last one keeps doubling from jumping past
// the good events behind a long run of refusals. Only a 2xx counts: a 4xx
// may be that event's own content being refused, which says nothing about
// the path. ok is false when no probe was accepted before the queue or the
// time budget ran out: an outage, as far as the uploader can tell, so the
// caller dead-letters nothing.
func auditProbeAhead(client *http.Client, creds *auth.Credentials, acct, path string,
	from int64, deadline time.Time, res *flushResult) (hit auditProbeHit, ok bool) {
	send := func(h auditProbeHit) bool {
		status, err := postAuditBatch(client, creds, []queuedEvent{h.event})
		res.Requests++
		if classifyUpload(status, err) != uploadOK {
			return false
		}
		res.Sent++
		return true
	}
	var last *auditProbeHit // the latest event read and not probed yet
	pos, n, next := from, 0, 1
	for auditNow().Before(deadline) {
		b, err := readAuditBatch(path, pos, acct, 1, auditBatchMaxBytes)
		if err != nil {
			return hit, false
		}
		if b.bad != nil { // the walk dead-letters it; it cannot be a probe
			pos = b.end
			continue
		}
		if len(b.events) == 0 {
			if last != nil && send(*last) {
				return *last, true
			}
			return hit, false
		}
		// start is where the uploader's cursor stands when this event is next:
		// just past the line before it, empty lines included.
		h := auditProbeHit{event: b.events[0], start: pos, end: b.end}
		pos = b.end
		if n++; n != next {
			last = &h
			continue
		}
		next *= 2
		last = nil
		if send(h) {
			return h, true
		}
	}
	return hit, false
}

// recordAuditFailure counts one retryable failure of the batch at cursor and
// opens the backoff window. A failure inside an already-open window is not
// counted again (an uploader started before the window opened).
func recordAuditFailure(s *auditQueueState, cursor int64, now time.Time) {
	if auditBackingOff(*s, now) {
		return
	}
	s.Failures++
	delay := auditBackoffMax
	if s.Failures < 30 {
		if d := auditBackoffBase << (s.Failures - 1); d > 0 && d < auditBackoffMax {
			delay = d
		}
	}
	s.RetryAfter = now.Add(delay).UnixMilli()
	if s.HeadCursor == cursor && s.HeadFailures > 0 {
		s.HeadFailures++
	} else {
		s.HeadCursor, s.HeadFailures = cursor, 1
	}
}
