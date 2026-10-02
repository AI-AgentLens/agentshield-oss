package logger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/redact"
)

// defaultMaxLogBytes is the file size at which the log is rotated (10 MB).
const defaultMaxLogBytes = 10 * 1024 * 1024

// rotatedSuffix is appended to the log path to name the previous generation.
const rotatedSuffix = ".1"

// lockSuffix names the dedicated lock file (#4042). It is never renamed,
// closed, or reopened for the life of the logger — see the lockFd field
// comment for why that separation from the data file is load-bearing.
const lockSuffix = ".lock"

// maxLogBytes is the live rotation threshold. It exists as a var only so tests
// can exercise the rotation boundary without writing 10 MB of chained entries.
var maxLogBytes int64 = defaultMaxLogBytes

// NoteAuditLockUnavailable is the one note kind the logger itself writes
// (#4052 round 2): the cross-process lock file could not be opened, so this
// event was appended without the lock and with size-triggered rotation
// suspended. Detail names the open error's class (the errno text, never a
// path). A later prev_hash break adjacent to such events may be a lost lock
// race; the note does not prove it (an entry deleted from a degraded run
// gives the same verdict), and VerifyChain treats the break as broken either
// way. The note is context for the investigator, never a pass. It covers
// only this state, the lock file being unopenable: a lock held past the
// wait budget or a filesystem without flock support (lock_unix.go) still
// appends and rotates without the lock, and writes no note. The other kinds
// are written by evaluation and defined in internal/analyzer/types.go.
const NoteAuditLockUnavailable = "audit_lock_unavailable"

// Note is one attestation record on an event (#3995): where evaluation
// excused a match (kind "excused"/"downgraded", Rule set) or knowingly gave
// up ("parse_fallback", "scope_alternates_capped",
// "executed_text_unresolved"), or where the logger itself ran degraded
// (NoteAuditLockUnavailable). Mirrors analyzer.Note without importing the
// analyzer into this leaf package. Never a decision input.
type Note struct {
	Kind   string `json:"kind"`
	Rule   string `json:"rule,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// appendNote returns notes plus n unless an identical note is already there.
// Always copies: the caller's event is passed by value but its Notes slice is
// shared, and an append into spare capacity would surface in the caller.
func appendNote(notes []Note, n Note) []Note {
	for _, have := range notes {
		if have == n {
			return notes
		}
	}
	return append(append(make([]Note, 0, len(notes)+1), notes...), n)
}

type AuditEvent struct {
	Timestamp      string   `json:"timestamp"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	Decision       string   `json:"decision"`
	Flagged        bool     `json:"flagged,omitempty"`
	TriggeredRules []string `json:"triggered_rules,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	// Notes: where evaluation excused a match or knowingly gave up (#3995).
	// Omitted when empty, so an event with none is byte-identical to before.
	Notes []Note `json:"notes,omitempty"`
	// TaxonomyRefs are the taxonomy node ids behind this decision. Issue
	// #3111: this is the first hop of the fusion chain
	// (block -> taxonomy node -> compliance control -> attestation receipt).
	// Without it the SaaS receives a rule id it cannot resolve to a control,
	// and a runtime block cannot become auditor-defensible evidence.
	// Empty when the decision came from a built-in intercept that has no
	// taxonomy entry (protected-path, unicode-*, enterprise-self-protect) —
	// an absent ref is better than an unresolvable placeholder.
	TaxonomyRefs []string `json:"taxonomy,omitempty"`
	// Mode reflects the AgentShield enforcement mode at decision time:
	// "enforce" (default) or "audit-only". Always emitted so the SaaS can
	// segment telemetry by rollout cohort. Issue #1952.
	Mode string `json:"mode"`
	// OriginalDecision is the pre-downgrade decision when audit-only mode
	// turned a BLOCK / REQUIRE_APPROVAL into AUDIT. Empty (and omitted) in
	// enforce mode and in audit-only mode when no downgrade happened — so
	// the presence of this field is itself the "shadow block" signal the
	// dashboard cares about. Issue #1952.
	OriginalDecision string `json:"original_decision,omitempty"`
	Source           string `json:"source,omitempty"`
	Error            string `json:"error,omitempty"`
	// Identity plane (issue #3111, six-planes note 2026-07-04). Carried from
	// day one because retrofitting identity onto an evidence schema is brutal.
	//
	// SessionID is the agent harness's own session identifier, taken verbatim
	// from the hook payload (Claude Code / Codex `session_id`, Windsurf
	// `trajectory_id`). AgentShield does NOT synthesize one: a fabricated id
	// would correlate events that the harness itself considers unrelated,
	// which is worse than an honest empty field. Empty for harnesses that
	// don't send one (Cursor today) and for direct CLI invocations.
	SessionID string `json:"session_id,omitempty"`
	// Principal is the OS user the agent process acted as. It is the only
	// identity AgentShield can observe first-hand at hook time — the agent
	// runs in-process with the developer's shell, so there is no separate
	// agent credential to report.
	Principal string `json:"principal,omitempty"`
	// MCP-specific fields (present when source starts with "mcp-proxy")
	ToolName     string                 `json:"tool_name,omitempty"`
	MCPArguments map[string]interface{} `json:"arguments,omitempty"`
}

// IsMCP returns true if this event came from the MCP proxy.
func (e AuditEvent) IsMCP() bool {
	return e.ToolName != ""
}

// DisplayLabel returns a human-readable label: the command (shell) or tool name (MCP).
func (e AuditEvent) DisplayLabel() string {
	if e.ToolName != "" {
		return "[MCP] " + mcpSummary(e.ToolName, e.MCPArguments)
	}
	return e.Command
}

// mcpSummary builds a friendly one-line summary from a tool name and its arguments.
func mcpSummary(tool string, args map[string]interface{}) string {
	if len(args) == 0 {
		return tool
	}

	str := func(key string) string {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	num := func(key string) (int, bool) {
		if v, ok := args[key]; ok {
			switch n := v.(type) {
			case float64:
				return int(n), true
			case int:
				return n, true
			}
		}
		return 0, false
	}

	switch tool {
	case "Read":
		fp := str("file_path")
		if fp == "" {
			return tool
		}
		offset, hasOff := num("offset")
		limit, hasLim := num("limit")
		if hasOff && hasLim {
			return fmt.Sprintf("Read %s (lines %d-%d)", fp, offset, offset+limit)
		} else if hasOff {
			return fmt.Sprintf("Read %s (from line %d)", fp, offset)
		} else if hasLim {
			return fmt.Sprintf("Read %s (first %d lines)", fp, limit)
		}
		return "Read " + fp

	case "Edit":
		fp := str("file_path")
		if fp == "" {
			return tool
		}
		return "Edit " + fp

	case "Write":
		fp := str("file_path")
		if fp == "" {
			return tool
		}
		return "Write " + fp

	case "Grep":
		pattern := str("pattern")
		path := str("path")
		if pattern == "" {
			return tool
		}
		if path != "" {
			return fmt.Sprintf("Grep %q in %s", pattern, path)
		}
		return fmt.Sprintf("Grep %q", pattern)

	case "Glob":
		pattern := str("pattern")
		path := str("path")
		if pattern == "" {
			return tool
		}
		if path != "" {
			return fmt.Sprintf("Glob %s in %s", pattern, path)
		}
		return "Glob " + pattern

	case "Bash":
		cmd := str("command")
		if cmd == "" {
			return tool
		}
		// Truncate long commands
		cmd = strings.ReplaceAll(cmd, "\n", " ")
		if len(cmd) > 80 {
			cmd = cmd[:77] + "..."
		}
		return "Bash: " + cmd

	default:
		// For unknown tools, show first string argument value
		for _, v := range args {
			if s, ok := v.(string); ok && s != "" {
				if len(s) > 60 {
					s = s[:57] + "..."
				}
				return tool + " " + s
				// only show the first one
			}
		}
		return tool
	}
}

// Ensure AuditLogger implements Logger.
var _ Logger = (*AuditLogger)(nil)

// AuditLogger (also known as FileLogger) writes audit events to a local JSONL file.
type AuditLogger struct {
	path string
	file *os.File
	mu   sync.Mutex

	// lockFd is the descriptor the cross-process advisory lock (#4042) is
	// taken on — a dedicated <path>.lock file, never the data file itself.
	// rotateIfNeeded closes and reopens l.file (and, on the rotated-away
	// path, may close it without any replacement yet), and flock is released
	// the instant every descriptor referring to that open file description
	// is closed. A lock tied to l.file therefore drops mid-rotation, in
	// exactly the stat -> close -> rename -> reopen window that has to stay
	// atomic across processes for another writer's concurrent rotation not
	// to see a half-done one. lockFd is untouched by any of that, so the
	// lock is held continuously across the whole of rotateIfNeeded.
	lockFd *os.File
	// lockUnavailable is set when lockFd is nil because the lock file could
	// not be opened (#4052 round 2): the errno class of that failure, which
	// becomes the Detail of the NoteAuditLockUnavailable note every event
	// appended in this state carries. Empty on a healthy logger.
	lockUnavailable string

	// prevHash is the chain head: the value the next entry must carry as its
	// prev_hash. Recovered from the tail of the log on the first write, so a
	// new process continues the existing chain. Restarting from empty on every
	// process start would be indistinguishable from truncate-and-rewrite at
	// verification time — i.e. every hook invocation would look like tampering.
	prevHash string
	// knownSize is the file size as of our last write, or -1 when we have not
	// read the log yet. A size that differs at the next write means another
	// process appended and our head is stale.
	knownSize int64
}

func New(path string) (*AuditLogger, error) {
	file, err := openLog(path)
	if err != nil {
		return nil, err
	}

	// Best effort, like lockFile itself. A lock file we cannot open (created
	// by root or another user, or a log directory that is read-only while the
	// log file is writable) must not fail New: the hook treats a logger that
	// fails to open as "audit log init failed" and skips evaluation entirely,
	// so a lost lock would silently turn every BLOCK into an unenforced AUDIT.
	// A nil lockFd makes lockFile a no-op, so appends are unserialized, which
	// risks a chain break under concurrency, never a missed decision. Log
	// records that state on every event it appends (NoteAuditLockUnavailable)
	// and never rotates while in it — see Log.
	lockUnavailable := ""
	lockFd, err := os.OpenFile(path+lockSuffix, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit-log lock unavailable, appends are unserialized and rotation is suspended: %v\n", err)
		lockFd = nil
		lockUnavailable = errClass(err)
	}

	// Deliberately no head read here. The head and the size it corresponds to
	// have to be sampled together while holding the file lock: reading them at
	// open time races with another process's in-flight append, and the two
	// values can straddle it — head from before the append, size from after —
	// which then suppresses the resync and writes a duplicate prev_hash.
	// knownSize -1 makes the first Log() read the head under the lock.
	return &AuditLogger{path: path, file: file, lockFd: lockFd, lockUnavailable: lockUnavailable, knownSize: -1}, nil
}

// errClass reduces an open error to its errno text ("permission denied",
// "is a directory", "read-only file system"), dropping the path so the note
// never carries a filesystem location. Falls back to a fixed word when the
// error is not a PathError.
func errClass(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Err.Error()
	}
	return "open failed"
}

// openLog opens the audit file for appending, readable as well as writable
// so resyncHead can read the chain head from the descriptor it is about to
// append to (#4057 Codex pass 2: a head read by path and a write by
// descriptor name different inodes during a sibling's rotation). Reads
// through this handle use pread, so the append position is untouched and
// O_APPEND still places every write at the end.
//
// A file we may write but not read (a mode a sysadmin set; we create 0600)
// falls back to the write-only open main used, so New never fails where it
// did not before — the hook treats a logger that fails to open as "audit
// log init failed" and skips evaluation (#4052). In that mode resyncHead
// has no readable descriptor and reads the head by path, the pre-round-5
// behaviour, with its rotation-window cost.
func openLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
	if err == nil {
		return f, nil
	}
	if f, werr := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); werr == nil {
		return f, nil
	}
	return nil, err
}

// followRotation reopens the live path when the held descriptor is no
// longer it, and reports the held descriptor's stat when it still is.
//
// Our descriptor may point at a generation another process has already
// rotated away (a long-running writer such as the enterprise watchdog, or
// a hook that opened the log before a sibling hook rotated it). Its size
// is still over the threshold, so rotating it again would os.Remove the
// .1 that other process just produced and rename the small live file
// over it: a whole generation lost, and with the head link intact the
// verifier would still say "linked". Reopen the live path instead; the
// caller re-takes the lock on the new descriptor and resyncHead reads
// the head from it. Its size is checked on the next write.
//
// Only two stat outcomes mean "rotated away": the path is gone, or it is
// a different file. Any other stat error (EACCES, EMFILE, ...) says
// nothing about rotation, so keep writing through the held descriptor.
// And open the new descriptor before closing the old one: closing first
// and then failing to open would leave the logger with no file at all,
// dead on every later write, and the watchdog discards Log errors.
//
// This half of rotation removes and renames nothing, so it is safe to run
// without the cross-process lock. That is why Log runs it on the degraded
// path too (#4057 pass 2, C1): a degraded writer that skipped it kept
// appending to an inode a healthy sibling had rotated to .1 and then
// unlinked, so its events landed in no file, and its prev_hash, read from
// the live path it was not writing to, made VerifyChain(live) report a
// false break at entry 0. Must be called with l.mu held.
func (l *AuditLogger) followRotation() (info fs.FileInfo, followed bool, err error) {
	info, err = l.file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat log file: %w", err)
	}
	cur, serr := os.Stat(l.path)
	rotatedAway := errors.Is(serr, fs.ErrNotExist) || (serr == nil && !os.SameFile(cur, info))
	if !rotatedAway {
		return info, false, nil
	}
	f, oerr := openLog(l.path)
	if oerr != nil {
		return nil, false, fmt.Errorf("reopen rotated-away log: %w", oerr)
	}
	_ = l.file.Close()
	l.file = f
	l.knownSize = -1
	return nil, true, nil
}

// rotateIfNeeded follows a rotation another process performed, then rotates
// the log file itself if it has reached maxLogBytes. Rotation renames the
// current file to <path>.1 (dropping any existing .1) and opens a fresh log
// file. Must be called with l.mu held.
//
// The hash chain deliberately carries across the boundary: the first entry of
// the fresh file keeps the rotated file's head as its prev_hash, so the
// rotation is a link rather than a reset. VerifyChain accepts that first
// prev_hash as a continuation and cross-checks it against <path>.1 while that
// file is still on disk. Starting a new chain at every rotation would instead
// hand an attacker a legitimate-looking way to drop history.
//
// Must be called with l.lockFd locked (#4042): the lock has to span the
// whole stat -> close -> rename -> reopen sequence below, or a second
// process can observe (and act on) an intermediate state — the rename half
// done, or the live path briefly gone.
func (l *AuditLogger) rotateIfNeeded() error {
	info, followed, err := l.followRotation()
	if err != nil || followed {
		return err
	}

	if info.Size() < maxLogBytes {
		return nil
	}

	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close log before rotation: %w", err)
	}

	rotated := l.path + rotatedSuffix
	_ = os.Remove(rotated)
	if err := os.Rename(l.path, rotated); err != nil {
		// The close above succeeded but the rename did not, so l.path still
		// holds the original (unrotated) file under its original name. Reopen
		// it rather than leave l.file a closed descriptor: every later Log()
		// would otherwise fail with "file already closed" until the process
		// restarts, and the watchdog and shield-server both discard Log
		// errors, so that death would be silent (#4042).
		f, oerr := openLog(l.path)
		if oerr != nil {
			return fmt.Errorf("rotate log: rename failed (%v) and reopen failed: %w", err, oerr)
		}
		l.file = f
		l.knownSize = -1
		return fmt.Errorf("rotate log: %w", err)
	}

	// Read the head from the rotated file itself, unconditionally (#4033).
	// The in-process head is not usable here: a fresh process has none yet
	// (its first write can be the one that rotates, and every hook invocation
	// is a fresh process), and a long-running one may hold a stale head when
	// another process appended after its last write. resyncHead cannot
	// recover either case, because the fresh file is empty and its size
	// matches knownSize. ChainHead(<path>.1) is exactly what VerifyChain's
	// cross-check computes, so the link agrees by construction.
	l.prevHash = ChainHead(rotated)

	f, err := openLog(l.path)
	if err != nil {
		return fmt.Errorf("open fresh log after rotation: %w", err)
	}
	l.file = f
	l.knownSize = 0
	return nil
}

// LockUnavailableNote returns the note Log stamps on every event while the
// lock file is unopenable, and whether the logger is in that state. Callers
// that send the same event elsewhere (the hook POSTs it to the SaaS) append
// it themselves so the wire payload matches the persisted line; Log
// deduplicates, so the line still carries it exactly once.
func (l *AuditLogger) LockUnavailableNote() (Note, bool) {
	if l == nil || l.lockUnavailable == "" {
		return Note{}, false
	}
	return Note{
		Kind:   NoteAuditLockUnavailable,
		Detail: "lock file could not be opened (" + l.lockUnavailable + "); appended without the cross-process lock, rotation suspended",
	}, true
}

func (l *AuditLogger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// l.mu only serializes writers inside this process. Several agentshield
	// processes share one audit.jsonl (parallel IDE hook invocations, the MCP
	// proxy, the watchdog), so the "read head, append entry" sequence is also
	// serialized across processes with an advisory file lock. Best effort — see
	// lockFile. The lock is taken on the dedicated l.lockFd, not l.file, and
	// held continuously through rotation and the write below (#4042) — see
	// the lockFd field comment for why a lock tied to l.file cannot do that.
	release := lockFile(l.lockFd)
	defer release()

	// Degraded (#4052 round 2, Codex pass 1 finding 1): with no lock, two
	// writers can both pass rotateIfNeeded's checks, and the second one's
	// os.Remove of <path>.1 deletes the generation the first just rotated
	// out — lockless rotation can destroy audit history, where a lockless
	// append can at worst leave a prev_hash mismatch. So while the lock file
	// could not be opened we never rotate. Accepted cost: the log grows past
	// maxLogBytes for as long as the lock stays unopenable. Every event
	// appended in this state says so (the note below), so a chain break next
	// to it may be a lost race; the note records the state, it does not
	// prove the cause, and VerifyChain still reports the break.
	//
	// We do still follow a rotation a healthy sibling performed (Opus pass 2
	// on #4057, C1): that half only reopens the live path, so it is safe
	// without the lock, and skipping it stranded this writer's events in an
	// unlinked inode. When the reopened live file is still empty, resyncHead
	// links this writer's line to <path>.1 exactly as the rotator would have
	// (pass 3, F1), so landing inside the sibling's rotation does not reset
	// the chain. Without the lock a sibling can still append or rotate
	// between the head read and the write below; the result is a prev_hash
	// mismatch VerifyChain reports as broken, never a fresh chain it accepts.
	// That is the lockless append's accepted cost, and the note marks it.
	// The one outcome that is not visible, two sibling rotations in that
	// window leaving the write in an unlinked inode, is caught after the
	// write by reappendIfUnlinked (Codex pass 1 on #4057).
	note, degraded := l.LockUnavailableNote()
	if degraded {
		event.Notes = appendNote(event.Notes, note)
		if _, _, err := l.followRotation(); err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log reopen failed: %v\n", err)
		}
		if afterDegradedFollow != nil {
			afterDegradedFollow()
		}
	} else if err := l.rotateIfNeeded(); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: log rotation failed: %v\n", err)
	}

	l.resyncHead()

	// Redact sensitive data before logging
	event.Command = redact.Redact(event.Command)
	event.Args = redact.RedactArgs(event.Args)
	if event.Error != "" {
		event.Error = redact.Redact(event.Error)
	}

	// Hash after redaction: the chain has to cover exactly the bytes that land
	// on disk. Hashing the pre-redaction event would make every entry fail
	// verification, and would put a digest of the unredacted secret in the log.
	entry := ChainedEvent{AuditEvent: event, PrevHash: l.prevHash}
	entry.EntryHash = ComputeEntryHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	n, err := l.file.Write(data)
	if err != nil {
		// Do not advance the head past an entry that may not be on disk, and
		// force a re-read next time in case the write landed partially.
		l.knownSize = -1
		return err
	}
	l.knownSize += int64(n)
	l.prevHash = ComputeChainedHash(entry)
	if !degraded {
		return nil
	}
	return l.reappendIfUnlinked(entry)
}

// afterDegradedFollow is a test seam: Log calls it, when set, after the
// degraded path's followRotation and before its head read and write. It
// is how a test puts a sibling's rotations inside that window without
// restructuring Log. Always nil in production.
var afterDegradedFollow func()

// afterReappendFollow is the same seam for the retry: reappendIfUnlinked
// calls it, when set, after each attempt's followRotation and before its
// head read and re-append, with the attempt index. It is how a test puts
// sibling rotations inside the retry window and exhausts the bound. Always
// nil in production.
var afterReappendFollow func(attempt int)

// maxUnlinkedReappends bounds reappendIfUnlinked. Each retry needs a
// healthy sibling to have rotated twice more during the previous attempt;
// two retries is already far past anything a real writer produces.
const maxUnlinkedReappends = 2

// reappendIfUnlinked closes the window Codex pass 1 on #4057 found in the
// degraded path. Log's followRotation and its write are not atomic (no
// lock): a healthy sibling can rotate in between. Once, and this writer's
// line lands in <path>.1, retained; VerifyChain(live) then reports a
// prev_hash break, visible, the lockless append's accepted cost. Twice,
// and the held inode is unlinked: the write succeeded, Log would return
// nil, and the event is in no file the verifier will ever read, with
// VerifyChain(live) still verified. That is a silent loss, and this is
// the one place it can be told from the visible case: nlink on the held
// descriptor is 0 only in the second (unlinked_unix.go says why not
// SameFile). So after every degraded write, fstat; if the bytes went to
// an unlinked inode, follow the rotation, re-read the head, re-chain the
// SAME event onto it and append again. Bounded: a sibling that keeps
// rotating twice per attempt beats the retry, and then the loss is
// reported rather than hidden: a warning on stderr for the callers that
// discard Log errors (the MCP path, the watchdog), and an error for the
// hook, which warns and enforces regardless. Nothing here runs on the
// healthy path: its lock spans rotate and write, so its output is
// unchanged. Must be called with l.mu held.
func (l *AuditLogger) reappendIfUnlinked(entry ChainedEvent) error {
	for attempt := 0; attempt < maxUnlinkedReappends; attempt++ {
		if !unlinked(l.file) {
			return nil
		}
		_, followed, err := l.followRotation()
		if err != nil {
			return l.lostUnlinked(fmt.Errorf("reopen failed: %w", err))
		}
		if !followed {
			// Unlinked, yet the live path is this same file or cannot
			// be stat'ed: writing here again cannot help.
			return l.lostUnlinked(errors.New("live path could not be followed"))
		}
		if afterReappendFollow != nil {
			afterReappendFollow(attempt)
		}
		l.resyncHead()
		entry.PrevHash = l.prevHash
		entry.EntryHash = ComputeEntryHash(entry)
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		n, err := l.file.Write(data)
		if err != nil {
			l.knownSize = -1
			return err
		}
		l.knownSize += int64(n)
		l.prevHash = ComputeChainedHash(entry)
	}
	if !unlinked(l.file) {
		return nil
	}
	return l.lostUnlinked(fmt.Errorf("still unlinked after %d re-appends", maxUnlinkedReappends))
}

// lostUnlinked reports an event that was written only to an unlinked inode.
// knownSize is reset so the next Log re-reads the head from wherever it
// lands. The event itself is gone: say so where it will be seen.
func (l *AuditLogger) lostUnlinked(cause error) error {
	l.knownSize = -1
	err := fmt.Errorf("audit event lost: appended to a held audit file that is no longer linked (%w)", cause)
	fmt.Fprintf(os.Stderr, "[AgentShield] warning: %v\n", err)
	return err
}

// resyncHead re-reads the chain head when the file changed underneath us —
// another process appended since our last write. Must be called with l.mu held
// and the file lock taken; the stat is the same one rotateIfNeeded already
// pays for, so the single-writer path costs nothing extra.
//
// An empty live file takes its head from <path>.1, the same source
// rotateIfNeeded uses for the rotator's own first line (#4057 pass 3, F1).
// A writer that only followed a rotation — a degraded one appending inside
// a healthy sibling's rotation, a lock wait that timed out, or any writer
// after an external `mv live .1 && touch live` — reaches here with an empty
// live file and no head of its own. Reading ChainHead(live) there gave "",
// a genesis line, and the healthy rotator then linked to it: VerifyChain
// reported the live file verified with no link to .1, and an entry deleted
// from .1's tail went undetected. With no .1, or one that ends unchained,
// ChainHead returns "" and the line is a genesis line as before.
//
// A non-empty file's head is read from the held descriptor, never from the
// path (#4057 Codex pass 2). The bytes go to the descriptor; during a
// sibling's rotation the path names a different inode, or none. A degraded
// writer whose held file had just been renamed to .1 read ChainHead(path)
// as "" and put a genesis line into .1, which the rotator then linked the
// fresh live file to: VerifyChain(live) verified, VerifyChain(.1) broken
// at that line. Every window found from round 2 on was this class: a head
// derived from one inode, bytes appended to another. The descriptor is the
// one source that cannot disagree with the append. On the healthy path the
// lock keeps descriptor and path the same inode, so its output is unchanged.
func (l *AuditLogger) resyncHead() {
	info, err := l.file.Stat()
	if err != nil {
		return
	}
	if info.Size() == l.knownSize {
		return
	}
	if info.Size() == 0 {
		l.prevHash = ChainHead(l.path + rotatedSuffix)
	} else if head, readable := chainHeadFile(l.file); readable {
		l.prevHash = head
	} else {
		// Write-only descriptor (openLog's fallback): the path is the
		// only head there is.
		l.prevHash = ChainHead(l.path)
	}
	l.knownSize = info.Size()
}

func (l *AuditLogger) Close() error {
	if l.lockFd != nil {
		_ = l.lockFd.Close()
	}
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
