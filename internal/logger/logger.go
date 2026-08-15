package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/redact"
)

// defaultMaxLogBytes is the file size at which the log is rotated (10 MB).
const defaultMaxLogBytes = 10 * 1024 * 1024

// rotatedSuffix is appended to the log path to name the previous generation.
const rotatedSuffix = ".1"

// maxLogBytes is the live rotation threshold. It exists as a var only so tests
// can exercise the rotation boundary without writing 10 MB of chained entries.
var maxLogBytes int64 = defaultMaxLogBytes

type AuditEvent struct {
	Timestamp      string   `json:"timestamp"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	Decision       string   `json:"decision"`
	Flagged        bool     `json:"flagged,omitempty"`
	TriggeredRules []string `json:"triggered_rules,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
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
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	// Deliberately no head read here. The head and the size it corresponds to
	// have to be sampled together while holding the file lock: reading them at
	// open time races with another process's in-flight append, and the two
	// values can straddle it — head from before the append, size from after —
	// which then suppresses the resync and writes a duplicate prev_hash.
	// knownSize -1 makes the first Log() read the head under the lock.
	return &AuditLogger{path: path, file: file, knownSize: -1}, nil
}

// rotateIfNeeded rotates the log file if it has reached maxLogBytes.
// It renames the current file to <path>.1 (dropping any existing .1) and
// opens a fresh log file. Must be called with l.mu held.
//
// The hash chain deliberately carries across the boundary: the first entry of
// the fresh file keeps the rotated file's head as its prev_hash, so the
// rotation is a link rather than a reset. VerifyChain accepts that first
// prev_hash as a continuation and cross-checks it against <path>.1 while that
// file is still on disk. Starting a new chain at every rotation would instead
// hand an attacker a legitimate-looking way to drop history.
//
// Returns true when a rotation happened, so the caller can re-take the file
// lock on the new descriptor.
func (l *AuditLogger) rotateIfNeeded() (bool, error) {
	info, err := l.file.Stat()
	if err != nil {
		return false, fmt.Errorf("stat log file: %w", err)
	}
	if info.Size() < maxLogBytes {
		return false, nil
	}

	if err := l.file.Close(); err != nil {
		return false, fmt.Errorf("close log before rotation: %w", err)
	}

	rotated := l.path + rotatedSuffix
	_ = os.Remove(rotated)
	if err := os.Rename(l.path, rotated); err != nil {
		return false, fmt.Errorf("rotate log: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return false, fmt.Errorf("open fresh log after rotation: %w", err)
	}
	l.file = f
	l.knownSize = 0
	return true, nil
}

func (l *AuditLogger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// l.mu only serializes writers inside this process. Several agentshield
	// processes share one audit.jsonl (parallel IDE hook invocations, the MCP
	// proxy, the watchdog), so the "read head, append entry" sequence is also
	// serialized across processes with an advisory file lock. Best effort — see
	// lockFile.
	release := lockFile(l.file)
	rotated, err := l.rotateIfNeeded()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: log rotation failed: %v\n", err)
	}
	if rotated {
		release()
		release = lockFile(l.file)
	}
	defer release()

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
	return nil
}

// resyncHead re-reads the chain head when the file changed underneath us —
// another process appended since our last write. Must be called with l.mu held
// and the file lock taken; the stat is the same one rotateIfNeeded already
// pays for, so the single-writer path costs nothing extra.
func (l *AuditLogger) resyncHead() {
	info, err := l.file.Stat()
	if err != nil {
		return
	}
	if info.Size() == l.knownSize {
		return
	}
	l.prevHash = ChainHead(l.path)
	l.knownSize = info.Size()
}

func (l *AuditLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
