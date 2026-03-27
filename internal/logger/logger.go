package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/security-researcher-ca/agentshield/internal/redact"
)

// defaultMaxLogBytes is the file size at which the log is rotated (10 MB).
const defaultMaxLogBytes = 10 * 1024 * 1024

type AuditEvent struct {
	Timestamp      string   `json:"timestamp"`
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	Cwd            string   `json:"cwd"`
	Decision       string   `json:"decision"`
	Flagged        bool     `json:"flagged,omitempty"`
	TriggeredRules []string `json:"triggered_rules,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	Mode           string   `json:"mode"`
	Source         string   `json:"source,omitempty"`
	Error          string   `json:"error,omitempty"`
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
}

func New(path string) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &AuditLogger{path: path, file: file}, nil
}

// rotateIfNeeded rotates the log file if it has reached defaultMaxLogBytes.
// It renames the current file to <path>.1 (dropping any existing .1) and
// opens a fresh log file. Must be called with l.mu held.
func (l *AuditLogger) rotateIfNeeded() error {
	info, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("stat log file: %w", err)
	}
	if info.Size() < defaultMaxLogBytes {
		return nil
	}

	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close log before rotation: %w", err)
	}

	rotated := l.path + ".1"
	_ = os.Remove(rotated)
	if err := os.Rename(l.path, rotated); err != nil {
		return fmt.Errorf("rotate log: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open fresh log after rotation: %w", err)
	}
	l.file = f
	return nil
}

func (l *AuditLogger) Log(event AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeeded(); err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] warning: log rotation failed: %v\n", err)
	}

	// Redact sensitive data before logging
	event.Command = redact.Redact(event.Command)
	event.Args = redact.RedactArgs(event.Args)
	if event.Error != "" {
		event.Error = redact.Redact(event.Error)
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	_, err = l.file.Write(data)
	return err
}

func (l *AuditLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
