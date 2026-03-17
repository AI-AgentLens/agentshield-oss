// Package shellparse provides AST-aware shell command parsing using mvdan.cc/sh/v3.
// It extracts structured command representations (ParsedCommand) that can be
// consumed by both the normalizer (for path extraction) and the structural
// analyzer (for security checks).
//
// This package was extracted from the structural analyzer to allow the
// normalizer to use AST-aware parsing for context-sensitive path extraction,
// eliminating false positives from text content that mentions sensitive paths.
package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParsedCommand is the structural representation of a shell command.
type ParsedCommand struct {
	// Segments are the pipeline-separated commands.
	// "curl ... | bash" → 2 segments.
	Segments []CommandSegment

	// Operators between segments: "|", "&&", "||", ";"
	Operators []string

	// Redirects at the top level (e.g., "> /dev/null")
	Redirects []Redirect

	// Subcommands found via indirect execution parsing (depth > 0).
	// E.g., for "bash -c 'rm -rf /'", the inner "rm -rf /" is a subcommand.
	Subcommands []*ParsedCommand
}

// CommandSegment is a single command within a pipeline.
type CommandSegment struct {
	Raw        string            // original text of this segment
	Executable string            // base command name (e.g., "rm", "curl")
	SubCommand string            // e.g., "install" for "npm install"
	Args       []string          // positional arguments
	Flags      map[string]string // normalized flags: key=flag name, value=flag value (or "")
	Redirects  []Redirect        // segment-level redirects
	IsShell    bool              // true if executable is a known shell interpreter
}

// Redirect represents a shell redirect operation.
type Redirect struct {
	Op   string // ">", ">>", "<", "2>"
	Path string // target path
}

// Parse converts a raw command string into a ParsedCommand AST.
// maxDepth controls recursion into indirect execution (e.g., bash -c '...').
func Parse(command string, maxDepth int) *ParsedCommand {
	if maxDepth <= 0 {
		maxDepth = 2
	}
	return parseWithDepth(command, 0, maxDepth)
}

func parseWithDepth(command string, depth, maxDepth int) *ParsedCommand {
	if depth >= maxDepth {
		return nil
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return fallbackParse(command)
	}

	pc := &ParsedCommand{}
	for _, stmt := range file.Stmts {
		walkStmt(pc, stmt, command, depth, maxDepth)
	}
	return pc
}

func walkStmt(pc *ParsedCommand, stmt *syntax.Stmt, raw string, depth, maxDepth int) {
	if stmt.Cmd == nil {
		return
	}

	// Collect redirects from the statement
	for _, redir := range stmt.Redirs {
		r := Redirect{Op: redirectOpString(redir)}
		if redir.Word != nil {
			r.Path = WordToString(redir.Word)
		}
		pc.Redirects = append(pc.Redirects, r)
	}

	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		seg := callExprToSegment(cmd, raw)
		// Check for indirect execution (bash -c, python -c, etc.)
		if seg.IsShell {
			inner := ExtractInlineCode(seg)
			if inner != "" {
				sub := parseWithDepth(inner, depth+1, maxDepth)
				if sub != nil {
					pc.Subcommands = append(pc.Subcommands, sub)
				}
			}
		}
		pc.Segments = append(pc.Segments, seg)

	case *syntax.BinaryCmd:
		op := binaryOpString(cmd.Op)
		leftPC := &ParsedCommand{}
		rightPC := &ParsedCommand{}
		walkStmt(leftPC, cmd.X, raw, depth, maxDepth)
		walkStmt(rightPC, cmd.Y, raw, depth, maxDepth)
		pc.Segments = append(pc.Segments, leftPC.Segments...)
		pc.Operators = append(pc.Operators, op)
		pc.Segments = append(pc.Segments, rightPC.Segments...)
		pc.Subcommands = append(pc.Subcommands, leftPC.Subcommands...)
		pc.Subcommands = append(pc.Subcommands, rightPC.Subcommands...)

	case *syntax.Subshell:
		for _, s := range cmd.Stmts {
			walkStmt(pc, s, raw, depth, maxDepth)
		}
	}
}

func callExprToSegment(call *syntax.CallExpr, raw string) CommandSegment {
	seg := CommandSegment{
		Flags: make(map[string]string),
	}

	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		words = append(words, WordToString(word))
	}

	if len(words) == 0 {
		return seg
	}

	seg.Executable = words[0]

	// Handle sudo: skip sudo and its flags, then re-assign the real executable.
	remaining := words[1:]
	if seg.Executable == "sudo" && len(remaining) > 0 {
		for len(remaining) > 0 {
			if strings.HasPrefix(remaining[0], "-") {
				remaining = remaining[1:]
			} else {
				break
			}
		}
		if len(remaining) > 0 {
			seg.Executable = remaining[0]
			remaining = remaining[1:]
		}
	}

	seg.IsShell = IsShellInterpreter(seg.Executable)
	for i := 0; i < len(remaining); i++ {
		w := remaining[i]
		if strings.HasPrefix(w, "--") && len(w) > 2 {
			flag := w[2:]
			if eqIdx := strings.Index(flag, "="); eqIdx >= 0 {
				seg.Flags[flag[:eqIdx]] = flag[eqIdx+1:]
			} else {
				seg.Flags[flag] = ""
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "--") {
			for _, ch := range w[1:] {
				seg.Flags[string(ch)] = ""
			}
		} else {
			seg.Args = append(seg.Args, w)
		}
	}

	// Detect subcommand for known tools
	if len(seg.Args) > 0 {
		if IsSubcommandTool(seg.Executable) {
			seg.SubCommand = seg.Args[0]
			seg.Args = seg.Args[1:]
		}
	}

	seg.Raw = strings.Join(words, " ")
	return seg
}

// fallbackParse handles commands that mvdan.cc/sh can't parse.
func fallbackParse(command string) *ParsedCommand {
	pc := &ParsedCommand{}
	parts := strings.Split(command, "|")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		words := strings.Fields(part)
		seg := CommandSegment{
			Raw:        part,
			Executable: words[0],
			Flags:      make(map[string]string),
			IsShell:    IsShellInterpreter(words[0]),
		}
		for _, w := range words[1:] {
			if strings.HasPrefix(w, "-") {
				for _, ch := range w[1:] {
					seg.Flags[string(ch)] = ""
				}
			} else {
				seg.Args = append(seg.Args, w)
			}
		}
		pc.Segments = append(pc.Segments, seg)
		if i < len(parts)-1 {
			pc.Operators = append(pc.Operators, "|")
		}
	}
	return pc
}

// ---------------------------------------------------------------------------
// Exported helpers
// ---------------------------------------------------------------------------

// WordToString converts a syntax.Word AST node to its string representation.
func WordToString(word *syntax.Word) string {
	var sb strings.Builder
	printer := syntax.NewPrinter()
	if err := printer.Print(&sb, word); err != nil {
		return ""
	}
	return sb.String()
}

// AllSegments returns all segments including those in subcommands.
func AllSegments(parsed *ParsedCommand) []CommandSegment {
	if parsed == nil {
		return nil
	}
	segs := make([]CommandSegment, len(parsed.Segments))
	copy(segs, parsed.Segments)
	for _, sub := range parsed.Subcommands {
		segs = append(segs, AllSegments(sub)...)
	}
	return segs
}

// ReparseArgsAsFlags re-parses a list of args into flags and positional args.
func ReparseArgsAsFlags(words []string) (map[string]string, []string) {
	flags := make(map[string]string)
	var args []string
	for _, w := range words {
		if strings.HasPrefix(w, "--") && len(w) > 2 {
			flag := w[2:]
			if eqIdx := strings.Index(flag, "="); eqIdx >= 0 {
				flags[flag[:eqIdx]] = flag[eqIdx+1:]
			} else {
				flags[flag] = ""
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 {
			for _, ch := range w[1:] {
				flags[string(ch)] = ""
			}
		} else {
			args = append(args, w)
		}
	}
	return flags, args
}

// ExtractInlineCode extracts the code argument from interpreters that accept
// inline code: bash -c 'code', python -c 'code', etc.
func ExtractInlineCode(seg CommandSegment) string {
	if !seg.IsShell && !CodeInterpreters[seg.Executable] {
		return ""
	}
	if _, hasC := seg.Flags["c"]; hasC {
		if len(seg.Args) > 0 {
			return seg.Args[0]
		}
	}
	return ""
}

// HasFlag checks if a flag key exists in the flags map.
func HasFlag(flags map[string]string, key string) bool {
	_, ok := flags[key]
	return ok
}

// ---------------------------------------------------------------------------
// Predicate helpers
// ---------------------------------------------------------------------------

var ShellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"ksh": true, "fish": true, "csh": true, "tcsh": true,
}

var CodeInterpreters = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"node": true, "ruby": true, "perl": true, "lua": true,
	"php": true,
}

func IsShellInterpreter(exe string) bool {
	return ShellInterpreters[exe]
}

func IsShellOrInterpreter(exe string) bool {
	return ShellInterpreters[exe] || CodeInterpreters[exe]
}

func IsDownloadCommand(exe string) bool {
	switch exe {
	case "curl", "wget", "fetch", "aria2c":
		return true
	}
	return false
}

func IsDangerousPipeTarget(exe string) bool {
	switch exe {
	case "crontab", "at", "tee", "dd", "mysql", "psql", "sqlite3":
		return true
	}
	return false
}

func IsSubcommandTool(exe string) bool {
	switch exe {
	case "npm", "pip", "pip3", "yarn", "pnpm", "cargo", "go",
		"git", "docker", "kubectl", "brew", "apt", "apt-get",
		"systemctl", "service", "gh":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func redirectOpString(redir *syntax.Redirect) string {
	switch redir.Op {
	case syntax.RdrOut:
		return ">"
	case syntax.AppOut:
		return ">>"
	case syntax.RdrIn:
		return "<"
	default:
		return redir.Op.String()
	}
}

func binaryOpString(op syntax.BinCmdOperator) string {
	switch op {
	case syntax.Pipe:
		return "|"
	case syntax.AndStmt:
		return "&&"
	case syntax.OrStmt:
		return "||"
	default:
		return op.String()
	}
}
