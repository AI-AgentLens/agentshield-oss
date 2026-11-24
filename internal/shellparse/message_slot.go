package shellparse

import (
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// MessageSlotsSurviveImpureLine reports whether command is a line on which a
// git/gh message keeps its doc-text exemption although CommandLineIsPure
// says no (#4988, Gary 2026-11-19).
//
// # Why
//
// The strict purity gate (#3798) withdraws every doc-text exemption once any
// command on the line is off its closed list, because the channels that
// carry text into an executor could not be enumerated. That is right for a
// heredoc written to a file, which `go test` or `make` may run. It also
// withdraws the exemption from a commit message when a build step shares the
// line (`make build | tail -5; git commit -F - <<'EOF' … EOF`), and that was
// one Shield night-lane BLOCK a night on 11-17, 11-18 and 11-19.
//
// A git/gh message is narrower than a heredoc to a file. It goes into git's
// or gh's argv or stdin, and neither runs it. On the same line it can come
// back out only through the line's own syntax: an expansion in the slot, the
// committing statement's output, or a statement that reads the stored copy
// (`.git/COMMIT_EDITMSG`, the object store, GitHub) and hands it to
// something that runs it. This predicate admits a line only when the syntax
// rules every one of those out. Each clause below closes one of them, and
// anything it does not recognise keeps the strict gate.
//
// # What it accepts
//
// The line is a list (`;`, `&&`, `||`, newline) of simple commands, with at
// least one message slot and nothing but these:
//
//   - A message slot: `git commit|tag` or `gh issue|pr|release <sub>`, pure
//     under callIsPure, not piped, every word static except the commit
//     idiom `"$(cat <<'EOF' … EOF)"`, stdin only from a quoted-delimiter
//     heredoc or a static here-string.
//   - A git read: `git add|status|log|rev-parse|diff|show` with plain words
//     and no `--output`.
//   - `cd`, `pwd`, `ls`, `true` with plain words.
//   - A plain command: a bare command name that is neither on the pure list
//     nor a shell, interpreter, eval-like builtin or known exec wrapper, with
//     plain words only.
//
// A git read or a plain command may be the first command of a pipeline whose
// later commands are `head`, `tail`, `grep` or `wc` with plain words. No
// statement may redirect output anywhere but /dev/null or another standard
// descriptor. No word outside a message slot may contain ".git" in any case
// (APFS folds case). No assignment, export, background job, subshell,
// function, loop or other compound command appears anywhere.
//
// A plain word is one unquoted literal of [A-Za-z0-9_./=:,+@%-], optionally
// after a leading `~` or `~/`: no quote, expansion, glob, brace, escape or
// whitespace, so the shells cannot read it differently from the parser.
//
// # The residual, on purpose
//
// A reader planted in an EARLIER tool call (a Makefile, a test or a hook
// that reads the message back) is invisible to any line-level gate. On main
// that two-call form already decides AUDIT (`git commit -m '<text>'` alone,
// then `bash .git/COMMIT_EDITMSG` alone), so the strict gate only ever
// protected the one-line form. Closing it needs session state (#4774).
func MessageSlotsSurviveImpureLine(command string) bool {
	if strings.TrimSpace(command) == "" {
		return false
	}
	// The raw text, not ifsNormalized's: `$IFS` is an expansion the shell
	// word-splits, and a plain word must have none. Parsing the folded text
	// let `systemd-run${IFS}--system x` read as plain words (caught by
	// TestIntentExcludedForStatements_RawMatcherReproducesTheBug_3717).
	src := command
	file := parseBashFile(src)
	if file == nil {
		return false
	}
	// Walk the whole tree once for constructs no clause below admits in any
	// position, including inside a slot's substitution.
	ok := true
	syntax.Walk(file, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.Assign, *syntax.FuncDecl, *syntax.CoprocClause, *syntax.ProcSubst,
			*syntax.DeclClause, *syntax.LetClause, *syntax.ArithmCmd, *syntax.ArithmExp:
			ok = false
		}
		return ok
	})
	if !ok || len(file.Stmts) == 0 {
		return false
	}
	slots := 0
	var visit func(st *syntax.Stmt) bool
	visit = func(st *syntax.Stmt) bool {
		if st == nil || st.Background || st.Coprocess || st.Negated || st.Disown {
			return false
		}
		switch cmd := st.Cmd.(type) {
		case *syntax.BinaryCmd:
			switch cmd.Op {
			case syntax.AndStmt, syntax.OrStmt:
				return len(st.Redirs) == 0 && visit(cmd.X) && visit(cmd.Y)
			case syntax.Pipe, syntax.PipeAll:
				return len(st.Redirs) == 0 && pipelineAllowed(cmd)
			}
			return false
		case *syntax.CallExpr:
			switch classifyLineCall(src, st, cmd) {
			case lineCallSlot:
				slots++
				return true
			case lineCallGitRead, lineCallNavigation, lineCallPlain:
				return true
			}
			return false
		}
		return false
	}
	for _, st := range file.Stmts {
		if !visit(st) {
			return false
		}
	}
	return slots > 0
}

// IsMessageSlotStatement reports whether stmt, the text of one top-level
// statement, is a git/gh message slot as MessageSlotsSurviveImpureLine
// defines it. The analyzer honours is_doc_text on an impure line only for
// such a statement (#4988).
func IsMessageSlotStatement(stmt string) bool {
	if strings.TrimSpace(stmt) == "" {
		return false
	}
	src := stmt // raw, as in MessageSlotsSurviveImpureLine
	file := parseBashFile(src)
	if file == nil || len(file.Stmts) != 1 {
		return false
	}
	st := file.Stmts[0]
	if st.Background || st.Coprocess || st.Negated || st.Disown {
		return false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	return ok && classifyLineCall(src, st, call) == lineCallSlot
}

type lineCall int

const (
	lineCallRejected lineCall = iota
	lineCallSlot
	lineCallGitRead
	lineCallNavigation
	lineCallPlain
)

// plainWordRe is the whole alphabet a plain word may use. `~` is allowed
// only as the leading home-directory tilde, `~` or `~/…`. A leading `=` is
// refused: zsh expands `=name` to a path from PATH (review of #4988).
var plainWordRe = regexp.MustCompile(`^(?:~(?:/[A-Za-z0-9_./=:,+@%-]*)?|[A-Za-z0-9_./:,+@%-][A-Za-z0-9_./=:,+@%-]*)$`)

// bareCommandRe: a command looked up on PATH by name. A path (`./x`,
// `/bin/x`) is refused, and so is a name zsh would expand (`=sh`).
var bareCommandRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]*$`)

var (
	slotGhGroups = map[string]map[string]bool{
		"issue":   {"create": true, "comment": true, "edit": true, "close": true, "reopen": true},
		"pr":      {"create": true, "comment": true, "edit": true, "close": true, "reopen": true, "review": true, "merge": true},
		"release": {"create": true, "edit": true},
	}
	slotGitSubcommands = map[string]bool{"commit": true, "tag": true}
	gitReadSubcommands = map[string]bool{
		"add": true, "status": true, "log": true, "rev-parse": true, "diff": true, "show": true,
	}
	navigationCommands = map[string]bool{"cd": true, "pwd": true, "ls": true, "true": true}
	pipeFilterCommands = map[string]bool{"head": true, "tail": true, "grep": true, "wc": true}

	// plainRefused: names a plain command may not have, because they run
	// text, read a program from a file or stdin, or run their arguments as
	// a command. The plain-word alphabet already keeps inline programs out;
	// this list is the second layer.
	plainRefused = map[string]bool{
		// shells
		"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
		"yash": true, "fish": true, "csh": true, "tcsh": true, "pwsh": true, "powershell": true,
		"busybox": true, "rbash": true,
		// interpreters
		"python": true, "python2": true, "python3": true, "pypy": true, "pypy3": true,
		"node": true, "nodejs": true, "deno": true, "bun": true, "ruby": true, "perl": true,
		"php": true, "lua": true, "luajit": true, "Rscript": true, "R": true, "osascript": true,
		"tclsh": true, "wish": true, "expect": true, "julia": true, "swift": true,
		"groovy": true, "jshell": true, "irb": true, "ghci": true, "runghc": true,
		// builtins and wrappers that run text or their arguments
		"eval": true, "source": true, "exec": true, "command": true, "builtin": true,
		"env": true, "sudo": true, "doas": true, "su": true, "nice": true, "nohup": true,
		"timeout": true, "gtimeout": true, "xargs": true, "stdbuf": true, "time": true,
		"watch": true, "parallel": true, "setsid": true, "script": true, "unbuffer": true,
		"caffeinate": true, "chronic": true, "flock": true, "chroot": true, "unshare": true,
		"nsenter": true, "taskset": true, "ionice": true, "chrt": true, "trap": true,
		"npx": true, "bunx": true, "pnpx": true, "uvx": true, "pipx": true, "fc": true,
		"systemd-run": true, "run0": true, "pkexec": true, "firejail": true, "bwrap": true,
		"sandbox-exec": true, "at": true, "batch": true, "tmux": true, "screen": true,
		"open": true, "launchctl": true, "ssh": true,
		"git": true, "gh": true,
	}
)

func classifyLineCall(src string, st *syntax.Stmt, call *syntax.CallExpr) lineCall {
	if len(call.Assigns) > 0 || len(call.Args) == 0 {
		return lineCallRejected
	}
	name, ok := plainWordValue(call.Args[0])
	if !ok {
		return lineCallRejected
	}
	switch name {
	case "git", "gh":
		if isSlotCall(src, st, call, name) {
			return lineCallSlot
		}
		if name == "git" && isGitReadCall(src, st, call) {
			return lineCallGitRead
		}
		return lineCallRejected
	}
	if !redirectsOnlyToStandardSinks(st) || !argsPlainOutsideGitDir(call.Args[1:]) || strings.Contains(strings.ToLower(name), ".git") {
		return lineCallRejected
	}
	if navigationCommands[name] {
		return lineCallNavigation
	}
	if !bareCommandRe.MatchString(name) || pureCommands[name] || plainRefused[name] {
		return lineCallRejected
	}
	if _, interp := codeInterpreters[name]; interp {
		return lineCallRejected
	}
	return lineCallPlain
}

// isSlotCall: a git commit/tag or gh issue/pr/release call that callIsPure
// accepts, every word static (or the commit idiom), stdin at most a quoted
// heredoc or a static here-string, output only to standard sinks.
func isSlotCall(src string, st *syntax.Stmt, call *syntax.CallExpr, name string) bool {
	if !callIsPure(src, st, call, false, nil) {
		return false
	}
	for _, w := range call.Args {
		if !wordIsStatic(w) && !isCatHeredocIdiom(w) {
			return false
		}
	}
	words := callWordsDequoted(call)
	if len(words) < 2 {
		return false
	}
	switch name {
	case "git":
		if !slotGitSubcommands[gitSubcommand(words[1:])] {
			return false
		}
	case "gh":
		if len(words) < 3 {
			return false
		}
		subs, ok := slotGhGroups[words[1]]
		if !ok || !subs[words[2]] {
			return false
		}
	}
	for _, r := range st.Redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if r.Word == nil || !heredocDelimiterQuoted(r.Word) {
				return false
			}
		case syntax.WordHdoc:
			if r.Word == nil || !wordIsStatic(r.Word) {
				return false
			}
		default:
			if !isStandardSinkRedirect(r) {
				return false
			}
		}
	}
	return true
}

// isGitReadCall: git add/status/log/rev-parse/diff/show with plain words,
// none of them `--output` (which writes the text to a file a later
// statement could run) and none naming the git directory.
func isGitReadCall(src string, st *syntax.Stmt, call *syntax.CallExpr) bool {
	if !callIsPure(src, st, call, false, nil) || !redirectsOnlyToStandardSinks(st) {
		return false
	}
	if !argsPlainOutsideGitDir(call.Args[1:]) {
		return false
	}
	words := callWordsDequoted(call)
	for _, w := range words[1:] {
		if strings.HasPrefix(w, "--output") || strings.HasPrefix(w, "--ext-diff") || strings.HasPrefix(w, "--textconv") {
			return false
		}
	}
	return gitReadSubcommands[gitSubcommand(words[1:])]
}

// gitSubcommand returns the first non-option word after git's global
// options, skipping the values of the ones that take a separate value.
func gitSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "-C" || w == "--git-dir" || w == "--work-tree" || w == "--namespace" {
			i++
			continue
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		return w
	}
	return ""
}

// pipelineAllowed: the first command is a git read or a plain command, and
// every later one is a display filter with plain words. Nothing is piped
// into a command that could run what it reads.
func pipelineAllowed(bc *syntax.BinaryCmd) bool {
	var stmts []*syntax.Stmt
	var flatten func(s *syntax.Stmt) bool
	flatten = func(s *syntax.Stmt) bool {
		if s == nil || s.Background || s.Coprocess || s.Negated || s.Disown {
			return false
		}
		if b, ok := s.Cmd.(*syntax.BinaryCmd); ok {
			if b.Op != syntax.Pipe && b.Op != syntax.PipeAll {
				return false
			}
			if len(s.Redirs) > 0 {
				return false
			}
			return flatten(b.X) && flatten(b.Y)
		}
		stmts = append(stmts, s)
		return true
	}
	if !flatten(bc.X) || !flatten(bc.Y) || len(stmts) < 2 {
		return false
	}
	for i, s := range stmts {
		call, ok := s.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) > 0 || len(call.Args) == 0 {
			return false
		}
		if i == 0 {
			// src is only used by callIsPure for interpreter heredocs, which
			// a git read never is.
			switch classifyLineCall("", s, call) {
			case lineCallGitRead, lineCallPlain:
				continue
			}
			return false
		}
		name, ok := plainWordValue(call.Args[0])
		if !ok || !pipeFilterCommands[name] || len(s.Redirs) > 0 || !argsPlainOutsideGitDir(call.Args[1:]) {
			return false
		}
	}
	return true
}

// isCatHeredocIdiom: the word is exactly `"$(cat <<'EOF' … EOF)"`, the
// commit idiom. The substitution runs only `cat` of a quoted-delimiter
// heredoc, so its output is the heredoc body, verbatim.
func isCatHeredocIdiom(w *syntax.Word) bool {
	if len(w.Parts) != 1 {
		return false
	}
	dq, ok := w.Parts[0].(*syntax.DblQuoted)
	if !ok || dq.Dollar || len(dq.Parts) != 1 {
		return false
	}
	cs, ok := dq.Parts[0].(*syntax.CmdSubst)
	if !ok || cs.Backquotes || cs.TempFile || cs.ReplyVar || len(cs.Stmts) != 1 || len(cs.Last) > 0 {
		return false
	}
	st := cs.Stmts[0]
	if st.Background || st.Coprocess || st.Negated || st.Disown || len(st.Redirs) != 1 {
		return false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) != 1 {
		return false
	}
	if name, ok := plainWordValue(call.Args[0]); !ok || name != "cat" {
		return false
	}
	r := st.Redirs[0]
	if r.N != nil {
		return false
	}
	return (r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc) && r.Word != nil && heredocDelimiterQuoted(r.Word)
}

func redirectsOnlyToStandardSinks(st *syntax.Stmt) bool {
	for _, r := range st.Redirs {
		if !isStandardSinkRedirect(r) {
			return false
		}
	}
	return true
}

// isStandardSinkRedirect: an output redirect to /dev/null, or a duplication
// onto stdout or stderr (`2>&1`, `>&2`). Nothing else: no file, no input.
func isStandardSinkRedirect(r *syntax.Redirect) bool {
	if r.N != nil && r.N.Value != "1" && r.N.Value != "2" {
		return false
	}
	target, ok := plainWordValue(r.Word)
	if !ok {
		return false
	}
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
		return target == "/dev/null"
	case syntax.DplOut:
		return target == "1" || target == "2"
	}
	return false
}

func argsPlainOutsideGitDir(args []*syntax.Word) bool {
	for _, w := range args {
		v, ok := plainWordValue(w)
		if !ok || strings.Contains(strings.ToLower(v), ".git") {
			return false
		}
	}
	return true
}

// plainWordValue returns w's text when it is a single unquoted literal in
// the plain-word alphabet.
func plainWordValue(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok || !plainWordRe.MatchString(lit.Value) {
		return "", false
	}
	return lit.Value, true
}
