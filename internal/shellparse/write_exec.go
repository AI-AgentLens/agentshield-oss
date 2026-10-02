package shellparse

import (
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// simpleBraceParam matches `${NAME}` with a plain parameter name and no
// operator, the only brace form normalizePathKey folds to `$NAME`.
var simpleBraceParam = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// TextReachesExecutor reports whether text that a statement in command
// presents as inert — an echo/printf argument, a heredoc body — is handed to
// a shell or interpreter by that same command, by either route:
//
//   - piped straight into one (PipesIntoExecutor, #3796)
//   - written to a path that another statement of the command then executes
//     (WritesThenExecutes, #3800)
//
// It is the single question the two intent.go sites ask before honouring an
// inertness label, and it parses the command exactly once for both answers.
func TextReachesExecutor(command string) bool {
	r := AnalyzeTextReach(command)
	return r.PipesIntoExecutor || len(r.Correlated) > 0
}

// TextReach is everything the intent sites need to know about where a
// command's text goes, from one parse.
type TextReach struct {
	// PipesIntoExecutor: some pipeline feeds a shell or interpreter (#3796).
	// Command-wide by nature: the splitter separates pipeline stages, so the
	// upstream fragment can never see the pipe on its own.
	PipesIntoExecutor bool

	// Correlated holds every path the command both writes and executes
	// (#3800), keyed as normalizePathKey produces. A statement that writes
	// one of these paths (StatementWritesAny) has handed its text to an
	// executor and loses its inertness label; a statement that writes a
	// different path, or nothing, keeps it.
	Correlated map[string]bool

	// CoarseCorrelated: a correlated path is written by something the
	// statement splitter cannot attribute to the labelled statement — a
	// `tee P` that is a pipe TARGET (the doc-shaped stage is upstream of
	// it), a redirect on a compound command (`{ echo ...; } > P`, the echo
	// is split out without its redirect), or a write inside a `-c` string.
	// For those the withdrawal is command-wide, which is exactly the
	// granularity #3797 accepted for pipes: on main today, `echo "<doc>" >
	// notes.txt; echo true | bash` already withdraws the notes write's
	// label. Measured, and the reason this field exists rather than a
	// per-statement answer that would silently miss the pipe-to-tee shape.
	CoarseCorrelated bool
}

// AnalyzeTextReach parses command once and answers both #3796 and #3800.
// Parse failure yields the zero value: no evidence, no withdrawal (the
// fail-closed posture for unparseable commands lives in
// IntentExcludedForStatements' own parsed flag).
func AnalyzeTextReach(command string) TextReach {
	// Held in a variable because the binding retry (#3798 item 2a) must see
	// the SAME text the file was parsed from, or it resolves a command that
	// was never analysed.
	normalized := ifsNormalized(command)
	file := parseBashFile(normalized)
	if file == nil {
		return TextReach{}
	}
	var r TextReach
	r.PipesIntoExecutor = pipesIntoExecutorCmd(normalized, file)
	c := newPathCollector()
	c.collectFile(file, 0)
	c.followExecutedContent()
	for p := range c.executed {
		if c.written[p] || c.coarseWritten[p] {
			if r.Correlated == nil {
				r.Correlated = map[string]bool{}
			}
			r.Correlated[p] = true
			if c.coarseWritten[p] {
				r.CoarseCorrelated = true
			}
		}
	}
	return r
}

// StatementWritesAny reports whether statement — one of the splitter's
// top-level statements — writes any of paths, by output redirect or as a
// tee operand (including inside a shell -c string it carries). It is how
// IntentExcludedForStatements attributes a correlated write to the
// statement that made it, so an unrelated helper script run in the same
// command (`echo "<doc>" > notes.txt; echo true > check.sh; bash check.sh`)
// does not cost the notes write its label (Codex, #3800 review pass 2).
func StatementWritesAny(statement string, paths map[string]bool) bool {
	if len(paths) == 0 {
		return false
	}
	file := parseBashFile(ifsNormalized(statement))
	if file == nil {
		return false
	}
	c := newPathCollector()
	c.collectFile(file, 0)
	for p := range paths {
		if c.written[p] || c.coarseWritten[p] {
			return true
		}
	}
	return false
}

// WritesThenExecutes reports whether command writes into some path AND
// invokes that same path as a program — `echo "..." > /tmp/x.sh; bash
// /tmp/x.sh`, `tee /tmp/x.sh <<'EOF' ... EOF` followed by `sh /tmp/x.sh`,
// `printf ... > x && chmod +x x && ./x`, `cat > f <<EOF ... EOF; source f`.
//
// # Why this exists (#3800)
//
// #3797 withdrew the inertness labels when text is PIPED into an executor.
// That is one of two ways shell text becomes a program; the other is to
// write it to a file and run the file. Measured on main: a firewall-disable
// command BLOCKed on its own and BLOCKed when piped into a shell, but written
// to a script and executed it returned REQUIRE_APPROVAL naming no rule at
// all, because the writing statement carried in_heredoc / is_doc_text and
// the rule's command_intent_exclude honoured it. 518 rules carry one of
// these labels, 327 of them deciding BLOCK.
//
// # What counts as executing a path
//
//   - a shell or code interpreter (IsShellOrInterpreter) taking the path as
//     a non-flag operand: `bash P`, `sudo sh P`, `python3 P`
//   - `source P` / `. P`
//   - the path itself as the command word, which the shell only does for a
//     word containing a slash: `./P`, `/tmp/P`, `$D/P`
//   - stdin redirect into an executor: `bash < P`, `sh -s < P`
//
// # What counts as writing a path
//
//   - an output redirect on any statement: `> P`, `>> P`, `>| P`, `&> P`
//   - a non-flag operand of `tee`, whether it is a pipe target or carries
//     the heredoc itself
//
// # Correlation, and what is deliberately not resolved
//
// Paths are compared after quote removal and path.Clean, so `> ./x.sh`
// matches `bash x.sh` and `"$D/x.sh"` matches `$D/x.sh`. A word carrying an
// expansion keeps its source text as the key — its runtime value is
// unknowable, and two identical unknowns are treated as the same file, which
// fails closed. Nothing else is resolved: `~` against $HOME, symlinks, a
// relative path against an absolute one, or a second hop (`cp P Q; bash Q`).
// Those are named gaps, not accidents; each widens the match and wants its
// own measurement.
//
// Order does not matter: a write and an execution of the same path anywhere
// in one command withdraw the label. Reversed order is a re-run or a loop,
// and there is no inert reading of "run it, then overwrite it" worth an FP
// carve-out.
//
// A write with NO later execution keeps its label. `cat > notes.md <<EOF`
// with payload text in the body is the doc-text population #3793 protects,
// and it is the other side of every test here.
//
// Parse failure returns false, for the reason PipesIntoExecutor gives:
// withdrawing an excuse takes evidence, and an unparseable blob is not
// evidence. The fail-closed posture for unparseable commands lives in
// IntentExcludedForStatements' own parsed flag.
func WritesThenExecutes(command string) bool {
	return len(AnalyzeTextReach(command).Correlated) > 0
}

// ifsNormalized returns command with unquoted $IFS / ${IFS} separators
// collapsed to spaces (NormalizeIFS), or command itself when there is
// nothing to normalise — NormalizeIFS returns "" as its no-op sentinel,
// the same convention the semantic, substitution and regex paths rely on.
//
// The collector must parse the normalised text, not the raw one: `tee
// /tmp/x.sh${IFS}<<'EOF'` keys the WRITE side as `/tmp/x.sh${IFS}` while
// `bash /tmp/x.sh` keys the execute side as `/tmp/x.sh`, and the miss lets
// the label survive. Caught by TestIFSSeparatorParity in CI (three corpus
// cases BLOCK -> AUDIT under the second-space substitution), not by the
// targeted runs that preceded it.
func ifsNormalized(command string) string {
	if n := NormalizeIFS(command); n != "" {
		return n
	}
	return command
}

func parseBashFile(command string) *syntax.File {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	return file
}

// maxInlineDepth bounds the recursion into `sh -c '...'` strings. One level
// covers every measured laundering shape; a deeper nest is a contrived
// command, and the bound keeps a pathological input from re-parsing itself
// without limit.
const maxInlineDepth = 3

// pathCollector accumulates, over one walk, the paths a command writes and
// the paths it executes. written holds writes a labelled statement makes
// itself (a redirect on a simple command, a tee that carries its own
// heredoc); coarseWritten holds writes the splitter cannot attribute to the
// labelled statement (see TextReach.CoarseCorrelated).
type pathCollector struct {
	written       map[string]bool
	coarseWritten map[string]bool
	executed      map[string]bool
	// pipeTargets / pipeTargetStmts: every pipeline stage after the first,
	// as its leftmost call and as its statement. A write made by such a
	// stage — `| tee P`, `| cat > P`, `| dd of=P` — is filled by the text
	// UPSTREAM of it, which the splitter hands out as a separate statement,
	// so the write is real but never attributable to the labelled text.
	pipeTargets     map[*syntax.CallExpr]bool
	pipeTargetStmts map[*syntax.Stmt]bool
	// content holds, per path an attributable statement writes, the static
	// text it puts there — an echo/printf argument list or a cat/tee
	// heredoc body. If that path is later executed the text is a program,
	// and followExecutedContent walks it for what IT executes (#3814, one
	// level of indirection).
	content map[string][]string
	// execOnly is set while walking executed CONTENT: the generated
	// script's own writes belong to the script, not to any labelled
	// statement, so only its executions are recorded.
	execOnly bool
}

func newPathCollector() *pathCollector {
	return &pathCollector{
		written:         map[string]bool{},
		coarseWritten:   map[string]bool{},
		executed:        map[string]bool{},
		pipeTargets:     map[*syntax.CallExpr]bool{},
		pipeTargetStmts: map[*syntax.Stmt]bool{},
		content:         map[string][]string{},
	}
}

// followExecutedContent (#3814, one level of indirection): a path the
// command both writes and executes is a program whose text the collector
// already holds. Parse that text as shell and collect what IT executes, so
//
//	echo "<payload>" > lib.sh; echo '. lib.sh' > run.sh; bash run.sh
//
// correlates lib.sh — whose writer is the statement whose text actually
// runs — and not only run.sh. Measured on main with a downgrade rule: the
// payload statement kept its label (AUDIT) because the correlated write
// was run.sh. Each round follows one more hop, maxInlineDepth rounds in
// all. Content that is not statically known (`echo "$x" > run.sh`) is not
// followed, which leaves that indirection where it was rather than guessed
// at.
func (c *pathCollector) followExecutedContent() {
	followed := map[string]bool{}
	c.execOnly = true
	defer func() { c.execOnly = false }()
	for round := 1; round <= maxInlineDepth; round++ {
		var next []string
		for p := range c.executed {
			if !followed[p] && (c.written[p] || c.coarseWritten[p]) && len(c.content[p]) > 0 {
				next = append(next, p)
			}
		}
		if len(next) == 0 {
			return
		}
		for _, p := range next {
			followed[p] = true
			for _, text := range c.content[p] {
				if inner := parseBashFile(text); inner != nil {
					c.collectFile(inner, round)
				}
			}
		}
	}
}

// markPipeTarget records y — the right-hand side of a pipe — and EVERY
// statement and call beneath it as pipeline stages after the first. The
// walk, not just the leftmost call, is the point (Codex, #3800 review pass
// 4): `| (cat > P)`, `| { tee P; }`, `| if …; then cat > P; fi` and `| a &&
// cat > P` all bury the writer inside a compound, and the text that fills
// it is still the stage upstream. A chain nests (`a | b | c` is a pipe whose
// Y is itself a pipe), so descending into y reaches every later stage in
// either nesting direction; the first stage is the one node never beneath
// a pipe's Y.
func (c *pathCollector) markPipeTarget(y *syntax.Stmt) {
	if y == nil {
		return
	}
	syntax.Walk(y, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Stmt:
			c.pipeTargetStmts[n] = true
		case *syntax.CallExpr:
			c.pipeTargets[n] = true
		}
		return true
	})
}

func (c *pathCollector) collectFile(file *syntax.File, depth int) {
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			// Pre-order: mark the pipe target before its CallExpr is
			// visited, so a `tee P` stage is known to sit downstream of the
			// text that fills it.
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				c.markPipeTarget(n.Y)
			}
		case *syntax.Stmt:
			// A redirect is attributable to the labelled statement only
			// when it sits on a simple command that is not a pipeline
			// stage after the first: `echo x > P` yes; `{ echo x; } > P`
			// and `echo x | cat > P` no — the splitter separates the echo
			// from both (Codex, #3800 review pass 3 for the pipe case).
			_, simple := n.Cmd.(*syntax.CallExpr)
			attributable := simple && depth == 0 && !c.pipeTargetStmts[n]
			var wrote []string
			for _, r := range n.Redirs {
				switch r.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll:
					if p, ok := pathKey(r.Word); ok {
						c.write(p, attributable)
						wrote = append(wrote, p)
					}
				case syntax.DplOut:
					// `>&word` with a non-numeric word is bash's `&>word`:
					// a file write, not a descriptor duplication (Codex,
					// #3800 review pass 5). `>&2` and `>&-` stay ignored.
					if r.Word != nil && !isFdOperand(payloadValue(WordToString(r.Word))) {
						if p, ok := pathKey(r.Word); ok {
							c.write(p, attributable)
							wrote = append(wrote, p)
						}
					}
				case syntax.RdrIn, syntax.RdrInOut:
					// `bash < P` (and `bash <> P`): the executor reads its
					// program from the file. Same question, same answer, as
					// the pipe path — pipeTargetIsExecutor already knows
					// which flag means "stdin is data" for which executor
					// (#3797), so `python3 -m json.tool < P` stays a data
					// read.
					if pipeTargetIsExecutor(n) {
						if p, ok := pathKey(r.Word); ok {
							c.executed[p] = true
						}
					} else if r.Op == syntax.RdrInOut {
						// `<>` opens the file read-write, so on any OTHER
						// statement it is a write to that path — `echo …
						// 1<> P` fills P just as `> P` does (Codex, #3800
						// review pass 6). On an executor it is the
						// program's input, not a write of this statement's
						// text, and recording it as one would make `bash
						// <> y.sh` correlate with itself.
						if p, ok := pathKey(r.Word); ok {
							c.write(p, attributable)
							wrote = append(wrote, p)
						}
					}
				}
			}
			// #3814: remember what an attributable statement writes, so a
			// path that turns out to be executed can be walked as the
			// program it is. `tee P <<'EOF'` carries its body on the
			// statement's redirects and its target in the call's operands.
			if attributable && !c.execOnly {
				if text, ok := stmtEmittedText(n); ok {
					call := n.Cmd.(*syntax.CallExpr)
					words := peelExecWrappers(callWordsDequoted(call))
					if len(words) > 0 && path.Base(NormalizeExecName(words[0])) == "tee" {
						for _, w := range teeOperands(words[1:]) {
							if p, ok := normalizePathKey(w); ok {
								wrote = append(wrote, p)
							}
						}
					}
					for _, p := range wrote {
						c.content[p] = append(c.content[p], text)
					}
				}
			}
		case *syntax.CallExpr:
			c.collectCall(n, depth)
		}
		return true
	})
}

func (c *pathCollector) write(p string, attributable bool) {
	if c.execOnly {
		return
	}
	if attributable {
		c.written[p] = true
	} else {
		c.coarseWritten[p] = true
	}
}

// stmtEmittedText returns the static text a simple statement writes to its
// output: a heredoc body on the statement (cat/tee, quoted or unquoted
// delimiter, as long as the body is literal), or the argument list of echo
// / the operands of printf. Only text known statically qualifies — `echo
// "$x" > run.sh` carries an unknown program and yields nothing.
func stmtEmittedText(stmt *syntax.Stmt) (string, bool) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return "", false
	}
	for _, r := range stmt.Redirs {
		if (r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc) && r.Hdoc != nil {
			return staticWordText(r.Hdoc)
		}
	}
	words := peelExecWrappers(callWordsDequoted(call))
	if len(words) < 2 {
		return "", false
	}
	args := words[1:]
	switch path.Base(NormalizeExecName(words[0])) {
	case "echo":
		for len(args) > 0 && isEchoOption(args[0]) {
			args = args[1:]
		}
	case "printf":
		if args[0] == "--" {
			args = args[1:]
		}
		// bash decodes escapes in the FORMAT only. The newline is the one
		// that separates statements in a generated script; the rest of the
		// `\` family is left to DecodeEmittedSeparators' own concern.
		if len(args) > 0 {
			args[0] = strings.ReplaceAll(args[0], `\n`, "\n")
		}
	default:
		return "", false
	}
	if len(args) == 0 {
		return "", false
	}
	return strings.Join(args, " "), true
}

// isEchoOption reports whether w is an echo option cluster (-n, -e, -E, or
// a bundle of them) rather than text to print.
func isEchoOption(w string) bool {
	if len(w) < 2 || w[0] != '-' {
		return false
	}
	for _, r := range w[1:] {
		if r != 'n' && r != 'e' && r != 'E' {
			return false
		}
	}
	return true
}

// peelExecWrappers strips leading exec wrappers (`sudo`, `env FOO=1`, …)
// without recording them — for a caller that wants the wrapped command
// only. collectCall keeps its own loop because it must record each hop.
func peelExecWrappers(words []string) []string {
	for len(words) > 1 && isExecWrapper(words[0]) {
		target := wrapperTargetIndex(words)
		if target >= len(words) {
			break
		}
		words = words[target:]
	}
	return words
}

// teeOperands returns tee's file operands: every word past the options,
// where `--` ends option processing so a later dash-word is an operand
// (`tee -- -x.sh`; Codex, #3800 review pass 5).
func teeOperands(args []string) []string {
	var out []string
	pastOptions := false
	for _, w := range args {
		if !pastOptions {
			if w == "--" {
				pastOptions = true
				continue
			}
			if strings.HasPrefix(w, "-") {
				continue // -a, --append, -i, -p …
			}
		}
		out = append(out, w)
	}
	return out
}

// collectCall records the paths a call writes (tee operands) and the paths
// it executes (interpreter operands, source/. operands, or its own
// slash-bearing command word).
func (c *pathCollector) collectCall(call *syntax.CallExpr, depth int) {
	words := callWordsDequoted(call)
	if len(words) == 0 {
		return
	}
	// A slash-bearing command word is executed as a path whatever its
	// basename: a generated script named /tmp/bash or /tmp/tee is still
	// the file that was just written (Codex, #3800 review pass 4), and so
	// is one named /tmp/env or /tmp/sudo — the wrapper stripper recognises
	// those by basename and would discard the path before anything saw it
	// (Codex, pass 6). So every hop is recorded BEFORE it is peeled, then
	// the real executable, and only then does the basename switch add
	// operand handling on top. A bare `x.sh` is a PATH lookup, not the
	// file written to the cwd, and is not recorded.
	for len(words) > 1 && isExecWrapper(words[0]) {
		c.recordCommandWord(words[0])
		target := wrapperTargetIndex(words)
		if target >= len(words) {
			break
		}
		words = words[target:]
	}
	c.recordCommandWord(words[0])
	name := path.Base(NormalizeExecName(words[0]))
	switch {
	case name == "tee":
		// A tee that is a pipe target is filled by the stage upstream of
		// it, which the splitter hands out as a separate statement — the
		// write is real but not attributable to the labelled text.
		attributable := !c.pipeTargets[call] && depth == 0
		for _, w := range teeOperands(words[1:]) {
			if p, ok := normalizePathKey(w); ok {
				c.write(p, attributable)
			}
		}
	case name == "dd":
		// `| dd of=P` writes its stdin to P, the same shape as `| tee P`.
		attributable := !c.pipeTargets[call] && depth == 0
		for _, w := range words[1:] {
			if v, ok := strings.CutPrefix(w, "of="); ok {
				if p, ok := normalizePathKey(v); ok {
					c.write(p, attributable)
				}
			}
		}
	case name == "source" || name == ".":
		// `source -- P` is accepted by bash; the first operand past any
		// options is the file (Codex, #3800 review pass 1).
		if p, ok := normalizePathKey(firstOperand(words[1:])); ok {
			c.executed[p] = true
		}
	case IsShellOrInterpreter(name):
		c.collectInterpreterOperands(name, words[1:], depth)
	}
}

// collectInterpreterOperands walks the argv of a shell or code interpreter.
//
// Every non-option operand is a candidate program: `bash -x P`, `sh -s P`,
// `bash -o pipefail P` all run P, and a flag table that knows which flags
// take a value is the trap #3797 hit. The over-approximation — `python3
// process.py DATA` marks DATA too — only ever withdraws a label, which
// fails closed; a data file whose contents match a BLOCK rule and is then
// handed to a script is the one accepted FP shape (measured, stated in
// #3800's PR).
//
// The options that mean "the program is NOT a file operand" are the #3797
// set, per executor: c for everyone (inline source), and e / m for code
// interpreters only (inline code, module). Past one of those the remaining
// words are that program's argv, not files to run — `python3 -m json.tool
// P` formats P. A SHELL's -c string is shell source, so it is walked with
// this same collector: `bash -c 'bash P'` runs P exactly as the bare form
// would. Short options bundle — `bash -ec '...'` is `-e -c` — so the letter
// is looked for inside the cluster, not matched as a whole token (Codex,
// #3800 review pass 2). `--` ends option processing: `bash -- -c` runs a
// file named -c.
func (c *pathCollector) collectInterpreterOperands(name string, args []string, depth int) {
	shell := IsShellInterpreter(name)
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			for _, rest := range args[i+1:] {
				if p, ok := normalizePathKey(rest); ok {
					c.executed[p] = true
				}
			}
			return
		}
		if shell {
			// A SHELL's options bundle (`-ec` is `-e -c`), and a missed
			// `-c` walk fails OPEN — the string after it is a program this
			// collector would never see. So the letter is looked for
			// inside the cluster.
			if isShortOptionCluster(w) {
				if strings.ContainsRune(w[1:], 'c') {
					if i+1 < len(args) && depth < maxInlineDepth {
						if inner := parseBashFile(args[i+1]); inner != nil {
							c.collectFile(inner, depth+1)
						}
					}
					return
				}
				continue
			}
		} else if w == "-c" || w == "-e" || w == "-m" {
			// A CODE interpreter's inline-code flags are matched as exact
			// tokens and never as clusters, and the asymmetry is the point
			// (Codex, #3800 review pass 5): an attached option VALUE
			// (`python3 -Wignore x.py`, `perl -Mstrict x.pl`) reads as a
			// cluster containing e or m, and stopping there fails OPEN —
			// the script is never recorded. Missing a bundled `-uc` only
			// over-records that program's argv as candidate paths, which
			// fails closed. Past an exact -c/-e/-m the remaining words
			// are that program's argv, not files to run.
			return
		}
		if strings.HasPrefix(w, "-") {
			continue // any other option, an attached value, or a lone "-" (stdin)
		}
		if p, ok := normalizePathKey(w); ok {
			c.executed[p] = true
		}
	}
}

// isFdOperand reports whether w names a file descriptor rather than a file
// in a `>&word` redirect: bare digits, or `-` (close).
func isFdOperand(w string) bool {
	if w == "-" {
		return true
	}
	if w == "" {
		return false
	}
	for _, r := range w {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isShortOptionCluster reports whether w is `-` followed by one or more
// option letters (`-c`, `-ec`, `-xeu`), as opposed to a long option, a
// lone `-`, or an operand.
func isShortOptionCluster(w string) bool {
	if len(w) < 2 || w[0] != '-' || w[1] == '-' {
		return false
	}
	for _, r := range w[1:] {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// firstOperand returns the first word that is not an option: `--` ends
// option processing and the word after it is an operand even if it starts
// with a dash.
func firstOperand(words []string) string {
	for i, w := range words {
		if w == "--" {
			if i+1 < len(words) {
				return words[i+1]
			}
			return ""
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		return w
	}
	return ""
}

// recordCommandWord marks a slash-bearing command word as an executed path.
func (c *pathCollector) recordCommandWord(w string) {
	if !strings.Contains(w, "/") {
		return
	}
	if p, ok := normalizePathKey(w); ok {
		c.executed[p] = true
	}
}

// callWordsDequoted returns call's argv with each word reduced to its static
// value where it has one (quotes removed, ANSI-C escapes decoded) or its
// source text where it does not. Exec wrappers are NOT stripped here: the
// caller peels them one hop at a time so a slash-bearing wrapper path is
// recorded before it disappears.
func callWordsDequoted(call *syntax.CallExpr) []string {
	if call == nil || len(call.Args) == 0 {
		return nil
	}
	words := make([]string, len(call.Args))
	for i, a := range call.Args {
		words[i] = payloadValue(WordToString(a))
	}
	return words
}

func pathKey(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	return normalizePathKey(payloadValue(WordToString(w)))
}

// normalizePathKey returns the comparison key for a path operand. path.Clean
// folds `./x.sh` and `x.sh` together and `/tmp//x.sh` with `/tmp/x.sh`; it
// leaves an expansion's source text intact, which is the intended
// "identical unknowns are the same file" reading. Empty words, `-` (tee's
// stdout) and /dev/null carry no file.
func normalizePathKey(w string) (string, bool) {
	w = strings.TrimSpace(w)
	if w == "" || w == "-" {
		return "", false
	}
	// `${D}/x.sh` and `$D/x.sh` are one unknown, not two: the design says
	// identical unknowns are the same file, and the brace is spelling, not
	// value (Kai, #3800 review). Only the bare-name form is folded — `${D:-x}`,
	// `${D#…}` and every other operator change the value and stay as written.
	w = simpleBraceParam.ReplaceAllString(w, "$$$1")
	p := path.Clean(w)
	if p == "." || p == "/dev/null" {
		return "", false
	}
	return p, true
}
