package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ExecutedText returns text inside command that a shell will run as a
// program of its own, so a rule can be retried against it as a command:
//
//   - the text an echo / printf / cat-heredoc statement emits, when the
//     command hands that text to an executor (a pipe into a shell or
//     interpreter, or a write to a path the command then executes — the
//     TextReachesExecutor evidence #3796/#3800 established);
//   - the body of every command or process substitution, which executes
//     unconditionally;
//   - the text an echo / printf / tee / cat-heredoc statement INSIDE a
//     substitution emits, when the substitution's OUTPUT is itself run
//     (`bash -c "$(cat <<'EOF' … EOF)"`, `eval "$(…)"`, `bash <(…)`,
//     `x=$(…); eval "$x"` — ExecutedSubstitutionBodies' evidence, #3976;
//     #3979).
//
// # Why (#3938)
//
// The inertness-label withdrawals (#3797 pipe, #3801 write-then-execute,
// #3928 substitution) only ever act on a rule that has ALREADY matched the
// raw text. A leading-anchor alternation — `(?:^|[\s;&|])install`,
// `(?:^|[|&;`]|\bsudo\s+)install` — lists every separator but a quote, so
// inside `echo 'install -m 4755 x y' | bash` the payload never matches:
// the character before it is `'`. No match, nothing to withdraw, BLOCK
// becomes AUDIT naming no rule. Measured on 2026-09-20: 291 of 1839
// fitness probes, 78 BLOCK rules (TestDocTextDowngradeCannotBeLaundered).
//
// Retrying the emitted text as a command is #3057's "^ means start of a
// command" applied to text the shell executes rather than text it parses,
// and #3928's re-attribution of a substitution body applied to matching
// rather than labelling. One candidate list closes the class for every
// rule; editing 78 anchors would close it for 78.
//
// # Why the executor gate for emitted text and none for substitutions
//
// `echo 'install -m 4755 x y'` alone prints; the same text piped into bash
// runs. The gate is the evidence that distinguishes them, and it is the
// same predicate DecodeEmittedSeparators uses, for the same reason. A
// substitution body needs no gate: `$(...)` runs by definition, in a commit
// message as surely as at top level.
//
// # What it returns, and what it refuses
//
// Only statically known text: `echo "$x" | bash` carries an unknown program
// and yields nothing. Parse failure yields nil — a candidate is only ever an
// ADDITIONAL match, so refusing costs a miss while guessing costs a wrong
// enforcement. Results are deduplicated and never include the empty string.
func ExecutedText(command string) []string {
	out, _ := ExecutedTextReport(command)
	return out
}

// ExecutedTextReport is ExecutedText plus the number of distinct emitted
// texts that reach an executor and were refused because they carried an
// unexpanded `$` or backquote — the program the shell will run is not the
// text written here, so there was nothing static to retry. The count is an
// attestation input (#3995, analyzer.NoteExecutedTextUnresolved): a caller
// that retried nothing can say whether that is because nothing was emitted
// or because what was emitted could not be resolved.
//
// The count is per statement, not per command: the candidate texts are
// gated on the WHOLE command reaching an executor (unchanged, so no decision
// moves), but a status line such as `echo "done $x"` next to `echo ls | bash`
// reaches nothing and must not be counted (Opus review of #4005: 12 of 43
// real-traffic notes were wholly false under the coarse gate, and a text
// visited by both passes was counted twice). A statement counts when it
// pipes into an executor itself or writes a path the command later
// executes; substitution output that runs counts through the second pass.
// A parse failure reports nil, 0 — the parser's own fallback is recorded
// elsewhere (analyzer.NoteParseFallback).
func ExecutedTextReport(command string) (texts []string, unresolved int) {
	if !strings.ContainsAny(command, "'\"$`<>|") {
		return nil, 0
	}
	file := parseBashFile(command)
	if file == nil {
		return nil, 0
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	unresolvedSeen := map[string]bool{}
	countUnresolved := func(stmt *syntax.Stmt) {
		if text, ok := stmtEmittedText(stmt); ok && strings.ContainsAny(text, "$`") {
			unresolvedSeen[text] = true
		}
	}

	// addEmitted adds the program an emitting statement hands on.
	addEmitted := func(stmt *syntax.Stmt) {
		// An unexpanded `$` or backquote means the program the shell
		// receives is not the text written here (`echo "$x" | bash`),
		// so there is nothing static to retry against. Conservative:
		// `echo 'x=$HOME' | bash` is dropped too — a miss, not a wrong
		// enforcement, and the substitution walk below still sees any
		// `$(...)` that is a real CmdSubst node.
		text, ok := stmtEmittedText(stmt)
		if !ok || strings.ContainsAny(text, "$`") {
			return
		}
		add(text)
		// `printf '\nrm -rf /' | sh` and `echo -e '\nrm -rf /' | bash` hand
		// the executor a newline, not a backslash and an n. Decode the
		// separator escapes in the program's own dialect (#3802's
		// decodeSeparatorEscapes, same restriction to whitespace/control
		// characters) so the candidate is the text the shell receives.
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if _, style := emittedEscapeWords(call); style != octalNone {
				if decoded, changed := decodeSeparatorEscapes(text, style); changed {
					add(decoded)
				}
			}
		}
	}

	reach := AnalyzeTextReach(command)
	if reach.PipesIntoExecutor || len(reach.Correlated) > 0 {
		syntax.Walk(file, func(node syntax.Node) bool {
			if stmt, ok := node.(*syntax.Stmt); ok {
				addEmitted(stmt)
			}
			return true
		})
		// Per-statement count: only a statement that itself pipes into an
		// executor, or writes a path the command later executes, has handed
		// its unresolved text to anything.
		for _, s := range SplitSequencedStatements(command) {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !AnalyzeTextReach(s).PipesIntoExecutor && !StatementWritesAny(s, reach.Correlated) {
				continue
			}
			sf := parseBashFile(s)
			if sf == nil {
				continue
			}
			syntax.Walk(sf, func(node syntax.Node) bool {
				if stmt, ok := node.(*syntax.Stmt); ok {
					countUnresolved(stmt)
				}
				return true
			})
		}
	}
	for _, stmt := range SplitSequencedStatements(command) {
		for _, body := range SubstitutionBodies(stmt) {
			add(body)
		}
	}
	// A substitution whose OUTPUT runs (#3979, on #3976's ExecutedSubstitutionBodies):
	// the body is `cat <<'EOF' … EOF`, and what executes is the heredoc
	// text, not the cat. The body itself is already a candidate above, but
	// retried as a command it starts with `cat`, so a rule anchored on the
	// payload's first word — `^(?:sudo\s+)?frida\b…` — never matched, and
	// `bash -c "$(cat <<'EOF'\nfrida -n chrome\nEOF\n)"` went BLOCK→AUDIT
	// naming no rule while the same heredoc piped into bash BLOCKed. The
	// position withdrawal #3976 added had nothing to act on: no match.
	for _, body := range ExecutedSubstitutionBodies(command) {
		bodyFile := parseBashFile(body)
		if bodyFile == nil {
			continue
		}
		for _, stmt := range bodyFile.Stmts {
			visitSubstitutionOutput(stmt, func(s *syntax.Stmt) {
				addEmitted(s)
				countUnresolved(s)
			})
		}
	}
	return out, len(unresolvedSeen)
}

// visitSubstitutionOutput calls emit for every emitting statement whose
// standard output IS the substitution's output — the text the enclosing
// eval / bash -c / bash <(…) runs. Only positive evidence counts, because a
// candidate that is not executed could only ever add a wrong enforcement:
//
//   - a statement whose stdout is redirected away (`> f`, `>> f`, `&> f`,
//     `>| f`, `>&2`) contributes nothing;
//   - in a pipeline only the LAST stage writes to the substitution
//     (`cat <<'EOF' | sed …` runs sed's output, not the heredoc);
//   - `;`, `&&`, `||`, `{ … }` and `( … )` are descended — each member
//     writes to the same stdout, and a conditional member is treated like a
//     top-level conditional statement, which the rules already match;
//   - other compound commands (if / for / while / case) and nested
//     substitutions are not descended: a nested `$(…)`'s output is captured
//     by ITS word, not written to this stdout;
//   - the emitter must be echo, printf, tee, or a cat reading only its
//     stdin — `cat notes.txt <<'EOF'` prints notes.txt, and `python3 -
//     <<'PY'` runs the heredoc rather than printing it.
func visitSubstitutionOutput(stmt *syntax.Stmt, emit func(*syntax.Stmt)) {
	if stmt == nil || stdoutRedirectedAway(stmt) {
		return
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if emitsItsTextToStdout(cmd) {
			emit(stmt)
		}
	case *syntax.BinaryCmd:
		if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
			visitSubstitutionOutput(cmd.Y, emit)
			return
		}
		visitSubstitutionOutput(cmd.X, emit)
		visitSubstitutionOutput(cmd.Y, emit)
	case *syntax.Block:
		for _, s := range cmd.Stmts {
			visitSubstitutionOutput(s, emit)
		}
	case *syntax.Subshell:
		for _, s := range cmd.Stmts {
			visitSubstitutionOutput(s, emit)
		}
	}
}

// stdoutRedirectedAway reports whether stmt sends its standard output
// somewhere other than the stdout it inherited.
func stdoutRedirectedAway(stmt *syntax.Stmt) bool {
	for _, r := range stmt.Redirs {
		if r.N != nil && r.N.Value != "1" {
			continue // 2> f, 3> f: not stdout
		}
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.DplOut, syntax.RdrClob,
			syntax.AppClob, syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll,
			syntax.AppAllClob:
			return true
		}
	}
	return false
}

// emitsItsTextToStdout reports whether call prints the text
// stmtEmittedText would attribute to it: echo and printf print their
// arguments, tee copies its stdin (the heredoc) to stdout whatever files it
// also writes, and cat copies its stdin only with no file operand and no
// option that rewrites the text.
func emitsItsTextToStdout(call *syntax.CallExpr) bool {
	words := peelExecWrappers(callWordsDequoted(call))
	if len(words) == 0 {
		return false
	}
	switch path.Base(NormalizeExecName(words[0])) {
	case "echo", "printf", "tee":
		return true
	case "cat":
		// Only a verbatim copy of stdin: a file operand prints the file,
		// and -n / -A / -v and kin rewrite the text the executor receives.
		for _, w := range words[1:] {
			if w != "-" && w != "--" && w != "-u" {
				return false
			}
		}
		return true
	}
	return false
}
