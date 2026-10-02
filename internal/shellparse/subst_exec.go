package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ExecutedSubstitutionBodies returns the source text of every command or
// process substitution whose OUTPUT the command runs as a program:
//
//   - the program argument of a shell's -c (or an option cluster carrying c),
//     or of a code interpreter's exact -c / -e: `bash -c "$(…)"`;
//   - any argument of eval: `eval "$(…)"`;
//   - a process substitution as the script operand of a shell or interpreter,
//     or of source / `.`: `bash <(…)`, `source <(…)`;
//   - a here-string fed to a shell or interpreter that takes its program from
//     stdin: `bash <<< "$(…)"`;
//   - a substitution in the command word itself: `"$(…)" args` runs the
//     output as a command;
//   - any of the above reached through a variable captured from a
//     substitution in the same command: `x=$(…); eval "$x"`, `bash -c "$x"`,
//     `$x`. Plain assignments and export/local/declare/readonly/typeset only.
//
// # Why (#3976)
//
// A substitution body always RUNS (SubstitutionBodies, #3814), but what it
// runs may be `cat` of inert text: `echo "$(cat <<'EOF' … EOF)"` prints a
// note. Whether the heredoc text itself executes depends on where the
// substitution's output goes, which is the question this answers. The
// inertness LABELS never needed it, because they are judged per statement
// and `bash -c …` is not doc-text-shaped. The command_position_exclude
// data-text positions (heredoc_body, quoted_program_arg,
// interp_heredoc_literal) find their item anywhere in the command, so
// without this `bash -c "$(cat <<'EOF' <payload> EOF)"` stayed excused
// while the label twin of the same rule blocked.
//
// # What it deliberately does not claim
//
// Only positive evidence. A dynamic program (`bash -c "$cmd"`) carries no
// substitution and yields nothing. A process substitution passed as a
// later argument (`python3 x.py <(…)`) is that script's data, not its
// program. Options that take a separate value (`bash -o pipefail <(…)`)
// can misplace the operand and yield nothing, which leaves today's
// behaviour in place rather than guessing.
func ExecutedSubstitutionBodies(command string) []string {
	if !strings.ContainsAny(command, "$`<") {
		return nil
	}
	src := ifsNormalized(command)
	file := parseBashFile(src)
	if file == nil {
		return nil
	}
	captured := capturedSubstitutions(file)
	var out []string
	seen := map[string]bool{}
	var add func(n syntax.Node)
	add = func(n syntax.Node) {
		for _, b := range substitutionBodiesIn(n, src) {
			if !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
		// `eval "$x"` where x=$(…): the captured substitution's output runs.
		syntax.Walk(n, func(node syntax.Node) bool {
			if pe, ok := node.(*syntax.ParamExp); ok && pe.Param != nil {
				if v, ok := captured[pe.Param.Value]; ok {
					delete(captured, pe.Param.Value) // x=$x-style cycles cannot recurse
					add(v)
				}
			}
			return true
		})
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				collectExecutedSubstitutions(stmt, call, add, captured)
			}
		}
		return true // nested statements inside substitutions are walked too
	})
	return out
}

func collectExecutedSubstitutions(stmt *syntax.Stmt, call *syntax.CallExpr, add func(syntax.Node), captured map[string]*syntax.Word) {
	words := make([]string, len(call.Args))
	for i, a := range call.Args {
		words[i] = WordToString(a)
	}
	// StripExecWrappers returns a suffix, so the real command's index is
	// the number of words it peeled.
	k := len(words) - len(StripExecWrappers(words))
	if k < 0 || k >= len(call.Args) {
		return
	}
	if wordHasSubstitution(call.Args[k]) || wordRefsCaptured(call.Args[k], captured) {
		add(call.Args[k])
		return
	}
	name := path.Base(NormalizeExecName(words[k]))
	args, argWords := call.Args[k+1:], words[k+1:]
	switch {
	case name == "eval":
		for _, a := range args {
			add(a)
		}
	case name == "source" || name == ".":
		if i := firstOperandIndex(argWords); i >= 0 && wordIsProcessSubstitution(args[i]) {
			add(args[i])
		}
	case IsShellOrInterpreter(name):
		shell := IsShellInterpreter(name)
		for i, w := range argWords {
			if w == "--" {
				break
			}
			if isInlineProgramFlag(w, shell) {
				if i+1 < len(args) {
					add(args[i+1])
				}
				return // the program is inline; stdin and operands are its data
			}
		}
		if i := firstOperandIndex(argWords); i >= 0 && wordIsProcessSubstitution(args[i]) {
			add(args[i])
		}
		for _, r := range stmt.Redirs {
			if r.Op == syntax.WordHdoc && r.Word != nil {
				add(r.Word)
			}
		}
	}
}

// isInlineProgramFlag mirrors collectInterpreterOperands: a shell's options
// bundle (`-ec` is `-e -c`), a code interpreter's inline-code flags are exact
// tokens (`python3 -Wignore` is an attached value, not -W -i ...).
func isInlineProgramFlag(w string, shell bool) bool {
	if shell {
		return w == "-c" || (isShortOptionCluster(w) && strings.ContainsRune(w[1:], 'c'))
	}
	return w == "-c" || w == "-e"
}

// firstOperandIndex is firstOperand's index form.
func firstOperandIndex(words []string) int {
	for i, w := range words {
		if w == "--" {
			if i+1 < len(words) {
				return i + 1
			}
			return -1
		}
		if strings.HasPrefix(w, "-") {
			continue
		}
		return i
	}
	return -1
}

// capturedSubstitutions maps each variable assigned a value that contains a
// command or process substitution to that value. Attributed to the whole
// command, like the rest of this file: `x=$(…)` anywhere and `eval "$x"`
// anywhere is positive evidence enough.
func capturedSubstitutions(file *syntax.File) map[string]*syntax.Word {
	captured := map[string]*syntax.Word{}
	record := func(as []*syntax.Assign) {
		for _, a := range as {
			if a != nil && a.Name != nil && a.Value != nil && wordHasSubstitution(a.Value) {
				captured[a.Name.Value] = a.Value
			}
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				record(n.Assigns)
			}
		case *syntax.DeclClause:
			record(n.Args)
		}
		return true
	})
	return captured
}

func wordRefsCaptured(w *syntax.Word, captured map[string]*syntax.Word) bool {
	found := false
	syntax.Walk(w, func(n syntax.Node) bool {
		if pe, ok := n.(*syntax.ParamExp); ok && pe.Param != nil && captured[pe.Param.Value] != nil {
			found = true
		}
		return !found
	})
	return found
}

func wordHasSubstitution(w *syntax.Word) bool {
	found := false
	syntax.Walk(w, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
		}
		return !found
	})
	return found
}

func wordIsProcessSubstitution(w *syntax.Word) bool {
	if len(w.Parts) != 1 {
		return false
	}
	_, ok := w.Parts[0].(*syntax.ProcSubst)
	return ok
}

// substitutionBodiesIn is SubstitutionBodies scoped to one node: the source
// text inside every outermost substitution under n.
func substitutionBodiesIn(n syntax.Node, src string) []string {
	var bodies []string
	syntax.Walk(n, func(node syntax.Node) bool {
		switch s := node.(type) {
		case *syntax.CmdSubst:
			open := 2
			if s.Backquotes {
				open = 1
			}
			if b, ok := sliceBody(src, int(s.Left.Offset())+open, int(s.Right.Offset())); ok {
				bodies = append(bodies, b)
			}
			return false
		case *syntax.ProcSubst:
			if b, ok := sliceBody(src, int(s.OpPos.Offset())+2, int(s.Rparen.Offset())); ok {
				bodies = append(bodies, b)
			}
			return false
		}
		return true
	})
	return bodies
}
