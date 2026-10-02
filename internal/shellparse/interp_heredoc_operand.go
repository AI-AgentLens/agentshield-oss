package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// interpreterHeredocExecName is exactly the exec-name set the
// InInterpreterHeredoc label (internal/analyzer/intent.go's interpHered
// regex) can grant an excuse to. Kept as its own list, not a reuse of
// shellparse.CodeInterpreters, because that map also carries python2, lua
// and tclsh — names the regex does not recognize (a discrepancy pre-dating
// this fix, tracked separately) — and widening this list without widening
// the regex (or vice versa) would be a silent no-op: the withdrawal check
// would run against a statement Classify never labelled in the first place.
var interpreterHeredocExecName = map[string]bool{
	"python": true, "python3": true,
	"node": true, "ruby": true, "perl": true, "php": true,
	"Rscript": true, "osascript": true,
}

// InterpreterOperandDefeatsHereString reports whether command contains a
// non-shell-interpreter statement (python3/node/ruby/perl/php/Rscript/
// osascript) that redirects a HERE-STRING (<<<, syntax.WordHdoc only) while
// also being given an operand that makes the interpreter NOT read its
// program from stdin — a script-file path, or the value of a flag that
// carries the program inline (-c/-e/-m ...). Either way the interpreter
// never consumes the here-string as source, so it is inert filler bash still
// sets up (#3970, one shape of the InInterpreterHeredoc twin of #3964's cat
// fix) — `python3 backup.py -c ~/.ssh/id_rsa <<< x` runs backup.py with
// argv ["-c", "~/.ssh/id_rsa"]; python3 itself never looks at stdin, and
// "-c"/"~/.ssh/id_rsa" are backup.py's own arguments, not python's.
//
// # Scoped to here-strings only — NOT <<//<<- heredocs
//
// A multi-line heredoc body is left alone on purpose, even with the same
// operand present (`python3 script.py <<'PY' … PY`): ts-block-authorized-
// keys-write's own FP-fix (#3540) deliberately excuses that exact shape,
// because the body is genuinely SOURCE-CODE TEXT — a shell-command-shaped
// string sitting inside a `s = "curl … > authorized_keys"` assignment is a
// Python string literal, not a command, regardless of whether python3 reads
// it from stdin or backup.py reads it from disk via a totally different
// path. Withdrawing InInterpreterHeredoc there re-opened that FP (measured:
// TestRuleYAMLTests' ATTESTED case for that rule started firing at BLOCK
// instead of downgrading to AUDIT the first time this fix covered <</<<-).
//
// A here-string carries no such "this is a separate source file's body"
// reading: `<<< x` is one inline token glued to the SAME line as the
// interpreter invocation, textually indistinguishable in kind from an
// ordinary argv word — which is exactly what #3970's own reproduction
// exploits (the sensitive text sits in argv, not after any body delimiter).
// So only syntax.WordHdoc is inspected here; syntax.Hdoc/DashHdoc redirects
// are skipped entirely, leaving the established heredoc-body behavior
// unchanged.
//
// Residual, left open on purpose: the identical argv-vs-body confusion for
// a REAL heredoc with an operand present (`python3 script.py -c SECRET
// <<EOF … EOF`, sensitive text in argv) is not covered by this function —
// closing it needs match-position tracking (does the rule's own match fall
// before or after the heredoc delimiter), not a syntax.Hdoc case added here.
// TestDocTextDowngradeCannotBeLaundered's here-string-suffix channel (the
// only channel #3970 was measured against) does not probe that shape either.
//
// Unlike cat, these interpreters have value-taking flags (-c CODE, -m
// MODULE, -e EXPR, ...) whose VALUE is itself a non-flag token — but that
// value being present is exactly as much evidence the interpreter isn't
// reading its program from stdin as a bare script path is, so the same
// "first non-flag token found = withdraw" walk cat's fix uses applies here
// unchanged: it never needs to know which flags take values, because a
// value token looks like an operand and implies the same thing either way.
// A flag with no separate value token (`-u`, `--version`, `-Mstrict`) still
// starts with `-` and is skipped, so `python3 -u <<< x` (no operand at all)
// is unaffected — that invocation genuinely reads its program from stdin.
//
// A dynamic operand (`python3 "$F" <<< x`) cannot be proven to be `-`, so it
// is conservatively treated as an operand — the caller withdraws the
// inertness label rather than assume the read is safe, same posture as
// CatReadsFileOperandInsteadOfHeredoc.
func InterpreterOperandDefeatsHereString(command string) bool {
	if !strings.Contains(command, "<<<") {
		return false
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}

	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		st, ok := node.(*syntax.Stmt)
		if !ok || len(st.Redirs) == 0 {
			return true
		}
		ce, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}

		hasHereString := false
		for _, r := range st.Redirs {
			if r == nil {
				continue
			}
			if r.Op == syntax.WordHdoc {
				hasHereString = true
			}
		}
		if !hasHereString {
			return true
		}

		words := make([]string, len(ce.Args))
		for i, a := range ce.Args {
			words[i] = WordToString(a)
		}
		stripped := StripExecWrappers(words)
		if len(stripped) == 0 {
			return true
		}
		offset := len(words) - len(stripped)
		exe := staticWord(ce.Args[offset])
		if exe == "" || !interpreterHeredocExecName[path.Base(NormalizeExecName(exe))] {
			return true
		}

		for _, arg := range ce.Args[offset+1:] {
			w := staticWord(arg)
			if w == "-" || (w != "" && strings.HasPrefix(w, "-")) {
				continue // stdin marker, or a boolean/attached-value interpreter flag
			}
			// A script-file operand, or the value of a code-carrying flag
			// (-c/-e/-m/...) — either way the interpreter is not reading the
			// here-string as its program.
			found = true
			return false
		}
		return true
	})
	return found
}
