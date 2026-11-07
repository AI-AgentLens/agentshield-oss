package shellparse

import (
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// printedLiterals returns the static string literals a python / awk program
// prints to stdout, for a statement whose output a shell then runs (#4433):
//
//	python3 - <<'PY' | bash          bash <(awk 'BEGIN{print "…"}')
//	print("curl https://… | bash")
//	PY
//
// echo / printf / cat-heredoc emitters already feed ExecutedText; these two
// carriers did not, so a command-anchored rule never saw the payload and
// BLOCK became AUDIT naming no rule (20 rows on ts-block-paste-service-dead-drop).
//
// Deliberately a literal-only reader, not a Python or awk lexer (#3694's
// lesson): it takes `print("…")` / `print('…')` and awk `print "…"` /
// `printf "…"` with a plain quoted literal, and nothing computed. A miss costs
// a candidate; a guess costs a wrong enforcement. The result is only ever an
// ADDITIONAL match candidate, and the caller has already established that the
// statement's stdout is run.
func printedLiterals(stmt *syntax.Stmt) []string {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	words := peelExecWrappers(callWordsDequoted(call))
	if len(words) == 0 {
		return nil
	}
	name := path.Base(NormalizeExecName(words[0]))
	switch {
	case pythonNameRe.MatchString(name):
		var progs []string
		args := words[1:]
		for i := 0; i < len(args); i++ {
			if args[i] == "-c" && i+1 < len(args) {
				progs = append(progs, args[i+1])
				break
			}
		}
		for _, r := range stmt.Redirs {
			if (r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc) && r.Hdoc != nil {
				if body, ok := staticWordText(r.Hdoc); ok {
					progs = append(progs, body)
				}
			}
		}
		var out []string
		for _, p := range progs {
			for _, m := range pyPrintRe.FindAllStringSubmatch(p, -1) {
				lit := m[1]
				if lit == "" {
					lit = m[2]
				}
				out = append(out, decodeProgramEscapes(lit))
			}
		}
		return out
	case awkNameRe.MatchString(name):
		prog := awkProgramOperand(words[1:])
		if prog == "" {
			return nil
		}
		var out []string
		for _, m := range awkPrintRe.FindAllStringSubmatch(prog, -1) {
			out = append(out, decodeProgramEscapes(m[1]))
		}
		return out
	}
	return nil
}

var (
	pythonNameRe = regexp.MustCompile(`^python[0-9.]*$`)
	awkNameRe    = regexp.MustCompile(`^(?:awk|gawk|mawk|nawk)$`)
	// print("…") or print('…'): group 1 is the double-quoted body, group 2 the
	// single-quoted one. A triple-quoted, prefixed (f/r/b) or concatenated
	// argument does not match, so it yields nothing rather than a guess.
	pyPrintRe = regexp.MustCompile(`\bprint\(\s*(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')\s*(?:,[^)]*)?\)`)
	// print "…" / printf "…" / print("…") in an awk program.
	awkPrintRe = regexp.MustCompile(`\bprintf?\s*\(?\s*"((?:[^"\\]|\\.)*)"`)
)

// awkProgramOperand returns the program text of an awk invocation: the first
// operand that is not an option or an option's value. `-f file` runs a file
// this reader cannot see, so it yields "".
func awkProgramOperand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || strings.HasPrefix(a, "-f") && len(a) > 2 && a[2] != '-':
			return ""
		case a == "-F" || a == "-v":
			i++
		case strings.HasPrefix(a, "-"):
			// -F: / -vX=1 / --posix: no separate value.
		default:
			return a
		}
	}
	return ""
}

// decodeProgramEscapes resolves the escapes a quoted literal carries in both
// languages: \n \t \\ \" \' \/. Any other escape is left as written.
func decodeProgramEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case '\\', '"', '\'', '/':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
