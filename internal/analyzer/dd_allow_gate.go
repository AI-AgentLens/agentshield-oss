package analyzer

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ddCommandProvablySafe reports whether the WHOLE command is nothing but
// literal dd invocations writing to known-safe targets. st-allow-dd-to-file
// withholds its ALLOW unless this says yes (#3994).
//
// It walks the ORIGINAL shell AST and accepts an explicit set of node types,
// rejecting everything else. An earlier version checked the parser's derived
// segment model instead. Four Codex passes kept finding what that model does
// not carry: wrappers stripped before the check (env -C /dev, strace -o), a
// group's redirect lost when statements are merged across && or
// process substitution, and redirect targets never checked for expansion
// (2>"$OUT" inside a for loop). A walk over the source AST has no such blind
// spots. A construct it does not know is simply not accepted.
//
// Accepted:
//   - statements joined by ;, && or || (no pipes, no !, no &, no coproc);
//   - each command a call whose words are all plain literals (no quotes,
//     expansions, substitutions or backslashes), whose first word is dd or
//     sudo dd with no sudo options, with no environment assignments, no dash
//     options, and no glob, brace or tilde characters in any operand;
//   - each dd names at least one of=, and every of= is a known-safe target
//     (see ddTargetMayBeDevice);
//   - each redirect is either input from a literal file, or output to a
//     literal known-safe target (fd duplication such as 2>&1 included).
//
// Rejected, by not being accepted: groups, subshells, loops, conditionals,
// functions, command and process substitution, heredocs, here-strings, every
// execution wrapper, and anything the parser fails on. The failure mode is a
// withheld ALLOW, which leaves ts-block-dd-zero's own decision in place.
func ddCommandProvablySafe(raw, cwd string) bool {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(raw), "")
	if err != nil || len(file.Stmts) == 0 {
		return false
	}
	for _, st := range file.Stmts {
		if !ddSafeStmt(st, cwd) {
			return false
		}
	}
	return true
}

func ddSafeStmt(st *syntax.Stmt, cwd string) bool {
	if st == nil || st.Negated || st.Background || st.Coprocess {
		return false
	}
	for _, r := range st.Redirs {
		if !ddSafeRedirect(r, cwd) {
			return false
		}
	}
	switch c := st.Cmd.(type) {
	case *syntax.CallExpr:
		return ddSafeCall(c, cwd)
	case *syntax.BinaryCmd:
		if c.Op != syntax.AndStmt && c.Op != syntax.OrStmt {
			return false // pipes route stdout to the next stage
		}
		return ddSafeStmt(c.X, cwd) && ddSafeStmt(c.Y, cwd)
	default:
		return false
	}
}

func ddSafeCall(c *syntax.CallExpr, cwd string) bool {
	if len(c.Assigns) > 0 {
		return false
	}
	words := make([]string, 0, len(c.Args))
	for _, w := range c.Args {
		lit, ok := ddLiteralWord(w)
		if !ok {
			return false
		}
		words = append(words, lit)
	}
	if len(words) >= 2 && words[0] == "sudo" {
		words = words[1:]
	}
	if len(words) == 0 || words[0] != "dd" {
		return false
	}
	ofs := 0
	for _, w := range words[1:] {
		if strings.HasPrefix(w, "-") || strings.ContainsAny(w, "*?[]{}~") {
			return false
		}
		if strings.HasPrefix(w, "of=") {
			ofs++
			if ddTargetUnsafeInCwd(w[3:], cwd) {
				return false
			}
		}
	}
	return ofs > 0
}

// ddSafeRedirect accepts input from a literal file, and output to a literal
// known-safe target. Heredocs, here-strings, <> and every other form reject.
func ddSafeRedirect(r *syntax.Redirect, cwd string) bool {
	t, ok := ddLiteralWord(r.Word)
	if !ok {
		return false
	}
	switch r.Op {
	case syntax.RdrIn:
		return true
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		return !ddTargetUnsafeInCwd(t, cwd)
	case syntax.DplOut:
		// Only onto stdout, stderr or a close. Any other number duplicates a
		// descriptor this command never opened, which leads wherever the
		// parent left it (2>&4, Codex pass 5 on #3997). Stdout and stderr
		// themselves are the harness's, the one inherited destination
		// treated as trusted.
		return t == "1" || t == "2" || t == "-"
	default:
		return false
	}
}

// ddTargetUnsafeInCwd classifies a dd target after resolving a relative one
// against the command's working directory, when that is known. of=sda is a
// disk when the shell sits in /dev.
func ddTargetUnsafeInCwd(t, cwd string) bool {
	if cwd != "" && !path.IsAbs(t) && !strings.HasPrefix(t, "~") {
		t = path.Join(cwd, t)
	}
	return ddTargetMayBeDevice(t)
}

// ddLiteralWord returns the text of a word made of a single plain literal:
// no quoting, expansion, substitution or backslash escape.
func ddLiteralWord(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok || lit.Value == "" || strings.Contains(lit.Value, `\`) {
		return "", false
	}
	return lit.Value, true
}
