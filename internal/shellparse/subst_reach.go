package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SubstitutionBodies returns the source text inside every OUTERMOST command
// substitution (`$(...)`, “ `...` “) and process substitution (`<(...)`,
// `>(...)`) in statement, in source order. Each body is a shell program the
// statement runs before, or while, doing whatever the statement itself
// does.
//
// # Why this exists (#3814)
//
// #3797 withdrew the inertness labels (is_doc_text, in_heredoc,
// in_interpreter_heredoc) when text is PIPED into an executor; #3800 when
// it is WRITTEN to a path the command then runs. Command substitution is a
// third route, and neither saw it: `echo "$(<payload>)"` is an echo, so the
// statement is doc-text-shaped, but the payload runs in a subshell and only
// its OUTPUT is echoed. Measured on main: a command_intent_downgrade rule
// dropped BLOCK -> AUDIT, and a command_intent_exclude rule dropped to
// REQUIRE_APPROVAL naming no rule at all.
//
// # Why the caller decides, not this function
//
// The label must go only when the rule's MATCH lies inside the
// substitution. `echo "note: <keyword> ($(date))"` is genuine documentation
// carrying a benign timestamp, and withdrawing on "a substitution exists
// somewhere in this statement" would BLOCK it. This function cannot know
// what a rule matched, so it hands back the bodies and intent.go's
// IntentExcludedForStatements applies the rule's own predicate to each — the
// same per-statement attribution discipline #3800 landed for written paths.
//
// # Heredoc delimiter quoting
//
// `<<EOF` (unquoted delimiter) expands the body the way a double-quoted
// string is expanded, so `$(...)` inside it runs; `<<'EOF'` keeps the body
// literal. mvdan/sh encodes that structurally: an unquoted body parses into
// Lit and CmdSubst parts, a quoted body is a single Lit. So a quoted body
// contributes nothing here and keeps its label, an unquoted one contributes
// its substitutions, and this function never has to inspect the delimiter
// (the same fact HeredocBodies relies on, #3730).
//
// # What does not count
//
// `${var}` parameter expansion and `$(( ))` arithmetic are ParamExp and
// ArithmExp nodes, not substitutions: nothing is executed. A `$(...)` in
// single quotes is a Lit. A substitution NESTED inside another is not
// returned separately — the outer body is returned whole, and the caller
// recurses into it as a command of its own, which is where the inner one is
// found. A `-c` string is not entered either: the carrier machinery
// (AttributionStatements) already hands its statements to the caller.
//
// Parse failure returns nil, for the reason PipesIntoExecutor gives:
// withdrawing an excuse takes evidence, and an unparseable blob is not
// evidence.
func SubstitutionBodies(statement string) []string {
	// Cheap prefilter: every shape this handles carries one of these
	// openers, and the AST parse is the expensive part. Callers run this
	// once per opted-in rule per labelled statement.
	if !strings.ContainsAny(statement, "$`<>") {
		return nil
	}
	src := ifsNormalized(statement)
	file := parseBashFile(src)
	if file == nil {
		return nil
	}
	var bodies []string
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CmdSubst:
			// `$(` is two bytes, a backquote one; Right is the closer.
			open := 2
			if n.Backquotes {
				open = 1
			}
			if b, ok := sliceBody(src, int(n.Left.Offset())+open, int(n.Right.Offset())); ok {
				bodies = append(bodies, b)
			}
			return false
		case *syntax.ProcSubst:
			// `<(` / `>(` are two bytes; Rparen is the closer.
			if b, ok := sliceBody(src, int(n.OpPos.Offset())+2, int(n.Rparen.Offset())); ok {
				bodies = append(bodies, b)
			}
			return false
		}
		return true
	})
	return bodies
}

// sliceBody returns src[from:to] trimmed, guarding the offsets the parser
// reports against the text actually parsed. An empty body (`$()`) carries
// no program.
func sliceBody(src string, from, to int) (string, bool) {
	if from < 0 || to > len(src) || from > to {
		return "", false
	}
	b := strings.TrimSpace(src[from:to])
	if b == "" {
		return "", false
	}
	return b, true
}
