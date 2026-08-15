package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestIFSSeparatorParity is the fitness function for issue #3044
// (taxonomy: unauthorized-execution/agentic-attacks/pre-expansion-command-guard-bypass),
// in the same shape as TestCompoundWrappingParity (#3045),
// TestLineContinuationParity (#3055) and TestExecWrapperParity (#3057).
//
// The invariant: $IFS defaults to space/tab/newline in every POSIX shell, so
// swapping a literal space for an unquoted ${IFS} reference does not change
// WHICH command runs — `rm${IFS}-rf${IFS}/` is exactly as destructive as
// `rm -rf /`. A guard that matches pre-expansion text sees no whitespace in
// the source and silently stops matching.
//
// This had to be measured corpus-wide to be seen at all, the same way #3045
// and #3055 were: nothing failed, nothing was logged. Before the fix
// (internal/shellparse/ifs_normalize.go, wired into shellparse.Parse for
// every AST-based analyzer and into RegexAnalyzer/SubstitutionAnalyzer's
// text-matching candidates), swapping the FIRST space of every BLOCKing
// corpus command for ${IFS} downgraded 1,657 of 2,414 commands (68.6%) — the
// largest single bypass class found in this codebase, well past the 20.8%
// compound-wrapping gap (#3045) and the 52.5% line-continuation gap (#3055).
func TestIFSSeparatorParity(t *testing.T) {
	t.Parallel()
	// Zero leaks at both probed positions. Getting there took three fixes
	// beyond the base shellparse.Parse canonicalization: RegexAnalyzer and
	// SubstitutionAnalyzer needed their own IFS-normalized text candidates
	// (they match/re-parse raw text independently of ctx.Parsed);
	// SemanticAnalyzer's built-in Go checks needed the same, since several
	// (e.g. sem-block-pip-config-index) match via strings.Contains(raw, ...)
	// rather than through the AST; and NormalizeIFS itself needed a trailing
	// TrimSpace, since a substitution at the very start of a statement
	// ("...;${IFS}dd ..." after a ";") produced a leading space that
	// defeated every "^"-anchored regex. See internal/shellparse/ifs_normalize.go
	// and its call sites in regex.go/substitution.go/semantic.go.
	const maxLeaks = 0

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	positions := []struct {
		name string
		n    int // substitute the nth space (1-based)
	}{
		{"first-space", 1},
		{"second-space", 2},
	}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local.
	engine, baseline := blockingBaseline(t)

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			tried := 0
			for _, tc := range baseline {
				substituted, ok := ifsAtSpace(tc.Command, p.n)
				if !ok {
					continue
				}
				tried++
				got := string(engine.Evaluate(substituted, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, substituted))
				}
			}

			if len(leaks) > maxLeaks {
				t.Errorf("substituting ${IFS} for the %s lowered the decision for %d/%d commands (budget %d).\n"+
					"$IFS defaults to whitespace — swapping it in must never weaken enforcement (see #3044).\n%s",
					p.name, len(leaks), tried, maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), tried, maxLeaks)
		})
	}
}

// ifsAtSpace replaces the nth UNQUOTED space on the first line of cmd with
// "${IFS}", the documented pattern-guard bypass that swaps a literal
// separator for the shell's default word-splitting variable. Reports false
// when there is no such space, or when the substitution doesn't round-trip
// to valid, equivalent shell — not every space position is a legal swap. Two
// guards, mirroring the same honesty requirement continueAtSpace applies to
// line continuation:
//
//   - Heredoc delimiters are matched as literal text, never expanded, so a
//     space immediately before one ("<< 'EOF'") is a DIFFERENT terminator
//     once swapped, not an equivalent rewrite. Skipped explicitly.
//   - Reserved-word boundaries ("function name", "if cmd", ...) and some
//     operator-adjacent gaps aren't lexically valid with $IFS glued on
//     (`function${IFS}sudo` is a syntax error in real bash, verified with
//     `bash -n`) — mvdan.cc/sh rejects the same shapes real bash does, so
//     re-parsing the candidate and requiring success catches these without
//     having to enumerate every reserved word by hand.
func ifsAtSpace(cmd string, n int) (string, bool) {
	var inSingle, inDouble bool
	seen := 0
	for i := 0; i < len(cmd); i++ {
		switch c := cmd[i]; {
		case c == '\n':
			return "", false // heredoc bodies and later lines are out of scope
		case c == '\\' && !inSingle:
			i++ // escaped character, never a separator
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ' ' && !inSingle && !inDouble:
			if seen++; seen != n {
				continue
			}
			if i >= 2 && cmd[i-2:i] == "<<" {
				return "", false // heredoc delimiter boundary — not equivalent
			}
			if prefixWordBoundary(cmd, i) {
				return "", false // assignment/negation prefix gap — not equivalent
			}
			candidate := cmd[:i] + "${IFS}" + cmd[i+1:]
			if !parsesAsShell(candidate) {
				return "", false
			}
			return candidate, true
		}
	}
	return "", false
}

func parsesAsShell(cmd string) bool {
	_, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	return err == nil
}

// prefixWordBoundary reports whether the space at cmd[i] immediately follows
// a leading env-assignment ("LC_ALL=C") or "!" negation token. Gluing that
// token to what follows via ${IFS} doesn't leave the command equivalent: an
// assignment's value can itself contain a ParamExp, so "LC_ALL=C${IFS}dd"
// parses as ONE assignment (LC_ALL="C<IFS-value>dd") with no command at all,
// not "LC_ALL=C dd" (verified with `bash -c 'set -x; ...'` — the "dd" is
// swallowed into the assignment value and never runs). parsesAsShell alone
// can't catch this, the same way it can't catch the heredoc-delimiter case:
// both stay syntactically valid while meaning something else entirely.
func prefixWordBoundary(cmd string, i int) bool {
	start := strings.LastIndexByte(cmd[:i], ' ') + 1 // 0 if no earlier space
	word := cmd[start:i]
	return word == "!" || strings.Contains(word, "=")
}
