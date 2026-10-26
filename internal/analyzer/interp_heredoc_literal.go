package analyzer

import (
	"regexp"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// InterpHeredocLiteralPlaceholder is the text substituted for a redacted
// interpreter-heredoc string literal. Opaque and single-token for the same
// reason as the other position-exclusion placeholders (position.go): it
// must survive re-parsing as shell and match no shipped rule pattern.
const InterpHeredocLiteralPlaceholder = "INTERPHEREDOCLITERAL"

// pyTripleQuotedRe matches a Python triple-quoted string literal, DOTALL so
// it spans the multi-line body a doc-generation script commonly builds —
// the concrete shape #3809 was filed against: a `python3 -` heredoc
// building a markdown paragraph as a triple-quoted string and writing it to
// a file. The plain quotedLiteralRe (shared with interp_exec.go/
// interp_paths.go) does not understand triple quotes and would either miss a literal
// entirely or split it into bogus sub-matches at each internal quote
// character.
var pyTripleQuotedRe = regexp.MustCompile(`(?s)"""(?:\\.|[^\\])*?"""|'''(?:\\.|[^\\])*?'''`)

// interpHeredocLiteralLangs is the subset of shellparse.CodeInterpreters
// this function can reason about at all — exactly the languages
// interp_exec.go's own interpreterExecLiterals switch recognizes. lua, php,
// tclsh, osascript and Rscript are CodeInterpreters too (in_interpreter_heredoc
// applies to them), but this package has no exec-call detector for their
// syntax (os.execute, shell_exec, do shell script, system()), so offering
// this exclusion there would rest on "no recognized call was found" meaning
// nothing more than "this extractor never checked" — refuse rather than
// guess.
var interpHeredocLiteralLangs = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"node": true, "ruby": true, "perl": true,
}

// InertInterpreterHeredocLiterals redacts literals only in bodies accepted by
// both the historical exec-call check and the closed inert grammar. Unknown
// imports, calls or syntax withhold the exemption for the entire body.
//
// The old check and old span extraction are deliberately retained: new-inert
// implies old-inert, and every redacted byte must belong to BOTH the old
// regex spans and the comment-aware scanner's spans. Neither fixing lexical
// mistakes nor admitting a new inert construct can widen the old exemption.
// The shared quotedLiteralRe and its other callers are unchanged.
//
// Returns (nil, "") if no literal qualifies. The command-line purity gate
// separately withholds this position exclusion for later execution, live shell
// expansions, and other impure statements.
func InertInterpreterHeredocLiterals(command string) (items []string, redacted string) {
	if !strings.Contains(command, "<<") {
		return nil, ""
	}
	spans := shellparse.InterpreterHeredocLiteralSpans(command)
	if len(spans) == 0 {
		return nil, ""
	}

	type byteSpanAbs struct{ start, end int }
	var redact []byteSpanAbs
	for _, sp := range spans {
		if !interpHeredocLiteralLangs[sp.Lang] {
			continue
		}
		if sp.Start < 0 || sp.End > len(command) || sp.Start >= sp.End {
			continue
		}
		legacyBody := command[sp.Start:sp.End]
		body := command[sp.Start:sp.BodyEnd]
		if !legacyInterpHeredocExecFree(sp.Lang, legacyBody) || !interpHeredocExecFree(sp.Lang, body) {
			continue
		}
		for _, ls := range intersectInertLiteralSpans(sp.Lang, legacyBody, body) {
			redact = append(redact, byteSpanAbs{sp.Start + ls[0], sp.Start + ls[1]})
		}
	}
	if len(redact) == 0 {
		return nil, ""
	}

	sort.Slice(redact, func(i, j int) bool { return redact[i].start < redact[j].start })
	var sb strings.Builder
	last := 0
	for _, s := range redact {
		if s.start < last {
			continue // overlapping span — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteString(InterpHeredocLiteralPlaceholder)
		last = s.end
		items = append(items, command[s.start:s.end])
	}
	sb.WriteString(command[last:])

	out := sb.String()
	if out == command {
		return nil, ""
	}
	return items, out
}

// interpHeredocExecFree is the purity gate's view of the same body-wide
// conditions. Keep the historical check as an AND requirement, even when its
// quote regex mistakes comments for literals: the closed grammar is additional.
func interpHeredocExecFree(lang, body string) bool {
	return legacyInterpHeredocExecFree(lang, body) && closedInertBody(lang, body)
}

func legacyInterpHeredocExecFree(lang, body string) bool {
	return !hasExecCall(lang, execDetectionText(body, interpLiteralSpansForLang(lang, body)))
}

func hasExecCall(lang, body string) bool {
	switch lang {
	case "python", "python2", "python3":
		return pyOsSystemRe.MatchString(body) || pySubprocessRe.MatchString(body)
	case "node":
		return nodeChildProcRe.MatchString(body)
	case "ruby", "perl":
		return bareSystemCallRe.MatchString(body) || backtickRe.MatchString(body)
	default:
		return true // unknown to this extractor — refuse rather than guess
	}
}

// interpLiteralSpansForLang returns the byte spans, relative to body, of
// every quoted string literal in body. Python gets triple-quoted (docstring)
// literals in addition to the ordinary single/double-quoted form shared with
// interp_exec.go/interp_paths.go — see pyTripleQuotedRe's doc comment for
// why that matters for this specific bug. Triple-quoted spans are resolved
// first and anything inside one is excluded from the plain-quote pass, so
// an internal quote character inside a docstring (`"""He said "hi""""`) is
// never independently split into a second, malformed span.
func interpLiteralSpansForLang(lang, body string) [][]int {
	var spans [][]int
	if lang == "python" || lang == "python2" || lang == "python3" {
		spans = append(spans, pyTripleQuotedRe.FindAllStringIndex(body, -1)...)
	}
	for _, m := range quotedLiteralRe.FindAllStringIndex(body, -1) {
		if withinAnySpan(spans, m) {
			continue
		}
		spans = append(spans, m)
	}
	return spans
}

// execDetectionText preserves the historical quote-regex masking behavior for
// the monotonicity AND check only. It can hide real code after a quote in a
// comment; the independent closed grammar must also accept the unmasked body.
func execDetectionText(body string, literalSpans [][]int) string {
	if len(literalSpans) == 0 {
		return body
	}
	sorted := make([][]int, len(literalSpans))
	copy(sorted, literalSpans)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i][0] < sorted[j][0] })

	var sb strings.Builder
	last := 0
	for _, s := range sorted {
		if s[0] < last {
			continue // overlapping — leave as-is, defensive, never corrupt
		}
		sb.WriteString(body[last:s[0]])
		sb.WriteString("HEREDOCLIT")
		last = s[1]
	}
	sb.WriteString(body[last:])
	return sb.String()
}

func withinAnySpan(spans [][]int, m []int) bool {
	for _, s := range spans {
		if m[0] >= s[0] && m[1] <= s[1] {
			return true
		}
	}
	return false
}
