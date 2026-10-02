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
// interp_paths.go) is single-line only and would either miss such a literal
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

// InertInterpreterHeredocLiterals reports the byte spans, within command, of
// every quoted string literal (Python triple-quoted docstrings included)
// inside a supported CodeInterpreters heredoc body that contains NO
// command-execution call recognized by interp_exec.go's allowlist anywhere
// in that same body — together with a rendering of command in which those
// spans have been replaced by InterpHeredocLiteralPlaceholder.
//
// # Why this exists (#3809)
//
// #3796/#3800 correctly withdraw the doc-text/heredoc inertness labels once
// TextReachesExecutor is true, and that withdrawal is not the bug here — a
// bare `python3 - <<'EOF' … EOF` with no further pipe or write-then-execute
// correlation doesn't even trip that withdrawal (measured: TextReachesExecutor
// is false for it). The gap is a level in, on the in_interpreter_heredoc
// label itself: a rule that opts into it is choosing between two bad
// options, not fixing a bug — see "why not just downgrade" below.
//
// # Why not just add in_interpreter_heredoc to the rule's own
// command_intent_downgrade (the obvious, one-line fix)
//
// That was tried and measured, then reverted. It fixes the reported FP, but
// it opens a real regression on the SAME rule:
//
//	python3 - <<'PY'
//	cmd = "ufw disable"
//	os.system(cmd)
//	PY
//
// Before any fix this BLOCKs (the whole-body text match holds, unexcused).
// With in_interpreter_heredoc on downgrade it becomes AUDIT — a real
// firewall-disable, laundered by one assignment. interp_exec.go's own
// extractor does not recover this statement (os.system(cmd) takes a bare
// identifier, not a literal — "refusing on anything but a quoted literal is
// the safe direction" for THAT extractor's purpose of finding candidates,
// but it means nothing else stands in for the withdrawn label here). This is
// exactly the risk packs/community/terminal-safety.yaml's
// ts-block-security-daemon-deactivate reason text already names for its own
// (deliberately un-excused) in_interpreter_heredoc case.
//
// # The narrower rule this function implements instead
//
// A quoted literal is redacted only when the ENTIRE heredoc body contains
// NO command-execution call recognized by interp_exec.go's allowlist —
// not "this literal specifically isn't an exec argument", which is the
// version that fails on the os.system(cmd) shape above (the literal
// "ufw disable" is not itself a call argument; it is one assignment away
// from one). Requiring the whole body to be exec-call-free is what makes
// the exclusion provable: interp_exec.go recovers every call this package
// knows how to recognize as its own whole-command candidate (with none of
// the original statement's CommandFacts), so a body with zero such calls
// has, by the same allowlist logic, no execution mechanism this extractor
// can see at all — every literal in it is safe to redact. A body that mixes
// an unrelated real call with an inert literal elsewhere gets NO exclusion
// for either (hasExecCall bails the whole segment); that is a known,
// accepted narrowing, not a bypass — it can only cost an exemption, never
// grant one that wasn't provably safe.
//
// Verified against the concrete #3809 repro and the os.system(cmd)
// regression above via the built binary before this comment was written:
// doc-only body -> excluded (falls through to whatever else applies);
// os.system("ufw disable") / subprocess.run(["ufw","disable"]) -> body
// contains a recognized call, bail, rule still BLOCKs; os.system(cmd) with
// cmd assigned from a literal -> body still contains a recognized call
// (the call's own argument being non-literal does not matter), bail, rule
// still BLOCKs.
//
// # Granularity fix (#3822)
//
// hasExecCall's regexes scan body as plain text — blind to whether a match
// sits inside a string literal or in real code. A heredoc that WRITES A
// DOCUMENT quoting a call as prose (a report describing this very rule, the
// #3822 repro: a 400-line markdown string that mentions `os.system(cmd)` as
// an example, built and handed to `io.open(...).write(...)`) matched
// pyOsSystemRe just as readily as a real call would, bailing exclusion for
// every literal in the body — including the one the prose was quoted
// inside, hundreds of lines from the mention.
//
// hasExecCall now runs against body with every literal span (the same spans
// this function would otherwise redact) replaced by a placeholder, via
// execDetectionText. Real code is, by construction, never itself the
// CONTENTS of a quoted string literal — masking can only remove a match that
// existed solely because a string's text happened to spell out call syntax;
// it cannot hide a call that is actually there, because an actual call's
// call-name and parens sit outside any literal span, only its argument
// (which may itself be a literal) sits inside one. Verified this preserves
// every existing regression: os.system("ufw disable") and os.system(cmd)
// (cmd assigned from a literal) both still bail, because `os.system(` and
// `)` are untouched by masking regardless of what lies between them.
//
// Returns (nil, "") when command has no qualifying heredoc, when parsing
// fails, or when nothing was rewritten — the same no-op sentinel convention
// as the shellparse position-label functions.
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
		body := command[sp.Start:sp.End]
		literalSpans := interpLiteralSpansForLang(sp.Lang, body)
		if hasExecCall(sp.Lang, execDetectionText(body, literalSpans)) {
			continue
		}
		for _, ls := range literalSpans {
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

// hasExecCall reports whether body (a CodeInterpreters heredoc body already
// known to be language lang) contains any command-execution call recognized
// by interp_exec.go's allowlist — regardless of whether that call's own
// argument is a literal. Presence alone, not just a literal argument, is
// what triggers the bail (see the "narrower rule" section above).
// interpHeredocExecFree is the purity gate's view of an interpreter heredoc
// (#3798): the same exec-free analysis this file's position uses, with string
// literals blanked so a quoted mention of a call is not mistaken for one.
func interpHeredocExecFree(lang, body string) bool {
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

// execDetectionText returns body with every span in literalSpans (already
// computed by interpLiteralSpansForLang) replaced by a fixed placeholder
// containing no parenthesis, backtick, or quote character — for use ONLY as
// input to hasExecCall's regexes, never as the actual redacted output.
//
// The placeholder is deliberately parenthesis-free so a real call's own
// structure survives: `os.system("ufw disable")` becomes
// `os.system(HEREDOCLIT)`, and pyOsSystemRe still matches the call — masking
// hides what a literal SAYS, never whether a call is actually wrapped around
// it. See InertInterpreterHeredocLiterals' "#3822" section for why that
// direction is safe: a call's name and parens are never themselves inside a
// quoted literal, only (optionally) its argument is.
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
