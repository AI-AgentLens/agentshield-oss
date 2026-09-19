package analyzer

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Command-execution literals inside interpreter HEREDOC bodies (#3697,
// follow-up to #3555/#3668).
//
// in_interpreter_heredoc excuses a shell-pattern hit inside a non-shell
// interpreter's heredoc body on the theory that the body is source code in
// another language, so the hit is a string literal the shell will never
// execute (see intent.go's doc comment on InInterpreterHeredoc). That is
// true for a body that only MENTIONS a phrase in prose or a comment — but
// false the moment the body hands the phrase to a call that shells out:
//
//	python3 - <<'PY'
//	os.system("csrutil disable")
//	PY
//
// really does run `/bin/sh -c "csrutil disable"`, exactly as if the bare
// command had been typed at the prompt. #3668 found both readings inside
// the SAME statement text — a bare mention and a real invocation are
// byte-for-byte indistinguishable to a rule's own command_regex, which is
// why the label cannot safely apply to either without this extractor.
//
// InterpreterHeredocExecStatements recovers the string an interpreter's body
// would actually pass to a shell and returns each as its own candidate.
// It has two independent uses, and both are needed — neither subsumes the
// other:
//
//  1. Added alongside AttributionStatements' other recovered statements, so
//     a candidate carries none of the ORIGINAL statement's CommandFacts (in
//     particular InInterpreterHeredoc is false for "csrutil disable" in
//     isolation — it contains no "<<"). This is what stops
//     IntentExcludedForStatements from excusing a match that already fired
//     on the raw heredoc text (e.g. `os.system("touch x && csrutil
//     disable")`, where a space happens to precede "csrutil" and the rule's
//     own regex matches the whole statement directly).
//  2. Added as its own whole-command candidate form (alongside
//     dequotedCommand, ifsNormalized, etc. in both RegexAnalyzer.Analyze and
//     policy.Engine.Evaluate), so a rule's pattern gets to match the
//     RECOVERED text on its own. This is what closes the more common case:
//     `os.system('csrutil disable')` never matches the ORIGINAL statement at
//     all, because the character immediately before "csrutil" is a quote,
//     not one of the whitespace/separator characters
//     ts-block-macos-sip-disable's own regex requires — the rule's pattern
//     was never given a chance to see "csrutil disable" as its own
//     candidate until this exists.
//
// No per-rule change is needed for either use: every rule that opts into
// in_interpreter_heredoc gets use 1, and every rule (anchored or not) gets
// use 2, the same as any other whole-command candidate form.
//
// Closed allowlist, one call form per supported language — Python
// os.system/subprocess.{run,call,check_call,check_output,Popen}, Node
// child_process.{exec,execSync,spawn,spawnSync}, Ruby/Perl system() and
// backticks. Deliberately does NOT evaluate string concatenation, f-strings,
// or any other non-literal argument — those need a real expression
// evaluator, not a regex, and getting one wrong here can only ever WIDEN a
// rule's candidate set (one more statement to test, never fewer are
// removed), so refusing on anything but a quoted literal is the safe
// direction. Same posture as interp_paths.go's extractFileCallPaths: expand
// the allowlist when a real bypass shows it's needed, not speculatively.
//
// Also does not follow an alias — `const cp = require('child_process');
// cp.exec(...)` is not recognized, only the literal `child_process.exec(`
// spelling is. Same reasoning: a name-resolution pass is a bigger feature
// than this extractor, and refusing on the aliased form only means a real
// call is missed (the safe direction), never that a bare mention is wrongly
// promoted.
var (
	pyOsSystemRe     = regexp.MustCompile(`\bos\.system\s*\(([^)]*)\)`)
	pySubprocessRe   = regexp.MustCompile(`\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(([^)]*)\)`)
	nodeChildProcRe  = regexp.MustCompile(`\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(([^)]*)\)`)
	bareSystemCallRe = regexp.MustCompile(`\bsystem\s*\(([^)]*)\)`)
	backtickRe       = regexp.MustCompile("`([^`]+)`")
)

// InterpreterHeredocExecStatements scans command for interpreter heredoc
// bodies — including those embedded inside a command/process substitution,
// e.g. `x=$(python3 - <<'PY' ... PY)` — and returns the shell command text
// recovered from any command-execution call inside them. Returns nil when
// the command has no `<<` at all (cheap prefilter — the AST parse is the
// expensive part) or when nothing qualifies.
func InterpreterHeredocExecStatements(command string) []string {
	if !strings.Contains(command, "<<") {
		return nil
	}
	return collectInterpreterHeredocExecStatements(shellparse.Parse(command, 2))
}

func collectInterpreterHeredocExecStatements(parsed *shellparse.ParsedCommand) []string {
	if parsed == nil {
		return nil
	}
	var out []string
	for _, seg := range parsed.Segments {
		if seg.InterpHeredocBody == "" || !shellparse.CodeInterpreters[seg.Executable] {
			continue
		}
		out = append(out, interpreterExecLiterals(seg.Executable, seg.InterpHeredocBody)...)
	}
	for _, sub := range parsed.Subcommands {
		out = append(out, collectInterpreterHeredocExecStatements(sub)...)
	}
	return out
}

// interpreterExecLiterals recovers the shell command text from every
// recognized command-execution call inside body, a heredoc body written in
// lang (a shellparse.CodeInterpreters key).
//
// stripHashComments runs first so a "#"-prefixed comment that merely
// mentions call syntax as an example — the exact shape #3668 was filed to
// document as an FP — is never mistaken for a real call. It is quote-aware
// since #3755: a "#" inside a string literal is data, not a comment. The
// quote-blind version truncated
// `os.system('sudo csrutil disable # comment')` at the "#", destroying the
// closing quote and paren so nothing was recovered at all — a measured
// BLOCK->AUDIT bypass on ts-block-macos-sip-disable.
//
// It does NOT try to skip recovery from inside string literals. #3755's
// first cut masked quoted bytes so `print("os.system('csrutil disable')")`
// (which only prints text) would not recover — but a per-line, quote-blind
// mask cannot tell that INERT case apart from `f"{os.system('csrutil
// disable')}"` (an f-string interpolation, which EXECUTES) or from a real
// call after a triple-quoted string closes (which also executes). Both were
// measured as new BLOCK->AUDIT bypasses — the mask fails OPEN on running
// code to spare a false positive on printed text. Telling them apart is
// Python string lexing, the open-ended reimplementation trap that twice
// NO-SHIPped #3694: each layer added lets a fourth spelling through. So the
// mask is dropped. The only cost is that a printed example like case D
// BLOCKs — a benign false positive on the same accepted-FP footing as
// #3668's comment-only mention, and the fail-SAFE direction. Recovering one
// candidate too many can only ever WIDEN a rule's candidate set (see the
// package doc); it never suppresses a real block.
func interpreterExecLiterals(lang, body string) []string {
	if body == "" {
		return nil
	}
	body = stripHashComments(body)
	if body == "" {
		return nil
	}

	var out []string
	collect := func(re *regexp.Regexp) {
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if lit := joinedLiteralArg(m[1]); lit != "" {
				out = append(out, lit)
			}
		}
	}

	switch lang {
	case "python", "python2", "python3":
		collect(pyOsSystemRe)
		collect(pySubprocessRe)
	case "node":
		collect(nodeChildProcRe)
	case "ruby", "perl":
		collect(bareSystemCallRe)
		for _, m := range backtickRe.FindAllStringSubmatch(body, -1) {
			if m[1] != "" {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// joinedLiteralArg reconstructs the command text an exec call's argument
// list represents, by concatenating every quoted string literal found in
// argText with a single space — `os.system("csrutil disable")` and
// `subprocess.run(["csrutil", "disable"])` both yield "csrutil disable".
// Non-literal arguments (variables, f-strings, concatenation expressions)
// contribute nothing, per the package doc above.
func joinedLiteralArg(argText string) string {
	var parts []string
	for _, lit := range quotedLiteralRe.FindAllStringSubmatch(argText, -1) {
		v := lit[1]
		if v == "" {
			v = lit[2]
		}
		if v == "" {
			continue
		}
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// stripHashComments truncates every line of body at its first "#" that is
// NOT inside a string literal (#3755). `os.system('a # b')` keeps its whole
// argument; `os.system('a')  # b` loses only the comment.
//
// A line whose quoting does not close by end of line is truncated the OLD,
// quote-blind way, at the first "#" whatever its context. Such a line is not
// self-contained source — an unterminated literal, or one arm of a
// triple-quoted/template string — so its quote state says nothing reliable,
// and over-stripping only means a real call is missed. That is the failure
// direction that cannot invent a match (see the package doc above).
func stripHashComments(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		idx, unterminated := firstBareHash(line)
		if unterminated {
			idx = strings.IndexByte(line, '#')
		}
		if idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

// firstBareHash walks one line of interpreter source once, tracking single-
// and double-quote state with backslash escapes (the lexing Python, Ruby,
// Perl and JavaScript agree on), and reports the byte index of the first "#"
// that is NOT inside a string literal (or -1 if there is none), plus whether
// a quote was still open when the line ended.
//
// Scanning stops at the returned index on purpose: everything after a bare
// "#" is comment text the caller drops, and lexing an apostrophe in comment
// prose ("it's fine") as an opening quote would misjudge the rest of a line
// that is already destined for truncation.
func firstBareHash(line string) (idx int, unterminated bool) {
	var quote byte // 0 when outside a string literal
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++ // skip the escaped byte
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '#':
			return i, false
		}
	}
	return -1, quote != 0
}
