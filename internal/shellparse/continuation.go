package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// JoinLineContinuations returns the command re-rendered on a single line, with
// backslash-newline continuations removed the way the shell removes them.
// Returns "" when there is nothing to join, when the command does not parse, or
// when the result is identical to the input.
//
//	"dd \\\nif=/dev/zero of=/dev/sda"  ->  "dd if=/dev/zero of=/dev/sda"
//	"rm \\\n  -rf /"                   ->  "rm -rf /"
//	"echo 'a\\\nb'"                    ->  ""   (inside quotes: not a continuation)
//
// Why this exists: a backslash-newline is pure lexical whitespace. The shell
// deletes it before the command is even tokenized, so `rm \<NL>-rf /` and
// `rm -rf /` are the same command by the time anything runs. mvdan.cc/sh agrees
// — the AST for both is identical, which is why the structural, semantic and
// dataflow layers never noticed. The REGEX layer did: it matches raw text, and
// no `\s`, `\s+` or literal-space pattern matches a backslash. `^rm\s+-rf\s+/`
// simply does not match `rm \<NL>-rf /`.
//
// That made a two-character edit the single widest bypass in the corpus:
// 1,252 of 2,385 BLOCKing commands (52.5%) degraded to AUDIT when one space was
// replaced with " \<NL>". It is also not purely adversarial — agents and humans
// alike emit continuations whenever a command is long enough to wrap, so these
// were live false negatives on multi-line `curl ... \<NL> | bash` installers.
//
// The naive fix — strings.ReplaceAll(cmd, "\\\n", "") — is wrong, and wrong in
// the direction that creates false positives: inside single quotes and quoted
// heredocs a backslash-newline is ordinary literal text, so collapsing it
// fabricates content the shell would never produce. Printing the parsed AST
// gets this right for free: the printer emits each word as the parser understood
// it, so a continuation that was really whitespace disappears and one that was
// really data survives.
func JoinLineContinuations(command string) string {
	// Fast path: the overwhelming majority of commands have no continuation at
	// all, and this runs on every command through the regex analyzer. Parsing
	// unconditionally would spend a full parse per statement for nothing.
	if !strings.Contains(command, "\\\n") && !strings.Contains(command, "\\\r\n") {
		return ""
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return ""
	}

	var sb strings.Builder
	printer := syntax.NewPrinter(syntax.SingleLine(true))
	if err := printer.Print(&sb, file); err != nil {
		return ""
	}

	joined := strings.TrimRight(sb.String(), " \t\n")
	if joined == "" || joined == command {
		return ""
	}
	return joined
}
