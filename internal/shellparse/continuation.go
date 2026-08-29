package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// JoinLineContinuations returns the command with backslash-newline
// continuations removed the way the shell removes them, leaving every other
// byte — crucially, every statement-separating newline — untouched. Returns
// "" when there is nothing to join, when the command does not parse, or when
// the result is identical to the input.
//
//	"dd \\\nif=/dev/zero of=/dev/sda"  ->  "dd if=/dev/zero of=/dev/sda"
//	"rm \\\n  -rf /"                   ->  "rm   -rf /"  (whitespace-equivalent)
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
// fabricates content the shell would never produce.
//
// An earlier version fixed that by reprinting the WHOLE parsed file with
// syntax.SingleLine(true) — correct for the AST, wrong for the regex layer
// that consumes the result: the SingleLine printer also collapses every
// statement-separating newline into "; ", not just the true continuations, so
// a completely unrelated pair of statements elsewhere in the same command
// ends up textually adjacent with only a "; " between them. An unanchored
// `.*`-based rule can then bridge across what were two separate statements —
// `.` does not match `\n`, so it could never do that against the original
// text (issue #3472: a read-only two-statement script got BLOCKed by
// sc-block-mcp-config-injection purely because ONE of its statements happened
// to wrap with a "\<NL>" continuation, which single-lined the entire script
// and let the rule's redirect-then-path pattern span from one statement's
// pipe into an unrelated later statement's path literal).
//
// This version never reformats anything. It deletes only the exact
// backslash-newline BYTE SEQUENCES that the AST confirms are real
// continuations (i.e. not inside a single-quoted string or a heredoc body,
// where the same two bytes are literal data) and leaves every other byte —
// including every other newline in the command, whatever separates it —
// exactly where it was. A statement-separating newline is never preceded by
// a backslash, so it can never be mistaken for a continuation by
// construction; no statement-boundary tracking is needed to protect it.
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

	protected := literalContinuationSpans(file)

	var sb strings.Builder
	changed := false
	i := 0
	for i < len(command) {
		if command[i] == '\\' && i+1 < len(command) {
			nlLen := 0
			switch {
			case command[i+1] == '\n':
				nlLen = 2
			case command[i+1] == '\r' && i+2 < len(command) && command[i+2] == '\n':
				nlLen = 3
			}
			if nlLen > 0 && !withinProtectedSpan(protected, i) {
				i += nlLen
				changed = true
				continue
			}
		}
		sb.WriteByte(command[i])
		i++
	}

	if !changed {
		return ""
	}
	joined := sb.String()
	if joined == "" || joined == command {
		return ""
	}
	return joined
}

// literalContinuationSpans returns the byte ranges in which a
// backslash-newline is literal data, not a continuation: single-quoted
// string bodies and heredoc bodies (quoted or not — a heredoc reads its body
// verbatim line-by-line; it is never subject to continuation removal,
// matching real shell behavior).
func literalContinuationSpans(file *syntax.File) []byteSpan {
	var spans []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.SglQuoted:
			spans = append(spans, byteSpan{int(n.Pos().Offset()), int(n.End().Offset())})
		case *syntax.Stmt:
			for _, redir := range n.Redirs {
				if redir.Hdoc != nil {
					spans = append(spans, byteSpan{int(redir.Hdoc.Pos().Offset()), int(redir.Hdoc.End().Offset())})
				}
			}
		}
		return true
	})
	return spans
}

func withinProtectedSpan(spans []byteSpan, offset int) bool {
	for _, s := range spans {
		if offset >= s.start && offset < s.end {
			return true
		}
	}
	return false
}
