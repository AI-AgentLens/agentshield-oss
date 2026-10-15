package shellparse

import (
	"regexp"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// plainFlagTokenRe is a flag token with no byte the shell treats specially:
// one or two dashes, then letters, digits and `-=._`. No space, quote,
// backslash, `$`, backquote, glob, brace or tilde, so quoting such a token
// changes nothing about its value: `rm "-rf" /etc` runs exactly `rm -rf /etc`
// (#4289).
var plainFlagTokenRe = regexp.MustCompile(`^-{1,2}[A-Za-z0-9][-A-Za-z0-9=._]*$`)

// UnquoteFlagWords returns command with every command argument that is a
// quoted plain flag token written bare — `rm "-rf" /etc` becomes
// `rm -rf /etc`, `git reset '--hard'` becomes `git reset --hard` — or "" when
// the command has no such word (or does not parse).
//
// Bash removes those quotes before the program sees argv, so the rewrite is
// the command the program actually receives. Every other byte is kept as
// written: the spans are spliced into the original text, not re-printed.
//
// Only words that do not already start with `-` are rewritten. The splice
// forms that do (`-"rf"`, `--ha'rd'`) are already read as flags by the
// parser (#3003) and dequoted by DequoteCommand (2+ parts), so the as-written
// evaluation sees them.
//
// The caller (policy.Engine.EvaluateWithParsedCwd) evaluates this text as a
// SECOND reading and keeps it only when strictly more restrictive, the same
// construction as #3991 and #4194. Nothing here is ever a replacement for the
// as-written text.
func UnquoteFlagWords(command string) string {
	// A word whose VALUE starts with `-` but whose TEXT does not can only
	// open with quote characters, so a quote directly precedes its first
	// dash. Commands without that byte pair pay one scan and no parse.
	if !strings.Contains(command, `"-`) && !strings.Contains(command, `'-`) {
		return ""
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return ""
	}
	type span struct {
		start, end int
		value      string
	}
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for _, w := range call.Args {
			start, end := int(w.Pos().Offset()), int(w.End().Offset())
			if start < 0 || end > len(command) || start >= end {
				continue
			}
			text := command[start:end]
			if strings.HasPrefix(text, "-") {
				continue
			}
			if v, ok := unquotePlainFlagWord(text); ok {
				spans = append(spans, span{start, end, v})
			}
		}
		return true
	})
	if len(spans) == 0 {
		return ""
	}
	// A rewritten word's value is a flag token, so it holds no substitution
	// and no nested word can sit inside it: spans never overlap. Splice from
	// the end so earlier offsets stay valid.
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	out := command
	for _, s := range spans {
		out = out[:s.start] + s.value + out[s.end:]
	}
	return out
}

// unquotePlainFlagWord returns the value bash gives the word text w after
// quote removal, when w carries at least one quote character and that value
// is a plain flag token: `"-rf"`, `'--hard'`, `"-r"'f'`, `""-rf`.
//
// The scan is exact rather than a blind strip. Every byte inside a quoted
// span is kept literally and an unquoted byte is kept as written, so a
// backslash, `$` or backquote anywhere in w survives into the value and fails
// the token pattern. That matters because inside double quotes `\r` stays two
// bytes: `"-\rf"` runs as `-\rf`, not `-rf`.
func unquotePlainFlagWord(w string) (string, bool) {
	hasQuote := false
	buf := make([]byte, 0, len(w))
	var open byte
	for i := 0; i < len(w); i++ {
		c := w[i]
		if open != 0 {
			if c == open {
				open = 0
				continue
			}
			buf = append(buf, c)
			continue
		}
		if c == '\'' || c == '"' {
			open = c
			hasQuote = true
			continue
		}
		buf = append(buf, c)
	}
	if !hasQuote || open != 0 {
		return "", false
	}
	v := string(buf)
	if !plainFlagTokenRe.MatchString(v) {
		return "", false
	}
	return v, true
}
