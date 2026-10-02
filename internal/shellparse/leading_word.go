package shellparse

import "unicode"

// FoldLeadingExecWord returns cmd with quote/backslash artifacts removed from
// its first whitespace-delimited word — the executable position of the whole
// command — while leaving every other byte untouched, including statement
// separators (";", "&&", "||", "|") and newlines. Returns "" (the no-op
// sentinel every normalizer in this package uses) when there is nothing to
// fold.
//
// This exists because DequoteCommand's AST-based fold re-renders the whole
// command through mvdan/sh's printer, which reformats a top-level ";" as a
// newline. So a splice in the FIRST statement's executable name of a
// multi-statement command — "s\leep 120; curl ..." — dequotes to
// "sleep 120\ncurl ...", and no command_regex rule written against the
// original punctuation (";", "&&") between two statements can match a "\n"
// (#3848 class B). Folding only the first word's own bytes in place, rather
// than going through the printer, keeps every separator exactly as written.
//
// Scoped to the first word only: NormalizeExecName is documented safe for
// "the executable position" specifically (real command names never contain
// quote or backslash characters), and the first word of a raw command is
// that position in the common case (a leading env assignment or compound-
// command keyword just passes through unchanged, since neither needs
// folding).
func FoldLeadingExecWord(cmd string) string {
	start := -1
	end := len(cmd)
	for i, r := range cmd {
		if unicode.IsSpace(r) {
			if start >= 0 {
				end = i
				break
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start < 0 {
		return ""
	}
	word := cmd[start:end]
	folded := NormalizeExecName(word)
	if folded == word {
		return ""
	}
	return cmd[:start] + folded + cmd[end:]
}
