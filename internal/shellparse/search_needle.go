package shellparse

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SearchNeedlePlaceholder is the text substituted for a redacted grep-family
// pattern operand. Opaque and single-token for the same reason as
// LoopItemPlaceholder: it must survive re-parsing as shell and match no
// shipped rule pattern.
const SearchNeedlePlaceholder = "SEARCHNEEDLE"

// grepFamilyNames are the executables SearchToolNeedles treats as search
// tools. Kept in one place so the cheap substring prefilter and the AST
// switch cannot drift.
var grepFamilyNames = []string{"grep", "egrep", "fgrep", "rg", "ag"}

// SearchToolNeedles reports the PATTERN operand of every grep-family
// invocation in command, together with a rendering of command in which
// exactly those operands have been replaced by SearchNeedlePlaceholder.
//
// # Why this exists
//
// A grep pattern operand is the NEEDLE of a search — data being compared
// against file content, never a target being opened, executed, or attached
// to. `grep -i "frida -n <process>" -r docs/` runs frida on nothing; it reads
// documentation looking for a string that happens to spell out a dangerous
// invocation. A rule keyed on that literal text sees it anyway, which is
// issue #3382 — the same "count without position" shape InertLoopWordLists
// closed for `for … in` word lists (#3376), on a different syntactic
// position: the loop case redacts DATA BEING ITERATED, this one redacts DATA
// BEING SEARCHED FOR. Both are consumed positions, neither is a target.
//
// # What is deliberately NOT covered
//
// grepNeedleSpan already refuses to identify the pattern when a flag that
// might consume a SEPARATE following token (`-e VALUE`, -f, -m, -A, --include,
// …) is present — see its doc comment. That refusal propagates here unchanged:
// an ambiguous invocation keeps every word live rather than guessing which one
// is the needle, so a mis-scoped flag costs a block that stands, not a bypass
// that ships. Inline pattern-bearing flags (`-e"$p"`, `--regexp=…`) are the
// exception it CAN resolve: the value is glued into the same word, so
// grepNeedleSpan returns just that value subspan (#3728).
//
// Unlike InertLoopWordLists this does not gate on whether the invocation's
// output escapes to somewhere that could act on it. That gate exists there
// because the loop VALUE (e.g. a candidate file path) is the thing at risk if
// it survives to a consumer. Here the redacted text is the search TERM, not a
// value being carried forward — PositionExcluded's own subtraction check
// (does the rule's pattern still match once the needle is removed) is what
// catches a real invocation that happens to share the string elsewhere in the
// command, so no separate escape analysis is needed.
//
// Returns (nil, "") when the command has no qualifying invocation, when
// parsing fails, or when nothing was rewritten — the same no-op sentinel
// convention as InertLoopWordLists, NormalizeIFS and DequoteCommand.
func SearchToolNeedles(command string) (items []string, redacted string) {
	hasCandidate := false
	for _, name := range grepFamilyNames {
		if strings.Contains(command, name) {
			hasCandidate = true
			break
		}
	}
	if !hasCandidate {
		return nil, ""
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, ""
	}

	var spans []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		c, ok := node.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		exe := staticWord(c.Args[0])
		if exe == "" || !isGrepFamily(path.Base(NormalizeExecName(exe))) {
			return true
		}
		span, ok := grepNeedleSpan(c.Args)
		if !ok {
			return true
		}
		if span.start < 0 || span.end > len(command) || span.start >= span.end {
			return true
		}
		spans = append(spans, span)
		return true
	})
	if len(spans) == 0 {
		return nil, ""
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var sb strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			continue // overlapping span — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteString(SearchNeedlePlaceholder)
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

func isGrepFamily(exe string) bool {
	for _, name := range grepFamilyNames {
		if exe == name {
			return true
		}
	}
	return false
}
