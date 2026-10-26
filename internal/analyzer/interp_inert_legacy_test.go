package analyzer

// Frozen pre-fix oracle (e8710f88/b5c86dc7 mechanism). Do not refactor this
// to call production helpers: that would make the monotonicity test vacuous.

import (
	"regexp"
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

const reviewLegacyPlaceholder = "INTERPHEREDOCLITERAL"

var reviewLegacyTripleRe = regexp.MustCompile(`(?s)"""(?:\\.|[^\\])*?"""|'''(?:\\.|[^\\])*?'''`)

var reviewLegacyLangs = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"node": true, "ruby": true, "perl": true,
}

func reviewLegacyInertLiterals(command string) (items []string, redacted string) {
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
		if !reviewLegacyLangs[sp.Lang] {
			continue
		}
		if sp.Start < 0 || sp.End > len(command) || sp.Start >= sp.End {
			continue
		}
		body := command[sp.Start:sp.End]
		literalSpans := reviewLegacySpans(sp.Lang, body)
		if reviewLegacyHasExec(sp.Lang, reviewLegacyDetectionText(body, literalSpans)) {
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
		sb.WriteString(reviewLegacyPlaceholder)
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

func reviewLegacyExecFree(lang, body string) bool {
	return !reviewLegacyHasExec(lang, reviewLegacyDetectionText(body, reviewLegacySpans(lang, body)))
}

func reviewLegacyHasExec(lang, body string) bool {
	switch lang {
	case "python", "python2", "python3":
		return reviewLegacyOSRe.MatchString(body) || reviewLegacySubprocessRe.MatchString(body)
	case "node":
		return reviewLegacyNodeRe.MatchString(body)
	case "ruby", "perl":
		return reviewLegacySystemRe.MatchString(body) || reviewLegacyBacktickRe.MatchString(body)
	default:
		return true // unknown to this extractor — refuse rather than guess
	}
}

func reviewLegacySpans(lang, body string) [][]int {
	var spans [][]int
	if lang == "python" || lang == "python2" || lang == "python3" {
		spans = append(spans, reviewLegacyTripleRe.FindAllStringIndex(body, -1)...)
	}
	for _, m := range reviewLegacyQuoteRe.FindAllStringIndex(body, -1) {
		if reviewLegacyWithin(spans, m) {
			continue
		}
		spans = append(spans, m)
	}
	return spans
}

func reviewLegacyDetectionText(body string, literalSpans [][]int) string {
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

func reviewLegacyWithin(spans [][]int, m []int) bool {
	for _, s := range spans {
		if m[0] >= s[0] && m[1] <= s[1] {
			return true
		}
	}
	return false
}

var (
	reviewLegacyQuoteRe      = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
	reviewLegacyOSRe         = regexp.MustCompile(`\bos\.system\s*\(([^)]*)\)`)
	reviewLegacySubprocessRe = regexp.MustCompile(`\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\(([^)]*)\)`)
	reviewLegacyNodeRe       = regexp.MustCompile(`\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(([^)]*)\)`)
	reviewLegacySystemRe     = regexp.MustCompile(`\bsystem\s*\(([^)]*)\)`)
	reviewLegacyBacktickRe   = regexp.MustCompile("`([^`]+)`")
)
