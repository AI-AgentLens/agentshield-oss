package analyzer

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Position-exclusion labels, referenced from YAML rules via
// command_position_exclude. Unlike command_intent_exclude — which asks a
// question about the whole command's TEXT ("is this a git commit message?")
// — a position label asks where the rule's OWN match landed in the parsed
// command. It is the mechanism for "exempt the position, never the value"
// (#2594/#2730) on rules whose signal is a literal string.
const (
	// LabelPosLoopWordList — the match exists only inside the word list of a
	// `for NAME in …` clause whose loop variable never reaches a position
	// that could open, run, or retain it. See
	// shellparse.InertLoopWordLists for why the body has to be judged and
	// not just the position (#3376).
	LabelPosLoopWordList = "loop_wordlist"
	// LabelPosSearchNeedle — the match exists only inside the PATTERN
	// operand of a grep-family invocation (grep, egrep, fgrep, rg, ag): a
	// search term being compared against file content, never a target being
	// opened, executed, or attached to. See shellparse.SearchToolNeedles
	// (#3382).
	LabelPosSearchNeedle = "search_needle"
	// LabelPosHeredocBody — the match exists only inside the BODY of a
	// `cat`/`tee <<DELIM … DELIM` heredoc: text being written or printed as
	// data, never a command-line token (executable name, redirect target,
	// flag value). Never applies to a heredoc fed to an interpreter
	// (bash/sh/python3/…) — that body is code, not data. See
	// shellparse.HeredocBodies (#3397).
	LabelPosHeredocBody = "heredoc_body"
)

// IsValidPositionLabel reports whether a position-exclusion label is
// recognized. Policy loading rejects unknown labels for the same reason it
// rejects unknown intent labels: a typo would suppress nothing and leave a
// rule shipping the false positive it opted out of.
func IsValidPositionLabel(name string) bool {
	return name == LabelPosLoopWordList || name == LabelPosSearchNeedle || name == LabelPosHeredocBody
}

// PositionExcluded reports whether a match that has already fired should be
// suppressed because it exists ONLY at one of the named syntactic positions.
//
// matches is the rule's own raw predicate (regex/prefix/exact plus any
// command_regex_exclude) applied to an arbitrary piece of text — supplied by
// the caller because the two evaluation paths spell it differently
// (analyzer.RegexAnalyzer.matchRegexRule and policy.Engine.matchRulePattern),
// exactly as IntentExcludedForStatements takes it.
//
// Two independent conditions must hold, and needing both is the point:
//
//  1. ATTRIBUTION — the rule's pattern fires on one of the excluded positions
//     in isolation. Without this, any command that happens to contain an
//     inert loop would qualify.
//  2. SUBTRACTION — the pattern no longer fires once that text is removed.
//     Without this, `for p in "/etc/shadow"; do echo "$p"; done && cat
//     /etc/shadow` would be excused by its harmless first half.
//
// Subtraction is checked against the redacted command in the same alternative
// renderings the matcher itself uses (dequoted, IFS-normalized, per
// statement), so a second occurrence that is only visible after a transform —
// `cat /etc/sha'dow'` — still keeps the block.
func PositionExcluded(command string, positions []string, matches func(string) bool) bool {
	for _, p := range positions {
		var items []string
		var redacted string
		switch p {
		case LabelPosLoopWordList:
			items, redacted = shellparse.InertLoopWordLists(command)
		case LabelPosSearchNeedle:
			items, redacted = shellparse.SearchToolNeedles(command)
		case LabelPosHeredocBody:
			items, redacted = shellparse.HeredocBodies(command)
		default:
			continue
		}
		if redacted == "" || !anyMatches(matches, itemForms(items)) {
			continue
		}
		if !anyMatches(matches, redactedForms(redacted)) {
			return true
		}
	}
	return false
}

func anyMatches(matches func(string) bool, texts []string) bool {
	for _, t := range texts {
		if t != "" && matches(t) {
			return true
		}
	}
	return false
}

// itemForms renders each redacted item (a loop word-list entry or a grep
// pattern operand) both as written and with its surrounding quotes removed —
// `"/etc/shadow"` and `/etc/shadow` — because a rule's pattern may be
// anchored in a way that the quote characters defeat.
func itemForms(items []string) []string {
	out := make([]string, 0, len(items)*2)
	for _, it := range items {
		out = append(out, it)
		if len(it) >= 2 {
			if q := it[0]; (q == '\'' || q == '"') && it[len(it)-1] == q {
				out = append(out, it[1:len(it)-1])
			}
		}
	}
	return out
}

// redactedForms is the set of texts the pattern must NOT match for the
// exclusion to hold. It deliberately mirrors the cheap whole-command and
// per-statement candidates the regex layer already derives, rather than the
// full arsenal: every form here is a way the SAME match could survive
// redaction, and missing one would suppress a real second occurrence.
func redactedForms(redacted string) []string {
	forms := []string{
		redacted,
		shellparse.DequoteCommand(redacted),
		shellparse.NormalizeIFS(redacted),
	}
	for _, st := range shellparse.SplitTopLevelStatements(redacted) {
		st = strings.TrimRight(st, " \t\n;")
		if st != "" {
			forms = append(forms, st)
		}
	}
	return forms
}
