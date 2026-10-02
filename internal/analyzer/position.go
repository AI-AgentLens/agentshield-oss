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
	// LabelPosQuotedProgramArg — the match exists only inside a word that is
	// ENTIRELY one shell quote (`'…'` / `"…"`, no unquoted characters
	// concatenated onto it), passed as an argument to a fixed allowlist of
	// domain-specific-syntax consumers (awk, sed, perl, jq — never a shell
	// or code interpreter that could execute the string as shell source).
	// Filename generation only applies to UNQUOTED words on the invoking
	// shell's own command line, so a wholly-quoted argument to one of these
	// tools can never carry a live zsh glob qualifier. See
	// shellparse.QuotedProgramArgs (#3631).
	LabelPosQuotedProgramArg = "quoted_program_arg"
	// LabelPosInterpHeredocLiteral — the match exists only inside a quoted
	// string literal in a python3/node/ruby/perl heredoc body that contains
	// NO command-execution call this package can recognize anywhere in that
	// body: data being assigned, printed, or written to a file, never a
	// program the interpreter runs. A body that DOES contain a recognized
	// exec call gets no exclusion at all, even for a literal that isn't
	// itself that call's argument — see InertInterpreterHeredocLiterals
	// (#3809) for why that's the line, not "not itself an exec argument".
	LabelPosInterpHeredocLiteral = "interp_heredoc_literal"
)

// IsValidPositionLabel reports whether a position-exclusion label is
// recognized. Policy loading rejects unknown labels for the same reason it
// rejects unknown intent labels: a typo would suppress nothing and leave a
// rule shipping the false positive it opted out of.
func IsValidPositionLabel(name string) bool {
	switch name {
	case LabelPosLoopWordList, LabelPosSearchNeedle, LabelPosHeredocBody, LabelPosQuotedProgramArg, LabelPosInterpHeredocLiteral:
		return true
	default:
		return false
	}
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
// foldCtx is the whole-command fold context (see StatementFoldContext) used
// to give the SUBTRACTION check below the same obfuscation-aware candidates
// the top-level match and command_intent_exclude/downgrade attribution
// already get (#3717). Pass nil for "no context" — every lexical fold still
// applies, only indirect-executable resolution and sibling-assignment
// invalidation are skipped.
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
// statement, and — #3725 — every StatementMatchCandidates fold of each
// statement), so a second occurrence that is only visible after a transform —
// `cat /etc/sha'dow'`, or an obfuscated real invocation sitting next to an
// unrelated excluded-position sibling — still keeps the block. Before #3725
// the per-statement half of this list was raw statement text only: a real
// statement obfuscated with `${IFS}` or an unset-parameter splice (which the
// top-level match already resolves via the same fold candidates) did not
// match here, so it was invisible to subtraction and the command was
// excluded on the strength of an unrelated needle/loop sibling alone — a
// fail-open in the same direction and shape as #3717.
func PositionExcluded(command string, positions []string, foldCtx *StatementFoldContext, matches func(string) bool) bool {
	var pure, pureSet bool
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
		case LabelPosQuotedProgramArg:
			items, redacted = shellparse.QuotedProgramArgs(command)
		case LabelPosInterpHeredocLiteral:
			items, redacted = InertInterpreterHeredocLiterals(command)
		default:
			continue
		}
		if redacted == "" || !anyMatches(matches, itemForms(items)) {
			continue
		}
		if positionAssertsDataText(p) {
			// #3798 (strict purity): a data-text position holds only on a
			// command line of commands that never run their input. The
			// channel withdrawals (#3967 / #3976) stay as defence in depth.
			if !pureSet {
				pure, pureSet = shellparse.CommandLineIsPure(command, interpHeredocExecFree), true
			}
			if !pure || shellparse.TextReachesExecutor(command) || matchedItemInExecutedSubstitution(command, items, matches) {
				continue
			}
		}
		if !anyMatches(matches, redactedForms(redacted, foldCtx)) {
			return true
		}
	}
	return false
}

// positionAssertsDataText reports whether a position label's premise is "this
// text is data, never run": a heredoc body written by cat/tee (heredoc_body),
// a wholly-quoted awk/sed/perl/jq program (quoted_program_arg), a string
// literal in an exec-free interpreter heredoc (interp_heredoc_literal). Each
// is the position-exclusion twin of an inertness LABEL (in_heredoc,
// in_interpreter_heredoc), and each is false the moment the command hands
// that text to a shell.
//
// # The withdrawal (#3967)
//
// PositionExcluded skips such a label when shellparse.TextReachesExecutor
// holds: the command pipes its text into a shell or interpreter (#3796), or
// writes it to a path it then runs or sources (#3800). That is the SAME
// predicate, at the same command-wide granularity, that withdraws the
// inertness labels in IntentClassifier.classify. A position exclusion is a
// finer-grained statement of the same "never executed" premise, so it cannot
// outlive the evidence that already withdraws the label. It restores a BLOCK
// only on positive evidence that the text runs; the plain note shape
// (`cat > notes.md <<'EOF' … EOF`, nothing executes it) keeps its exclusion.
//
// Measured on main 09a1762a before this existed: 15 of the 19 inline TPs of
// the five BLOCK rules carrying heredoc_body went BLOCK→AUDIT when the TP was
// the body of `cat <<'EOF' | bash`, or of `cat > /tmp/x.sh <<'EOF'` followed
// by `bash /tmp/x.sh` — the rule that should block was excluded outright.
//
// ExecutedText (#3938) was the other candidate and is rejected as the
// withdrawal predicate: it drops emitted text carrying an unexpanded `$` or
// backquote, which is right for what it is for (retrying STATIC text as a
// command) and wrong here — a body piped into bash executes whether or not
// its text is static. Gated on ExecutedText, every TP of
// ts-block-paramexp-prompt-transform (parameter-expansion payloads, all
// carrying `$`) would stay excused.
//
// Both evaluation paths reach this through PositionExcluded — the analyzer
// pipeline (RegexAnalyzer.Analyze) and the regex-only fallback
// (policy.Engine.positionExcluded) — so the withdrawal is written once and the
// paths cannot drift; TestHeredocBodyExclusionWithdrawnWhenBodyExecutes and
// the policy package's parity test assert both.
//
// loop_wordlist and search_needle are NOT in this class: a loop word whose
// variable never reaches an executor, and a grep pattern operand, are words
// on the invoking command line — piping grep's OUTPUT into bash executes the
// matched file lines, not the needle.
//
// # The substitution channel (#3976)
//
// TextReachesExecutor covers pipe and write-then-execute, not a substitution
// whose OUTPUT is executed: `bash -c "$(cat <<'EOF' … EOF)"`,
// `eval "$(…)"`. The inertness labels never needed that case, because they
// are judged per statement and `bash -c …` is not doc-text-shaped. A position
// item is found anywhere in the command, so it did need it: the claim above
// ("cannot outlive the evidence that withdraws the label") was false for
// this channel until matchedItemInExecutedSubstitution. Unlike the
// command-wide predicate, this one is attributed: it withdraws only when an
// item the rule matches lies inside a substitution whose output runs, so
// `echo "$(cat <<'EOF' … EOF)"` (printed, not run) keeps its exclusion.
//
// Cost: consulted only after attribution has already put a match in a
// data-text position, so a command with no such match pays no extra parse.
func positionAssertsDataText(label string) bool {
	switch label {
	case LabelPosHeredocBody, LabelPosQuotedProgramArg, LabelPosInterpHeredocLiteral:
		return true
	}
	return false
}

// matchedItemInExecutedSubstitution reports whether an item the rule matches
// sits inside a command or process substitution whose output the command
// runs as a program (shellparse.ExecutedSubstitutionBodies, #3976).
// Containment is textual: a body is the substitution's source text, so the
// heredoc body or quoted program it contains appears in it verbatim. A miss
// (e.g. a transform that changes the text) leaves the exclusion in place,
// which is the pre-#3976 behaviour, never a new block.
func matchedItemInExecutedSubstitution(command string, items []string, matches func(string) bool) bool {
	var bodies []string
	computed := false
	for _, it := range items {
		needle := strings.TrimSpace(it)
		if needle == "" || !anyMatches(matches, itemForms([]string{it})) {
			continue
		}
		if !computed {
			bodies, computed = shellparse.ExecutedSubstitutionBodies(command), true
		}
		for _, b := range bodies {
			if strings.Contains(b, needle) {
				return true
			}
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
// exclusion to hold. It mirrors the whole-command candidates the regex layer
// already derives, plus — per statement (#3725) — the FULL
// StatementMatchCandidates fold set, not just the raw split text: every form
// here is a way the SAME match could survive redaction, and missing one would
// suppress a real second occurrence. StatementMatchCandidates always includes
// the statement's own raw text as its first element, so this subsumes the
// plain per-statement check it replaces.
func redactedForms(redacted string, foldCtx *StatementFoldContext) []string {
	forms := []string{
		redacted,
		shellparse.DequoteCommand(redacted),
		shellparse.NormalizeIFS(redacted),
	}
	for _, st := range shellparse.SplitTopLevelStatements(redacted) {
		st = strings.TrimRight(st, " \t\n;")
		if st == "" {
			continue
		}
		// Restrict candidates for a restricting rule (#3991): a form here can
		// only CANCEL an exclusion, so for a BLOCK/AUDIT rule reading a
		// path-spelled command word as its program is stricter — a real
		// `/usr/bin/tar …` next to a quoted doc-text copy of the pattern is
		// not excused on the copy's account. For an ALLOW rule cancelling
		// the exclusion LOOSENS the verdict, so the caller only sets
		// restrictForms for restricting rules (Codex pass 2, R1).
		if foldCtx != nil && foldCtx.restrictForms {
			forms = append(forms, StatementRestrictCandidates(st, foldCtx)...)
		} else {
			forms = append(forms, StatementMatchCandidates(st, foldCtx)...)
		}
	}
	return forms
}
