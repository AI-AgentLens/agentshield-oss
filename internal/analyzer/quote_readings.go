package analyzer

import (
	"runtime"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// quoteReading is one of the two readings of a shell word that the analyzer
// compares on Windows (#5049, stricter-of-two).
//
// On Windows a backslash inside quotes is the path separator Git Bash keeps:
// it opens `cat 'C:\Users\u\'.aws/credentials`. Main deleted every quote and
// backslash, so it read some words Git Bash opens as nothing, and some it
// never opens (`"/Users/u\proj"` as /Users/uproj) as a protected or system
// name. Either reading alone is weaker than the other somewhere. So on
// Windows every comparison takes both, and joins them by the way a match
// moves the verdict:
//
//   - a match that adds a finding (a BLOCK or AUDIT condition) counts when
//     EITHER reading matches;
//   - a match that takes a finding away (an ALLOW, an exemption, a veto, a
//     negated predicate) counts only when BOTH do.
//
// readMain is main's reading, byte for byte, so no comparison made here is
// weaker than main's. (A program name is not one of them: shellparse reads it
// once, as Git Bash does, before the analyzer sees it.) On every other OS
// readMain is the only reading.
type quoteReading uint8

const (
	// readMain is main's: pathnorm.MainShellQuotes, then main's matching.
	readMain quoteReading = iota
	// readBash is Git Bash's on Windows: pathnorm.StripShellQuotes, then every
	// backslash read as the separator it is, so `*` and the `/` prefix forms
	// cross it as they cross '/'. Never taken off Windows.
	readBash
)

// combineReadings evaluates f under main's reading and, on Windows, under Git
// Bash's, and joins the two by the way f's truth moves the verdict. adds says
// a true f adds a finding: then f holds if either reading holds it.
// Otherwise a true f takes one away, and it holds only if both do.
//
// f is a whole evaluation under one reading, so every predicate inside it
// (a negation, an exemption, a veto, a chain step) reads that one reading:
// the join is applied once, to the evaluation's result.
func combineReadings(adds bool, f func(quoteReading) bool) bool {
	return combineReadingsOn(runtime.GOOS, adds, f)
}

// combineReadingsOn is combineReadings as goos runs it, for tests.
func combineReadingsOn(goos string, adds bool, f func(quoteReading) bool) bool {
	got := f(readMain)
	if goos != "windows" || got == adds {
		// Off Windows main's is the only reading. On Windows a main match
		// that adds is already "either", and a main miss that would have
		// taken a finding away already fails "both".
		return got
	}
	return f(readBash)
}

// wordOn is s's quote removal under r, as goos runs it. readBash on Windows
// also reads every backslash as '/': Git Bash treats both as the separator,
// and every comparison downstream ('/'-anchored prefixes, `*` across '/',
// path.Clean) was written for '/'.
func (r quoteReading) wordOn(s, goos string) string {
	if r == readBash && goos == "windows" {
		return toSlash(pathnorm.StripShellQuotesFor(s, goos))
	}
	return pathnorm.MainShellQuotes(s)
}

// word is wordOn for this OS.
func (r quoteReading) word(s string) string { return r.wordOn(s, runtime.GOOS) }

// toSlash turns every backslash into '/'. strings, not filepath.ToSlash, so a
// test can take the Windows reading on another OS.
func toSlash(s string) string { return strings.ReplaceAll(s, `\`, "/") }

// combineReadingsIf is combineReadings when twoWays says Git Bash's evaluation
// can differ from main's, and main's evaluation alone when it cannot.
//
// The gate is exact by construction: an evaluation under readBash differs from
// one under readMain only through readBash's reading of a word it reads, or
// through a pattern's backslash, which readBash puts in slash form. When no
// such word or pattern exists the two evaluations are the same, so skipping
// the second loses nothing. And a gate that missed one would leave main's
// evaluation alone, which is no weaker than main by construction: it could
// only lose a finding Git Bash's reading adds.
func combineReadingsIf(twoWays, adds bool, f func(quoteReading) bool) bool {
	if !twoWays {
		return f(readMain)
	}
	return combineReadings(adds, f)
}

// anyReadingOf reports whether f holds under either reading of word: a
// predicate on one word whose match adds a finding.
func anyReadingOf(word string, f func(quoteReading) bool) bool {
	return combineReadingsIf(wordReadsTwoWays(word), true, f)
}

// wordReadsTwoWays reports whether Git Bash's reading of w differs from
// main's on this OS.
func wordReadsTwoWays(w string) bool { return wordReadsTwoWaysOn(w, runtime.GOOS) }

// wordReadsTwoWaysOn is wordReadsTwoWays as goos runs it. Without a quote or a
// backslash both readings are the word itself.
func wordReadsTwoWaysOn(w, goos string) bool {
	if goos != "windows" || !strings.ContainsAny(w, `'"\`) {
		return false
	}
	return readMain.wordOn(w, goos) != readBash.wordOn(w, goos)
}

// textMayReadTwoWays reports whether some word of s, text that is parsed into
// words again later (a carrier's payload, a heredoc), might read differently.
// A word reads differently only by keeping a backslash or a quote character,
// so text with no backslash and only one kind of quote cannot.
func textMayReadTwoWays(s string) bool {
	return strings.ContainsRune(s, '\\') || (strings.ContainsRune(s, '\'') && strings.ContainsRune(s, '"'))
}

// readsTwoWays reports whether any word of parsed, its subcommands or the
// text they carry reads differently under the two readings on this OS: the
// gate for evaluating a whole rule or check a second time (combineReadingsIf).
func readsTwoWays(parsed *ParsedCommand) bool { return readsTwoWaysOn(parsed, runtime.GOOS) }

// readsTwoWaysOn is readsTwoWays as goos runs it.
func readsTwoWaysOn(parsed *ParsedCommand, goos string) bool {
	if goos != "windows" || parsed == nil {
		return false
	}
	w := func(s string) bool { return wordReadsTwoWaysOn(s, goos) }
	for _, pc := range shellparse.AllParsedCommands(parsed) {
		for _, rd := range pc.Redirects {
			if w(rd.Path) {
				return true
			}
		}
	}
	for _, seg := range allSegments(parsed) {
		carrier := shellparse.CarriesShellSource(seg)
		if w(seg.Executable) || w(seg.Program) {
			return true
		}
		for _, a := range seg.Args {
			if w(a) || (carrier && textMayReadTwoWays(a)) {
				return true
			}
		}
		for _, v := range seg.Flags {
			if w(v) || (carrier && textMayReadTwoWays(v)) {
				return true
			}
		}
		for _, rd := range seg.Redirects {
			if w(rd.Path) {
				return true
			}
		}
		for _, a := range append(append([]string{}, seg.RawWords...), seg.ZshOperandWords...) {
			if w(a) {
				return true
			}
		}
		for _, t := range []string{seg.CFlagArg, seg.HeredocBody, seg.InterpHeredocBody, seg.HereStringBody,
			seg.SourceArg, seg.ProcSubstLiteral, seg.ZshShellWord} {
			if textMayReadTwoWays(t) {
				return true
			}
		}
	}
	return false
}

// globsHaveBackslash reports whether any pattern has a backslash, which
// readBash reads in slash form even when no word reads differently.
func globsHaveBackslash(lists ...[]string) bool {
	for _, l := range lists {
		for _, p := range l {
			if strings.ContainsRune(p, '\\') {
				return true
			}
		}
	}
	return false
}
