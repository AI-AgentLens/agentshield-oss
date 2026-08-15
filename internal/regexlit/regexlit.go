// Package regexlit adds a required-literal prescan in front of a compiled
// regexp.
//
// Why this exists
//
// The regex analyzer evaluates every rule in the corpus against every
// candidate form of a command (raw, dequoted, IFS-normalised, per-statement,
// unset-param-folded — see internal/analyzer/regex.go). Cost is therefore
// O(rules x forms x len(command)), and the rules half of that product has
// tripled since the perf budget was calibrated. Profiling the budget breach
// (2026-08-09) put ~100% of pipeline CPU in regexp, 44% of it in
// tryBacktrack, with no single pathological pattern: 811 community patterns
// each scanned a 4000-byte argument, the worst costing 1.4ms and the whole
// pass 117ms. Broad N x len cost, not a ReDoS.
//
// The observation that makes it cheap to fix: nearly every one of those
// patterns has the shape
//
//	(cat|strings|dd|xxd|...)\s+.*/proc/kcore
//
// — an unanchored alternation of tool names, then ".*", then a literal that
// MUST be present for any match to exist. If "/proc/kcore" is not a
// substring of the command, the regex cannot match, and strings.Contains
// proves that in nanoseconds instead of the regex engine proving it in
// milliseconds.
//
// So: statically derive from the pattern a set of literals L such that every
// string matching the pattern contains at least one member of L, then gate
// the regex on a substring scan. This is a pure accelerator — never a
// semantic change. Soundness is the whole ballgame, so the derivation is
// deliberately conservative: any construct it cannot reason about yields "no
// requirement", which disables the prescan and falls through to the regex.
// Being wrong in that direction costs speed; being wrong in the other
// direction silently disables security rules.
//
// TestDifferentialAgainstCorpus in regexlit_test.go is the fitness function:
// every shipped pattern x the whole command corpus, prescan verdict must
// equal raw regex verdict.
//
// Not implemented on purpose: a single Aho-Corasick automaton over the union
// of all rules' literals, giving O(len) once per command instead of per
// rule. That is the next step if corpus growth outruns this one; it needs the
// matched-literal set threaded through matchRegexRule's call sites, which is
// a wider change than the budget breach currently justifies.
package regexlit

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// Tuning constants for whether a derived literal set is worth using.
//
// A prescan only pays when it is both cheap and selective. Two literals of
// length 2 ("su", "az") appear in most command lines, so the scan costs real
// time and rejects nothing — worse than no prescan at all. These thresholds
// keep the prescan on the patterns where it wins big and off the ones where
// it would be noise.
const (
	// minLiteralLen is the shortest literal considered selective enough to
	// gate on. Below this the substring is common enough in ordinary shell
	// text that the scan rarely rejects.
	minLiteralLen = 3

	// maxLiteralSet caps how many alternatives we will scan for. Past this,
	// the sum of the scans approaches the cost of just running the regex.
	maxLiteralSet = 24
)

// Matcher is a compiled regexp plus an optional required-literal prescan.
// The zero value is not usable; build one with Compile.
type Matcher struct {
	re *regexp.Regexp

	// lits is the required-literal set: any string matching re contains at
	// least one element as a substring (case-insensitively when fold is
	// set, in which case the elements are already lowercase ASCII). Empty
	// means no prescan — MatchString goes straight to the regex.
	lits []string
	fold bool
}

// Compile compiles pattern and derives its required-literal prescan.
// The returned Matcher behaves exactly like the underlying regexp for
// MatchString; the prescan only ever skips work that could not have matched.
func Compile(pattern string) (*Matcher, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return NewFromRegexp(re), nil
}

// NewFromRegexp wraps an already-compiled regexp, deriving the prescan from
// its source pattern. Used by call sites that keep their own compile cache.
func NewFromRegexp(re *regexp.Regexp) *Matcher {
	m := &Matcher{re: re}
	if lits, fold, ok := RequiredLiterals(re.String()); ok {
		m.lits, m.fold = lits, fold
	}
	return m
}

// Regexp exposes the underlying compiled regexp for call sites that need
// more than a boolean match (submatches, replacement, LiteralPrefix).
func (m *Matcher) Regexp() *regexp.Regexp { return m.re }

// String returns the source pattern.
func (m *Matcher) String() string { return m.re.String() }

// HasPrescan reports whether a required-literal set was derived. Test and
// diagnostic use — coverage of the prescan across the shipped corpus is the
// number that predicts whether the perf budget holds as rules are added.
func (m *Matcher) HasPrescan() bool { return len(m.lits) > 0 }

// Literals returns a copy of the derived required-literal set (diagnostics).
func (m *Matcher) Literals() []string {
	out := make([]string, len(m.lits))
	copy(out, m.lits)
	return out
}

// MatchString reports whether s contains any match of the pattern. It is
// semantically identical to (*regexp.Regexp).MatchString; the prescan only
// short-circuits inputs that provably cannot match.
func (m *Matcher) MatchString(s string) bool {
	if len(m.lits) > 0 && !m.prescan(s) {
		return false
	}
	return m.re.MatchString(s)
}

// prescan reports whether any required literal is present in s.
func (m *Matcher) prescan(s string) bool {
	if m.fold {
		for _, lit := range m.lits {
			if containsFoldASCII(s, lit) {
				return true
			}
		}
		return false
	}
	for _, lit := range m.lits {
		if strings.Contains(s, lit) {
			return true
		}
	}
	return false
}

// RequiredLiterals derives a set of literals such that every string matching
// pattern contains at least one of them as a substring. ok is false when no
// useful set could be derived, in which case callers must run the regex
// unconditionally.
//
// When fold is true the returned literals are lowercase ASCII and must be
// compared case-insensitively.
func RequiredLiterals(pattern string) (lits []string, fold bool, ok bool) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false, false
	}
	set := requiredSet(parsed.Simplify())
	if set == nil || len(set.lits) == 0 {
		return nil, false, false
	}
	if len(set.lits) > maxLiteralSet {
		return nil, false, false
	}

	out := make([]string, 0, len(set.lits))
	seen := make(map[string]bool, len(set.lits))
	for _, lit := range set.lits {
		text := lit
		if set.fold {
			// Case-insensitive matching is only sound with ASCII folding
			// when the literal is ASCII: Unicode simple folding maps
			// characters across scripts (Kelvin sign K folds to k, Latin
			// small long s to s), and this repo ships homoglyph rules where
			// getting that wrong would silently disable a detection. Anything
			// non-ASCII under fold disqualifies the whole set.
			if !isASCII(text) {
				return nil, false, false
			}
			text = strings.ToLower(text)
		}
		if len(text) < minLiteralLen {
			return nil, false, false
		}
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	return out, set.fold, true
}

// litSet is a required-literal set under construction: any match of the node
// it was derived from contains at least one member of lits.
type litSet struct {
	lits []string
	fold bool
}

// score ranks two candidate sets. A set is better when its weakest literal is
// longer (more selective), and among equals when it has fewer alternatives
// (fewer scans). Returned as (minLen, count).
func (s *litSet) minLen() int {
	m := -1
	for _, l := range s.lits {
		if m < 0 || len(l) < m {
			m = len(l)
		}
	}
	if m < 0 {
		return 0
	}
	return m
}

// better reports whether s is a more useful prescan than other.
func (s *litSet) better(other *litSet) bool {
	if other == nil {
		return true
	}
	sm, om := s.minLen(), other.minLen()
	if sm != om {
		return sm > om
	}
	return len(s.lits) < len(other.lits)
}

// requiredSet computes a required-literal set for a parsed regexp node, or
// nil when the node can match without containing any fixed literal.
//
// The recursion is the conservative half of a classic literal-extraction
// analysis. Each case answers one question: "must every string matching this
// node contain one of these literals?" If the answer is not provably yes, the
// case returns nil and the prescan is disabled for the enclosing pattern.
func requiredSet(re *syntax.Regexp) *litSet {
	if re == nil {
		return nil
	}
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil
		}
		return &litSet{
			lits: []string{string(re.Rune)},
			fold: re.Flags&syntax.FoldCase != 0,
		}

	case syntax.OpCapture:
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredSet(re.Sub[0])

	case syntax.OpPlus:
		// One or more repetitions: the body occurs at least once, so its
		// requirement is the whole node's requirement.
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredSet(re.Sub[0])

	case syntax.OpRepeat:
		// {n,m} with n >= 1 behaves like OpPlus for our purposes; n == 0 can
		// match empty and requires nothing. (Simplify usually rewrites these,
		// but handle the shape directly rather than depend on that.)
		if len(re.Sub) != 1 || re.Min < 1 {
			return nil
		}
		return requiredSet(re.Sub[0])

	case syntax.OpConcat:
		// Every element of a concatenation must match, so ANY element's
		// requirement is a requirement of the whole. Pick the most selective
		// one and discard the rest.
		var best *litSet
		for _, sub := range re.Sub {
			if got := requiredSet(sub); got != nil && got.better(best) {
				best = got
			}
		}
		return best

	case syntax.OpAlternate:
		// A match takes exactly one branch, so the requirement is the union of
		// the branches' requirements — and only if EVERY branch has one. A
		// single branch that can match without a literal (say "(?:/etc/shadow|.)")
		// means the alternation as a whole requires nothing.
		merged := &litSet{}
		for _, sub := range re.Sub {
			got := requiredSet(sub)
			if got == nil {
				return nil
			}
			merged.lits = append(merged.lits, got.lits...)
			merged.fold = merged.fold || got.fold
			if len(merged.lits) > maxLiteralSet {
				return nil
			}
		}
		if len(merged.lits) == 0 {
			return nil
		}
		return merged

	default:
		// OpStar / OpQuest (can match empty), OpCharClass / OpAnyChar (no
		// fixed text), anchors and word boundaries (zero width), OpEmptyMatch,
		// and anything added to regexp/syntax in a future Go release. All
		// correctly yield "no requirement".
		return nil
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// containsFoldASCII reports whether s contains lit, comparing ASCII letters
// case-insensitively. lit must already be lowercase ASCII.
//
// Written by hand rather than as strings.Contains(strings.ToLower(s), lit)
// because the allocation and full copy of s would be paid once per rule —
// hundreds of times per command — which is the cost this package exists to
// remove.
func containsFoldASCII(s, lit string) bool {
	n := len(lit)
	if n == 0 {
		return true
	}
	if len(s) < n {
		return false
	}
	lo := lit[0]
	up := lo
	if lo >= 'a' && lo <= 'z' {
		up = lo - ('a' - 'A')
	}
	last := len(s) - n
	for i := 0; i <= last; i++ {
		c := s[i]
		if c != lo && c != up {
			continue
		}
		if equalFoldASCII(s[i:i+n], lit) {
			return true
		}
	}
	return false
}

// equalFoldASCII compares a candidate against an already-lowercase ASCII
// literal, folding ASCII letters in the candidate.
func equalFoldASCII(candidate, lowerLit string) bool {
	for i := 0; i < len(lowerLit); i++ {
		c := candidate[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lowerLit[i] {
			return false
		}
	}
	return true
}
