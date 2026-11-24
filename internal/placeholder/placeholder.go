// Package placeholder decides whether a credential-shaped value is visibly a
// placeholder rather than key material (#4958). The MCP structural rules that
// name a placeholder_capture group (the credential-in-prompt family) read
// each matched value through it and decide AUDIT, under their own rule id,
// when every credential-shaped value they matched is a placeholder. The shell
// path does not use it: Gary, 2026-11-19, merged the MCP half only, after
// both review passes found their blocking defects in the guardian's shell
// reading, so guardian-secrets_in_command and sec-block-ai-apikey-inline
// decide exactly as before.
//
// Why AUDIT is justified (Gary, 2026-11-19, option 2 of #4958): real keys are
// generated, high-entropy strings. A body that is one repeated character, or
// that is made of placeholder words and x padding with fewer characters left
// over than the rule's own minimum key length, is positive evidence that the
// value is not a key. Every secret scanner's test suite needs such fixtures.
//
// The definition, exactly:
//
//   - the body is the value after its provider prefix;
//   - it is a visible placeholder when every byte of it is the same byte, or
//     when it contains a placeholder token AND the bytes of it outside every
//     token number fewer than minBody, the rule's own minimum body length;
//   - a token is one of Words, matched as written (lowercase), or a run of at
//     least MinXRun lowercase x.
//
// What it deliberately does not do: there is no entropy estimate of the
// remainder. On 12 to 36 characters no byte-scan separates English filler
// from a lowercase key, so any remainder of key length counts as key material
// and the value keeps its BLOCK. A real key with a placeholder word inside it
// therefore stays BLOCKed whenever the key part alone is as long as the rule's
// shortest key, whether it sits before or after the word.
//
// Words are matched lowercase on purpose: real key bodies are mixed case, so
// a case-folded match raises the chance that a random key contains a word by
// 2^len(word), and AWS's documented example id (…EXAMPLE, upper case) stands
// in for a real key in tests across this repository.
package placeholder

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// Words are the placeholder words of #4958.
var Words = [...]string{"placeholder", "example", "fake", "dummy", "sample"}

// MinXRun is the shortest run of lowercase x that counts as padding: the
// `xxxx` the issue and the rule's existing placeholder list name.
const MinXRun = 4

// Visible reports whether body, the part of a credential-shaped value after
// its provider prefix, is visibly a placeholder; minBody is the shortest body
// the rule calls a key. See the package comment for the definition.
func Visible(body string, minBody int) bool {
	return judge(body, 0, minBody)
}

// judge is Visible with extra bytes of key material that sit outside the
// body, counted toward the remainder as if they were in it.
func judge(body string, extra, minBody int) bool {
	if body == "" {
		return false
	}
	if oneByte(body) {
		return extra < minBody
	}
	covered := make([]bool, len(body))
	found := false
	for _, w := range Words {
		for i := 0; i < len(body); {
			j := strings.Index(body[i:], w)
			if j < 0 {
				break
			}
			found = true
			for k := i + j; k < i+j+len(w); k++ {
				covered[k] = true
			}
			i += j + len(w)
		}
	}
	for i := 0; i < len(body); {
		if body[i] != 'x' {
			i++
			continue
		}
		j := i
		for j < len(body) && body[j] == 'x' {
			j++
		}
		if j-i >= MinXRun {
			found = true
			for k := i; k < j; k++ {
				covered[k] = true
			}
		}
		i = j
	}
	if !found {
		return false
	}
	rest := extra
	for _, c := range covered {
		if !c {
			rest++
		}
	}
	return rest < minBody
}

func oneByte(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// providerPrefix is a vendor prefix that a Shield credential rule already
// names and that ends in a separator: the cip rules' sk-, sk-proj-,
// sk-svcacct-, sk-admin-, sk-ant-<type>NN-, glpat- and ghp_, and the
// guardian's credentialValuePrefixes. A prefix without a separator (AKIA,
// AIza, eyJ) is left in the body: it is at most four bytes, and a separator is
// what lets this stay anchored to a whole value. A provider a rule does not
// name keeps its prefix in the body too, which can only keep a BLOCK.
var providerPrefix = regexp.MustCompile(`^(?:sk-ant-(?:api|admin|oat|ort)[0-9]{2}-|sk-(?:proj|svcacct|admin)-|github_pat_|(?:sk|pk|rk)_live_|dop_v1_|sk-|sk_|gh[pousr]_|glpat-|xox[bpas]-|xapp-|ya29\.|npm_|pypi-|hf_|shpat_|SG\.)`)

// TrimProviderPrefix removes one provider prefix from the start of a whole
// value (an assigned or quoted value, a bearer token). Only one: what follows
// the provider prefix is the body, whatever it looks like.
func TrimProviderPrefix(value string) string {
	if loc := providerPrefix.FindStringIndex(value); loc != nil {
		return value[loc[1]:]
	}
	return value
}

// Capture reads one named capture group of a credential regex as the body of
// each match. The group's own minimum length, computed from the regex, is the
// rule's minimum body length. A pattern may define the group once per
// alternative (Go allows a name to repeat); each keeps its own minimum.
type Capture struct {
	re  *regexp.Regexp
	idx []int       // subexpression indexes named the group, in order
	min map[int]int // subexpression index → minimum length of its text
}

// NewCapture returns the Capture of group in re, or nil when re does not
// define the group. A nil Capture judges every match key material.
func NewCapture(re *regexp.Regexp, group string) *Capture {
	if re == nil || group == "" {
		return nil
	}
	var idx []int
	for i, name := range re.SubexpNames() {
		if i > 0 && name == group {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return nil
	}
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}
	min := map[int]int{}
	var walk func(r *syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpCapture && r.Name == group {
			min[r.Cap] = minLen(r.Sub[0])
		}
		for _, s := range r.Sub {
			walk(s)
		}
	}
	walk(parsed)
	return &Capture{re: re, idx: idx, min: min}
}

// minLen is the fewest bytes r can match, counting a character class as one.
func minLen(r *syntax.Regexp) int {
	switch r.Op {
	case syntax.OpLiteral:
		return len(string(r.Rune))
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minLen(r.Sub[0])
	case syntax.OpRepeat:
		return r.Min * minLen(r.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, s := range r.Sub {
			n += minLen(s)
		}
		return n
	case syntax.OpAlternate:
		n := -1
		for _, s := range r.Sub {
			if m := minLen(s); n < 0 || m < n {
				n = m
			}
		}
		if n < 0 {
			return 0
		}
		return n
	default: // star, quest, empty-width assertions, empty match
		return 0
	}
}

// Classify reports whether the regex matches s at all, and whether one of
// its matches is key material: a match where no group of the name took part,
// or whose body is not a placeholder (placeholderMatch). Matches for which
// skip reports true are left out entirely, as if absent.
//
// After a placeholder match the scan resumes one byte into its body, not at
// its end (#4958 review, follow-up 1): a greedy or fixed-length body can
// swallow the start of a key glued to it with no separator (`ghp_` + 33 x +
// a whole `ghp_` token, against a fixed-length body of 36; `sk-` + 20 x +
// `sk-` + a key, against a greedy one), and a scan that resumed after the
// match would never see that key. A rescan starts mid-text, where
// `\b` and `^` read the slice start as text start, so it can find a match the
// whole-text scan would not; that can only add key material, and the rule
// has already fired, so it can only restore the rule's own decision.
//
// Linear in practice: the plain match test (Go's DFA) runs first, so text
// with no credential shape costs what MatchString cost before; after that
// every byte is scanned once, plus once more for each placeholder body. A
// body re-scanned because a match starts inside another one carries that
// match's prefix bytes as remainder, so a placeholder body can hold only a
// few of them before it is key material.
func (c *Capture) Classify(s string, skip func(start, end int) bool) (matched, keyMaterial bool) {
	if !c.re.MatchString(s) {
		return false, false
	}
	for pos := 0; pos <= len(s); {
		m := c.re.FindStringSubmatchIndex(s[pos:])
		if m == nil {
			break
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += pos
			}
		}
		next := m[1]
		if next == m[0] {
			next++
		}
		if skip != nil && skip(m[0], m[1]) {
			pos = next
			continue
		}
		matched = true
		bodyStart, ok := c.placeholderMatch(s, m)
		if !ok {
			return true, true
		}
		if bodyStart+1 > pos {
			next = bodyStart + 1
		}
		pos = next
	}
	return matched, false
}

// placeholderMatch reports whether match m's body is a placeholder, and
// where the body starts. Three readings, each counting a doubtful case as
// key material:
//
//   - A group that holds a whole value (it starts the match, or follows a
//     quote, `=`, `:` or whitespace) loses one provider prefix
//     (TrimProviderPrefix).
//   - Otherwise the key-alphabet run inside the match that leads into the
//     body (the prefix the regex spelled out, and any segments it allowed
//     after it) counts toward the remainder, less one provider prefix a rule
//     names at its start (#4958 review, follow-up 2: `sk-` + two 19-byte
//     segments + an x body is key material; `sk-ant-api03-` + padding is not).
//     On the shipped MCP patterns that run is the literal prefix, which is
//     trimmed, or AKIA's four bytes.
//   - A body that runs on, past the match, through `-` or `_` was cut out of
//     a longer token by the regex: key material (#4958 review, follow-up 1:
//     `sk-` + 40 x glued to a project key, whose `\b` the glue removes; an x
//     body glued by `_` to 40 more key characters).
func (c *Capture) placeholderMatch(s string, m []int) (bodyStart int, placeholder bool) {
	for _, i := range c.idx {
		a, b := m[2*i], m[2*i+1]
		if a < 0 {
			continue
		}
		body := s[a:b]
		extra := 0
		if a == m[0] || strings.IndexByte("\"'=: \t\r\n", s[a-1]) >= 0 {
			// The group holds a whole value, not the text after a prefix
			// the regex itself spelled out.
			body = TrimProviderPrefix(body)
		} else {
			k := a
			for k > m[0] && prefixByte(s[k-1]) {
				k--
			}
			extra = len(TrimProviderPrefix(s[k:a]))
		}
		if b < len(s) && (s[b] == '-' || s[b] == '_') {
			return a, false
		}
		return a, judge(body, extra, c.min[i])
	}
	return m[0], false
}

// prefixByte reports whether b can be part of a provider prefix or a key
// segment: an ASCII letter or digit, `-` or `_`.
func prefixByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}
