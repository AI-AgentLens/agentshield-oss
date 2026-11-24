package placeholder

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Key-shaped strings in this file are assembled at runtime: AgentShield
// guards the machine this is written on and reads test sources as content.

// gen is a deterministic high-entropy body of n characters from the key
// alphabet. It is never a real key.
func gen(n int) string {
	const alphabet = "Q7mZ2kR9vT4wX1pL8nB6cJ3hF5dG0sYaE"
	var b strings.Builder
	x := uint32(2463534242)
	for b.Len() < n {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte(alphabet[x%uint32(len(alphabet))])
	}
	return b.String()
}

func TestVisible(t *testing.T) {
	ph := "place" + "holder"
	rows := []struct {
		name    string
		body    string
		minBody int
		want    bool
	}{
		// One repeated character.
		{"one-char-a", strings.Repeat("a", 24), 20, true},
		{"one-char-X", strings.Repeat("X", 16), 16, true},
		{"one-char-0", strings.Repeat("0", 40), 20, true},
		// Placeholder words and x runs, with less than minBody left over.
		{"word-repeated", strings.Repeat(ph, 5), 20, true},
		{"word-repeated-partial-tail", strings.Repeat(ph, 4) + "plac", 20, true},
		{"each-word-example", strings.Repeat("exam"+"ple", 3), 20, true},
		{"each-word-fake", strings.Repeat("fa"+"ke", 6), 20, true},
		{"each-word-dummy", strings.Repeat("dum"+"my", 5), 20, true},
		{"each-word-sample", strings.Repeat("sam"+"ple", 4), 20, true},
		{"x-run", strings.Repeat("x", 30) + "12", 20, true},
		// The run boundary: four x's are a token, three are not.
		{"x-run-of-exactly-four", "xxxx" + gen(15), 20, true},
		{"x-run-of-three-is-key-material", "xxx" + gen(16), 20, false},
		{"x-run-mixed-words", ph + strings.Repeat("x", 12) + "0123", 12, true},
		{"remainder-one-below", ph + gen(19), 20, true},
		// Must stay key material.
		{"high-entropy", gen(40), 20, false},
		{"word-then-key", ph + gen(20), 20, false},
		{"key-then-word", gen(20) + ph, 20, false},
		{"key-split-around-word", gen(10) + ph + gen(10), 20, false},
		{"key-with-x-runs-inside", gen(12) + "xxxx" + gen(12), 20, false},
		{"three-x-is-not-a-run", gen(10) + "xxx" + strings.Repeat(ph, 2), 12, false},
		{"upper-case-word-is-not-a-word", "IOSFODNN7" + "EXAM" + "PLE", 16, false},
		{"upper-x-is-not-a-run", "SyB" + strings.Repeat("X", 30) + "12", 35, false},
		{"english-filler-of-key-length", ph + "_not_a_real_key_for_tests", 12, false},
		{"no-token", "your-project-key-goes-here", 20, false},
		{"empty", "", 20, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := Visible(r.body, r.minBody); got != r.want {
				t.Errorf("Visible(%q, %d) = %v, want %v", r.body, r.minBody, got, r.want)
			}
		})
	}
}

func TestTrimProviderPrefix(t *testing.T) {
	sk := "s" + "k-"
	rows := []struct{ in, want string }{
		{sk + "ant-" + "api03-" + "rest", "rest"},
		{sk + "ant-" + "admin01-" + "rest", "rest"},
		{sk + "proj-" + "rest", "rest"},
		{sk + "svcacct-" + "rest", "rest"},
		{sk + "rest", "rest"},
		{"gh" + "p_" + "rest", "rest"},
		{"hf" + "_" + "rest", "rest"},
		{"glpat" + "-" + "rest", "rest"},
		// Only one prefix is removed.
		{sk + "proj-" + "hf_" + "rest", "hf_rest"},
		// No separator, or a provider no Shield rule names: left in place.
		{"AKIA" + "rest", "AKIArest"},
		{"AIza" + "rest", "AIzarest"},
		{"gsk" + "_rest", "gsk_rest"},
		{"plain", "plain"},
	}
	for _, r := range rows {
		if got := TrimProviderPrefix(r.in); got != r.want {
			t.Errorf("TrimProviderPrefix(%q) = %q, want %q", r.in, got, r.want)
		}
	}
}

func TestNewCapture_MinimumIsTheGroupsOwn(t *testing.T) {
	re := regexp.MustCompile(`(?i)(?:a(?P<body>[a-z0-9]{20,})|b(?P<body>[0-9A-Z]{16})|c\s+(?P<body>[A-Za-z0-9._-]{20,}={0,2})|d(?P<body>(?:ab|c)+x?)|e)`)
	c := NewCapture(re, "body")
	if c == nil {
		t.Fatal("NewCapture returned nil for a defined group")
	}
	want := []int{20, 16, 20, 1}
	if len(c.idx) != len(want) {
		t.Fatalf("idx = %v, want %d groups", c.idx, len(want))
	}
	for k, i := range c.idx {
		if c.min[i] != want[k] {
			t.Errorf("group %d (subexp %d): min %d, want %d", k, i, c.min[i], want[k])
		}
	}
	if NewCapture(re, "nope") != nil {
		t.Error("NewCapture of an undefined group must be nil")
	}
	if NewCapture(nil, "body") != nil {
		t.Error("NewCapture(nil) must be nil")
	}
}

func TestClassify_PerMatch(t *testing.T) {
	sk := "s" + "k-"
	ph := "place" + "holder"
	re := regexp.MustCompile(`(?i)` + sk + `(?P<body>[a-zA-Z0-9]{20,})|(?i)(?:password|api[_-]key)\s*[:=]\s*["'](?P<body>[^"'();.]{12,})["']`)
	c := NewCapture(re, "body")
	kw := "api" + "_key" + " = \""
	rows := []struct {
		name            string
		s               string
		matched, keyMat bool
	}{
		{"none", "nothing here", false, false},
		{"placeholder-only", sk + strings.Repeat(ph, 3), true, false},
		{"real-only", sk + gen(40), true, true},
		{"real-beside-placeholder", sk + strings.Repeat(ph, 3) + " and " + sk + gen(40), true, true},
		{"placeholder-beside-real", sk + gen(40) + " and " + sk + strings.Repeat(ph, 3), true, true},
		{"keyword-value-with-provider-prefix", kw + sk + "ant-" + "api03-" + strings.Repeat(ph, 6) + "\"", true, false},
		{"keyword-value-prefix-then-key", kw + sk + "proj-" + gen(12) + "\"", true, true},
		{"keyword-value-unnamed-provider", kw + "gsk" + "_" + strings.Repeat(ph, 4) + "\"", true, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			m, k := c.Classify(r.s, nil)
			if m != r.matched || k != r.keyMat {
				t.Errorf("Classify = (%v, %v), want (%v, %v)", m, k, r.matched, r.keyMat)
			}
		})
	}
	// skip removes a match entirely: a skipped real match leaves only the
	// placeholder one.
	s := sk + gen(40) + " and " + sk + strings.Repeat(ph, 3)
	first := re.FindStringIndex(s)
	m, k := c.Classify(s, func(a, b int) bool { return a == first[0] })
	if !m || k {
		t.Errorf("with the real match skipped: Classify = (%v, %v), want (true, false)", m, k)
	}
}

// The provider prefix is removed only from a whole value. A body the regex
// already placed after its own prefix keeps whatever follows that prefix,
// even text that looks like a second provider prefix: here the remainder is
// that text plus 17 characters, 20 in all, the group's minimum.
func TestClassify_PrefixTrimmedOnlyFromAWholeValue(t *testing.T) {
	sk := "s" + "k-"
	ph := "place" + "holder"
	re := regexp.MustCompile(`\b` + sk + `proj-(?P<body>[A-Za-z0-9_-]{20,})`)
	c := NewCapture(re, "body")
	s := sk + "proj-" + "h" + "f_" + gen(17) + ph
	if _, k := c.Classify(s, nil); !k {
		t.Error("a body that does not start a value must not lose a prefix-looking head")
	}
	// The same text as a whole value: a quoted value's provider prefix goes.
	re2 := regexp.MustCompile(`k = "(?P<body>[^"]{12,})"`)
	c2 := NewCapture(re2, "body")
	if _, k := c2.Classify(`k = "`+sk+"proj-"+strings.Repeat(ph, 3)+`"`, nil); k {
		t.Error("a whole value's provider prefix must not count as body")
	}
}

// #4958 review R14ctx: after a provider prefix is trimmed from a whole value,
// the body can be shorter than the group's minimum. A lone x in it is not a
// token, so nothing is found and the value is key material.
func TestClassify_TrimmedShortBodyWithALoneX(t *testing.T) {
	sk := "s" + "k-"
	re := regexp.MustCompile(`k = "(?P<body>[^"]{12,})"`)
	c := NewCapture(re, "body")
	s := `k = "` + sk + "proj-" + gen(5) + "x" + gen(5)[1:] + `"`
	if _, k := c.Classify(s, nil); !k {
		t.Errorf("a trimmed 10-byte body with one x must be key material: %q", s)
	}
}

// #4958 review, follow-up 1: a placeholder body glued, with no separator, to
// a following key must not hide it. Each row fails on f9f4007f.
func TestClassify_GluedKeyIsKeyMaterial_4958(t *testing.T) {
	sk, ghp, akia, aiza := "s"+"k-", "gh"+"p_", "AK"+"IA", "AI"+"za"
	rows := []struct{ name, pattern, s string }{
		// The greedy body takes "sk" of the next key; the scan used to resume
		// after the match. Caught by the rescan inside the body, and by `-`.
		{"MB1-sk-x20-glued-sk-key", `(?i)` + sk + `(?P<body>[a-zA-Z0-9]{20,})`, sk + strings.Repeat("x", 20) + sk + gen(40)},
		// Fixed length 36 ends inside the next prefix.
		{"MB2-ghp-x33-glued-ghp-key", `(?i)` + ghp + `(?P<body>[A-Za-z0-9]{36})`, ghp + strings.Repeat("x", 33) + ghp + gen(36)},
		// The guardian's combined pattern: the greedy ghp_ body swallows a
		// whole AWS key id; only the rescan sees it.
		{"B3-ghp-x36-glued-akia", `(` + ghp + `(?P<body>[A-Za-z0-9]{36,})|\b` + sk + `(?P<body>[A-Za-z0-9]{20,})|` + akia + `(?P<body>[A-Z0-9]{16}))`, ghp + strings.Repeat("x", 36) + akia + "Q7Z2M4K9R1V8T3W6"},
		// Fixed length 35 ends inside the next AIza key.
		{"B6-aiza-x31-glued-aiza-key", aiza + `(?P<body>[0-9A-Za-z\-_]{35})`, aiza + strings.Repeat("x", 31) + aiza + "Sy" + gen(33)},
		// The glue removes the next key's \b; this pattern never sees it, so
		// the `-` the body runs into decides.
		{"f1-sk-x40-glued-project-key", `(?i)` + sk + `(?P<body>[a-zA-Z0-9]{20,})`, sk + strings.Repeat("x", 40) + sk + "proj-" + gen(48)},
		{"MB4-x-body-underscore-tail", `(?i)` + sk + `(?P<body>[a-zA-Z0-9]{20,})`, sk + strings.Repeat("x", 20) + "_" + gen(40)},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c := NewCapture(regexp.MustCompile(r.pattern), "body")
			if m, k := c.Classify(r.s, nil); !m || !k {
				t.Errorf("Classify = (%v, %v), want (true, true): %q", m, k, r.s)
			}
		})
	}
	// Controls: the same placeholders, separated or alone, stay placeholders.
	c := NewCapture(regexp.MustCompile(aiza+`(?P<body>[0-9A-Za-z\-_]{35})`), "body")
	if _, k := c.Classify("export K="+aiza+"SyB"+strings.Repeat("x", 31)+"12", nil); k {
		t.Error("an x-padded AIza value one byte longer than the body is still a placeholder")
	}
	c = NewCapture(regexp.MustCompile(`(?i)`+sk+`(?P<body>[a-zA-Z0-9]{20,})`), "body")
	if _, k := c.Classify(sk+strings.Repeat("x", 20)+"\n"+sk+strings.Repeat("x", 30)+"\"", nil); k {
		t.Error("two separated placeholders are placeholders")
	}
}

// #4958 review, follow-up 2: key-alphabet bytes inside the match but outside
// the body (the shell rule's free segments) count toward the remainder, less
// a provider prefix a rule names. Fails on f9f4007f.
func TestClassify_SegmentsOutsideTheBodyCount_4958(t *testing.T) {
	sk := "s" + "k-"
	ph := "place" + "holder"
	c := NewCapture(regexp.MustCompile(`((?:^|[^a-zA-Z0-9])`+sk+`(?:[a-z0-9]+-){0,2}(?P<body>[a-zA-Z0-9]{20,}))`), "body")
	seg := "q7m2k9v4w1p8n6c3h5" // 18 bytes of segment material, not a token
	rows := []struct {
		name string
		s    string
		key  bool
	}{
		{"f2-two-free-segments-then-x-body", "export K=" + sk + seg + "-" + seg + "-" + strings.Repeat("x", 24), true},
		{"one-free-segment-of-key-length", "export K=" + sk + seg + "dd-" + strings.Repeat("x", 24), true},
		{"named-anthropic-segments", "export K=" + sk + "ant-api03-" + strings.Repeat("x", 35), false},
		{"named-project-segment", "curl -H 'X-Key: " + sk + "proj-" + strings.Repeat(ph, 3) + "'", false},
		{"short-free-segment", "export K=" + sk + "test1-" + strings.Repeat("x", 24), false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if m, k := c.Classify(r.s, nil); !m || k != r.key {
				t.Errorf("Classify = (%v, %v), want (true, %v)", m, k, r.key)
			}
		})
	}
	// The MCP Anthropic pattern: its named prefix is outside the body and
	// does not count, so placeholder words plus 10 other bytes (under 20)
	// stay a placeholder. Counting the 13-byte prefix would make it 23.
	ant := NewCapture(regexp.MustCompile(`\b`+sk+`ant-(?:api|admin|oat|ort)[0-9]{2}-(?P<body>[A-Za-z0-9_-]{20,})`), "body")
	if _, k := ant.Classify("k = \""+sk+"ant-api03-"+strings.Repeat(ph, 5)+gen(10)+"\"", nil); k {
		t.Error("a named provider prefix outside the body counted toward the remainder")
	}
}

// A group that does not take part in a match (the alternative without it
// matched) makes that match key material: only a captured body is judged.
func TestClassify_MatchWithoutTheGroupIsKeyMaterial(t *testing.T) {
	re := regexp.MustCompile(`AKIA(?P<body>[0-9A-Z]{16})|bearer\s+[A-Za-z0-9]{20,}`)
	c := NewCapture(re, "body")
	if _, k := c.Classify("bearer "+strings.Repeat("a", 24), nil); !k {
		t.Error("a match outside the group must be key material")
	}
	if _, k := c.Classify("AKIA"+strings.Repeat("A", 16), nil); k {
		t.Error("a one-character AKIA body must be a placeholder")
	}
}

// BenchmarkClassify: the cost per byte stays flat from 16 KiB to 1 MiB, on
// text with no credential shape (the common hook case, one DFA pass) and on
// text that is all placeholder matches (the worst case, every body scanned).
func BenchmarkClassify(b *testing.B) {
	sk := "s" + "k-"
	re := regexp.MustCompile(`(?i)` + sk + `(?P<body>[a-zA-Z0-9]{20,})`)
	c := NewCapture(re, "body")
	for _, size := range []int{16 << 10, 1 << 20} {
		plain := strings.Repeat("the quick brown fox jumps over the lazy dog\n", size/44+1)[:size]
		dense := strings.Repeat(sk+strings.Repeat("place"+"holder", 4)+"\n", size/48+1)[:size]
		for _, tc := range []struct{ name, s string }{{"plain", plain}, {"placeholders", dense}} {
			b.Run(tc.name+"-"+strconv.Itoa(size>>10)+"KiB", func(b *testing.B) {
				b.SetBytes(int64(len(tc.s)))
				for i := 0; i < b.N; i++ {
					c.Classify(tc.s, nil)
				}
			})
		}
	}
}

// Classify is linear: a long content of placeholder padding is judged in one
// pass. Guards against a quadratic rescan creeping in.
func TestClassify_LongContent(t *testing.T) {
	sk := "s" + "k-"
	re := regexp.MustCompile(sk + `(?P<body>[a-zA-Z0-9]{20,})`)
	c := NewCapture(re, "body")
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString(sk + strings.Repeat("x", 40) + "\n")
	}
	m, k := c.Classify(b.String(), nil)
	if !m || k {
		t.Errorf("Classify = (%v, %v), want (true, false)", m, k)
	}
}
