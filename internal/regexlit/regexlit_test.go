package regexlit

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// TestRequiredLiteralsDerivation pins the shapes the derivation must handle,
// and — more importantly — the shapes it must REFUSE. A wrong "no requirement"
// costs speed; a wrong requirement silently disables a security rule, so the
// refusal cases carry the weight here.
func TestRequiredLiteralsDerivation(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantOK  bool
		wantLit []string
		wantFld bool
	}{
		// --- Derivable: the shapes the shipped corpus actually uses --------
		{
			name:    "alternation then dot-star then literal picks the literal",
			pattern: `(cat|strings|dd|xxd|od|cp)\s+.*/proc/kcore`,
			wantOK:  true,
			wantLit: []string{"/proc/kcore"},
		},
		{
			name:    "trailing alternation of long literals unions them",
			pattern: `(?i)(cat|head)\s+.*\b(memory\.pkl|agent_state\.json)`,
			wantOK:  true,
			wantLit: []string{"memory.pkl", "agent_state.json"},
			wantFld: true,
		},
		{
			name:    "plus requires its body",
			pattern: `(?:/etc/shadow)+`,
			wantOK:  true,
			wantLit: []string{"/etc/shadow"},
		},
		{
			name:    "anchors and char classes are skipped, literal still found",
			pattern: `^\s*[a-z]+\s+--kubeconfig\s*\S*$`,
			wantOK:  true,
			wantLit: []string{"--kubeconfig"},
		},
		{
			name:    "counted repeat with min>=1 requires its body",
			pattern: `(?:\.password-store){1,3}`,
			wantOK:  true,
			wantLit: []string{".password-store"},
		},

		// --- Must refuse ---------------------------------------------------
		{
			name:    "star can match empty so requires nothing",
			pattern: `(?:/etc/shadow)*`,
			wantOK:  false,
		},
		{
			name:    "quest can match empty so requires nothing",
			pattern: `(?:sudo\s+)?`,
			wantOK:  false,
		},
		{
			name:    "alternation with one literal-free branch requires nothing",
			pattern: `(/etc/shadow|.)`,
			wantOK:  false,
		},
		{
			name:    "alternation with an empty branch requires nothing",
			pattern: `(/etc/shadow|)`,
			wantOK:  false,
		},
		{
			name:    "pure char class requires nothing",
			pattern: `[a-z]+\s+[0-9]+`,
			wantOK:  false,
		},
		{
			name:    "short literals are not selective enough to gate on",
			pattern: `(sudo|ssh|su|az)\s+`,
			wantOK:  false,
		},
		{
			name:    "non-ASCII under fold is refused (Unicode folding is not ASCII folding)",
			pattern: `(?i)rm\s+\-rf\s+/hоme`, // Cyrillic о — a homoglyph rule shape
			wantOK:  false,
		},
		{
			name:    "counted repeat with min 0 requires nothing",
			pattern: `(?:/etc/shadow){0,3}`,
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lits, fold, ok := RequiredLiterals(tc.pattern)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (lits=%q)", ok, tc.wantOK, lits)
			}
			if !ok {
				return
			}
			if fold != tc.wantFld {
				t.Errorf("fold = %v, want %v", fold, tc.wantFld)
			}
			if !sameSet(lits, tc.wantLit) {
				t.Errorf("lits = %q, want %q", lits, tc.wantLit)
			}
		})
	}
}

// TestNonASCIILiteralWithoutFoldIsExact guards the other half of the Unicode
// story: a non-folded non-ASCII literal is matched byte-exactly, so it is
// sound to gate on — and homoglyph rules depend on that still working.
func TestNonASCIILiteralWithoutFoldIsExact(t *testing.T) {
	// Cyrillic 'а' (U+0430) in place of Latin 'a' — the homoglyph shape.
	const pattern = `rm\s+-rf\s+/homе`
	m, err := Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasPrescan() {
		t.Fatalf("expected a prescan for a non-folded literal pattern")
	}
	homoglyph := "rm -rf /homе" // Cyrillic е
	latin := "rm -rf /home"     // pure Latin — must NOT match
	if !m.MatchString(homoglyph) {
		t.Errorf("homoglyph input should match")
	}
	if m.MatchString(latin) {
		t.Errorf("latin input must not match")
	}
	if got, want := m.MatchString(latin), regexp.MustCompile(pattern).MatchString(latin); got != want {
		t.Errorf("prescan diverged from regexp: %v vs %v", got, want)
	}
}

// TestFoldPrescanMatchesRegexpSemantics checks case-insensitive gating against
// the regexp engine's own verdict, including the mixed-case forms an attacker
// would reach for.
func TestFoldPrescanMatchesRegexpSemantics(t *testing.T) {
	const pattern = `(?i)(cat|head)\s+.*\.KDBX\b`
	m, err := Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasPrescan() {
		t.Fatal("expected a prescan")
	}
	re := regexp.MustCompile(pattern)
	for _, in := range []string{
		"cat secrets.kdbx",
		"cat secrets.KDBX",
		"CAT secrets.KdBx",
		"head ~/vault/db.kDbX ",
		"cat notes.txt",
		"",
		".kdbx",
		strings.Repeat("z", 5000) + " cat x.kdbx",
	} {
		if got, want := m.MatchString(in), re.MatchString(in); got != want {
			t.Errorf("input %q: prescan=%v regexp=%v", in, got, want)
		}
	}
}

// TestContainsFoldASCII exercises the hand-rolled scanner directly, including
// the boundary cases a naive implementation gets wrong.
func TestContainsFoldASCII(t *testing.T) {
	tests := []struct {
		s, lit string
		want   bool
	}{
		{"", "", true},
		{"", "abc", false},
		{"ab", "abc", false},
		{"abc", "abc", true},
		{"ABC", "abc", true},
		{"xxABCxx", "abc", true},
		{"xxABxx", "abc", false},
		{"abc", "abd", false},
		// Literal at the very end (off-by-one in the loop bound).
		{"zzzabc", "abc", true},
		// Overlapping false start: first char matches repeatedly before the
		// real hit.
		{"aaab", "aab", true},
		// Non-letter first byte takes the same path.
		{"read /PROC/kcore", "/proc/kcore", true},
		// Non-ASCII bytes must not be folded into ASCII.
		{"АBC", "abc", false},
	}
	for _, tc := range tests {
		if got := containsFoldASCII(tc.s, tc.lit); got != tc.want {
			t.Errorf("containsFoldASCII(%q, %q) = %v, want %v", tc.s, tc.lit, got, tc.want)
		}
	}
}

// TestMatcherWithoutPrescanIsPassthrough confirms the fallback path is a plain
// delegation — the case that must stay correct when derivation refuses.
func TestMatcherWithoutPrescanIsPassthrough(t *testing.T) {
	const pattern = `[a-z]+\s+[0-9]+`
	m, err := Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if m.HasPrescan() {
		t.Fatal("did not expect a prescan for a literal-free pattern")
	}
	re := regexp.MustCompile(pattern)
	for _, in := range []string{"abc 123", "ABC 123", "", "abc"} {
		if got, want := m.MatchString(in), re.MatchString(in); got != want {
			t.Errorf("input %q: matcher=%v regexp=%v", in, got, want)
		}
	}
}

func TestCompileInvalidPattern(t *testing.T) {
	if _, err := Compile(`(unclosed`); err == nil {
		t.Fatal("expected a compile error")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// TestFoldOnlyRunes_AreEveryASCIIOrbitMember derives foldOnlyRunes again from
// Go's case-folding tables: every rune outside ASCII that shares a fold orbit
// with an ASCII letter. A Unicode update that adds one fails here.
func TestFoldOnlyRunes_AreEveryASCIIOrbitMember(t *testing.T) {
	var want []rune
	for r := rune('a'); r <= 'z'; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f > unicode.MaxASCII {
				want = append(want, f)
			}
		}
	}
	got := []rune(foldOnlyRunes)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("foldOnlyRunes = %q, the Unicode tables give %q", got, want)
	}
}

// TestReplaceAllString_FoldOnlyRunesRunTheRegexp: (?i) matches the Kelvin
// sign as k and the long s as s, which the ASCII fold prescan cannot see
// (#4803's Opus pass: a secret after "--to\u212aen" stayed in the record). An
// input carrying one gets the regexp's own output, from a derived literal set
// and from a hand-given one. Each row first checks that the prescan alone
// would have skipped it, so the row exercises the branch it is for.
func TestReplaceAllString_FoldOnlyRunesRunTheRegexp(t *testing.T) {
	rows := []struct{ pattern, in string }{
		{`(?i)--token\s+\S+`, "mysql -u root --to\u212aen hunter2hunter2"},
		{`(?i)--token\s+\S+`, "mysql --TO\u212aEN hunter2hunter2"},
		{`(?i)secret[=:]\S+`, "echo \u017fecret=hunter2hunter2"},
		{`(?i)--user\s+\S+`, "curl --u\u017fer bob:hunter2 https://x.example"},
	}
	for _, row := range rows {
		re := regexp.MustCompile(row.pattern)
		derived := NewFromRegexp(re)
		if len(derived.Literals()) == 0 {
			t.Fatalf("%s: no derived literals; the row would not exercise the prescan", row.pattern)
		}
		hand := derived.WithRequiredLiterals(derived.Literals(), true)
		want := re.ReplaceAllString(row.in, "[X]")
		if want == row.in {
			t.Fatalf("%s: the regexp does not match %q; the row proves nothing", row.pattern, row.in)
		}
		for name, m := range map[string]*Matcher{"derived": derived, "hand": hand} {
			if m.prescan(row.in) {
				t.Fatalf("%s %s: the prescan already finds a literal in %q; the row proves nothing", name, row.pattern, row.in)
			}
			if got := m.ReplaceAllString(row.in, "[X]"); got != want {
				t.Errorf("%s %s: ReplaceAllString(%q) = %q, the regexp gives %q", name, row.pattern, row.in, got, want)
			}
			// FindAllStringIndex shares the guard (#4813).
			if got, want := m.FindAllStringIndex(row.in, -1), re.FindAllStringIndex(row.in, -1); !slices.EqualFunc(got, want, slices.Equal[[]int]) {
				t.Errorf("%s %s: FindAllStringIndex(%q) = %v, the regexp gives %v", name, row.pattern, row.in, got, want)
			}
		}
	}
}
