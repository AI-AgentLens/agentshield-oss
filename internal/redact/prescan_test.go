package redact

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// #4785: Redact runs each secret pattern behind its required-literal prescan
// (regexlit). The prescan may only skip a pattern that cannot match, so
// Redact must return exactly what the plain regexps return. These tests hold
// it to a frozen copy of the plain loop.

// plainRedact is Redact before #4785: every pattern's regexp, in order.
func plainRedact(input string) string {
	result := input
	for _, re := range rawSensitivePatterns {
		result = re.ReplaceAllString(result, redactedPlaceholder)
	}
	return result
}

// plainRedactArgs is RedactArgs over plainRedact.
func plainRedactArgs(args []string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		result[i] = plainRedact(arg)
	}
	joined := strings.Join(result, " ")
	if redacted := plainRedact(joined); redacted != joined {
		return strings.Fields(redacted)
	}
	return result
}

// prescanCorpus is the analyzer corpus, secret shapes for every pattern
// family (assembled at runtime), each in several cases and spacings, and the
// same shapes glued to ordinary command text.
func prescanCorpus() []string {
	jwt := "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NSJ9" + "." + "dGhpc2lzdGhlc2ln"
	pw := "pw" + "Secret99xyz"
	shapes := []string{
		"aws_secret_access_key = '" + strings.Repeat("Ab1/", 10) + "'",
		"AKIA" + strings.Repeat("Q7", 8),
		"github_token: " + strings.Repeat("g", 32),
		"ghp_" + strings.Repeat("a1", 18), "gho_" + strings.Repeat("b2", 18), "ghu_" + strings.Repeat("c3", 18),
		"ghs_" + strings.Repeat("d4", 18), "ghr_" + strings.Repeat("e5", 18),
		"api-key=" + strings.Repeat("k", 20), "access_token: " + strings.Repeat("z", 16),
		"-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc\n-----END " + "OPENSSH PRIVATE KEY-----",
		"-----BEGIN " + "EC PRIVATE KEY-----",
		"Bea" + "rer " + jwt, "Authorization: Bea" + "rer abc123def",
		"https://user:" + pw + "@host/x", "redis://u:" + pw + "@cache:6379",
		"--password " + pw, "--token '" + pw + "'", "-u admin:" + pw, "--user bob:" + pw,
		"TOKEN=" + strings.Repeat("t0k", 6), `"token":"` + strings.Repeat("Q", 14) + `"`,
		"sk-" + "ant-" + strings.Repeat("Z9", 12), "xox" + "p-1234567890-1234567890-abc",
		"sk_" + "live_" + strings.Repeat("a", 24), "rk_" + "live_" + strings.Repeat("b", 24),
		"pass" + "word=" + pw, "SECRET: " + pw, "pwd=" + pw,
		// Near misses: the literal without the rest of the pattern.
		"token=42", "bearer authentication", "the password file", "--password-file x", "AKIA",
	}
	var out []string
	for _, s := range shapes {
		out = append(out, s, strings.ToUpper(s), strings.ToLower(s),
			"curl -s https://example.com/api && echo "+s+" | tee out.log",
			"cat <<'EOF' > cfg.env\n"+s+"\nmore text\nEOF")
	}
	for _, tc := range testdata.AllTestCases() {
		out = append(out, tc.Command)
	}
	return out
}

// TestRedact_PrescanMatchesPlainRegexp: Redact and RedactArgs return exactly
// what the plain regexps return, over the corpus. The positive control
// counts inputs the redactor changes, so a vacuous corpus fails.
func TestRedact_PrescanMatchesPlainRegexp(t *testing.T) {
	corpus := prescanCorpus()
	changed, skippedAll := 0, 0
	for _, in := range corpus {
		got, want := Redact(in), plainRedact(in)
		if got != want {
			t.Fatalf("Redact(%q)\n got %q\nwant %q", in, got, want)
		}
		if want != in {
			changed++
		}
		args := strings.Fields(in)
		if g, w := RedactArgs(args), plainRedactArgs(args); strings.Join(g, "\x00") != strings.Join(w, "\x00") || len(g) != len(w) {
			t.Fatalf("RedactArgs(%q)\n got %q\nwant %q", args, g, w)
		}
		live := 0
		for _, m := range sensitivePatterns {
			if m.MatchString(in) || !m.HasPrescan() {
				live++
			}
		}
		if live == 0 {
			skippedAll++
		}
	}
	prescanned := 0
	for _, m := range sensitivePatterns {
		if m.HasPrescan() {
			prescanned++
		} else {
			t.Logf("no prescan (always runs): %s", m)
		}
	}
	t.Logf("%d inputs, %d redacted, %d skipped every pattern; %d of %d patterns have a prescan", len(corpus), changed, skippedAll, prescanned, len(sensitivePatterns))
	if changed < 50 {
		t.Fatalf("only %d corpus inputs are redacted; the equivalence says little about the patterns that fire", changed)
	}
	if prescanned < len(sensitivePatterns)/2 {
		t.Errorf("only %d of %d patterns have a prescan: the redaction is not faster", prescanned, len(sensitivePatterns))
	}
}

// TestRedact_PrescanMatchesPlainRegexp_Random: random texts spliced from the
// patterns' own literals and secret shapes, so the prescans pass and fail at
// random places, including across a replacement made by an earlier pattern.
func TestRedact_PrescanMatchesPlainRegexp_Random(t *testing.T) {
	var parts []string
	for _, m := range sensitivePatterns {
		parts = append(parts, m.Literals()...)
	}
	parts = append(parts, prescanCorpus()[:200]...)
	parts = append(parts, " ", "=", ":", "'", `"`, "\n", "@", "/", "[REDACTED]", "x", "0123456789abcdef", "ABCDEFGHIJKLMNOP")
	r := rand.New(rand.NewPCG(4785, 4781))
	for i := 0; i < 20000; i++ {
		var sb strings.Builder
		for n := 1 + r.IntN(8); n > 0; n-- {
			p := parts[r.IntN(len(parts))]
			if r.IntN(3) == 0 {
				p = strings.ToUpper(p)
			}
			sb.WriteString(p)
		}
		in := sb.String()
		if got, want := Redact(in), plainRedact(in); got != want {
			t.Fatalf("Redact(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// FuzzRedact_PrescanMatchesPlainRegexp is the same property under the fuzzer.
func FuzzRedact_PrescanMatchesPlainRegexp(f *testing.F) {
	for _, s := range prescanCorpus()[:300] {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if got, want := Redact(in), plainRedact(in); got != want {
			t.Fatalf("Redact(%q)\n got %q\nwant %q", in, got, want)
		}
	})
}

// TestRedact_HandLiteralsAreRequired checks the three hand-derived literal
// sets (handLiterals) directly: every match each regexp finds, in the corpus
// and in random splices, contains one of its set's literals. A set missing a
// spelling would skip a pattern that matches, and leave a secret in the
// record; the output comparison above would catch that only on an input that
// exercises it, this checks the set itself on every match. The positive
// control: each pattern matches somewhere.
func TestRedact_HandLiteralsAreRequired(t *testing.T) {
	inputs := prescanCorpus()
	r := rand.New(rand.NewPCG(4785, 3))
	words := []string{"--password", "--PASSWD", "--pwd", "--Token", "--secret", "--api-key", "--APIKEY", "-u", "-U", "--user", "--USER",
		"password", "Passwd", "PWD", "secret", " ", "\t", "\n", "\r", "\f", "\v", "=", ":", "'", `"`, "x", "hunter2hunter2", "bob:pw9", "-"}
	for i := 0; i < 20000; i++ {
		var sb strings.Builder
		for n := 1 + r.IntN(7); n > 0; n-- {
			sb.WriteString(words[r.IntN(len(words))])
		}
		inputs = append(inputs, sb.String())
	}
	checked := 0
	for _, re := range rawSensitivePatterns {
		lits, ok := handLiterals[re.String()]
		if !ok {
			continue
		}
		checked++
		matches := 0
		for _, in := range inputs {
			for _, m := range re.FindAllString(in, -1) {
				matches++
				if strings.ContainsAny(m, foldOnlyRunesForTest) {
					// ReplaceAllString runs the regexp on any input carrying
					// one of these, so the set need not hold there.
					continue
				}
				low := asciiLower(m)
				found := false
				for _, l := range lits {
					if strings.Contains(low, l) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s matched %q in %q, which holds none of %q", re, m, in, lits)
				}
			}
		}
		t.Logf("%d matches of %s, each holding a literal", matches, re)
		if matches < 20 {
			t.Errorf("only %d matches of %s: the check is close to vacuous", matches, re)
		}
	}
	if checked != len(handLiterals) {
		t.Fatalf("checked %d hand-literal patterns; handLiterals names %d (a key no longer matches its pattern's source)", checked, len(handLiterals))
	}
}

// foldOnlyRunesForTest are the two runes Go's (?i) folds onto ASCII letters
// (regexlit.foldOnlyRunes): the Kelvin sign onto k, the long s onto s.
const foldOnlyRunesForTest = "\u212a\u017f"

// asciiLower lowercases ASCII letters only, as the fold prescan compares.
// strings.ToLower also maps the Kelvin sign to k, so a check written with it
// passed the very inputs the prescan missed (#4803's Opus pass).
func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// foldRuneVariants returns s with its first k or K replaced by the Kelvin
// sign, and with its first s or S replaced by the long s, where s has one.
func foldRuneVariants(s string) []string {
	var out []string
	if i := strings.IndexAny(s, "kK"); i >= 0 {
		out = append(out, s[:i]+"\u212a"+s[i+1:])
	}
	if i := strings.IndexAny(s, "sS"); i >= 0 {
		out = append(out, s[:i]+"\u017f"+s[i+1:])
	}
	return out
}

// TestRedact_FoldOnlyRunesMatchPlainRegexp: a secret whose name is spelt with
// the Kelvin sign or the long s (`--to\u212aen <secret>`) is redacted exactly as
// the plain regexps redact it. Before the fix the ASCII fold prescan skipped
// the pattern and the secret stayed in the record (#4803's Opus pass, F1).
// The positive control counts inputs the plain loop changes, so the test
// fails if no variant reaches a pattern.
func TestRedact_FoldOnlyRunesMatchPlainRegexp(t *testing.T) {
	changed := 0
	for _, s := range prescanCorpus() {
		for _, in := range foldRuneVariants(s) {
			want := plainRedact(in)
			if got := Redact(in); got != want {
				t.Fatalf("Redact(%q)\n got %q\nwant %q", in, got, want)
			}
			if want != in {
				changed++
			}
		}
	}
	pw := "pw" + "Secret99xyz"
	for _, in := range []string{"mysql -u root --to\u212aen " + pw, "curl --u\u017fer bob:" + pw + " https://x.example"} {
		if got := Redact(in); strings.Contains(got, pw) {
			t.Errorf("Redact(%q) = %q: the secret survived", in, got)
		}
	}
	if changed < 50 {
		t.Fatalf("only %d fold-rune variants are changed by the plain regexps; the check is close to vacuous", changed)
	}
	t.Logf("%d fold-rune variants redacted, all equal to the plain regexps", changed)
}
