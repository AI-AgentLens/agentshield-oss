package analyzer

import "testing"

// The two kinds of command_regex_exclude want OPPOSITE scoping, and
// isPositionSensitive is the only thing that tells them apart (#3901).
//
//   - POSITIONAL  "this benign tool is what is being run HERE". A claim about a
//     statement, so it must be re-evaluated per statement — otherwise a tool in
//     a statement that merely PRECEDES the malicious one suppresses the rule.
//   - GUARD       "this command carries a safety property" (AUTH_ENABLED=true,
//     --host 127.0.0.1). A claim about the WHOLE command; re-evaluating it per
//     statement breaks it, because a candidate form of one statement need not
//     carry the property that proves the command safe.
//
// The first cut of the #3901 fix retried EVERY rule carrying an exclusion and
// turned `AUTH_ENABLED=true AUTH_TOKEN=s3cr3t python api_server.py` into a
// BLOCK. TN-ORCHFAILOPEN-002 caught it in the corpus; this pins the intent
// directly, so the next person to widen the predicate has to delete a row that
// says why they should not.
func TestIsPositionSensitive_ExclusionKinds(t *testing.T) {
	cases := []struct {
		name string
		rule RegexRule
		want bool
	}{
		// Positional exclusions — the #3901 class. Each must be retried.
		{
			name: "positional: separator-anchored tool exclusion",
			rule: RegexRule{
				Regex:        `\bclaude\b.*--dangerously-skip-permissions\b`,
				RegexExclude: `(?:^|&&\s*|;\s*|\|\s*)\s*sed\s`,
			},
			want: true,
		},
		{
			name: "positional: bare ^ anchored exclusion",
			rule: RegexRule{
				Regex:        `(?i)\bsure[,!]?\s+here`,
				RegexExclude: `^(echo|printf|cat|#)\b`,
			},
			want: true,
		},

		// Guard-condition exclusions — a property of the whole command. These
		// must NOT be retried, or the guard stops proving anything.
		{
			name: "guard: no anchor at all (the ORCHFAILOPEN shape)",
			rule: RegexRule{
				Regex:        `\bpython[23]?\s+api_server\.py\b`,
				RegexExclude: `--host\s+(?:127\.0\.0\.1|localhost)\b|\bAUTH_ENABLED\s*=\s*(?:true|1|True)\b`,
			},
			want: false,
		},
		{
			name: "guard: unanchored tool alternation is still a guard",
			rule: RegexRule{
				Regex:        `\bsomething\b`,
				RegexExclude: `\b(grep|rg|awk|sed)\b`,
			},
			want: false,
		},

		// A `^` that only negates a character class is not an anchor. Without
		// this, every exclusion carrying `[^;&|]` — which is exactly what the
		// same-statement FIX shape uses — would be misread as positional.
		{
			name: "negated char class is not an anchor",
			rule: RegexRule{
				Regex:        `\bfoo\b`,
				RegexExclude: `\bbar\s[^;&|]*baz`,
			},
			want: false,
		},
		{
			name: "negated char class AND a real anchor is positional",
			rule: RegexRule{
				Regex:        `\bfoo\b`,
				RegexExclude: `(?:^|&&\s*)\s*bar\s[^;&|]*baz`,
			},
			want: true,
		},

		// The pre-existing reasons, unchanged by #3901.
		{name: "own regex anchored ^", rule: RegexRule{Regex: `^rm\b`}, want: true},
		{name: "own regex anchored $", rule: RegexRule{Regex: `\.safetensors$`}, want: true},
		{name: "exact match", rule: RegexRule{Exact: "rm -rf /"}, want: true},
		{name: "prefix match", rule: RegexRule{Prefixes: []string{"sudo "}}, want: true},
		{name: "plain unanchored, no exclusion", rule: RegexRule{Regex: `\bcurl\b`}, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPositionSensitive(tc.rule); got != tc.want {
				t.Errorf("isPositionSensitive = %v, want %v\n  regex:   %q\n  exclude: %q",
					got, tc.want, tc.rule.Regex, tc.rule.RegexExclude)
			}
		})
	}
}

func TestHasPositionalAnchor(t *testing.T) {
	cases := []struct {
		pat  string
		want bool
	}{
		{"", false},
		{`^foo`, true},
		{`(?:^|&&\s*|;\s*)sed\s`, true},
		{`[^;&|]*`, false},
		{`[^']*'[^']*`, false},
		{`\bfoo\b|\bbar\b`, false},
		{`[^a]^b`, true}, // a negated class does not hide a later real anchor
	}
	for _, tc := range cases {
		if got := hasPositionalAnchor(tc.pat); got != tc.want {
			t.Errorf("hasPositionalAnchor(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
}
