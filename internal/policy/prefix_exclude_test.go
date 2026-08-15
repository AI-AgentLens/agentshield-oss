package policy

import "testing"

// TestPrefixRuleHonoursRegexExclude is the test whose absence made
// command_regex_exclude a latent trap on prefix/exact rules (#3232).
//
// The exclude was consulted only inside matchRule's command_regex branch, so a
// rule combining command_prefix with command_regex_exclude got an exclude that
// parsed, passed load-time validation, and did nothing. Nothing failed. No
// shipped rule used that combination, which is precisely why it survived — the
// first rule to reach for it would silently have got no exclusion.
//
// That is this repo's "documented != enforced" shape one level in: not a gate
// nobody runs, but a schema field that is honoured on one match kind and
// ignored on the others. Both directions are asserted here, and for ALLOW rules
// specifically, because an ALLOW that fires when it should not is worse than a
// missing rule — it decides the command safe BELOW the AUDIT default.
func TestPrefixRuleHonoursRegexExclude(t *testing.T) {
	rule := Rule{
		ID: "test-allow-readonly-like",
		Match: Match{
			CommandPrefix:       []string{"man ", "sort "},
			CommandRegexExclude: `man\b[^;|&]*\s-P\b|sort\b[^;|&]*\s--compress-program[=\s]`,
		},
		Decision: "ALLOW",
	}
	exactRule := Rule{
		ID: "test-exact",
		Match: Match{
			CommandExact:        "man ls",
			CommandRegexExclude: `-P\b`,
		},
		Decision: "ALLOW",
	}

	engine, err := NewEngine(&Policy{Rules: []Rule{rule, exactRule}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name    string
		rule    Rule
		command string
		want    bool
	}{
		{"prefix matches, exclude quiet", rule, "man ls", true},
		{"prefix matches, exclude quiet (sort)", rule, "sort -u /tmp/list.txt", true},
		{"prefix matches but exclude fires", rule, "man -P /bin/sh ls", false},
		{"prefix matches but exclude fires (sort)", rule, "sort --compress-program=/bin/sh f", false},
		{"prefix does not match at all", rule, "rm -rf /", false},
		{"exact matches, exclude quiet", exactRule, "man ls", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := engine.matchRule(tc.command, tc.rule); got != tc.want {
				t.Errorf("matchRule(%q) = %v, want %v — command_regex_exclude must apply "+
					"to prefix/exact matches, not only to command_regex ones", tc.command, got, tc.want)
			}
			// matchRulePattern is the #2843 downgrade's per-statement predicate
			// and duplicates the same three branches; it must agree.
			if got := engine.matchRulePattern(tc.command, tc.rule); got != tc.want {
				t.Errorf("matchRulePattern(%q) = %v, want %v (drifted from matchRule)", tc.command, got, tc.want)
			}
		})
	}
}
