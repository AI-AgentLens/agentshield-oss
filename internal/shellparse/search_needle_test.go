package shellparse

import "testing"

// The FP that motivated this (#3382): a search for a documented command
// example, quoted so the pattern operand spans a whole phrase.
func TestSearchToolNeedles(t *testing.T) {
	tests := []struct {
		name    string
		command string
		found   bool
		items   []string
	}{
		{
			name:    "quoted multi-word needle — the reported FP",
			command: `grep -i "frida -n <process>" -r docs/`,
			found:   true,
			items:   []string{`"frida -n <process>"`},
		},
		{
			name:    "bare needle, no flags after the pattern",
			command: `grep frida -r .`,
			found:   true,
			items:   []string{`frida`},
		},
		{
			name:    "single-quoted needle",
			command: `grep -i 'frida --name chrome' -r .`,
			found:   true,
			items:   []string{`'frida --name chrome'`},
		},
		{
			name:    "ripgrep",
			command: `rg -i "frida -n <process>" docs/`,
			found:   true,
			items:   []string{`"frida -n <process>"`},
		},
		{
			name:    "egrep and fgrep",
			command: `egrep "frida -n x" . ; fgrep "frida -n y" .`,
			found:   true,
			items:   []string{`"frida -n x"`, `"frida -n y"`},
		},
		{
			name:    "ag",
			command: `ag "frida -n <process>" docs/`,
			found:   true,
			items:   []string{`"frida -n <process>"`},
		},
		{
			name:    "short flag cluster before the needle",
			command: `grep -rni "frida -n <process>" docs/`,
			found:   true,
			items:   []string{`"frida -n <process>"`},
		},
		{
			name:    "two independent invocations",
			command: `grep -i "frida -n x" . && grep -i "chrome --name y" .`,
			found:   true,
			items:   []string{`"frida -n x"`, `"chrome --name y"`},
		},

		// --- not redacted: ambiguous or non-search shapes ---
		{
			name:    "no grep-family executable at all",
			command: `cat "frida -n <process>"`,
		},
		{
			name:    "-e consumes the pattern — layout unknown, grepPatternOperand refuses",
			command: `grep -e "frida -n <process>" -r docs/`,
		},
		// #3690: an $IFS-glued flag+value pair parses as ONE dynamic word
		// (Lit("-e") + ParamExp("IFS") + the quoted pattern) — staticWord
		// can't resolve it, so it reports "" the same as a fully-dynamic
		// standalone word. Before the #3690 fix, grepPatternOperand treated
		// "" as "definitely not a flag" and returned this word's index as
		// the pattern operand, redacting a REAL hex-encoded command word
		// along with the ambiguous "-e" flag it was fused to — a live
		// bypass of any rule using search_needle. Must refuse (no redaction)
		// exactly like the fully-static "-e" case above.
		{
			name:    "#3690: $IFS-glued flag+value fuses into one dynamic word — grepPatternOperand still refuses",
			command: "grep -e${IFS}\"frida -n <process>\" -r docs/",
		},
		// The other half of the #3690 fix: a BARE dynamic word with no
		// literal flag prefix (a loop variable standing on its own) is not
		// ambiguous — no expansion can synthesize a leading "-" out of
		// nothing written into the word — so it must still be identified as
		// the pattern operand, unchanged from before the fix.
		{
			name:    "#3690 regression guard: a bare dynamic pattern (no flag prefix) is still identified",
			command: `grep -n $p notes.txt`,
			found:   true,
			items:   []string{`$p`},
		},

		// --- #3728 finding B: INLINE pattern-bearing flags glued into one word
		// (`-eVALUE`, `-e"$p"`, `--regexp=VALUE`). The value is the needle and
		// is resolved to its subspan — the flag prefix is left intact. Before
		// the fix these were refused (the leading-dash guard treated the whole
		// -e"$p" word as ambiguous), which was a new false BLOCK on a plain
		// search.
		{
			name:    `#3728: -e"$p" glued quoted value — value subspan is the needle`,
			command: `grep -e"$p" notes.txt`,
			found:   true,
			items:   []string{`"$p"`},
		},
		{
			name:    "#3728: -efoo glued literal value",
			command: `grep -efoo notes.txt`,
			found:   true,
			items:   []string{`foo`},
		},
		{
			name:    `#3728: --regexp="$p" long inline form`,
			command: `grep --regexp="$p" notes.txt`,
			found:   true,
			items:   []string{`"$p"`},
		},
		{
			name:    "#3728: --regexp=foo long inline literal form",
			command: `grep --regexp=foo notes.txt`,
			found:   true,
			items:   []string{`foo`},
		},
		{
			name:    "#3728: -rie cluster ending in the pattern flag, glued value",
			command: `grep -rie"$p" notes.txt`,
			found:   true,
			items:   []string{`"$p"`},
		},

		// --- #3728 finding B, the other direction: forms that MUST still refuse
		// so the #3690 fix (and the #3729-tracked bypass) do not regress.
		{
			name:    "#3728: -e$p unquoted glued value can word-split — still refuses",
			command: `grep -e$p notes.txt`,
		},
		{
			name:    "#3728: -f is a pattern FILE, not a needle — stays live",
			command: `grep -f patterns.txt notes.txt`,
		},
		{
			name:    `#3728: -e"$(cmd)" executes (the #3729 class) — inline form declines`,
			command: `grep -e"$(cat x)" notes.txt`,
		},
		{
			name:    "haystack, not the needle — pattern is the first arg",
			command: `grep -i safe "frida -n <process>"`,
			// the needle ("safe") is redacted, but the sensitive text is the
			// HAYSTACK (second operand) and must stay live.
			found: true,
			items: []string{"safe"},
		},

		// --- #3729: a bare command/process substitution used as the WHOLE
		// pattern operand runs BEFORE grep ever sees a value, so it must
		// never be treated as an inert needle. These must stay live (no
		// redaction) so a rule matching the executed text keeps firing.
		{
			name:    "#3729: command substitution as the bare pattern — executes before grep, must stay live",
			command: `grep "$(frida -n chrome)" notes.txt`,
		},
		{
			name:    "#3729: hex-encoded command substitution as the pattern — must stay live",
			command: `grep "$(printf '\x74\x6f\x75\x63\x68 /tmp/x')" /dev/null`,
		},
		{
			name:    "#3729: unquoted bare command substitution — must stay live",
			command: `grep $(frida -n chrome) notes.txt`,
		},
		{
			name:    "#3729: process substitution as the pattern — must stay live",
			command: `grep <(frida -n chrome) notes.txt`,
		},
		{
			name:    "#3729: command substitution nested inside a parameter default — must stay live",
			command: `grep "${p:-$(frida -n chrome)}" notes.txt`,
		},
		{
			name:    "#3729 regression guard: a plain quoted variable is still an inert needle",
			command: `grep "$p" notes.txt`,
			found:   true,
			items:   []string{`"$p"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, redacted := SearchToolNeedles(tt.command)
			if tt.found {
				if redacted == "" {
					t.Fatalf("expected a redaction, got none")
				}
				if len(items) != len(tt.items) {
					t.Fatalf("items = %#v, want %#v", items, tt.items)
				}
				for i, want := range tt.items {
					if items[i] != want {
						t.Errorf("items[%d] = %q, want %q", i, items[i], want)
					}
				}
				for _, it := range items {
					if redacted == tt.command || containsAll(redacted, it) {
						t.Errorf("redacted command still contains needle %q: %q", it, redacted)
					}
				}
			} else if redacted != "" {
				t.Fatalf("expected no redaction, got items=%#v redacted=%q", items, redacted)
			}
		})
	}
}

func containsAll(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}

// The haystack argument (the file/text being searched) must never be treated
// as the needle — that would redact the wrong side of the search and hide a
// real target from the rule it belongs to.
func TestSearchToolNeedlesNeverRedactsHaystack(t *testing.T) {
	items, redacted := SearchToolNeedles(`grep -i safe "frida -n <process>"`)
	if redacted == "" {
		t.Fatal("expected a redaction of the pattern operand")
	}
	for _, it := range items {
		if it != "safe" {
			t.Errorf("redacted the haystack, not the needle: %q", it)
		}
	}
	if !containsAll(redacted, `"frida -n <process>"`) {
		t.Errorf("haystack was redacted away: %q", redacted)
	}
}

func TestSearchToolNeedlesNoOp(t *testing.T) {
	items, redacted := SearchToolNeedles(`ls -la /tmp`)
	if items != nil || redacted != "" {
		t.Fatalf("expected no-op sentinel, got items=%#v redacted=%q", items, redacted)
	}
}
