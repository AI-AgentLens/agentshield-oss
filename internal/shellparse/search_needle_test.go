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
			name:  "no grep-family executable at all",
			command: `cat "frida -n <process>"`,
		},
		{
			name:    "-e consumes the pattern — layout unknown, grepPatternOperand refuses",
			command: `grep -e "frida -n <process>" -r docs/`,
		},
		{
			name:    "haystack, not the needle — pattern is the first arg",
			command: `grep -i safe "frida -n <process>"`,
			// the needle ("safe") is redacted, but the sensitive text is the
			// HAYSTACK (second operand) and must stay live.
			found: true,
			items: []string{"safe"},
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
