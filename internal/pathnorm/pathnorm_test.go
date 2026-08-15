package pathnorm

import "testing"

// TestStripShellQuotes_QuoteSpliceCollapses is the core issue-2813 behavior:
// inline empty-quote pairs a shell removes must collapse so the token compares
// identically to its unquoted spelling.
func TestStripShellQuotes_QuoteSpliceCollapses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ssh-key-splice", `~/.ss'h'/id_r'sa'`, `~/.ssh/id_rsa`},
		{"double-quote-splice", `/etc/pass"w"d`, `/etc/passwd`},
		{"backslash-escape", `r\m`, `rm`},
		{"empty-double-quotes", `r""m`, `rm`},
		{"leading-quoted-abs", `"/etc/passwd"`, `/etc/passwd`},
		{"tilde-dir-splice", `~/.ss'h'/`, `~/.ssh/`},
		{"mixed-quotes", `/e't'c/pa"s"sw\d`, `/etc/passwd`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripShellQuotes(tc.in); got != tc.want {
				t.Errorf("StripShellQuotes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripShellQuotes_DynamicExpansionUntouched — tokens whose value depends on
// runtime expansion must be returned verbatim; dropping their quotes would
// corrupt the expansion syntax and can't be statically resolved anyway.
func TestStripShellQuotes_DynamicExpansionUntouched(t *testing.T) {
	cases := []string{
		`$HOME/.ss'h'`,
		`"$HOME/.ssh"`,
		"`cat file`",
		`$(cat ~/.ssh/id_rsa)`,
		`${VAR}/id_rsa`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := StripShellQuotes(in); got != in {
				t.Errorf("StripShellQuotes(%q) = %q, want unchanged", in, got)
			}
		})
	}
}

// TestStripShellQuotes_NoQuotesIsNoOp — clean tokens (the overwhelming common
// case) pass through unchanged, including empty input.
func TestStripShellQuotes_NoQuotesIsNoOp(t *testing.T) {
	cases := []string{"", "/etc/passwd", "~/.ssh/id_rsa", "rm", "--recursive", "./src/"}
	for _, in := range cases {
		if got := StripShellQuotes(in); got != in {
			t.Errorf("StripShellQuotes(%q) = %q, want unchanged", in, got)
		}
	}
}
