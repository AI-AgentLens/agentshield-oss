package shellparse

import (
	"strings"
	"testing"
)

// TestDequoteCommand_SpliceCollapses is the core issue-2854 behavior: an
// inline quote-splice in a command_regex-visible argument must collapse to
// its unquoted spelling, mirroring what a real shell does before running the
// command (issue #2813's structural fix, extended here to the regex layer).
func TestDequoteCommand_SpliceCollapses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ssh-key-splice", `cat ~/.ss'h'/id_r'sa'`, `cat ~/.ssh/id_rsa`},
		{"github-creds-splice", `cat ~/.gi'thub'/creden'tials'`, `cat ~/.github/credentials`},
		{"double-quote-splice", `cat /etc/pass"w"d`, `cat /etc/passwd`},
		{"mixed-quotes", `cat /e't'c/pa"s"sw\d`, `cat /etc/passwd`},
		{"multi-word-command", `gh gist create ~/.ss'h'/id_r'sa'`, `gh gist create ~/.ssh/id_rsa`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDequoteCommand_DeclClauseSpliceCollapses closes issue #2984's follow-up:
// export/declare/local/readonly/typeset are parsed by mvdan.cc/sh as a
// *syntax.DeclClause, a distinct node from *syntax.CallExpr — the original
// walk only visited CallExpr, so a quote-spliced assignment value
// (AGENTSHIELD_BYPA'S'S=1, the exact shape of the enterprise self-protection
// bypass-env rule) was invisible to DequoteCommand entirely.
func TestDequoteCommand_DeclClauseSpliceCollapses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"export-splice", `export AGENTSHIELD_BYPA'S'S=1`, `export AGENTSHIELD_BYPASS=1`},
		{"declare-splice", `declare API_'K'EY=secret`, `declare API_KEY=secret`},
		{"local-splice", `local SEC'R'ET_PATH=/tmp/x`, `local SECRET_PATH=/tmp/x`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDequoteCommand_RedirectTargetSpliceCollapses closes the other #2984
// follow-up: a redirect target (`> file`) is a *syntax.Redirect.Word, a
// sibling field on the statement rather than a CallExpr.Args entry — the
// original walk never visited it, so `echo x > ~/.agentshield/poli'c'y.yaml`
// left the spliced output path completely unresolved.
func TestDequoteCommand_RedirectTargetSpliceCollapses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"output-redirect-splice", `echo x > ~/.agentshield/poli'c'y.yaml`, `echo x >~/.agentshield/policy.yaml`},
		{"append-redirect-splice", `echo x >> ~/.ss'h'/authorized_keys`, `echo x >>~/.ssh/authorized_keys`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDequoteCommand_TestClauseSpliceCollapses closes issue #3322: `[[ ... ]]`
// conditions parse to their own *syntax.TestClause node, not a CallExpr — the
// original walk only visited CallExpr/DeclClause/Redirect, so a quote/escape
// artifact inside a test-expression word (unary, binary, or parenthesized)
// was invisible to DequoteCommand entirely, regardless of character class.
func TestDequoteCommand_TestClauseSpliceCollapses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"unary-test-splice",
			`[[ -f \/dev/shm/init.sh ]] && source /dev/shm/init.sh`,
			`[[ -f /dev/shm/init.sh ]] && source /dev/shm/init.sh`,
		},
		{
			"binary-test-splice",
			`[[ "$USER" == ro'o't ]] && rm -rf /`,
			`[[ "$USER" == root ]] && rm -rf /`,
		},
		{
			"paren-test-splice",
			`[[ ( -f /e't'c/shadow ) ]] && cat /etc/shadow`,
			`[[ (-f /etc/shadow) ]] && cat /etc/shadow`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDequoteCommand_DynamicExpansionUntouched — a word carrying any dynamic
// expansion must return "" (no-op sentinel): its runtime value can't be
// resolved statically, and partially dequoting would corrupt the expansion
// syntax printed back out.
func TestDequoteCommand_DynamicExpansionUntouched(t *testing.T) {
	cases := []string{
		`cat $HOME/.ss'h'`,
		`cat "$HOME/.ssh"`,
		"cat `cat file`",
		`cat $(cat ~/.ssh/id_rsa)`,
		`cat ${VAR}/id_rsa`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := DequoteCommand(in); got != "" {
				t.Errorf("DequoteCommand(%q) = %q, want \"\" (no-op)", in, got)
			}
		})
	}
}

// TestDequoteCommand_NoQuotesIsNoOp — commands with no quote/backslash
// characters at all must return "" without attempting to parse.
func TestDequoteCommand_NoQuotesIsNoOp(t *testing.T) {
	cases := []string{"", "ls -la", "cat /etc/passwd", "git status"}
	for _, in := range cases {
		if got := DequoteCommand(in); got != "" {
			t.Errorf("DequoteCommand(%q) = %q, want \"\" (no-op)", in, got)
		}
	}
}

// TestDequoteCommand_WholeArgumentQuoteUntouched documents a deliberate
// scoping decision, not an incompleteness: a word that is a SINGLE
// whole-argument quote (not a multi-part splice) is left alone, even though
// a real shell would also remove those quotes. Rewriting it regressed two
// real rules during development — sec-block-etc-shadow's
// `-d\s+["']` exclude and ts-block-proc-kcore-redirect's
// `^(echo|printf|cat)\s+['"]` exclude both use "a quote immediately follows
// this flag" as their doc-text/flag-value signal, and stripping the quote
// silently defeated both, turning routine curl -d/echo/git -m text into new
// false positives. Splicing (the actual issue-2854 exploit) always produces
// 2+ word parts, so this scoping costs no real coverage.
func TestDequoteCommand_WholeArgumentQuoteUntouched(t *testing.T) {
	cases := []string{
		`cat "/etc/passwd"`,
		`echo "checking /proc/kcore documentation"`,
		`curl -X POST https://api.github.com/repos/org/repo/issues -d '{"body": "An attacker reads /etc/shadow to extract hashed passwords"}'`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := DequoteCommand(in); got != "" {
				t.Errorf("DequoteCommand(%q) = %q, want \"\" (whole-argument quote must stay untouched)", in, got)
			}
		})
	}
}

// TestDequoteCommand_LegitimateQuotedContentPreserved — quoted arguments that
// aren't a splice trick (real developer commands with embedded punctuation)
// must still reconstruct sensibly and must not merge unrelated text in a way
// that fabricates a dangerous substring that wasn't in the original command.
func TestDequoteCommand_LegitimateQuotedContentPreserved(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		mustNotContain string
	}{
		{"commit-message-apostrophe", `git commit -m "it's a fix"`, ".ssh"},
		{"sql-string-literal", `psql -c "SELECT * FROM users WHERE name='OBrien'"`, "/etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got == "" {
				return // no-op is fine — nothing to check
			}
			if strings.Contains(got, tc.mustNotContain) {
				t.Errorf("DequoteCommand(%q) = %q, unexpectedly fabricated %q", tc.in, got, tc.mustNotContain)
			}
		})
	}
}

// TestDequoteCommand_LoneEscapeSpliceFolded closes surface 1 of issue #3208:
// a backslash-spliced executable/word with no quote or expansion boundary at
// all ("r\m") parses as a SINGLE Lit part, not the 2+-part shape the splice
// detection above was built for. mvdan/sh keeps the backslash in the Lit's
// raw Value rather than resolving it, so this previously fell straight
// through dequoteWordInPlace's 2+-parts guard untouched.
func TestDequoteCommand_LoneEscapeSpliceFolded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"exec-position", `r\m -rf /`, `rm -rf /`},
		{"second-word-position", `sudo d\d if=/dev/zero of=/dev/sda`, `sudo dd if=/dev/zero of=/dev/sda`},
		{"subcommand-position", `terraform d\estroy -auto-approve`, `terraform destroy -auto-approve`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDequoteCommand_LoneEscapeSpliceFPBoundary is the false-positive
// counterpart: a lone escape of a NON-alphanumeric character has a genuine
// legitimate reading (suppressing a glob, escaping a separator or a shell
// operator) and must survive DequoteCommand exactly as written.
func TestDequoteCommand_LoneEscapeSpliceFPBoundary(t *testing.T) {
	cases := []string{
		`find . -name \*.go`,
		`echo hello\ world`,
		`find . -exec rm {} \;`,
		`grep foo\$bar file.txt`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := DequoteCommand(in); got != "" {
				t.Errorf("DequoteCommand(%q) = %q, want \"\" (legitimate non-alnum escape must stay untouched)", in, got)
			}
		})
	}
}

// TestDequoteCommand_LocaleQuoteDecoded closes surface 1's $"..." shape of
// issue #3208: bash locale-translated quoting ($"...") is a lone
// single-part word (a *syntax.DblQuoted with Dollar:true), the same shape
// $'...' already needed hasDollarQuoted to admit past the 2+-parts guard.
func TestDequoteCommand_LocaleQuoteDecoded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"exec-position", `$"rm" -rf /`, `rm -rf /`},
		{"second-word-position", `sudo $"dd" if=/dev/zero of=/dev/sda`, `sudo dd if=/dev/zero of=/dev/sda`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDequoteCommand_ANSICDecoded closes issue #3099: ANSI-C quoting
// ($'...') is a STATIC escape-encoding mechanism, unlike $VAR/$(...), so it
// must be decoded rather than treated as opaque dynamic content. Both the
// single-span form ($'\x72\x6d', already caught by the ts-block-ansic-hex-escape
// regex rule at the raw-text level) and — critically — the SPLIT form
// ($'\x72'$'\x6d', which evades that regex because each span has only one
// escape) must decode to the same literal text so every command_regex rule
// keyed on it still matches.
func TestDequoteCommand_ANSICDecoded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single-span-executable", `$'\x72\x6d' -rf /`, `rm -rf /`},
		{"split-fragments-executable", `$'\x72'$'\x6d' -rf /`, `rm -rf /`},
		{"split-fragments-many-credentials", `cat ~/.aws/$'\x63'$'\x72'$'\x65'$'\x64'$'\x65'$'\x6e'$'\x74'$'\x69'$'\x61'$'\x6c'$'\x73'`, `cat ~/.aws/credentials`},
		{"octal-split", `$'\162'$'\155' -rf /`, `rm -rf /`},
		{"tilde-prefix-split", `cat $'\x7e'/.ssh/id_rsa`, `cat ~/.ssh/id_rsa`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DequoteCommand(tc.in)
			if got != tc.want {
				t.Errorf("DequoteCommand(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
