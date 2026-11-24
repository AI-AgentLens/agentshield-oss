package shellparse

import (
	"strings"
	"testing"
)

func TestFoldQuotedCommandWords(t *testing.T) {
	cases := []struct{ in, want string }{
		{"X=1 'cp' a b", "X=1 cp a b"},
		{"sudo \"cp\" a b", "sudo cp a b"},
		{"env 'cp' a b", "env cp a b"},
		{"echo $('cp' a b)", "echo $(cp a b)"},
		{"echo ok;  true && X=1 'mv' a b", "echo ok;  true && X=1 mv a b"},
		{"'sudo' 'cp' a b", "sudo cp a b"},
		// nothing to fold
		{"cp a b", ""},
		{"echo 'cp' a b", ""},
		{"ls 'a b' c", ""},
		{"'a b' c", ""},
		{"'$HOME/cp' a", ""},
		{"$'cp' a", ""},
		{"cp 'unterminated", ""},
		// pins from the pass 1 mutants (#4792): a word of several parts, a
		// double-quoted span holding an expansion, and a quoted verb split from
		// its path by a continuation stay as written
		{"'c'p a b", ""},
		{"\"${X}cp\" a b", ""},
		{"X=1 'cp' \\\n a", "X=1 cp \\\n a"},
		// several edits fold in one pass, text between them untouched
		{"'ls'; 'cp' a; \"mv\" b; X=1 'rm' c", "ls; cp a; mv b; X=1 rm c"},
	}
	for _, c := range cases {
		if got := FoldQuotedCommandWords(c.in); got != c.want {
			t.Errorf("FoldQuotedCommandWords(%q) = %q, want %q", c.in, got, c.want)
		}
		// Payload reading is a superset: on a command with no carrier it
		// folds exactly the same words.
		if got := FoldQuotedCommandWordsInPayloads(c.in); got != c.want {
			t.Errorf("FoldQuotedCommandWordsInPayloads(%q) = %q, want %q (no carrier here)", c.in, got, c.want)
		}
	}
}

// TestFoldQuotedCommandWordsInPayloads_4920: a quoted command word inside the
// shell source a carrier hands to a shell is folded in place, so the output is
// the bare twin; a quoted word that is data, a payload that is not shell
// source, and a spelling whose value is not its text are left alone.
func TestFoldQuotedCommandWordsInPayloads_4920(t *testing.T) {
	const p = `"cp" /tmp/x CLAUDE.md`
	const bare = `cp /tmp/x CLAUDE.md`
	carriers := []string{
		"bash -c '%s'",
		"sh -c '%s'",
		"sudo bash -c '%s'",
		"bash -s <<< '%s'",
		"bash <<< '%s'",
		"bash < <(echo '%s')",
		"bash 0< <(echo '%s')",
		"bash <(echo '%s')",
		"source <(echo '%s')",
		"bash <<EOF\n%s\nEOF",
		"bash <<'EOF'\n%s\nEOF",
		"man -P '%s' ls",
		"watch -n 1 '%s'",
		"env -S '%s'",
		"eval '%s'",
		"su -c '%s'",
		"runuser -u bob -c '%s'",
		"trap '%s' EXIT",
		"x=bash; $x -c '%s'",
		"echo ok; bash -c '%s' && true",
	}
	for _, c := range carriers {
		in := strings.Replace(c, "%s", p, 1)
		want := strings.Replace(c, "%s", bare, 1)
		if got := FoldQuotedCommandWordsInPayloads(in); got != want {
			t.Errorf("FoldQuotedCommandWordsInPayloads(%q) = %q, want %q", in, got, want)
		}
		// The top-level fold does not read payloads: main's behaviour, kept
		// for its other caller (self-protection, #4728).
		if got := FoldQuotedCommandWords(in); got != "" {
			t.Errorf("FoldQuotedCommandWords(%q) = %q, want \"\" (payloads are not its job)", in, got)
		}
	}

	cases := []struct{ in, want string }{
		// several statements in one payload, both quote styles
		{`bash -c 'echo CLAUDE.md; "cp" /tmp/x CLAUDE.md'`, `bash -c 'echo CLAUDE.md; cp /tmp/x CLAUDE.md'`},
		{`bash -c "'cp' /tmp/x CLAUDE.md"`, `bash -c "cp /tmp/x CLAUDE.md"`},
		{`bash -s <<< "echo x && 'mv' a .cursorrules"`, `bash -s <<< "echo x && mv a .cursorrules"`},
		// a quoted carrier and a quoted payload verb, folded together
		{`"bash" -c '"cp" /tmp/x CLAUDE.md'`, `bash -c 'cp /tmp/x CLAUDE.md'`},
		// a nested carrier, double quotes inside single quotes
		{`bash -c 'sh -c "'"'"'cp'"'"' a b"'`, ``},
		{`bash -c 'sh -c "echo x"; "cp" a b'`, `bash -c 'sh -c "echo x"; cp a b'`},
		{`bash -c 'eval "echo x; '"'"'cp'"'"' a b"'`, ``},
		// the payload is data, not a command word: nothing to fold
		{`bash -c 'echo "cp" /tmp/x CLAUDE.md'`, ``},
		{`bash -c 'grep "cp" CLAUDE.md'`, ``},
		{`bash -s <<< 'git commit -m "cp"'`, ``},
		// not shell source: an interpreter payload, printed text, a message
		{`python3 -c '"cp" /tmp/x CLAUDE.md'`, ``},
		{`node -e '"cp" /tmp/x CLAUDE.md'`, ``},
		{`echo '"cp" /tmp/x CLAUDE.md'`, ``},
		{`echo '"cp" /tmp/x CLAUDE.md' > notes.txt`, ``},
		{`git commit -m '"cp" /tmp/x CLAUDE.md'`, ``},
		{`echo '"cp" /tmp/x CLAUDE.md' | python3`, ``},
		{`echo '"cp" /tmp/x CLAUDE.md' | bash -c 'cat'`, ``},
		{`echo '"cp" /tmp/x CLAUDE.md' | grep cp`, ``},
		{`bash script.sh '"cp" /tmp/x CLAUDE.md'`, ``},
		{`python3 <<'EOF'` + "\n" + p + "\nEOF", ``},
		{`cat <<'EOF'` + "\n" + p + "\nEOF", ``},
		// a value that is not its text: escapes inside double quotes, an
		// unquoted heredoc with a backslash, an expansion, a joined argv
		{`bash -c "\"cp\" /tmp/x CLAUDE.md"`, ``},
		{"bash <<EOF\n\"cp\" /tmp/x \\$HOME CLAUDE.md\nEOF", ``},
		{`bash -c "$X; 'cp' /tmp/x CLAUDE.md"`, ``},
		{`bash -c $'"cp" /tmp/x CLAUDE.md'`, ``},
		{`eval '"cp"' /tmp/x CLAUDE.md`, ``},
		// a carrier's other words are data: $0 after a -c payload, man's
		// page name, a here-string to a carrier that is not a shell
		{`bash -c 'echo hi' '"cp" /tmp/x CLAUDE.md'`, ``},
		{`man -P 'less' '"cp" /tmp/x CLAUDE.md'`, ``},
		{`cat <<< '"cp" /tmp/x CLAUDE.md'`, ``},
		{`bash -c 'echo hi' <<< '"cp" /tmp/x CLAUDE.md'`, ``},
		// a carrier whose payload holds no quoted command word
		{`bash -c 'cp /tmp/x CLAUDE.md'`, ``},
		{`bash -c '"ls a" b'`, ``},
		// a parse failure
		{`bash -c '"cp" a`, ``},
	}
	for _, c := range cases {
		if got := FoldQuotedCommandWordsInPayloads(c.in); got != c.want {
			t.Errorf("FoldQuotedCommandWordsInPayloads(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// Pinned residual: an emitter piped into a shell is not read, as on
	// main. Its payload's value is not its text once the emitter decodes
	// escapes (`printf '\n"cp" …\n' | sh`), so reading only the plain
	// spelling put the plain form into TestEmittedEscapeParity's denominator
	// while the escaped spellings stayed unread, and that sweep went over
	// budget (#4929). Closing it means composing this fold with the
	// escape-decoding reading (decodeEscapes); these rows then fail and move
	// to the carriers above.
	for _, c := range []string{
		"echo '%s' | bash",
		"printf '%s' | sh",
		"echo '%s' | sudo bash -s",
		"cat <<'EOF' | bash\n%s\nEOF",
	} {
		in := strings.Replace(c, "%s", p, 1)
		if got := FoldQuotedCommandWordsInPayloads(in); got != "" {
			t.Errorf("FoldQuotedCommandWordsInPayloads(%q) = %q, want \"\" (pinned: a piped emitter is not read until the escape-decoding composition lands)", in, got)
		}
	}
	// Control for the pin: the same payload in a decomposed carrier on the
	// right of the same pipe IS read, so the "" above is about the emitter,
	// not about pipes or the payload.
	if in, want := `echo ok | bash -c '`+p+`'`, `echo ok | bash -c '`+bare+`'`; FoldQuotedCommandWordsInPayloads(in) != want {
		t.Errorf("FoldQuotedCommandWordsInPayloads(%q) = %q, want %q", in, FoldQuotedCommandWordsInPayloads(in), want)
	}
}

// TestFoldQuotedCommandWordsInPayloads_DepthBound: nested carriers are read
// up to maxPayloadFoldDepth levels, then the text is left as written.
func TestFoldQuotedCommandWordsInPayloads_DepthBound(t *testing.T) {
	// Each level wraps the previous one in `bash <<'E<n>' … E<n>`, a payload
	// whose value is its text at any depth.
	payload := `"cp" a b`
	wrap := func(s string, n int) string {
		tag := "E" + string(rune('0'+n))
		return "bash <<'" + tag + "'\n" + s + "\n" + tag
	}
	in := payload
	for n := 1; n < maxPayloadFoldDepth; n++ {
		in = wrap(in, n)
	}
	want := strings.Replace(in, payload, "cp a b", 1)
	if got := FoldQuotedCommandWordsInPayloads(in); got != want {
		t.Fatalf("depth %d: got %q, want %q", maxPayloadFoldDepth-1, got, want)
	}
	if got := FoldQuotedCommandWordsInPayloads(wrap(in, maxPayloadFoldDepth)); got != "" {
		t.Fatalf("depth %d: got %q, want \"\" (past the bound)", maxPayloadFoldDepth, got)
	}
}
