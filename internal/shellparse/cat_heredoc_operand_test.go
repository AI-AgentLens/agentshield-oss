package shellparse

import "testing"

// #3964: `cat FILE <<EOF`/`cat FILE <<< x` reads FILE and ignores the
// heredoc/here-string entirely — cat only consumes stdin when given no
// operand or an explicit `-`.
func TestCatReadsFileOperandInsteadOfHeredoc(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"file operand, here-string", `cat ~/.ssh/id_rsa <<< x`, true},
		{"file operand, quoted heredoc", "cat /etc/shadow <<'EOF'\nx\nEOF", true},
		{"file operand, unquoted heredoc", "cat /etc/shadow <<EOF\nx\nEOF", true},
		{"flag before file operand", `cat -A ~/.ssh/id_rsa <<< x`, true},
		{"dynamic operand — conservatively treated as a file", `cat "$KEY_PATH" <<< x`, true},
		{"sudo-wrapped file operand", `sudo cat ~/.ssh/id_rsa <<< x`, true},
		{"multiple file operands, second one live", `cat /dev/null ~/.ssh/id_rsa <<< x`, true},

		{"no operand — cat genuinely reads the heredoc", `cat <<< x`, false},
		{"only a flag — no operand", `cat -A <<< x`, false},
		{"explicit stdin marker", `cat - <<< x`, false},
		{"redirect target is not an argument to cat", "cat > /tmp/notes.txt <<'EOF'\nbody\nEOF", false},
		{"tee is unaffected — always reads stdin regardless of operand", `tee ~/.ssh/authorized_keys <<< x`, false},
		{"no heredoc/here-string at all", `cat ~/.ssh/id_rsa`, false},
		{"not cat", `wc -l ~/.ssh/id_rsa <<< x`, false},
		{"parse failure fails closed", `cat (( <<< x`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CatReadsFileOperandInsteadOfHeredoc(tc.command)
			if got != tc.want {
				t.Errorf("CatReadsFileOperandInsteadOfHeredoc(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}
