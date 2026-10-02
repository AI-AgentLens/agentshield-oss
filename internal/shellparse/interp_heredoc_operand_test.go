package shellparse

import "testing"

// #3970: an interpreter given a script-file operand, or the value of a
// code-carrying flag (-c/-e/-m/...), never reads a trailing HERE-STRING as
// its program — the InInterpreterHeredoc twin of #3964's cat fix, scoped to
// here-strings only (a multi-line heredoc BODY stays excused — see
// InterpreterOperandDefeatsHereString's doc comment).
func TestInterpreterOperandDefeatsHereString(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"script file operand, here-string", `python3 backup.py -c ~/.ssh/id_rsa <<< x`, true},
		{"inline code flag value, here-string", `python3 -c "print('~/.ssh/id_rsa')" <<< x`, true},
		{"node -e value, here-string", `node -e "console.log(1)" <<< x`, true},
		{"ruby script file, here-string", `ruby backup.rb -c ~/.ssh/id_rsa <<< x`, true},
		{"perl script file, here-string", `perl backup.pl -c ~/.ssh/id_rsa <<< x`, true},
		{"php script file, here-string", `php backup.php -c ~/.ssh/id_rsa <<< x`, true},
		{"Rscript script file, here-string", `Rscript backup.R -c ~/.ssh/id_rsa <<< x`, true},
		{"osascript script file, here-string", `osascript backup.scpt -c ~/.ssh/id_rsa <<< x`, true},
		{"flag before script file", `python3 -u backup.py -c ~/.ssh/id_rsa <<< x`, true},
		{"dynamic operand — conservatively treated as an operand", `python3 "$F" <<< x`, true},
		{"sudo-wrapped script file operand", `sudo python3 backup.py -c ~/.ssh/id_rsa <<< x`, true},

		{"no operand — python3 genuinely reads the here-string", `python3 <<< x`, false},
		{"only a flag — no operand", `python3 -u <<< x`, false},
		{"explicit stdin marker", `python3 - <<< x`, false},
		{"python2 not in the InInterpreterHeredoc label set", `python2 backup.py -c ~/.ssh/id_rsa <<< x`, false},
		{"no here-string at all", `python3 backup.py -c ~/.ssh/id_rsa`, false},
		{"not an interpreter", `wc -l app.py <<< x`, false},
		{"parse failure fails closed", `python3 (( <<< x`, false},

		// A multi-line HEREDOC body (not a here-string) is deliberately left
		// alone even with the identical operand present — ts-block-
		// authorized-keys-write's FP-fix (#3540) relies on the body being
		// treated as source-code text regardless of whether the interpreter
		// actually reads it from stdin.
		{"real heredoc, script file operand — NOT withdrawn", "node app.js <<EOF\nx\nEOF", false},
		{"real heredoc, inline code flag — NOT withdrawn", "python3 -c \"print(1)\" <<EOF\nx\nEOF", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := InterpreterOperandDefeatsHereString(tc.command)
			if got != tc.want {
				t.Errorf("InterpreterOperandDefeatsHereString(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}
