package shellparse

import (
	"reflect"
	"testing"
)

// TestSubstitutionBodies pins what #3814 hands to the intent site: the
// program text inside each outermost substitution, and nothing for the
// shapes that execute nothing. The "nil" half is the doc-text population
// the labels exist for and is as load-bearing as the other.
func TestSubstitutionBodies(t *testing.T) {
	cases := []struct {
		name string
		stmt string
		want []string
	}{
		// The three shapes from the issue.
		{"cmdsubst in echo arg", `echo "$(cat /tmp/x)"`, []string{"cat /tmp/x"}},
		{"unquoted cmdsubst", `echo $(cat /tmp/x)`, []string{"cat /tmp/x"}},
		{"backtick form", "echo \"`cat /tmp/x`\"", []string{"cat /tmp/x"}},
		{"cmdsubst in commit message", `git commit -m "$(cat /tmp/x)"`, []string{"cat /tmp/x"}},
		{"unquoted-delimiter heredoc body expands", "cat > /tmp/n.txt <<EOF\n$(cat /tmp/x)\nEOF", []string{"cat /tmp/x"}},
		{"dash-heredoc unquoted delimiter", "cat > /tmp/n.txt <<-EOF\n\t$(cat /tmp/x)\nEOF", []string{"cat /tmp/x"}},
		{"double-quoted delimiter is literal", "cat > /tmp/n.txt <<\"EOF\"\n$(cat /tmp/x)\nEOF", nil},

		// Trap 2: a quoted delimiter keeps the body literal.
		{"quoted-delimiter heredoc body is literal", "cat > /tmp/n.txt <<'EOF'\n$(cat /tmp/x)\nEOF", nil},
		{"backslash-quoted delimiter is literal", "cat > /tmp/n.txt <<\\EOF\n$(cat /tmp/x)\nEOF", nil},

		// Trap 1 is the caller's (the rule match must fall inside), but the
		// bodies it needs are exactly these.
		{"benign substitution beside doc text", `echo "note: cat /tmp/x is blocked ($(date))"`, []string{"date"}},
		{"two substitutions in source order", `echo "$(date) $(cat /tmp/x)"`, []string{"date", "cat /tmp/x"}},

		// Process substitution is the same executor semantics.
		{"input process substitution", `diff <(cat /tmp/x) /dev/null`, []string{"cat /tmp/x"}},
		{"output process substitution", `echo hi > >(tee /tmp/log)`, []string{"tee /tmp/log"}},

		// Nesting: the outer body is returned whole; the caller recurses.
		{"nested substitution returns the outer body", `echo "$(echo "$(cat /tmp/x)")"`, []string{`echo "$(cat /tmp/x)"`}},
		{"substitution inside arithmetic", `echo $(( $(cat /tmp/x) + 1 ))`, []string{"cat /tmp/x"}},
		{"substitution in a redirect target", `echo hi > "$(cat /tmp/x)"`, []string{"cat /tmp/x"}},
		{"substitution in an assignment", `X=$(cat /tmp/x)`, []string{"cat /tmp/x"}},
		{"substitution split across lines", "echo \"$(\n  cat /tmp/x\n)\"", []string{"cat /tmp/x"}},
		{"multi-statement body", `echo "$(cd /tmp; cat x)"`, []string{"cd /tmp; cat x"}},
		{"IFS glued to the opener", "echo${IFS}\"$(cat${IFS}/tmp/x)\"", []string{"cat /tmp/x"}},
		{"cat heredoc inside the substitution", "git commit -m \"$(cat <<'EOF'\nprose\nEOF\n)\"", []string{"cat <<'EOF'\nprose\nEOF"}},

		// Nothing executes.
		{"parameter expansion", `echo "note: ${USER}"`, nil},
		{"bare parameter", `echo "note: $USER"`, nil},
		{"arithmetic expansion", `echo "note: $((1+2))"`, nil},
		{"single-quoted dollar-paren is text", `echo 'note: $(cat /tmp/x)'`, nil},
		{"single-quoted backtick is text", "echo 'note: `cat /tmp/x`'", nil},
		{"escaped dollar-paren is text", `echo "note: \$(cat /tmp/x)"`, nil},
		{"empty substitution", `echo "$()"`, nil},
		{"plain doc text", `echo "note: cat /tmp/x is blocked"`, nil},
		{"pipe is the other function's job", `echo "cat /tmp/x" | bash`, nil},
		{"redirect angle brackets are not procsubst", `echo hi > /tmp/n.txt < /dev/null`, nil},
		{"-c string is not entered", `bash -c 'echo "$(cat /tmp/x)"'`, nil},
		{"unterminated is not evidence", `echo "$(cat /tmp/x`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SubstitutionBodies(tc.stmt)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SubstitutionBodies(%q)\n got  %q\n want %q", tc.stmt, got, tc.want)
			}
		})
	}
}
