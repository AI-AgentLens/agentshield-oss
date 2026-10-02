package shellparse

import (
	"reflect"
	"testing"
)

func TestExecutedText(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{"echo piped into bash", `echo 'install -m 4755 x y ' | bash`, []string{"install -m 4755 x y"}},
		{"printf piped into sh", `printf 'getent shadow\n' | sh`, []string{"getent shadow"}},
		{"echo -e decodes its separators (#3802)", `echo -e '\ngetent shadow' | bash`, []string{`\ngetent shadow`, "getent shadow"}},
		{"printf decodes a tab in the format", `printf '\tgetent shadow\n' | sh`, []string{`\tgetent shadow`, "getent shadow"}},
		{"echo without -e keeps the backslash", `echo '\ngetent shadow' | bash`, []string{`\ngetent shadow`}},
		{"heredoc piped into bash", "cat <<'EOF' | bash\ngetent shadow\nEOF", []string{"getent shadow"}},
		{"write then execute", `echo 'getent shadow' > /tmp/r.sh; bash /tmp/r.sh`, []string{"getent shadow"}},
		{"command substitution", `echo "$(pkexec bash )"`, []string{"pkexec bash"}},
		{"backquote substitution", "echo \"`pkexec bash`\"", []string{"pkexec bash"}},
		{"substitution inside a commit message", `git commit -m "$(pkexec bash)"`, []string{"pkexec bash"}},
		{"process substitution", `diff <(getent shadow) /dev/null`, []string{"getent shadow"}},

		// Refusals: nothing here executes the emitted text.
		{"echo alone prints", `echo 'install -m 4755 x y'`, nil},
		{"echo into a non-executor", `echo 'install -m 4755 x y' | grep x`, nil},
		{"echo into notes", `echo 'getent shadow' >> notes.md`, nil},
		{"single-quoted substitution is a literal", `echo '$(pkexec bash)'`, nil},
		{"unknown program", `echo "$x" | bash`, nil},
		{"plain command has nothing to add", `getent shadow`, nil},

		// A substitution whose OUTPUT runs: what executes is the text the
		// body emits, not the body (#3976 evidence). The body itself stays a
		// candidate from the substitution walk, so it is listed first.
		{"heredoc in cmdsub run by bash -c", "bash -c \"$(cat <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"cat <<'EOF'\nzqattach -n target\nEOF", "zqattach -n target"}},
		{"heredoc in cmdsub run by eval", "eval \"$(cat <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"cat <<'EOF'\nzqattach -n target\nEOF", "zqattach -n target"}},
		{"heredoc in procsub run by bash", "bash <(cat <<'EOF'\nzqattach -n target\nEOF\n)", []string{"cat <<'EOF'\nzqattach -n target\nEOF", "zqattach -n target"}},
		{"heredoc captured then eval'd", "x=$(cat <<'EOF'\nzqattach -n target\nEOF\n)\neval \"$x\"", []string{"cat <<'EOF'\nzqattach -n target\nEOF", "zqattach -n target"}},
		{"tee copies the heredoc to stdout", "bash -c \"$(tee /tmp/log <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"tee /tmp/log <<'EOF'\nzqattach -n target\nEOF", "zqattach -n target"}},
		{"last pipeline stage and && members write the output", "eval \"$(true | cat <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"true | cat <<'EOF'\nzqattach -n target\nEOF", "zqattach -n target"}},
		{"echo -e in an eval'd cmdsub decodes its separators", `eval "$(echo -e 'true\nzqattach -n target')"`, []string{`echo -e 'true\nzqattach -n target'`, `true\nzqattach -n target`, "true\nzqattach -n target"}},

		// Refusals: the substitution's output is not the heredoc text.
		{"printed, not run: body only", "echo \"$(cat <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"cat <<'EOF'\nzqattach -n target\nEOF"}},
		{"cat with a file operand prints the file", "bash -c \"$(cat notes.txt <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"cat notes.txt <<'EOF'\nzqattach -n target\nEOF"}},
		{"cat -n rewrites the text", "bash -c \"$(cat -n <<'EOF'\nzqattach -n target\nEOF\n)\"", []string{"cat -n <<'EOF'\nzqattach -n target\nEOF"}},
		{"stdout redirected away", "bash -c \"$(cat <<'EOF' > /tmp/n\nzqattach -n target\nEOF\n)\"", []string{"cat <<'EOF' > /tmp/n\nzqattach -n target\nEOF"}},
		{"stdout sent to stderr", "bash -c \"$(cat <<'EOF' >&2\nzqattach -n target\nEOF\n)\"", []string{"cat <<'EOF' >&2\nzqattach -n target\nEOF"}},
		{"not the last pipeline stage", "bash -c \"$(cat <<'EOF' | wc -l\nzqattach -n target\nEOF\n)\"", []string{"cat <<'EOF' | wc -l\nzqattach -n target\nEOF"}},
		{"an interpreter heredoc runs its body, it does not print it", "bash -c \"$(python3 - <<'PY'\nzqattach -n target\nPY\n)\"", []string{"python3 - <<'PY'\nzqattach -n target\nPY"}},
		{"nested substitution output is captured by its word", "eval \"$(x=$(cat <<'EOF'\nzqattach -n target\nEOF\n); echo ok)\"", []string{"x=$(cat <<'EOF'\nzqattach -n target\nEOF\n); echo ok", "ok"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExecutedText(tc.command); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExecutedText(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
