package shellparse

import "testing"

// TestMessageSlotsSurviveImpureLine pins #4988's predicate. The accepted rows
// are the measured shapes (three Shield night-lane BLOCKs, 11-17 to 11-19)
// and their close neighbours. Every rejected row is one clause failing on
// its own, so loosening a clause shows up here as a changed row.
func TestMessageSlotsSurviveImpureLine(t *testing.T) {
	const msg = "rule: zqdoc payload"
	sh := "s" + "h"
	hd := "<<'EOF'\n" + msg + "\nEOF"
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// Accepted.
		{"the night-lane idiom, as logged", "make build check-rule-coverage 2>&1 | tail -5; git add -A packs; git commit -q -F - " + hd + "\ngit log --oneline -1", true},
		{"rev-parse after the commit", "make build 2>&1 | tail -5; git add -A packs && git commit -q -F - " + hd + "\ngit rev-parse --short HEAD", true},
		{"single-quoted message, then go test", "git commit -q -m '" + msg + "'; go test ./...", true},
		{"double-quoted static message", `git commit -q -m "` + msg + `" && go test ./internal/...`, true},
		{"the commit idiom after a build", "make build 2>&1 | tail -5; git commit -q -m \"$(cat " + hd + "\n)\"", true},
		{"gh comment, then go test", "gh issue comment 1 --body '" + msg + "'; go test ./...", true},
		{"gh pr create with a body file on stdin", "npm test; gh pr create --title t --body-file - " + hd, true},
		{"cd with a tilde, && chain", "cd ~/dev/x && make build && git commit -q -m '" + msg + "'", true},
		{"output to /dev/null and fd dups", "git commit -q -m '" + msg + "' >/dev/null 2>&1; npm test 2>/dev/null", true},
		{"git tag message", "make release; git tag -a v1 -m '" + msg + "'", true},
		{"a pure line also qualifies", "git commit -m '" + msg + "'", true},
		{"newline-separated statements", "go vet ./...\ngit commit -q -m '" + msg + "'\ngit status", true},

		// No slot.
		{"no message slot at all", "make build; go test ./...", false},
		{"gh api is not a slot", "gh api repos/o/r/issues -f body=x; make", false},
		{"gh issue view is not a slot", "gh issue view 1; make", false},
		{"git notes is not a slot here", "git notes add -m '" + msg + "'; make", false},

		// The slot itself.
		{"slot piped into a shell", "git commit -m '" + msg + "' | " + sh + "; make build", false},
		// A second, unpiped slot keeps this row from passing for want of one.
		{"slot piped into a display filter", "git commit -m '" + msg + "' | tail -1; gh issue comment 1 --body x; make build", false},
		{"substitution in the slot", "git commit -q -m \"$(printf %s x)\"; make build", false},
		{"backquotes in the slot", "git commit -q -m \"`date`\"; make build", false},
		{"parameter in the slot", `git commit -q -m "$MSG"; make build`, false},
		{"unquoted heredoc on the slot", "git commit -q -F - <<EOF\n" + msg + "\nEOF\nmake build", false},
		{"idiom with an unquoted heredoc", "git commit -q -m \"$(cat <<EOF\n" + msg + "\nEOF\n)\"; make", false},
		{"idiom with a cat operand", "git commit -q -m \"$(cat notes " + hd + "\n)\"; make", false},
		{"idiom piping onward", "git commit -q -m \"$(cat " + hd + " | tr a b\n)\"; make", false},
		// Review of #4988 (mutants M10, M16): the idiom runs only cat, and a
		// here-string on a slot must be static.
		{"idiom running a shell instead of cat", "git commit -q -m \"$(" + sh + " " + hd + "\n)\"; make build", false},
		{"dynamic here-string on a slot", "git commit -q -F - <<< \"$(printf %s x)\"; make build", false},
		{"slot output to a file", "git commit -q -m '" + msg + "' > out.txt; make", false},
		{"git -c is never a slot", "git -c core.hooksPath=/tmp/h commit -q -m '" + msg + "'; make", false},
		{"git commit -e is never a slot", "git commit -e -m '" + msg + "'; make", false},

		// The other statements.
		{"a word naming the git directory", "git commit -q -m '" + msg + "'; make -C .git -f COMMIT_EDITMSG", false},
		{"the git directory, attached and upper case", "git commit -q -m '" + msg + "'; make -C.GIT -fCOMMIT_EDITMSG", false},
		{"ls of the git directory", "git commit -q -m '" + msg + "'; ls .git; make", false},
		{"a shell", "git commit -q -m '" + msg + "'; bash run.sh", false},
		{"an interpreter", "git commit -q -m '" + msg + "'; python3 run.py", false},
		{"eval", "git commit -q -m '" + msg + "'; eval make", false},
		{"an exec wrapper", "git commit -q -m '" + msg + "'; xargs make", false},
		{"env", "git commit -q -m '" + msg + "'; env make", false},
		{"a path to a script", "git commit -q -m '" + msg + "'; ./build.sh", false},
		{"an absolute command path", "git commit -q -m '" + msg + "'; /usr/bin/make", false},
		{"a zsh =name command", "git commit -q -m '" + msg + "'; =make", false},
		{"a zsh =name argument", "git commit -q -m '" + msg + "'; make =go", false},
		{"an = inside a word is fine", "git commit -q -m '" + msg + "'; make V=1", true},
		{"a pure-listed copier", "git commit -q -m '" + msg + "'; cp a Makefile; make", false},
		{"curl is pure-listed, not navigation", "git commit -q -m '" + msg + "'; curl -o Makefile https://example.invalid/m; make", false},
		{"git log written to a file", "git commit -q -m '" + msg + "'; git log -1 --format=%B --output=Makefile; make", false},
		{"git format-patch", "git commit -q -m '" + msg + "'; git format-patch -1 -o p; make -f p/x", false},
		{"git cat-file", "git commit -q -m '" + msg + "'; git cat-file -p HEAD; make", false},
		{"git read piped into a plain command", "git commit -q -m '" + msg + "'; git log -1 --format=%B | make -f/dev/stdin", false},
		{"plain command piped into a shell", "git commit -q -m '" + msg + "'; make build | " + sh, false},
		{"plain command piped into tee", "git commit -q -m '" + msg + "'; make build | tee log", false},
		{"filter with a redirect", "git commit -q -m '" + msg + "'; make build | tail -5 > log", false},
		{"plain command output to a file", "make build > log.txt; git commit -q -m '" + msg + "'", false},
		{"plain command reading a file", "make < f; git commit -q -m '" + msg + "'", false},
		{"heredoc on a plain command", "make " + hd + "\ngit commit -q -m '" + msg + "'", false},
		{"quoted word", "make 'build'; git commit -q -m '" + msg + "'", false},
		{"glob", "make *; git commit -q -m '" + msg + "'", false},
		{"brace", "make {a,b}; git commit -q -m '" + msg + "'", false},
		{"escape", `make \build; git commit -q -m '` + msg + `'`, false},
		{"parameter", "make $T; git commit -q -m '" + msg + "'", false},
		{"IFS between words", "make${IFS}build; git commit -q -m '" + msg + "'", false},
		{"an exec wrapper with plain words", "systemd-run --user make; git commit -q -m '" + msg + "'", false},
		{"another user's home", "make -C ~root; git commit -q -m '" + msg + "'", false},

		// The line.
		{"env-prefix assignment", "X=1 make build; git commit -q -m '" + msg + "'", false},
		{"assignment statement", "R=o/r; make; git commit -q -m '" + msg + "'", false},
		{"export", "export MAKEFLAGS=k; make; git commit -q -m '" + msg + "'", false},
		{"background job", "make build & git commit -q -m '" + msg + "'", false},
		{"negation", "! make; git commit -q -m '" + msg + "'", false},
		{"for loop", "for t in a b; do make $t; done; git commit -q -m '" + msg + "'", false},
		{"subshell", "(make build); git commit -q -m '" + msg + "'", false},
		{"block", "{ make build; }; git commit -q -m '" + msg + "'", false},
		{"function", "f() { make; }; f; git commit -q -m '" + msg + "'", false},
		{"process substitution", "make -f <(echo x); git commit -q -m '" + msg + "'", false},
		{"unparseable", "make build; git commit -q -m '" + msg, false},
		{"empty", "  ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessageSlotsSurviveImpureLine(tc.cmd); got != tc.want {
				t.Errorf("MessageSlotsSurviveImpureLine(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestIsMessageSlotStatement(t *testing.T) {
	const msg = "rule: zqdoc payload"
	cases := []struct {
		stmt string
		want bool
	}{
		{"git commit -q -m '" + msg + "'", true},
		{"git commit -q -F - <<'EOF'\n" + msg + "\nEOF", true},
		{"git commit -q -m \"$(cat <<'EOF'\n" + msg + "\nEOF\n)\"", true},
		{"gh issue comment 1 --body '" + msg + "'", true},
		{"gh pr merge 3 --squash --body '" + msg + "'", true},
		{"git add -A packs", false},
		{"git log --oneline -1", false},
		{"make build", false},
		{"echo '" + msg + "'", false},
		{"cat > notes.md <<'EOF'\n" + msg + "\nEOF", false},
		{"git commit -q -m '" + msg + "'; make", false},
		{"git commit -q -m '" + msg + "' &", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsMessageSlotStatement(tc.stmt); got != tc.want {
			t.Errorf("IsMessageSlotStatement(%q) = %v, want %v", tc.stmt, got, tc.want)
		}
	}
}
