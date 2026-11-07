package shellparse

import (
	"strings"
	"testing"
)

// TestCommandLineIsPure pins #3798's strict purity gate (Gary, 2026-09-23).
// Pure rows are the shapes real agent traffic needs the doc-text exemption
// for (measured: all 30 flips on 4,594 audit-log commands fell into them).
// Impure rows are each executor channel that previously needed its own
// withdrawal, plus the accepted costs, so loosening the list is a visible
// change here rather than a quiet regression elsewhere.
func TestCommandLineIsPure(t *testing.T) {
	// A stand-in for the analyzer's exec-free check: body free of "system".
	execFree := func(lang, body string) bool { return !strings.Contains(body, "sys"+"tem(") }
	const doc = "zqdoc payload"
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// Pure: the five measured shapes and ordinary neighbours.
		{"heredoc to a file", "cat > /tmp/notes.md <<'EOF'\n" + doc + "\nEOF", true},
		{"commit idiom", "git commit -m \"$(cat <<'EOF'\n" + doc + "\nEOF\n)\"", true},
		{"gh body", `gh issue comment 12 --body "` + doc + `"`, true},
		{"printf to a file", `printf '%s\n' "` + doc + `" > /tmp/p0.txt`, true},
		{"python heredoc, exec-free", "python3 - <<'PY'\ns = '" + doc + "'\nprint(s)\nPY", true},
		{"python heredoc, unquoted delimiter, no expansion", "python3 <<EOF\nref = '" + doc + "'\nEOF", true},
		{"echo piped to grep", `echo "` + doc + `" | grep zq`, true},
		{"cd && heredoc && git add", "cd /repo && cat > a.md <<'EOF'\n" + doc + "\nEOF\ngit add a.md", true},
		{"identity substitution", `echo "arr[$(whoami)]" | cat`, true},
		{"sed print", `sed -n '1,20p' notes.txt`, true},
		{"sed substitute, file named with e", `sed 's/a/b/g' some/file`, true},
		{"awk print", `awk '{print $1}' data.txt`, true},
		{"find without exec", `find . -name '*.md'`, true},
		{"command -v", `command -v jq`, true},

		// printf destination evaluation (#4562). Bash accepts attached
		// destinations: -vvout assigns to vout, rather than bundling flags.
		{"printf ordinary redirection", `printf '%s\n' x > f`, true},
		{"printf option terminator", `printf -- '%s\n' x > f`, true},
		{"printf v in ordinary text", `printf '%s\n' 'docs: v destination' > f`, true},
		{"printf variable destination", `printf -v out '%s' t`, false},
		{"printf subscript witness", `printf -v 'a[$(printf 0)]' '%s' t`, false},
		{"printf attached destination", `printf -vout '%s' t`, false},
		{"printf attached subscript witness", `printf -v'a[$(printf 0)]' '%s' t`, false},
		{"printf vv destination spelling", `printf -vv '%s' t`, false},
		{"printf vvout destination spelling", `printf -vvout '%s' t`, false},
		{"printf repeated destination option", `printf -vfirst -vsecond '%s' t`, false},
		{"printf quoted destination option", `printf '-'v out '%s' t`, false},
		{"printf missing destination conservatively withdraws", `printf -v`, false},
		{"printf v in data conservatively withdraws", `printf '%s\n' -v`, false},
		{"printf v after terminator conservatively withdraws", `printf -- -v`, false},

		// Git message/editor boundary (#4554), including gitcli(7)'s
		// abbreviated long options, bundled short options and option values.
		{"plain commit message", `git commit -m 'docs: rotate token'`, true},
		{"cd then plain commit", `cd x && git commit -m 'docs: rotate token'`, true},
		{"attached commit message", `git commit -mdocs:example`, true},
		{"bundled commit message", `git commit -am 'docs: example'`, true},
		{"edit spelling in message value", `git commit -m --edit`, true},
		{"edit spelling in long message value", `git commit --message --edit`, true},
		{"edit spelling in abbreviated message value", `git commit --mes --edit`, true},
		{"edit spelling in attached message value", `git commit --message=--edit`, true},
		{"edit spelling after option terminator", `git commit -m docs -- --edit`, true},
		{"no edit", `git commit --no-edit -m docs`, true},
		{"abbreviated no edit", `git commit --no-ed -m docs`, true},
		{"tag message without edit", `git tag -am 'docs: example' v1`, true},
		{"merge message without edit", `git merge -m 'docs: example' topic`, true},
		{"grep e is a pattern option", `git grep -e docs`, true},
		{"diff exit code is not edit", `git diff --exit-code`, true},
		{"editor text is not an assignment", `echo 'GIT_EDITOR=sh'; git commit -m docs`, true},
		{"unrelated assignment", `export OTHER_EDITOR=sh; git commit -m docs`, true},
		{"editor assignment without git", `export GIT_EDITOR=sh; echo docs`, true},
		{"commit edit", `git commit --edit -m docs`, false},
		{"commit shortest edit prefix", `git commit --e -m docs`, false},
		{"commit edit prefix ed", `git commit --ed -m docs`, false},
		{"commit edit prefix edi", `git commit --edi -m docs`, false},
		{"commit short edit", `git commit -e -m docs`, false},
		{"commit bundled edit", `git commit -aemdocs`, false},
		{"commit quoted edit", `git commit '--e'dit -m docs`, false},
		{"commit edit after path", `git commit -m docs README --ed`, false},
		{"commit global directory then edit", `git -C x commit --ed -m docs`, false},
		{"commit edit after optional short value", `git commit -S --edit -m docs`, false},
		{"tag edit", `git tag -aemdocs v1`, false},
		{"tag edit prefix", `git tag --ed -m docs v1`, false},
		{"merge edit", `git merge --ed -m docs topic`, false},
		{"cherry-pick edit", `git cherry-pick -se HEAD`, false},
		{"revert stays outside pure list", `git revert --edit HEAD`, false},
		{"notes stays outside pure list", `git notes add -e -m docs`, false},
		{"exported git editor witness", `export GIT_EDITOR=sh; git commit --allow-empty --edit -m ':; touch /tmp/ged-witness; exit 1'`, false},
		{"git editor heredoc witness", "export GIT_EDITOR=sh; git commit --allow-empty --edit -F - <<'EOF'\n:; touch /tmp/ged-witness; exit 1\nEOF", false},
		{"prefix editor assignment", `GIT_EDITOR=sh git commit --edit -m docs`, false},
		{"bare editor assignment", `GIT_EDITOR=sh; git commit`, false},
		{"visual editor assignment", `export VISUAL=sh; git commit`, false},
		{"fallback editor assignment", `export EDITOR=sh; git tag -a v1`, false},
		{"sequence editor assignment", `export GIT_SEQUENCE_EDITOR=sh; git rebase -i HEAD~2`, false},
		{"declared editor assignment", `declare -x GIT_EDITOR=sh; git commit`, false},
		{"typeset editor assignment", `typeset -x GIT_EDITOR=sh; git commit`, false},
		{"readonly editor assignment", `readonly GIT_EDITOR=sh; git commit`, false},
		{"local editor assignment", `local GIT_EDITOR=sh; git commit`, false},
		{"quoted export assignment", `export 'GIT_EDITOR=sh'; git commit`, false},
		{"later assignment conservatively withdraws", `git commit -m docs; export GIT_EDITOR=sh`, false},
		{"editor selection conservatively withdraws for read-only git", `export GIT_EDITOR=sh; git status`, false},

		// Impure: every channel that needed its own withdrawal before.
		{"pipe into bash (#3797)", `echo "` + doc + `" | bash`, false},
		{"write then run (#3800)", "cat > /tmp/x.sh <<'EOF'\n" + doc + "\nEOF\nbash /tmp/x.sh", false},
		{"cmdsub into bash -c (#3976)", "bash -c \"$(cat <<'EOF'\n" + doc + "\nEOF\n)\"", false},
		{"eval (#3976)", `eval "$(cat notes.md)"`, false},
		{"$SHELL (#3798)", `echo "` + doc + `" | $SHELL`, false},
		{"dot stdin (#3798)", `echo "` + doc + `" | . /dev/stdin`, false},
		{"xargs (#3798)", `echo "` + doc + `" | xargs -I{} sh -c "{}"`, false},
		{"source a file", `echo x | source ./lib.sh`, false},
		{"sudo wrapper", `sudo cat /etc/hosts`, false},
		{"env wrapper", `env FOO=1 cat notes.md`, false},
		{"script path", `./run.sh`, false},
		{"function defined in the line", `f(){ echo hi; }; f`, false},
		{"dynamic command word", `SH=cat; echo x | $SH`, false},
		{"git -c alias", `git -c alias.x='!sh' x`, false},
		{"git unknown subcommand", `git x-run`, false},
		{"gh extension", `gh my-ext run`, false},
		{"find -exec", `find . -exec sh -c 'echo {}' \;`, false},
		{"sed e flag", `sed 's/a/b/e' notes.txt`, false},
		{"sed e command", `sed '1e date' notes.txt`, false},
		{"sed script file", `sed -f prog.sed notes.txt`, false},
		{"awk system", `awk 'BEGIN{sys` + `tem("id")}'`, false},
		{"awk pipe to command", `awk '{print | "sh"}' f`, false},
		{"python -c", `python3 -c "print(1)"`, false},
		{"python script reading heredoc (accepted cost)", "python3 script.py <<'PY'\ns = '" + doc + "'\nPY", false},
		{"python heredoc that execs", "python3 - <<'PY'\nimport os; os.sys" + "tem('id')\nPY", false},
		{"python heredoc, unquoted delimiter WITH expansion", "python3 <<EOF\nx = '$(id)'\nEOF", false},
		{"go test after writing a test file (accepted cost)", "cat > x_test.go <<'GO'\npackage x\nGO\ngo test ./...", false},
		{"write a git hook, then commit", "cat > .git/hooks/pre-commit <<'EOF'\n" + doc + "\nEOF\ngit commit -m x", false},
		{"tee into a git hook", "echo x | tee .git/hooks/pre-push", false},
		{"cmdsub of an impure command", `echo "$(bash -c id)"`, false},
		{"unparseable", `echo "unterminated`, false},

		// Impure: shell/session startup files and autorun directories (#4039)
		// — a shell sources these on its own, so a write with no pipe and no
		// execute statement is still deferred execution.
		{"append into .zshenv (#4039)", `echo "` + doc + `" >> ~/.zshenv`, false},
		{"append into .bashrc via $HOME (#4039)", `echo "` + doc + `" >> $HOME/.bashrc`, false},
		{"overwrite .profile, bare relative name (#4039)", `echo "` + doc + `" > .profile`, false},
		{"heredoc into .zprofile (#4039)", "cat >> ~/.zprofile <<'EOF'\n" + doc + "\nEOF", false},
		{"tee into .bash_profile (#4039)", `echo x | tee -a ~/.bash_profile`, false},
		{"tee into fish config (#4039)", `echo x | tee ~/.config/fish/config.fish`, false},
		{"append into /etc/profile.d (#4039)", `echo "` + doc + `" >> /etc/profile.d/evil.sh`, false},
		{"append into /etc/environment (#4039)", `echo "` + doc + `" >> /etc/environment`, false},
		{"append into cron.d (#4039)", `echo "` + doc + `" >> /etc/cron.d/evil`, false},
		{"append into /etc/crontab (#4039)", `echo "` + doc + `" >> /etc/crontab`, false},

		// Pure control: a same-family name that is not actually sourced must
		// not be swept in by a loose match (#4039 — basename match, not
		// substring, is what keeps this true).
		{"write to a startup-file backup stays pure (#4039)", "cat > ~/.bashrc.bak <<'EOF'\n" + doc + "\nEOF", true},
		{"write to notes.profile.md stays pure (#4039)", `echo "` + doc + `" > notes.profile.md`, true},
	}
	for _, c := range cases {
		if got := CommandLineIsPure(c.cmd, execFree); got != c.want {
			t.Errorf("%s: CommandLineIsPure(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
	// A nil callback means interpreters are never pure.
	if CommandLineIsPure("python3 - <<'PY'\nprint(1)\nPY", nil) {
		t.Error("nil interpHeredocExecFree must make interpreters impure")
	}
}
