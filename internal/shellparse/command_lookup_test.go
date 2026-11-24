package shellparse

import (
	"strings"
	"testing"
)

// #5092: every way one line can change what a command NAME means, and a
// negative control beside each. Each "impure" row was run in bash 3.2, bash
// 5.3 or zsh 5.9 with a harmless body (`echo RAN-AS-SHELL`) and observed to
// EXECUTE the heredoc body the gate would otherwise call data; the PR has the
// table. A row without a recorded execution is marked "conservative".
func TestCommandLineIsPure_CommandLookupRebinding(t *testing.T) {
	execFree := func(lang, body string) bool { return true }
	const hd = "<<'EOF'\nzqdoc payload\nEOF"
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"control: plain cat heredoc", "cat " + hd, true},
		{"control: cat heredoc to a file", "cat > notes.md " + hd, true},

		// The command word names a file.
		{"path-qualified cat", "/tmp/e/cat " + hd, false},
		{"dot-slash cat", "./cat " + hd, false},
		{"home-relative cat", "~/bin/cat " + hd, false},
		{"quoted path-qualified cat", "'/tmp/e/cat' " + hd, false},
		{"zsh equals with a path", "=/tmp/e/cat " + hd, false},
		{"path-qualified tee", "/tmp/e/tee /dev/null " + hd, false},
		{"path-qualified git commit", "/tmp/e/git commit -F - " + hd, false},
		{"user-writable Homebrew dir", "/opt/homebrew/bin/cat " + hd, false},
		{"/usr/local/bin", "/usr/local/bin/cat " + hd, false},
		{"dot-dot out of /bin", "/bin/../tmp/cat " + hd, false},
		{"doubled slash", "/usr/bin//cat " + hd, false},
		{"control: /bin/cat stays trusted", "/bin/cat > notes.md " + hd, true},
		{"control: /usr/bin/tee stays trusted", "/usr/bin/tee notes.md " + hd, true},
		{"control: /usr/bin/git commit stays trusted", "/usr/bin/git commit -F - " + hd, true},
		{"control: bare git commit", "git commit -F - " + hd, true},
		{"control: zsh equals without a path", "=cat " + hd, true},

		// PATH, in every spelling.
		{"PATH prefix", "PATH=/tmp/e cat " + hd, false},
		{"PATH statement", "PATH=/tmp/e; cat " + hd, false},
		{"PATH append", "PATH+=:/tmp/e; cat " + hd, false},
		{"PATH prefix before another prefix", "PATH=/tmp/e LANG=C cat " + hd, false},
		{"export a quoted PATH append", "export 'PATH+=:/tmp/e'; cat " + hd, false},
		{"export PATH", "export PATH=/tmp/e:$PATH; cat " + hd, false},
		{"export PATH, no value (conservative)", "export PATH; cat " + hd, false},
		{"export quoted PATH", "export 'PATH=/tmp/e'; cat " + hd, false},
		{"export computed name", `v=PATH; export "$v=/tmp/e"; cat ` + hd, false},
		{"declare -x PATH", "declare -x PATH=/tmp/e; cat " + hd, false},
		{"typeset PATH", "typeset PATH=/tmp/e; cat " + hd, false},
		{"local PATH", "local PATH=/tmp/e; cat " + hd, false},
		{"readonly PATH", "readonly PATH=/tmp/e; cat " + hd, false},
		{"zsh path array", "path=(/tmp/e); cat " + hd, false},
		{"zsh path append", "path+=(/tmp/e); cat " + hd, false},
		{"zsh path element", "path[1]=/tmp/e; cat " + hd, false},
		{"bash EXECIGNORE", "EXECIGNORE=/bin/cat; cat " + hd, false},
		{"PATH after an unrelated assignment", "A=1; PATH=/tmp/e; B=2; cat " + hd, false},
		{"PATH inside a substitution", "echo \"$(PATH=/tmp/e; echo x)\"; cat " + hd, false},
		{"read into PATH", "read -r PATH <<< /tmp/e; cat " + hd, false},
		{"zsh read -A path", "read -A path <<< /tmp/e; cat " + hd, false},
		{"read with an attached name (conservative)", "read -rPATH <<< /tmp/e; cat " + hd, false},
		{"mapfile into PATH (conservative)", "mapfile -t PATH <<< /tmp/e; cat " + hd, false},
		{"readarray into path (conservative)", "readarray path <<< /tmp/e; cat " + hd, false},
		{"read a computed name (conservative)", `read -r "$v" <<< /tmp/e; cat ` + hd, false},
		{"unset PATH: bash searches the cwd", "unset PATH; cat " + hd, false},
		{"declare -n nameref", "declare -n r=PATH; r=/tmp/e; cat " + hd, false},
		{"declare -gn nameref", "declare -gn r=PATH; r=/tmp/e; cat " + hd, false},
		{"local -n nameref", "local -n r=PATH; cat " + hd, false},
		{"typeset -n nameref", "typeset -n r=PATH; cat " + hd, false},
		{"ksh nameref (conservative)", "nameref r=PATH; r=/tmp/e; cat " + hd, false},
		{"computed declare option (conservative)", `declare "-$o" r=PATH; cat ` + hd, false},
		{"control: unrelated prefix", "LANG=C cat " + hd, true},
		{"control: unrelated statement", "X=/tmp/e; cat " + hd, true},
		{"control: export an unrelated name", "export GOPATH=/tmp/e; cat " + hd, true},
		{"control: export with a computed value", `export "FOO=$v"; cat ` + hd, true},
		{"control: declare -x unrelated", "declare -x FOO=1; cat " + hd, true},
		{"control: declare -i", "declare -i n=1; cat " + hd, true},
		{"control: a name that starts with path", "pathname=/tmp/e; cat " + hd, true},
		{"control: read into a line", "read -r line <<< x; cat " + hd, true},
		{"control: mapfile into lines", "mapfile -t lines < f.txt; cat " + hd, true},
		{"control: unset an unrelated name", "unset FOO; cat " + hd, true},

		// The hash table.
		{"bash hash -p", "hash -p /bin/sh cat; cat " + hd, false},
		{"zsh hash name=path", "hash cat=/bin/sh; cat " + hd, false},
		{"zsh hash -d (conservative)", "hash -d x=/tmp; cat " + hd, false},
		{"bash BASH_CMDS", "BASH_CMDS[cat]=/bin/sh; cat " + hd, false},
		{"bash BASH_CMDS via read", "read -r 'BASH_CMDS[cat]' <<< /bin/sh; cat " + hd, false},
		{"zsh commands table", "commands[cat]=/bin/sh; cat " + hd, false},
		{"control: hash lists", "hash; cat " + hd, true},
		{"control: hash -r empties", "hash -r; cat " + hd, true},

		// zsh's function and alias tables, aliases, functions.
		{"zsh functions table", "functions[cat]=/bin/sh; cat " + hd, false},
		{"zsh aliases table (conservative)", "aliases[cat]=/bin/sh\ncat " + hd, false},
		{"zsh galiases table (conservative)", "galiases[cat]=/bin/sh\ncat " + hd, false},
		{"zsh saliases table (conservative)", "saliases[md]=sh\ncat " + hd, false},
		{"bash BASH_ALIASES (conservative)", "BASH_ALIASES[cat]=sh\ncat " + hd, false},
		{"alias", "alias cat=sh\ncat " + hd, false},
		{"function", "cat() { sh; }; cat " + hd, false},
		{"function keyword", "function cat { sh; }; cat " + hd, false},
		{"function named by a path", "/bin/cat() { sh; }; /bin/cat " + hd, false},
	}
	for _, c := range cases {
		if got := CommandLineIsPure(c.cmd, execFree); got != c.want {
			t.Errorf("%s: CommandLineIsPure(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

// #5092: HeredocBodies trusts a sink by name, so a sink named by a file, or
// behind a wrapper that names a file or sets PATH, leaves the body live. The
// line-level rebindings (hash, PATH statements, zsh tables) are
// CommandLineIsPure's, which heredoc_body also requires.
func TestHeredocBodies_SinkNamedByFile(t *testing.T) {
	const body = "zqdoc payload"
	const hd = "<<'EOF'\n" + body + "\nEOF"
	cases := []struct {
		name  string
		cmd   string
		inert bool
	}{
		{"control: cat", "cat " + hd, true},
		{"control: cat to a file", "cat > notes.md " + hd, true},
		{"control: /bin/cat", "/bin/cat > notes.md " + hd, true},
		{"control: /usr/bin/tee", "/usr/bin/tee notes.md " + hd, true},
		{"control: /usr/bin/git commit -F -", "/usr/bin/git commit -F - " + hd, true},
		{"control: nohup cat", "nohup cat " + hd, true},
		{"control: /usr/bin/env cat", "/usr/bin/env cat " + hd, true},
		{"control: quoted /usr/bin/nohup cat (dequoted first)", "'/usr/bin/nohup' cat " + hd, true},
		{"control: env with an unrelated assignment", "env LANG=C cat " + hd, true},
		{"path-qualified cat", "/tmp/e/cat " + hd, false},
		{"dot-slash cat", "./cat " + hd, false},
		{"quoted path-qualified cat", "'/tmp/e/cat' " + hd, false},
		{"path-qualified tee", "/tmp/e/tee /dev/null " + hd, false},
		{"path-qualified git commit -F -", "/tmp/e/git commit -F - " + hd, false},
		{"dot-dot out of /bin", "/bin/../tmp/cat " + hd, false},
		{"path-qualified wrapper", "/tmp/e/nohup cat " + hd, false},
		{"env sets PATH", "env PATH=/tmp/e cat " + hd, false},
		{"env sets a slash-free PATH: ./cat", "env PATH=. cat " + hd, false},
		{"env sets a quoted PATH", "env 'PATH=/tmp/e' cat " + hd, false},
		{"env sets a quoted slash-free PATH (dequoted first)", "env 'PATH=.' cat " + hd, false},
		{"env sets zsh path (conservative)", "env path=/tmp/e cat " + hd, false},
		{"chroot names a root", "chroot /tmp/r cat " + hd, false},
	}
	for _, c := range cases {
		items, _ := HeredocBodies(c.cmd)
		got := len(items) == 1 && strings.Contains(items[0], body)
		if got != c.inert {
			t.Errorf("%s: HeredocBodies(%q) items=%q, want inert=%v", c.name, c.cmd, items, c.inert)
		}
	}
}

// TestCommandLookupResidual pins what #5092 does NOT close, so closing it
// later is deliberate (the indirect_executor_gap_test.go pattern).
//
// A bare `cat` is found by searching PATH's directories. A program named cat
// placed in one that comes before /bin (on a stock Homebrew Mac,
// /opt/homebrew/bin is first and user-owned) changes what the name means with
// nothing on the line touching PATH, the hash table or a function. The plant
// can come from an earlier tool call, which no line-level gate sees, or from
// any write on the same line, whose target name can be computed. Observed to
// EXECUTE the body in bash 3.2, bash 5.3 and zsh 5.9 (the PR's ground-truth
// table, row "plant ln into PATH dir"). Closing it needs session state (#4774).
func TestCommandLookupResidual(t *testing.T) {
	execFree := func(lang, body string) bool { return true }
	const hd = "<<'EOF'\nzqdoc payload\nEOF"
	gaps := []string{
		"ln -s /bin/sh /opt/homebrew/bin/cat; cat " + hd,
		"cat " + hd, // the same body, after a plant made by an earlier call
	}
	for _, cmd := range gaps {
		if !CommandLineIsPure(cmd, execFree) {
			t.Errorf("GAP changed: CommandLineIsPure(%q) = false; if this closes the residual, move the row to TestCommandLineIsPure_CommandLookupRebinding and update command_lookup.go's doc comment", cmd)
		}
		if items, _ := HeredocBodies(cmd); len(items) != 1 {
			t.Errorf("GAP changed: HeredocBodies(%q) = %q, want the body as one inert item", cmd, items)
		}
	}
	// Positive control: the same plant made by naming the file, on the line,
	// is closed.
	if CommandLineIsPure("ln -s /bin/sh /opt/homebrew/bin/cat; /opt/homebrew/bin/cat "+hd, execFree) {
		t.Error("control: a path-qualified sink must be impure")
	}
}
