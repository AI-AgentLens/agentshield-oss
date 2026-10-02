package shellparse

import "testing"

// TestPureCommandsAllowlistIsPinned pins pureCommands to an explicit,
// reviewed list (#4076). Before this test, adding an arbitrary command —
// including a documented executor like "make" — to pureCommands passed
// every existing suite silently: TestCommandLineIsPure only names the ten
// or so specific words its own subtests happen to use, so it reacts to
// removing a word it names, never to adding one it doesn't. Any diff to
// pureCommands must now also touch this list, which is the point: the
// allowlist's closure becomes a deliberate, visible decision instead of a
// side effect of some other change.
func TestPureCommandsAllowlistIsPinned(t *testing.T) {
	pinned := []string{
		// text in, text out
		"cat", "tee", "echo", "printf", "head", "tail",
		"wc", "sort", "uniq", "cut", "tr", "paste",
		"column", "grep", "egrep", "fgrep", "rg", "diff",
		"cmp", "comm", "jq", "base64", "xxd", "od",
		"hexdump", "shasum", "sha256sum", "md5", "md5sum",
		"cksum", "fold", "fmt", "nl", "rev", "tac",
		"expand", "unexpand", "strings",
		// filesystem, no execution
		"cd", "pwd", "pushd", "popd", "mkdir", "rmdir",
		"rm", "cp", "mv", "ln", "ls", "touch",
		"chmod", "stat", "file", "du", "df", "realpath",
		"readlink", "basename", "dirname", "mktemp", "tree",
		// shell builtins that never run text
		"true", "false", ":", "test", "[", "exit",
		"return", "set", "unset", "shift", "wait",
		"read", "mapfile", "readarray", "export", "local",
		"declare", "typeset", "readonly", "type", "which",
		"hash", "printenv",
		// time, identity and transport: they report or fetch data, never run it
		"date", "sleep", "curl", "wget", "whoami", "id",
		"hostname", "uname", "nproc", "arch", "groups",
	}

	pinnedSet := make(map[string]bool, len(pinned))
	for _, name := range pinned {
		if pinnedSet[name] {
			t.Fatalf("duplicate entry in the pinned list: %q", name)
		}
		pinnedSet[name] = true
	}

	if len(pinnedSet) != len(pureCommands) {
		t.Errorf("pureCommands has %d entries, the pinned list has %d", len(pureCommands), len(pinnedSet))
	}
	for name := range pureCommands {
		if !pinnedSet[name] {
			t.Errorf("pureCommands declares %q, which is not in the pinned list — a deliberate addition must update TestPureCommandsAllowlistIsPinned in the same diff", name)
		}
	}
	for name := range pinnedSet {
		if !pureCommands[name] {
			t.Errorf("the pinned list names %q, which pureCommands no longer declares — stale entry, remove it here too", name)
		}
	}
}

// TestExecutorClassesAreImpure locks down every class purity.go's own doc
// comment names as impure — build tools, package managers, shells, and
// interpreters used outside the heredoc-argv carve-out — plus the
// xargs/find-exec style forwarders (#4076). Unlike
// TestPureCommandsAllowlistIsPinned, which only reacts to *any* diff to the
// map, this table hard-codes the expected verdict for representative
// members of each class, so a deliberate but wrong addition (e.g. adding
// "make" to pureCommands and also updating the pinned list above) still
// fails here and has to be reviewed on its own terms.
func TestExecutorClassesAreImpure(t *testing.T) {
	execFree := func(lang, body string) bool { return true }
	cases := []struct {
		class string
		cmd   string
	}{
		// build tools
		{"build tool", `make`},
		{"build tool", `make build`},
		{"build tool", `cmake --build .`},
		{"build tool", `ninja`},
		{"build tool", `bazel build //...`},
		{"build tool", `gradle build`},
		{"build tool", `mvn install`},
		// package managers
		{"package manager", `npm install`},
		{"package manager", `npm run build`},
		{"package manager", `yarn install`},
		{"package manager", `pip install requests`},
		{"package manager", `pip3 install requests`},
		{"package manager", `cargo build`},
		{"package manager", `gem install rails`},
		{"package manager", `apt-get install curl`},
		{"package manager", `brew install jq`},
		{"package manager", `go install ./...`},
		// shells
		{"shell", `bash`},
		{"shell", `sh`},
		{"shell", `zsh`},
		{"shell", `dash`},
		{"shell", `ksh`},
		{"shell", `fish`},
		{"shell", `csh`},
		{"shell", `tcsh`},
		// interpreters used outside the quoted-heredoc-on-stdin carve-out
		{"interpreter, inline -c", `python3 -c "print(1)"`},
		{"interpreter, script path", `python3 script.py`},
		{"interpreter, inline -e", `ruby -e "puts 1"`},
		{"interpreter, not modelled at all", `php -r "echo 1;"`},
		{"interpreter, not modelled at all", `lua -e "print(1)"`},
		// xargs / find -exec style forwarders
		{"xargs forwarder", `find . -name '*.txt' | xargs cat`},
		{"find -exec forwarder", `find . -exec rm {} \;`},
		{"find -execdir forwarder", `find . -execdir sh -c 'echo {}' \;`},
		{"find -ok forwarder", `find . -ok rm {} \;`},
	}
	for _, c := range cases {
		if CommandLineIsPure(c.cmd, execFree) {
			t.Errorf("%s: CommandLineIsPure(%q) = true, want impure", c.class, c.cmd)
		}
	}
}
