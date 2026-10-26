package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4481: a bare glob run from a directory holding a protected dot-dir names
// that dir only when a shell would. `*` never matches a leading dot, so `ls *`
// from $HOME does not read ~/.ssh and must not BLOCK; a pattern starting with
// `.`, a command that turns dot-matching on, a quoted pattern and a glob that
// matches only dot entries keep main's BLOCK. Paths are assembled at runtime:
// the hook reads test sources as commands.
func TestBareGlobSkipsDotEntriesLikeTheShell_4481(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dot := "." + "ssh"
	if err := os.MkdirAll(filepath.Join(home, dot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, dot, "config"), []byte("Host x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("foo"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"~/" + dot + "/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eval := func(cmd string) EvalResult {
		nc := normalize.NormalizeCommand(cmd, home)
		return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, home)
	}
	if r := eval("cat ~/" + dot + "/config"); r.Decision != DecisionBlock {
		t.Fatalf("control: %v; want BLOCK", r.Decision)
	}

	// BLOCK on main, and no shell expands them to the dot-dir.
	for _, cmd := range []string{
		"ls *",
		"grep -l foo *",
		"cat *",
		"for f in $(grep -l foo *); do echo $f; done",
		"wc -l * > /dev/null",
		"grep -l foo * <<EOF\nx\nEOF",
	} {
		if r := eval(cmd); r.Decision == DecisionBlock {
			t.Errorf("%q cwd=HOME: %v rules=%v; must not BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}

	for _, cmd := range []string{
		// the pattern starts with a literal dot, so every shell matches it
		"ls .ss*",
		"grep -r key .*",
		// the command turns dot-matching on
		"shopt -s dotglob; grep -r key *",
		"shopt -s extglob dotglob && ls *",
		"GLOBIGNORE=x; grep -r key *",
		"setopt GLOB_DOTS; grep -r key *",
		"setopt glob_dots; ls *",
		"setopt dot_glob; ls *",
		"set -4; ls *",
		"FIGNORE=x; ls *",
		// the switch reaches every extraction path: substitution, heredoc
		// fallback, redirect target
		"echo $(shopt -s dotglob; cat *)",
		"shopt -s dotglob; cat * <<EOF\nx\nEOF",
		"shopt -s dotglob; echo x > *",
		"shopt -s dotglob; { echo x; } > *",
		// globbing off: git gets `*` and stages dot entries itself
		"set -f; git add *",
		"set -o noglob; git add *",
		"noglob git add *",
		"setopt noglob; git add *",
		"unsetopt glob; git add *",
		// other spellings of the same switches (#4509 pass 2): the line runs
		// an option builtin, so it is not provably under default globbing
		"set +o glob; git add *",
		"setopt +o glob; git add *",
		"unsetopt G_LOB; git add *",
		"unsetopt +F; git add *",
		"set '-f'; git add *",
		`s""et -f; git add *`,
		"unsetopt gl''ob; git add *",
		"set +o glob\ngit add *",
		"c=set; $c -f; git add *",
		"eval 'set -f'; git add *",
		// a name built from fragments and bound across a line continuation
		// (#4509 Codex pass 1): bash then matches dot entries
		"v=GLOB; v+=IGNORE; export \\\n\"$v=x\"; ls *",
		// quoted: the program receives the pattern and may glob dot-files itself
		"git add '*'",
		// only a dot entry matches: the shell passes `?ssh` on unexpanded
		"ls ?ssh",
	} {
		if r := eval(cmd); r.Decision != DecisionBlock {
			t.Errorf("%q cwd=HOME: %v rules=%v; want BLOCK (main's reading)", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
