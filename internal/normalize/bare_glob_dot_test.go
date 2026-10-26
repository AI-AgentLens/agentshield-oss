package normalize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// defaultGlobbingOf calls defaultGlobbing the way normalize does: a heredoc
// command arrives unparsed.
func defaultGlobbingOf(cmd string) bool {
	var parsed *shellparse.ParsedCommand
	if !containsHeredoc(strings.Fields(cmd)) {
		parsed = shellparse.Parse(cmd, 2)
	}
	return defaultGlobbing(parsed, cmd)
}

// #4481 / #4509: a line is under default globbing only when it provably is.
// Each "not default" row is a way a real shell turns dot-matching on or
// globbing off, or a shape the check cannot see through.
func TestDefaultGlobbing(t *testing.T) {
	for _, cmd := range []string{
		// dot-matching on, by name
		"shopt -s dotglob; ls *",
		"shopt -s 'dotglob'; ls *",
		`shopt -s dot"glob"; ls *`,
		"GLOBIGNORE=.git; ls *",
		"export GLOBIGNORE=x; ls *",
		"setopt GLOB_DOTS; ls *",
		"setopt GlobDots; ls *",
		"unsetopt NO_GLOB_DOTS; ls *",
		"setopt DOT_GLOB; ls *",
		"set -4; ls *",
		"FIGNORE=x; ls *",
		"options[globdots]=on; ls *",
		// globbing off (#4509 pass 1)
		"set -f; git add *",
		"set -euf; git add *",
		"set -o noglob; git add *",
		"noglob git add *",
		"setopt NO_GLOB; git add *",
		"set -F; git add *",
		"unsetopt glob; git add *",
		// other spellings of the same switches (#4509 pass 2)
		"set +o glob; git add *",
		"setopt +o glob; git add *",
		"unsetopt G_LOB; git add *",
		"unsetopt +F; git add *",
		"set '-F'; git add *",
		`set -"F"; git add *`,
		"set '-f'; git add *",
		`s""et -f; git add *`,
		"unsetopt gl''ob; git add *",
		"set +o glob\ngit add *",
		"unsetopt G_LOB && git add *",
		"options[glob]=off; git add *",
		// the command is not named by a static word
		"c=set; $c -f; git add *",
		`$'\x73et' -f; git add *`,
		`\set -f; git add *`,
		"{set,} -f; git add *",
		"$(echo set) -f; git add *",
		"$CMD -f; git add *", // unbound: nothing resolves it, so it is unknown
		// commands that run text or a file in the current shell
		"eval 'set -f'; git add *",
		"source ./x.sh; ls *",
		". ./x.sh; ls *",
		"alias s=set; s -f; ls *",
		"trap 'set -f' DEBUG; ls *",
		"builtin set -f; git add *",
		"command set -f; git add *",
		"emulate sh; ls *",
		// builtins whose arguments name no option: only the command name says so
		"autoload -Uz compinit; compinit; ls *",
		"enable -n x; ls *",
		"disable -p x; ls *",
		"nocorrect ls *",
		// the switch inside a compound command or a function body
		"f(){ set -f; }; f; git add *",
		"(set -f; git add *)",
		"if true; then set -f; fi; git add *",
		// zsh syntax bash reads differently: `repeat` is valid bash, the
		// others do not parse as bash at all
		"repeat 1 set -f; git add *",
		"() { set -f; }; git add *",
		"for x (a) set -f; git add *",
		"foreach x (a)\nset -f\nend\ngit add *",
		// a variable bound by a name the text does not show
		`export "$v=x"; ls *`,
		"declare $v=x; ls *",
		`printf -v "$v" x; ls *`,
		": ${!v:=x}; ls *",
		// the same, where a text scan would stop early (#4509 Codex pass 1)
		"v=GLOB; v+=IGNORE; export \\\n\"$v=x\"; ls *",
		`export "a;b" "$v=x"; ls *`,
		"GLOB\\\nIGNORE=x; ls *",
		"(( $v = 1 )); ls *",
		"declare -n r=x; ls *",
		"export {GLOBIGN,}ORE=x; ls *",
		"read $v <<< x; ls *",
		// option or destination arriving through an expansion (#4509 Codex pass 2)
		"o=-v; printf $o x y; ls *",
		"print $o x y; ls *",
		"zstyle -s ':ctx' style x; ls *",
		// history re-execution runs a stored line in the current shell
		"history -s 'set -f'; fc -s; git add *",
		// a heredoc command gets the same checks
		"shopt -s dotglob; cat * <<EOF\nx\nEOF",
		"cat * <<EOF\nshopt -s dotglob\nEOF",
	} {
		if defaultGlobbingOf(cmd) {
			t.Errorf("defaultGlobbing(%q) = true; want false", cmd)
		}
	}
	for _, cmd := range []string{
		"ls *",
		"grep -l foo *",
		"cat *",
		"for f in $(grep -l foo *); do echo $f; done",
		"wc -l * > /dev/null",
		"git add *",
		"curl -4 https://example.com",
		"ssh -4 host ls *",
		"cp -f * /tmp/x",
		"grep -rn setopt *",
		"grep -rn unsetopt *",
		"printf '%s\\n' \"$x\"; ls *",
		"while read -r f; do echo \"$f\"; done < list.txt; ls *",
		"cd \"$HOME/src\" && ls *",
		"settings=1; ls *",
		`export PATH="$HOME/bin:$PATH"; ls *`,
		"f(){ local x=\"$1\"; echo \"$x\"; }; f a; ls *",
		"(( i += 1 )); ls *",
		"printf -- '%s' \"$x\"; ls *",
		"cat * <<EOF\nx\nEOF",
		"git commit -F - <<'EOF'\nfix: thing\nEOF\nls *",
		"[ -f x ] && ls *",
		"[[ -n $x ]] && ls *",
		"IFS=$'\\n'; for f in $(grep -l foo *); do echo \"$f\"; done",
	} {
		if !defaultGlobbingOf(cmd) {
			t.Errorf("defaultGlobbing(%q) = false; want true", cmd)
		}
	}
}

// Documented gap (#4509 Codex pass 2), pinned so closing it is deliberate:
// bash evaluates a variable's VALUE as arithmetic when the name is referenced
// in an arithmetic context, so a value holding an assignment to a name built
// from fragments binds that name with no binding construct in the text.
// defaultGlobbing does not model it and reads the line as default. Main already
// ALLOWs `grep -r key ~` and `git add -A` from $HOME, which reach the same
// entries with no binding, so the gap gives nothing main does not.
func TestDefaultGlobbingRecursiveArithmeticGap(t *testing.T) {
	cmd := "v=GLOB; w=\"${v}IGNORE=1\"; (( w )); ls *"
	if !defaultGlobbingOf(cmd) {
		t.Fatalf("defaultGlobbing(%q) = false: the documented gap closed; update the doc comment and this pin", cmd)
	}
}

func TestBareGlobPathsDotEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".hidden", "visible", ".only"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	has := func(paths []string, name string) bool {
		for _, p := range paths {
			if filepath.Base(p) == name {
				return true
			}
		}
		return false
	}
	cases := []struct {
		arg       string
		keepDots  bool
		wantDot   string // a dot entry that must be in the result, or ""
		wantNoDot string // a dot entry that must not be
	}{
		{"*", false, "", ".hidden"},
		{"*", true, ".hidden", ""},
		{".h*", false, ".hidden", ""},
		{"'*'", false, ".hidden", ""},
		{`\*`, false, ".hidden", ""},
		{".?nly", false, ".only", ""},
		{"?only", false, ".only", ""}, // only a dot entry matches: kept
	}
	for _, c := range cases {
		got := bareGlobPaths(c.arg, dir, c.keepDots)
		if c.wantDot != "" && !has(got, c.wantDot) {
			t.Errorf("bareGlobPaths(%q, keepDots=%v) = %v; want %s", c.arg, c.keepDots, got, c.wantDot)
		}
		if c.wantNoDot != "" && has(got, c.wantNoDot) {
			t.Errorf("bareGlobPaths(%q, keepDots=%v) = %v; must not name %s", c.arg, c.keepDots, got, c.wantNoDot)
		}
		if c.arg == "*" && !has(got, "visible") {
			t.Errorf("bareGlobPaths(%q) = %v; lost the visible entry", c.arg, got)
		}
	}
}
