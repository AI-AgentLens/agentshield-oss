package shellparse

import "testing"

// TestIsShellInterpreter_VersionedAndRestricted is the #4386 truth table:
// a ShellInterpreters entry, that entry with a version suffix, or a
// documented restricted spelling is a shell; anything that merely looks like
// one is not.
func TestIsShellInterpreter_VersionedAndRestricted(t *testing.T) {
	shells := []string{
		// the set itself
		"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ksh93", "mksh", "ash", "rbash",
		// version suffixes
		"zsh5", "bash5", "bash4", "sh5", "ksh93", "bash5.2", "zsh-5.9", "zsh-5", "dash0.5.12", "mksh59",
		// restricted spellings, bare and versioned
		"rzsh", "rksh", "rksh93", "rbash5", "rzsh-5.9",
	}
	for _, s := range shells {
		if !IsShellInterpreter(s) {
			t.Errorf("IsShellInterpreter(%q) = false, want true", s)
		}
		if !IsShellOrInterpreter(s) {
			t.Errorf("IsShellOrInterpreter(%q) = false, want true", s)
		}
	}
	notShells := []string{
		"", "5", "-5", "r", "zsh-", "zsh5.", "zsh5..1", "zsh.5", "zsh--5",
		// rsh is the BSD remote-shell client on macOS and Linux: deliberately out
		"rsh", "rsh5",
		// r + a shell that defines no restricted name
		"rdash", "rsh2", "rtcsh", "rcsh", "rfish", "rmksh", "rash",
		// look-alikes
		"rshell-tool", "zshrc", "bashrc", "sha256sum", "shasum5.34", "shellcheck", "shx", "bash-completion",
		"zsh-autosuggestions", "fish_indent", "ksh93x", "bashbug", "git-shell", "jshell", "ssh", "ssh5",
		// code interpreters are not shells (IsShellOrInterpreter covers them)
		"python3", "node",
	}
	for _, s := range notShells {
		if IsShellInterpreter(s) {
			t.Errorf("IsShellInterpreter(%q) = true, want false", s)
		}
	}
	if !IsShellOrInterpreter("python3") || IsShellOrInterpreter("rsh") {
		t.Error("IsShellOrInterpreter must keep code interpreters and exclude rsh")
	}
}

// TestIsShellInterpreter_ParsedSegment: the parser's IsShell flag follows the
// predicate, behind sudo and env too, so every structural consumer sees it.
func TestIsShellInterpreter_ParsedSegment(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want bool
	}{
		{"sudo zsh5 -s", true},
		{"env rzsh", true},
		{"rksh93", true},
		{"rsh host uptime", false},
		{"rshell-tool", false},
	} {
		p := Parse(tc.cmd, 2)
		if p == nil || len(p.Segments) == 0 {
			t.Fatalf("Parse(%q) produced no segment", tc.cmd)
		}
		if got := p.Segments[0].IsShell; got != tc.want {
			t.Errorf("Parse(%q).Segments[0].IsShell = %v (exe %q), want %v", tc.cmd, got, p.Segments[0].Executable, tc.want)
		}
	}
}
