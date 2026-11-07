package analyzer

import "github.com/AI-AgentLens/agentshield/internal/shellparse"

// shellFlagIsNotProgram reports whether flag, on a POSIX shell pipe target,
// is a `set` option rather than a source of the program (#4599). For
// sh/bash/zsh/dash/ksh only -c takes the program from an argument; -e is
// errexit and -m is job control, and stdin is still the script. The
// inline-code exemptions (`python3 -c`, `node -e`, `python3 -m`) were written
// for interpreters, and the -e entry from #3346 landed in lists shared with
// the shells. Only ever used to IGNORE an exemption, so it can only keep a
// pipe-to-interpreter finding that would otherwise be skipped.
func shellFlagIsNotProgram(seg CommandSegment, flag string) bool {
	if flag != "e" && flag != "m" {
		return false
	}
	return shellparse.IsShellInterpreter(seg.Executable) || shellparse.IsShellInterpreter(seg.Program)
}
