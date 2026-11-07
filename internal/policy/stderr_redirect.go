package policy

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// StderrRedirectMode selects how an evaluation treats a redirect that leaves
// stdout where it was: a stderr redirect (`2>/dev/null`), an fd duplication
// (`2>&1`, `>&2`) or a `|&` pipe (#4610).
type StderrRedirectMode int

const (
	// StderrRedirectStricter is production: evaluate as written and, for a
	// command carrying such a redirect, again with it removed
	// (shellparse.StripStderrRedirects); keep the stripped reading only when
	// strictly more restrictive (stricterResult).
	StderrRedirectStricter StderrRedirectMode = iota
	// StderrRedirectOff evaluates as written only, byte for byte pre-#4610.
	StderrRedirectOff
	// StderrRedirectOn is the stripped reading alone. Diagnostics and tests
	// only: on its own it carries no guarantee of being at least as strict
	// as Off.
	StderrRedirectOn
)

// EvaluateStderrRedirect is EvaluateWithParsedCwd with the #4610 mode explicit.
//
// # The bypass
//
// Rules written for pipe adjacency (`cat <history file> | grep <secret word>`)
// read the raw text, so a stderr redirect placed before the pipe broke the
// adjacency while the data flow stayed the same: stdout still reaches the
// pipe. `cat ~/.zsh_history 2>/dev/null | grep -i password` decided ALLOW
// (ts-allow-readonly) where the redirect-free twin BLOCKs. The audit that
// found it measured 13 of 106 pipe-bearing BLOCKs lowered this way, 3 to
// ALLOW; `|&` showed the same shape.
//
// # The guarantee, and where it comes from
//
// The construction of #3991, #4194, #4289, #4387 and #4540, outermost. The
// as-written evaluation is untouched. The stripped reading runs as a second,
// independent evaluation of the rewritten text, normalized the way the hook
// normalizes a command (its own argv paths and tree), and replaces the
// as-written result only when strictly more restrictive, so the returned
// decision is never below the as-written one. No tie rule: at an equal
// decision the as-written record is kept.
//
// Why a new BLOCK here is justified rather than guessed: the stripped text is
// the same command with only stderr's destination changed, so whatever it
// decides is this engine's own verdict on what the command does to stdout.
// Redirects that MOVE stdout (`>file`, `&>file`) are never removed; the pipe
// downstream would not receive the data, and the adjacency would be a reading
// the shell does not perform.
//
// # Cost
//
// Commands without `>`, `<&` or `|&` pay three substring scans. Commands with
// one pay a parse, and the second evaluation only when something was removed.
// `2>&1` is a common agent idiom, so that second evaluation is real traffic.
func (e *Engine) EvaluateStderrRedirect(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, mode StderrRedirectMode) EvalResult {
	if mode == StderrRedirectOff {
		return e.EvaluateANSICNUL(command, paths, parsed, cwd, ANSICNULStricter)
	}
	reading := shellparse.StripStderrRedirects(command)
	if reading == "" {
		return e.EvaluateANSICNUL(command, paths, parsed, cwd, ANSICNULStricter)
	}
	n := normalize.NormalizeCommand(reading, cwd)
	// Removing a redirect removes at most a redirect target; it never adds an
	// argv path. A caller that supplied no paths (Evaluate(cmd, nil): the
	// accuracy corpus, which deliberately leaves protected_paths unexercised)
	// gets none for the stripped reading either, so the two readings are
	// judged on the same evidence.
	strippedPaths := n.Paths
	if paths == nil {
		strippedPaths = nil
	}
	stripped := e.EvaluateANSICNUL(reading, strippedPaths, n.Parsed, cwd, ANSICNULStricter)
	if mode == StderrRedirectOn {
		return stripped
	}
	asWritten := e.EvaluateANSICNUL(command, paths, parsed, cwd, ANSICNULStricter)
	return stricterResult(asWritten, stripped)
}
