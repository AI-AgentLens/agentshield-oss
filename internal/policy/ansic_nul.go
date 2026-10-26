package policy

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// ANSICNULMode selects how an evaluation treats an escape inside $'...' that
// decodes to byte 0 (#4540).
type ANSICNULMode int

const (
	// ANSICNULStricter is production: evaluate as written and, for a command
	// with such an escape, again with each $'...' body cut where bash cuts it
	// (shellparse.ANSICNULReading); keep the cut reading only when strictly
	// more restrictive (stricterResult).
	ANSICNULStricter ANSICNULMode = iota
	// ANSICNULOff evaluates as written only — byte-for-byte pre-#4540.
	ANSICNULOff
	// ANSICNULOn is the cut reading alone. Diagnostics and tests only: on its
	// own it carries no guarantee of being at least as strict as Off.
	ANSICNULOn
)

// EvaluateANSICNUL is EvaluateWithParsedCwd with the #4540 mode explicit.
//
// # The bypass
//
// bash ends a $'...' body at the first escape that decodes to byte 0, so
// r$'\0'm runs rm and $'rm\0zz' runs rm. pathnorm.DecodeANSICEscapes writes
// a NUL byte there instead, so every layer read `r<NUL>m` and no verb- or
// path-anchored rule matched: a recursive delete of / decided AUDIT and an
// SSH private-key read decided ALLOW (ts-allow-readonly). Only the 3-digit
// octal spelling was held, by ts-block-ansic-octal-escape's regex on the raw
// text.
//
// # The guarantee, and where it comes from
//
// The construction of #3991, #4194, #4289 and #4387. Cutting the body in the
// decoder itself was measured first, and it is not additive: zsh, the
// default macOS shell, keeps the NUL inside the string, and its eval, trap,
// alias and source run the text after it. With the cut in place
// `eval $'true\0;<cmd>'` and `trap $'true\0;<cmd>' EXIT` dropped from BLOCK to
// AUDIT, though zsh runs <cmd>. A path whose meaning sits after the NUL
// (`rm -rf $'/tmp/x\0/../..'`) dropped from BLOCK to ALLOW; that text is dead
// in both shells, but it is still a lower decision.
//
// So the decoder is unchanged and the as-written evaluation is untouched. The
// cut reading runs as a second, independent evaluation of the rewritten text,
// normalized the way the hook normalizes a command: its own argv paths (the
// cut changes path words, and protected_paths compares them) and its own
// tree. Its result replaces the as-written one only when strictly more
// restrictive (stricterResult), so the returned decision is never below the
// as-written one. No tie rule: at an equal decision the as-written record is
// kept.
//
// # What it does not reach
//
// A $'...' span inside a carrier's quoted payload (`bash -c "r\$'\\0'm"`) is
// text at the top level and is not cut; the as-written evaluation decides it,
// as before #4540.
//
// # Cost
//
// The cut reading runs only when a $'...' body has a byte-0 escape: commands
// without both `$'` and a backslash pay two substring scans; those with them
// pay a parse, and the second evaluation only if a byte-0 escape is found.
func (e *Engine) EvaluateANSICNUL(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, mode ANSICNULMode) EvalResult {
	if mode == ANSICNULOff {
		return e.EvaluatePrivateAlias(command, paths, parsed, cwd, PrivateAliasStricter)
	}
	reading := shellparse.ANSICNULReading(command)
	if reading == "" {
		return e.EvaluatePrivateAlias(command, paths, parsed, cwd, PrivateAliasStricter)
	}
	// The cut reading is evaluated the way the hook evaluates a command:
	// normalize gives it its own argv paths and its own tree. parsed is the
	// as-written tree and is never reused for it.
	n := normalize.NormalizeCommand(reading, cwd)
	cut := e.EvaluatePrivateAlias(reading, n.Paths, n.Parsed, cwd, PrivateAliasStricter)
	if mode == ANSICNULOn {
		return cut
	}
	asWritten := e.EvaluatePrivateAlias(command, paths, parsed, cwd, PrivateAliasStricter)
	return stricterResult(asWritten, cut)
}
