package policy

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// ZshReadingMode selects how an evaluation treats a command the bash parser
// rejects and the zsh parser accepts (#4598).
type ZshReadingMode int

const (
	// ZshReadingStricter is production: evaluate as written and, for a
	// command the bash parser rejects, again as the zsh parser reads it
	// (shellparse.ZshReading); keep the zsh reading only when strictly more
	// restrictive (stricterResult).
	ZshReadingStricter ZshReadingMode = iota
	// ZshReadingOff evaluates as written only, byte for byte pre-#4598.
	ZshReadingOff
	// ZshReadingOn is the zsh reading alone. Diagnostics and tests only: on
	// its own it carries no guarantee of being at least as strict as Off.
	ZshReadingOn
)

// EvaluateZshReading is EvaluateWithParsedCwd with the #4598 mode explicit.
//
// # The bypass
//
// Every parser here reads bash, and on a stock Mac Claude Code's Bash tool
// runs commands through zsh. Any zsh-only syntax, even a harmless statement
// of its own (`: ${(U)HOME};`, a no-op in zsh), failed the bash parse. That
// switched off the structural, semantic, dataflow and stateful stages
// (#3211), and the regex stage's per-statement split and guardian's
// per-statement retry (#4291) each saw the whole text as one statement, so a
// `^`-anchored rule could not see a command after the prefix and a leading
// `git status;` exempted the prose after it. The issue measured, over the
// single-line BLOCKing corpus, 21.8% lowered by a `: ${(U)HOME};` prefix,
// 24.5% by `{ C }` and 22.4% by `() { C }`, all to AUDIT naming no rule.
//
// # The guarantee
//
// The construction of #3991, #4194, #4289, #4387, #4540 and #4610,
// outermost (Gary, 2026-10-28: "yes, as a second reading only"). The
// as-written evaluation is untouched. When the bash parser rejects the
// command and the zsh parser accepts it, shellparse.ZshReading writes the
// zsh tree as bash-parseable text, and that text runs as a second,
// independent evaluation, normalized the way the hook normalizes a command
// (its own argv paths and tree). Because the reading is ordinary bash text,
// every stage sees it whole: the AST stages get a tree, and the regex stage's
// per-statement split and guardian's per-statement retry split it into the
// statements zsh reads. Its result replaces the as-written one only when
// strictly more restrictive, so the returned decision is never below the
// as-written one. No tie rule: at an equal decision the as-written record,
// and its attribution, is kept.
//
// Outermost so the other readings compose with it: each of them parses the
// command as bash and so has nothing to read on a zsh-only command, while on
// the zsh reading's text they run as usual.
//
// # Why the trigger is the parse failure, not shell detection
//
// The attacker controls the text, not the shell. Reading as zsh whenever bash
// rejects the text costs, at worst, an extra BLOCK on a bash host, for a
// command that is a bash syntax error and would not have run. Gating on a
// detected shell would keep the fail-open whenever detection is wrong.
//
// # What it does not reach
//
// See shellparse.ZshReading: the short `for i (1) C` form (the zsh parser
// rejects it too; pinned by TestZshReading_ShortForIsAPinnedResidual_4598),
// a zsh construct inside a carrier's quoted payload, and commands that parse
// in both shells with different meanings.
//
// # Cost
//
// Every command pays one extra bash parse; a command the bash parser rejects
// pays a zsh parse, and the second evaluation only when a reading is made.
func (e *Engine) EvaluateZshReading(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, mode ZshReadingMode) EvalResult {
	if mode == ZshReadingOff {
		return e.EvaluateStderrRedirect(command, paths, parsed, cwd, StderrRedirectStricter)
	}
	reading := shellparse.ZshReading(command)
	if reading == "" {
		return e.EvaluateStderrRedirect(command, paths, parsed, cwd, StderrRedirectStricter)
	}
	n := normalize.NormalizeCommand(reading, cwd)
	// A caller that supplied neither paths nor a tree (Evaluate(cmd, nil):
	// the accuracy corpus) gets no paths for the zsh reading either, so the
	// two readings are judged on the same evidence. Unlike the other
	// readings, nil paths alone do not mean that here: the hook's paths for a
	// command the bash parser rejected come from the fallback parse and are
	// often nil, and the zsh reading's own paths are the evidence the
	// protected_paths check was missing (`echo x >> ~/.kube/config;
	// : ${(U)HOME}` decided AUDIT where its `: ${HOME}` twin BLOCKs).
	zshPaths := n.Paths
	if paths == nil && parsed == nil {
		zshPaths = nil
	}
	zsh := e.EvaluateStderrRedirect(reading, zshPaths, n.Parsed, cwd, StderrRedirectStricter)
	if mode == ZshReadingOn {
		return zsh
	}
	asWritten := e.EvaluateStderrRedirect(command, paths, parsed, cwd, StderrRedirectStricter)
	return stricterResult(asWritten, zsh)
}
