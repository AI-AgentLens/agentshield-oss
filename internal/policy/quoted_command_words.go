package policy

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// QuotedCommandWordsMode selects how an evaluation treats a command word
// written inside quotes, `"cp"` for `cp` (#4873).
type QuotedCommandWordsMode int

const (
	// QuotedCommandWordsStricter is production: evaluate as written and, for
	// a command carrying a whole-quoted command word, at the top level or in
	// a carrier's payload, again with every such word written bare
	// (shellparse.FoldQuotedCommandWordsInPayloads); keep the bare reading
	// only when strictly more restrictive (stricterResult).
	QuotedCommandWordsStricter QuotedCommandWordsMode = iota
	// QuotedCommandWordsOff evaluates as written only, byte for byte
	// pre-#4873.
	QuotedCommandWordsOff
	// QuotedCommandWordsOn is the bare reading alone. Diagnostics and tests
	// only: on its own it carries no guarantee of being at least as strict as
	// Off.
	QuotedCommandWordsOn
)

// EvaluateQuotedCommandWords sits between EvaluatePrivateAlias and
// EvaluateQuotedFlags.
//
// # The bypass
//
// Bash removes the quotes, so `"cp" /tmp/x CLAUDE.md` runs cp. The regex
// stage reads a quoted command word bare in one place only: the whole
// command's first word (shellparse.FoldLeadingExecWord, a whole-command form
// in analyzer/whole_command_forms.go). The per-statement retry
// (analyzer.StatementMatchCandidates) has no such fold, and DequoteCommand
// keeps whole-word quotes, so the same word after ANY earlier statement
// (`echo x; "cp" …`, `true && "cp" …`, a newline) was never read as cp:
// ts-block-agent-memory-copy-overwrite went from BLOCK to AUDIT naming no
// rule.
//
// # The guarantee
//
// The construction of #3991, #4194, #4289, #4387, #4540 and #4596: the
// as-written evaluation is untouched, the bare reading is a second evaluation
// of the rewritten text with its own argv paths and tree, and it replaces the
// as-written result only when strictly more restrictive. No tie rule, so an
// equal decision keeps main's record byte for byte.
//
// Adding the fold to the statement candidates instead was rejected: those
// candidates also attribute a match to a statement for command_intent_exclude
// and command_intent_downgrade, so a quoted verb in a doc-text or heredoc
// statement would start earning the excuse, lowering a decision below main.
// Inside this reading exclusions and ALLOWs act only on the bare text, where
// they cannot reach the as-written result.
//
// Because the bare reading is a whole evaluation, it also repairs attribution:
// `"cp" /tmp/x CLAUDE.md; echo "cp /tmp/x CLAUDE.md"` was downgraded to AUDIT
// on main, the echo being the only statement counted as matching.
//
// # Inside a carrier's payload (#4920)
//
// The same word inside the shell source a carrier hands to a shell
// (`bash -c '"cp" …'`, `bash -s <<< '…'`, `bash < <(echo '…')`, a heredoc
// to a shell, `eval`, `man -P`, `env -S`) was text to the top-level fold,
// so the copy decided AUDIT while the bare verb in the same carrier BLOCKed. FoldQuotedCommandWordsInPayloads folds those words in
// place in the outer text, so the reading is the bare twin byte for byte:
// same carrier, same payload, quotes removed from its command words. It
// recognises a payload only where the parser decomposes one
// (CarriesShellSource on the statement's own segment), so the reading cannot
// reach text no analyzer treats as shell source; a `python3 -c` payload,
// printed text and a commit message are left as written. Self-protection
// keeps the top-level FoldQuotedCommandWords.
//
// Evaluating each folded payload as a standalone command was rejected: it is
// not the bare twin. It drops the carrier's own rules and context
// (`ts-audit-ai-watch-loop`, `sudo`), so its result is a different
// command's, and a payload that is only shell source at runtime would be
// judged as a top-level statement.
//
// # What it does not reach
//
// The fold rewrites exactly one quoted span of plain literal text. A command
// word built from several parts (`'c'p`, `c""p`) is not folded here;
// DequoteCommand already reads those. A payload whose value is not its text
// is not read: `bash -c "\"cp\" …"` (escapes inside double quotes), an
// unquoted heredoc holding a backslash, an expansion, an `eval` payload
// joined from several argv words, a carrier the parser does not decompose
// (`ssh host '…'`, `xargs sh -c`). An emitter piped into a shell
// (`echo '…' | bash`) is not read either: an emitter that decodes escapes
// makes the payload's value differ from its text, and reading only the
// plain spelling put TestEmittedEscapeParity over budget (#4929); the fix is
// to compose the fold with the escape-decoding reading, a separate change.
// A quoted word spliced with `${IFS}` (`;${IFS}"cp" …`) is one multi-part
// word and is not folded either. With no
// tie rule, an AUDIT rule matched only by the bare reading is not added to an
// AUDIT receipt (#4920 items 2 and 3).
//
// # Cost
//
// The reading runs only when the fold finds a word: a command with no quote
// character pays a byte scan, one with a quote pays a bash parse (and one per
// quoted payload of a carrier, up to shellparse's depth bound), and the
// second evaluation runs only for a quoted command word.
func (e *Engine) EvaluateQuotedCommandWords(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, mode QuotedCommandWordsMode) EvalResult {
	if mode == QuotedCommandWordsOff {
		return e.EvaluateQuotedFlags(command, paths, parsed, cwd, QuotedFlagsStricter)
	}
	reading := shellparse.FoldQuotedCommandWordsInPayloads(command)
	if reading == "" {
		return e.EvaluateQuotedFlags(command, paths, parsed, cwd, QuotedFlagsStricter)
	}
	n := normalize.NormalizeCommand(reading, cwd)
	// A caller that supplied no paths (Evaluate(cmd, nil): the accuracy
	// corpus) gets none for the bare reading either, so the two readings are
	// judged on the same evidence.
	barePaths := n.Paths
	if paths == nil {
		barePaths = nil
	}
	bare := e.EvaluateQuotedFlags(reading, barePaths, n.Parsed, cwd, QuotedFlagsStricter)
	if mode == QuotedCommandWordsOn {
		return bare
	}
	asWritten := e.EvaluateQuotedFlags(command, paths, parsed, cwd, QuotedFlagsStricter)
	return stricterResult(asWritten, bare)
}
