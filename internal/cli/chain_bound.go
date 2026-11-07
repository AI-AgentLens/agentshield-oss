package cli

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The chain bound on the hook and `agentshield check` (#4778, Gary
// 2026-11-04: "AUDIT").
//
// A command with more than shellparse.MaxChainOperators `|`, `|&`, `||` and
// `&&` operators is not parsed: walking the parser's tree for a chain that
// long overflows the Go stack, which kills the hook with exit 2, a Go stack
// trace and no audit record (Claude Code and Copilot CLI read that as a block,
// Cursor as a pass). Past the bound the command is decided the way every
// evaluation failure is, through failSafeDecision's contract: BLOCK
// enterprise-fail-closed under managed fail_closed, AUDIT
// agentshield-eval-error otherwise, with a chain_too_long note on the one
// event. That covers a derived text too (a nested shell's text after its
// variables were substituted, which a 20 KiB command can make 800 KiB long):
// the parse of such a text panics with the bound's error, and the reading
// that ran it turns the panic into the same decision.
//
// Gary, 2026-11-04: past the bound every managed host BLOCKs, with or
// without fail_closed. Under fail_closed the record is enterprise-fail-closed;
// without it, enterprise-chain-too-long (failSafeVerdict); an unmanaged host
// stays AUDIT.
//
// On a managed host the self-protection rules still read a command past the
// bound, on its raw text, which needs no parse (enterprise.SelfProtectRawText):
// a match BLOCKs as enterprise-self-protect with main's rule id and message,
// with the note, before the fail-safe decision is reached (Kai, 2026-11-04:
// padding must not lower self-protection). Main's middleware also read
// readings that parse (dequoted, unset-folded, zsh, the setup argv walk);
// the spellings only those find are the residual (#4778 fix round).

// commandParseStage names a command past the chain bound at the fail-safe
// boundary: "AgentShield: command parse failed — …".
const commandParseStage = "command parse"

// chainTooLongNote is the note a decision past the chain bound carries.
func chainTooLongNote(e *shellparse.ChainTooLongError) analyzer.Note {
	return analyzer.Note{Kind: analyzer.NoteChainTooLong, Detail: e.NoteDetail()}
}

// withChainTooLongNote is notes plus e's note, in the audit event's shape.
func withChainTooLongNote(notes []logger.Note, e *shellparse.ChainTooLongError) []logger.Note {
	n := chainTooLongNote(e)
	return append(append([]logger.Note(nil), notes...), logger.Note{Kind: n.Kind, Detail: n.Detail})
}

// readPOSIXText is the POSIX lane's analysis of text on engine: the bash
// normalizer and the analyzer pipeline. It returns the chain bound's error,
// and no result, when text or a text a reading derived from it is past the
// bound.
func readPOSIXText(engine *policy.Engine, text, cwd string) (policy.EvalResult, *shellparse.ChainTooLongError) {
	var r policy.EvalResult
	e := shellparse.GuardChainBound(text, func() {
		normalized := normalize.NormalizeCommand(text, cwd)
		r = engine.EvaluateWithParsedCwd(text, normalized.Paths, normalized.Parsed, cwd)
	})
	return r, e
}

// readPastChainBound is the reading of a command past the chain bound:
// failSafeDecision's, with the chain_too_long note. It loads the config and
// opens the audit log as every reading does, so the one event is written and
// uploaded like any other fail-safe event, and a failure to do either is that
// failure's own fail-safe reading, still carrying the note.
func readPastChainBound(cmdStr, cwd, source, sessionID string, notes []logger.Note, e *shellparse.ChainTooLongError) *commandReading {
	notes = withChainTooLongNote(notes, e)
	if blocked, ok := middlewareBlockPastChainBound(cmdStr, cwd, source); ok {
		return selfProtectReading(blocked, cmdStr, cwd, source, sessionID, notes)
	}
	failSafe := func(f evalFailure, closer func()) *commandReading {
		result, event, write := failSafeReading(f, cmdStr, cwd, source, sessionID)
		return &commandReading{result: result, event: event, write: write, close: closer}
	}
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return failSafe(evalFailure{stage: "config load", err: err, notes: notes, chainTooLong: true}, nil)
	}
	auditLogger, err := logger.New(cfg.LogPath)
	if err != nil {
		return failSafe(evalFailure{stage: "audit log init", err: err, cfg: cfg, notes: notes, chainTooLong: true}, nil)
	}
	return failSafe(evalFailure{stage: commandParseStage, err: e, cfg: cfg, log: auditLogger, notes: notes, chainTooLong: true},
		func() { _ = auditLogger.Close() })
}

// pastChainBoundResult is failSafeDecision's decision for a text past the
// chain bound, with the note, for a reading that has no event of its own: a
// nested POSIX reading in the PowerShell lane, which the lane combines into
// its verdict, and `agentshield check`. cfg nil reads managed.json directly,
// as failClosedEnabled always does.
func pastChainBoundResult(e *shellparse.ChainTooLongError, cfg *config.Config) policy.EvalResult {
	result, _ := failSafeVerdict(evalFailure{stage: commandParseStage, err: e, cfg: cfg, chainTooLong: true})
	result.Notes = []analyzer.Note{chainTooLongNote(e)}
	return result
}

// middlewareBlockPastChainBound is middlewareBlock for a text past the chain
// bound: on a managed host, the guard on the AGENTSHIELD_BYPASS variable and
// the self-protection rules on the raw text only. Empty outside managed mode.
func middlewareBlockPastChainBound(cmdStr, cwd, source string) (*policy.EvalResult, bool) {
	managedCfg := enterprise.LoadManagedConfig()
	if managedCfg == nil || !managedCfg.Managed {
		return nil, false
	}
	chain := []enterprise.EvalMiddleware{enterprise.BypassGuard(managedCfg), enterprise.SelfProtectRawText()}
	return middlewareBlockWith(chain, cmdStr, cwd, source, selfProtectTaxonomyRefsUnparsed)
}

// selfProtectTaxonomyRefsUnparsed is selfProtectTaxonomyRefs for a text that
// may not be parsed. The two rules whose node depends on the target read it
// from a parse; for a text past the bound they answer as they do for a text
// that does not parse: sp-block-delete-config attests nothing, and
// sp-block-binary-replace cites tampering.
func selfProtectTaxonomyRefsUnparsed(ruleID, command string) []string {
	var refs []string
	if shellparse.GuardChainBound(command, func() { refs = selfProtectTaxonomyRefs(ruleID, command) }) == nil {
		return refs
	}
	switch ruleID {
	case spDeleteConfigRule:
		return nil
	case spBinaryReplaceRule:
		return spTargetRefs(spTargetConfig)
	}
	return selfProtectTaxonomyRefs(ruleID, command)
}
