package policy

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/guardian"
)

// EvaluateInlineSecrets is the shell pipeline's inline-secrets heuristic,
// and only that one, over a dialect lane's text (#4802). ok is false when it
// does not fire, or when this engine's shell pipeline does not run the
// guardian stage, so the lane never decides on it where the shell would not.
//
// Why a lane needs it: the guardian stage runs inside the POSIX pipeline, and
// Claude Code's PowerShell tool has no POSIX lane. A token written into a
// cmdlet call, an assignment or a .NET call (`Write-Output <tok>`,
// `$env:GITHUB_TOKEN = '<tok>'`, `-Headers @{Authorization='token <tok>'}`)
// decided AUDIT with no rule there, while the Bash tool BLOCKed the same text
// as guardian-secrets_in_command. The decision is the bash twin's: the same
// heuristic on the same text (guardian.InlineSecretsFinding), so the same
// rule id, tier (BLOCK for a token, AUDIT for a credential-named value with
// no credential shape), reason and taxonomy node. The other guardian
// heuristics are tuned on bash text and are not run.
//
// It takes text, not facts.Facts: EvaluateFacts decides on what the lane
// read and knows no dialect, while this heuristic reads characters as
// written, as the guardian reads the shell's raw command. The lane combines
// the two readings (assembly.PowerShellLane).
//
// The engine's mode applies as on the shell: audit-only lowers the BLOCK to
// AUDIT and records the BLOCK as the original decision. No self-protection
// keep: the keep's text test reads shell text (EvaluateFacts' keep reads
// paths only, for the same reason), and this is not a self-protection rule.
func (e *Engine) EvaluateInlineSecrets(text string) (EvalResult, bool) {
	if !e.runsGuardian() {
		return EvalResult{}, false
	}
	f, ok := guardian.InlineSecretsFinding(text)
	if !ok {
		return EvalResult{}, false
	}
	r := EvalResult{
		Decision:       Decision(f.Decision),
		TriggeredRules: []string{f.RuleID},
		Reasons:        []string{f.Reason},
		TaxonomyRefs:   analyzer.NormalizeTaxonomyRefs([]string{f.TaxonomyRef}),
	}
	r = applyModeDowngrade(r, e.mode)
	r.Explanation = buildExplanation(r)
	return r, true
}

// runsGuardian reports whether the engine's shell evaluation runs the
// guardian stage: it has an analyzer pipeline and the pipeline holds the
// stage. An engine without one (NewEngine alone, the regex-only fallback)
// never reports a guardian finding for a shell command.
func (e *Engine) runsGuardian() bool {
	if e.registry == nil {
		return false
	}
	for _, a := range e.registry.Analyzers() {
		if a.Name() == "guardian" {
			return true
		}
	}
	return false
}
