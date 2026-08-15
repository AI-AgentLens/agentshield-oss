package guardian

import (
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// GuardianAnalyzer adapts a GuardianProvider to the analyzer.Analyzer interface
// so it can be plugged into the pipeline as the 6th layer.
//
// Escalation semantics: the guardian can only escalate decisions, never downgrade.
// ALLOW → AUDIT or BLOCK, AUDIT → BLOCK, BLOCK stays BLOCK.
type GuardianAnalyzer struct {
	provider GuardianProvider
}

// NewGuardianAnalyzer creates a pipeline-compatible analyzer wrapping a provider.
func NewGuardianAnalyzer(provider GuardianProvider) *GuardianAnalyzer {
	return &GuardianAnalyzer{provider: provider}
}

func (g *GuardianAnalyzer) Name() string { return "guardian" }

// Analyze runs the guardian provider and converts signals into pipeline Findings.
// Each signal becomes a separate Finding so the combiner can evaluate them individually.
//
// The provider is run over every text form of the command, and the signals are
// unioned (first occurrence of a signal ID wins). Today that is the raw command
// plus, when it differs, its IFS-normalized form: $IFS defaults to
// space/tab/newline, so `tar${IFS}--to-command=...` invokes exactly the same
// command as `tar --to-command=...` (#3044). Every other text-matching decision
// layer — regex, substitution, semantic — already builds that candidate form;
// the guardian did not, so any BLOCK the guardian was the ONLY layer to produce
// could be dropped to AUDIT by swapping a single space. The raw form is kept in
// the set rather than replaced, so a heuristic keyed on the literal `${IFS}`
// obfuscation text is not lost by canonicalizing it away.
func (g *GuardianAnalyzer) Analyze(ctx *analyzer.AnalysisContext) []analyzer.Finding {
	forms := []string{ctx.RawCommand}
	// NormalizeIFS returns "" unless the command actually contains "IFS" AND a
	// bare $IFS/${IFS} separator was rewritten, so this is a no-op for every
	// command that does not use the bypass.
	if normalized := shellparse.NormalizeIFS(ctx.RawCommand); normalized != "" && normalized != ctx.RawCommand {
		forms = append(forms, normalized)
	}
	// Same shape, same reason, for the unset-parameter splice: a heuristic
	// keyed on the literal command text ("^curl\\s+.*\\|\\s*bash") stops
	// matching once a `cur${zqx}l` splice is spliced into the executable.
	// The raw form stays in the set so a heuristic keyed on the obfuscation
	// text itself is not lost by canonicalizing it away.
	if normalized := shellparse.NormalizeUnsetParamExp(ctx.RawCommand); normalized != "" && normalized != ctx.RawCommand {
		forms = append(forms, normalized)
	}
	// Same shape again for quote/escape splicing: `git push -\-no-verify`
	// removes the backslash in a real shell and runs `git push --no-verify`
	// exactly, but a heuristic keyed on the literal "--no-verify" text only
	// ever saw ctx.RawCommand. Every other text-matching layer already
	// consults shellparse.DequoteCommand (regex.go, datalabel.go,
	// enterprise/managed.go); the guardian was the one candidate-form list
	// that never gained it (issue #3322, follow-up to #3209/#3208).
	if dequoted := shellparse.DequoteCommand(ctx.RawCommand); dequoted != "" && dequoted != ctx.RawCommand {
		forms = append(forms, dequoted)
	}
	// A heredoc fed to a SHELL interpreter (`bash <<EOF`) — or an eval/trap
	// argument — is executed shell source, not inert text, exactly like `-c`
	// code delivered over stdin instead of argv. InlineCodeFragments already
	// isolates exactly these forms for the regex analyzer (#3050/#3081/#3084);
	// the guardian saw only ctx.RawCommand, so a heuristic anchored on the
	// unwrapped command's shape (e.g. "^python3\\s+-c") stopped matching once
	// the same text moved from the top of the command to mid-heredoc-body
	// (#3135). InlineCodeFragments already excludes non-shell interpreter
	// heredocs (python/node/...) and `cat`/`tee` document bodies — see its doc
	// comment — so this cannot turn a heredoc-written document into a scan
	// target.
	forms = append(forms, shellparse.InlineCodeFragments(ctx.RawCommand)...)
	// And the same shape a fifth time, for indirect executable names:
	// `$(echo tar) -cf x --checkpoint-action=exec=...` and `x=tar; $x ...` both
	// run tar, but a heuristic keyed on the literal command text never sees the
	// word. Every other text-matching layer consults
	// shellparse.ResolveIndirectExecutables (#3089); the guardian did not.
	//
	// Found by the OSS distribution ratchet, and only there — which is worth
	// recording, because it is the argument for keeping that gate. In the FULL
	// build a premium rule (ts-block-tar-checkpoint-action-exec) independently
	// covers the same command, so the guardian's miss changes no decision and no
	// test fails. Strip premium and the guardian is the only layer left, the
	// command drops BLOCK -> AUDIT, and the free tier has a real bypass. A
	// premium rule was masking a community-layer gap: measured 19/1528 leaked
	// against a budget of 18 in the OSS build, 18/2344 in the full build.
	//
	// The raw form stays in the set, as with every candidate above, so a
	// heuristic keyed on the obfuscation text itself is not lost.
	if resolved := shellparse.ResolveIndirectExecutables(ctx.RawCommand); resolved != "" && resolved != ctx.RawCommand {
		forms = append(forms, resolved)
	}

	var findings []analyzer.Finding
	seen := make(map[string]int) // signal ID -> index into findings
	for _, form := range forms {
		resp, err := g.provider.Analyze(GuardianRequest{RawCommand: form})
		if err != nil {
			// Guardian failure is non-fatal: skip this form and keep going.
			// The deterministic pipeline still provides baseline protection.
			continue
		}

		for _, sig := range resp.Signals {
			f := analyzer.Finding{
				AnalyzerName: "guardian",
				RuleID:       "guardian-" + sig.ID,
				Decision:     signalToDecision(sig),
				Confidence:   sig.Confidence,
				Reason:       sig.Description,
				TaxonomyRef:  signalToTaxonomy(sig),
				Tags:         []string{"guardian", sig.Category},
			}
			// Union across forms, most-restrictive wins. This was "first form
			// wins", which was equivalent while every signal ID carried one
			// fixed severity. Since #3345 a signal can be graded per-request
			// (secrets_in_command downgrades a credential-NAMED assignment whose
			// VALUE has no credential shape), so a form-order accident could
			// otherwise drop a later form's BLOCK to the raw form's AUDIT —
			// re-opening exactly the quote/IFS/splice bypasses the extra
			// candidate forms above exist to close.
			if i, ok := seen[sig.ID]; ok {
				if decisionRank(f.Decision) > decisionRank(findings[i].Decision) {
					findings[i] = f
				}
				continue
			}
			seen[sig.ID] = len(findings)
			findings = append(findings, f)
		}
	}

	return findings
}

// decisionRank orders pipeline decisions by restrictiveness.
func decisionRank(d string) int {
	switch d {
	case "BLOCK":
		return 2
	case "AUDIT":
		return 1
	default:
		return 0
	}
}

// signalToDecision maps a signal's severity to a pipeline decision.
func signalToDecision(sig Signal) string {
	switch sig.Severity {
	case "critical":
		return "BLOCK"
	case "high":
		return "BLOCK"
	case "medium":
		return "AUDIT"
	case "low":
		return "AUDIT"
	default:
		return "AUDIT"
	}
}

// signalToTaxonomy maps guardian signal categories to taxonomy references.
// This allows the combiner to correlate guardian findings with other analyzers.
func signalToTaxonomy(sig Signal) string {
	switch sig.Category {
	case "prompt-injection":
		return "unauthorized-execution/prompt-injection/" + sig.ID
	case "security-bypass":
		return "unauthorized-execution/security-bypass/" + sig.ID
	case "obfuscation":
		return "unauthorized-execution/obfuscation/" + sig.ID
	case "code-execution":
		return "unauthorized-execution/code-execution/" + sig.ID
	case "data-exfiltration":
		return "data-exfiltration/bulk-transfer/" + sig.ID
	case "steganography":
		return "data-exfiltration/steganography/" + sig.ID
	case "credential-exposure":
		return "credential-exposure/inline-secret/" + sig.ID
	default:
		return "guardian/" + sig.Category + "/" + sig.ID
	}
}
