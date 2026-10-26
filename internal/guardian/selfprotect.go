package guardian

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// disableSecurityRule is the disable_security heuristic over the given bypass
// phrases. buildRules ships it with disableSecurityTextPatterns; the
// AgentShield-only reading (DisablesAgentShield) runs it with
// agentshieldTextPatterns, so the two cannot drift in their FP exemptions.
func disableSecurityRule(patterns []*regexp.Regexp) heuristicRule {
	return heuristicRule{
		signal: Signal{
			ID:          "disable_security",
			Category:    "security-bypass",
			Severity:    "critical",
			Confidence:  0.90,
			Description: "Command attempts to disable or bypass security controls",
		},
		match: func(req GuardianRequest) bool {
			return matchesDisableSecurityWith(req.RawCommand, patterns)
		},
		refine: func(req GuardianRequest, sig *Signal) {
			// #3380: AGENTSHIELD_DISABLE is a direct bypass regardless of
			// context and must never be downgraded by the banner check below.
			if agentshieldDisableLive(req.RawCommand) {
				return
			}
			if disableSecurityIsBareBanner(req.RawCommand) {
				sig.Severity = "medium"
				sig.Confidence = 0.35
				sig.Description = "Command echoes/prints a security-bypass phrase with no other text (a banner/progress line, not a directive) — recorded for audit, not blocked"
				return
			}
			// #3633: a grep/sed/awk pattern argument is a search NEEDLE,
			// not a directive — see disableSecurityIsQuotedToolPattern.
			if disableSecurityIsQuotedToolPattern(req.RawCommand) {
				sig.Severity = "medium"
				sig.Confidence = 0.35
				sig.Description = "Command searches/matches for a security-bypass phrase as a tool pattern argument (grep/sed/awk), not a directive — recorded for audit, not blocked"
			}
		},
		escalate: "BLOCK",
	}
}

// agentshieldTextPatterns are the disableSecurityTextPatterns phrases whose
// object is AgentShield itself. --no-verify, "skip security" and the other
// phrases name some other control.
var agentshieldTextPatterns = compilePatterns([]string{
	`(?i)(disable|turn\s+off|bypass|skip|ignore)\s+agentshield`,
	`(?i)(remove|delete|uninstall)\s+agentshield`,
})

// agentshieldOnly is a guardian that knows only the disable_security
// phrases naming AgentShield (its disable variable and agentshieldTextPatterns).
var agentshieldOnly = NewGuardianAnalyzer(&HeuristicProvider{rules: []heuristicRule{disableSecurityRule(agentshieldTextPatterns)}})

const disableSecurityRuleID = "guardian-disable_security"

// RuleTaxonomy returns the taxonomy ref a guardian finding carries for its
// rule id ("guardian-<signal>"), or "" for an id that is not a guardian
// finding or a signal with no taxonomy node.
func RuleTaxonomy(ruleID string) string {
	sig, ok := strings.CutPrefix(ruleID, "guardian-")
	if !ok {
		return ""
	}
	return signalToTaxonomy(Signal{ID: sig})
}

// TargetsAgentShield reports whether the guardian finding ruleID, on command,
// is aimed at AgentShield itself (#4397, #4424). Only disable_security can be:
// it is the guardian's self-protection signal, and it is self-protection only
// when what it disables is AgentShield (DisablesAgentShield), not a git hook
// (`git commit --no-verify`) or another tool. Every other id is false.
//
// It is the audit-only keep rule's reading (mcp.ShellSelfProtectionKeep). It
// decides nothing in enforce mode, so it can only keep a BLOCK the guardian
// already made.
func TargetsAgentShield(ruleID, command string) bool {
	return ruleID == disableSecurityRuleID && DisablesAgentShield(command)
}

// DisablesAgentShield reports whether the disable_security signal fires at
// BLOCK on command when the only bypass phrases it knows are the ones naming
// AgentShield: its disable variable, or "disable/bypass/remove agentshield".
// It runs the shipped heuristic (the same candidate forms, statement split and
// FP exemptions) with those phrases alone, so a quoted gh/git argument, a bare
// echo banner or a grep needle is no more AgentShield's than it is a BLOCK.
func DisablesAgentShield(command string) bool {
	for _, f := range agentshieldOnly.Analyze(&analyzer.AnalysisContext{RawCommand: command}) {
		if f.RuleID == disableSecurityRuleID && f.Decision == "BLOCK" {
			return true
		}
	}
	return false
}
