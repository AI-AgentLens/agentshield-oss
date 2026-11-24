package policy

import "strings"

// The record of a BLOCK the audit-only keep kept (#5089).
//
// In audit-only mode every BLOCK is lowered to AUDIT except the ones the keep
// (SelfProtectionKeep) accepts. When a self-protection rule decided the BLOCK,
// its record already names why it stands. When the keep accepted it for
// another reason, its rules are ordinary ones that audit-only mode lowers
// everywhere else: `mkfs.ext4 /dev/sda1; rm ~/.agentshield/policy.yaml` BLOCKed
// with the receipt ts-block-mkfs on the filesystem-format node, on a host
// configured not to block filesystem creation. The keep's reason is what
// decided, so it leads the record, under SelfProtectRuleID, and the rules that
// fired stay on the record after it.
//
// Evidence only. Nothing here runs unless the keep has already kept the
// BLOCK, and nothing here changes a decision. Enforce mode never reaches it.
// SelfProtectRuleID contributes no taxonomy node: the keep's command reading
// counts any command that is not, as a whole, a plain read, so it does not
// tell a read from a write, and an absent node is better than a guessed one
// (#4666). The rules after it keep their own nodes.

// SelfProtectKeptReasonPrefix starts the reason the keep gives for a BLOCK
// whose rules do not say why it stands. mcp.ShellSelfProtectionKeep writes
// the reasons; ruleKeptReason and managedFactsKeptReason write the engine's.
const SelfProtectKeptReasonPrefix = "Self-protection keeps this BLOCK in audit-only mode: "

// keptFor is a BLOCK's provenance in audit-only mode: why it was not lowered.
// It is set where that is decided, so no layer has to guess it from rule ids:
// a customer rule may reuse SelfProtectRuleID, and a managed lane's own
// self-protection BLOCK records SelfProtectRuleID without any keep (Codex
// pass 1 on #5091).
type keptFor struct {
	// why is the reason the BLOCK stands, worded as the lead of a record:
	// the keep's own reason, or, when a self-protection rule decided, a
	// reason naming that rule (ruleKeptReason), or a managed lane's
	// self-protection reading (managedFactsKeptReason). keptOnTie leads the
	// reading it raises for this BLOCK with it. "" on every other result,
	// and on every result in enforce mode.
	why string
	// led reports that the record's first entry is the lead
	// keptForSelfProtection put there, not a rule that fired.
	led bool
}

// keptForSelfProtection is r, a BLOCK that stands for why, with why first on
// its record under SelfProtectRuleID, and why as its provenance. why "" (a
// self-protection rule decided) and a record the keep already led return r
// unchanged. A record that names SelfProtectRuleID for another reason (a
// customer rule under that id) keeps its record and takes the provenance.
func keptForSelfProtection(r EvalResult, why string) EvalResult {
	if why == "" || r.kept.led {
		return r
	}
	r.kept.why = why
	for _, id := range r.TriggeredRules {
		if id == SelfProtectRuleID {
			return r
		}
	}
	r.TriggeredRules = append([]string{SelfProtectRuleID}, r.TriggeredRules...)
	r.Reasons = append([]string{why}, r.Reasons...)
	r.kept.led = true
	return r
}

// keptRecord is r, a BLOCK the keep kept for why, as audit-only mode records
// it. why "" means a self-protection rule among r's decided: the record
// already names it and is unchanged, and its provenance names that rule.
func (e *Engine) keptRecord(command string, r EvalResult, why string) EvalResult {
	if why == "" {
		r.kept.why = e.ruleKeptReason(command, r.TriggeredRules)
		return r
	}
	return keptForSelfProtection(r, why)
}

// withoutKeptLead is r's rules without the keep's lead, for a layer that
// chooses between two readings of one command by their records
// (caseFoldResult's strict-superset test). The lead says why a BLOCK stands;
// it is not a rule that fired, so it must not change which reading's record
// is returned. Counting it did: a mixed-case `rm -rf ~/.AgentShield`'s folded
// reading carries ts-struct-block-agentshield-dir-delete and its
// audit-trail node, and lost to the as-written reading's led record, which
// carries neither (TestHook_AuditOnlyKeepsSelfProtectionBlock_EndToEnd).
// Only the lead the keep put there is set aside: a rule that fired under the
// same id is compared like any other.
func withoutKeptLead(r EvalResult) []string {
	if r.kept.led && len(r.TriggeredRules) > 0 {
		return r.TriggeredRules[1:]
	}
	return r.TriggeredRules
}

// ruleKeptReason is the reason a BLOCK stands when the self-protection rules
// among rules are why: the ones the keep accepts on their own.
func (e *Engine) ruleKeptReason(command string, rules []string) string {
	var sp []string
	for _, id := range rules {
		if keep, why := e.selfProtectionKeep(command, []string{id}, nil); keep && why == "" {
			sp = append(sp, id)
		}
	}
	if len(sp) == 0 {
		return SelfProtectKeptReasonPrefix + "the command also matches a self-protection rule"
	}
	return SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule " + strings.Join(sp, ", ")
}

// managedFactsKeptReason is the reason a managed lane's self-protection BLOCK
// (EvaluateFacts' configTouchRule mirror) stands, for a reading keptOnTie
// raises for it.
const managedFactsKeptReason = SelfProtectKeptReasonPrefix + "the command also names AgentShield's managed configuration and is not a known read (rule: " + configTouchRule + ")"

// maskedKeptReason is the reason a protected-path BLOCK decided before the
// pipeline is kept because the rest of the evaluation, m, is a kept BLOCK
// (keepsMaskedSelfProtectionBlock): why m stands. The protected-path rule on
// r's record is not why r stands.
func (e *Engine) maskedKeptReason(command string, m EvalResult) string {
	if m.kept.why != "" {
		return m.kept.why
	}
	return e.ruleKeptReason(command, m.TriggeredRules)
}
