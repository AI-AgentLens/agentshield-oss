package route

import "strings"

// The lane combiner (ADR-001 D4, D9). When a row names more than one lane,
// each lane reads the call, every reading is turned into a Verdict, and
// Combine decides which reading is the call's receipt and what the call is
// enforced with. A row that adds a lane can therefore only raise a decision:
// the old lane's verdict is always one of the candidates, and nothing below
// the strictest candidate is ever chosen.

// Decision values, spelled as policy.Decision spells them. This package
// imports only the standard library, so the lanes' adapters convert.
const (
	DecisionAllow           = "ALLOW"
	DecisionAudit           = "AUDIT"
	DecisionRequireApproval = "REQUIRE_APPROVAL"
	DecisionBlock           = "BLOCK"
)

// Verdict is one lane's result in the shape every lane converges on before
// combining (ADR-001 D9). The POSIX lane's policy.EvalResult and the
// Structured lane's mcp.MCPEvalResult each have an adapter in internal/cli.
type Verdict struct {
	Lane Lane
	// Decision is the lane's decision after the configured mode was applied.
	Decision string
	// OriginalDecision is the decision before an audit-only downgrade, or ""
	// when none happened, exactly as the lane's own result carries it.
	OriginalDecision string
	Rules            []string
	Reasons          []string
	TaxonomyRefs     []string
	Notes            []Note
}

// Note is one attestation note on a lane's result (analyzer.Note's fields),
// plus whether it records uncertainty.
type Note struct {
	Kind, Rule, Detail string
	// Uncertain marks a note saying the lane could not read the call fully,
	// such as the PowerShell lane's parse_error to come. It puts the AUDIT
	// floor under the combined decision (ADR-001 D4). The POSIX lane's
	// existing notes keep today's meaning, so neither of today's adapters
	// sets it.
	Uncertain bool
}

// Combined is the verdict of a row's lanes.
type Combined struct {
	// Winner indexes the verdict whose record is kept: its rules, reasons,
	// taxonomy and notes are the call's receipt. -1 only for no verdicts.
	Winner int
	// Pick indexes the verdict the decision rules alone keep: the strictest,
	// the earlier on a tie, the kept BLOCK under KeptBlock. It is Winner,
	// except where the AUDIT tie rule moved the record to a verdict that
	// names a rule (Combine); then Pick is the rule-less verdict before it,
	// whose notes a consumer carried before that rule and still carries
	// (#4779). -1 only for no verdicts.
	Pick int
	// Decision and OriginalDecision are what the call is enforced and
	// recorded with. They are the winner's own, except when Floored raised
	// them.
	Decision, OriginalDecision string
	// KeptBlock: in audit-only mode the strictest lane's BLOCK was downgraded
	// while a lane it tied with kept its BLOCK (the self-protection keep), so
	// the call BLOCKs, and the winner is the lane that KEPT it: its rule is
	// what decided the BLOCK, so its record is the receipt (rules, taxonomy,
	// stderr, remediation), the one the Bash path gives for the same command.
	// The decision is stricterResult's keptOnTie (internal/policy): enforce
	// mode's decision exactly, so it never reaches above enforce, and in
	// enforce mode it never applies. The record is not keptOnTie's, which
	// keeps the reading it picked: two readings of one command share their
	// rules, two lanes do not, and the downgraded lane's rules did not
	// decide this BLOCK (#4753 Opus pass 1, C1).
	KeptBlock bool
	// Floored: a verdict carried an uncertainty note and the pick ranked
	// below AUDIT, so Decision was raised to AUDIT (the AUDIT floor).
	Floored bool
}

// Rank is the combiner's order, stricterResult's in internal/policy: ALLOW <
// AUDIT < REQUIRE_APPROVAL < BLOCK on the decision before any audit-only
// downgrade, and -1 for anything outside it. Ranking on the pre-downgrade
// decision keeps a "would have blocked" record from losing to a plain AUDIT
// in audit-only mode (#4021).
func Rank(v Verdict) int {
	d := v.Decision
	if v.OriginalDecision != "" {
		d = v.OriginalDecision
	}
	return decisionRank(d)
}

func decisionRank(d string) int {
	switch d {
	case DecisionAllow:
		return 0
	case DecisionAudit:
		return 1
	case DecisionRequireApproval:
		return 2
	case DecisionBlock:
		return 3
	}
	return -1
}

// Combine picks the strictest verdict. vs is in the row's lane order, and on
// a tie the earlier lane wins, so a row that gains a lane keeps the old
// lane's record (main's rule ids and receipt) wherever the new lane decides
// no more strictly. Two exceptions move the record on a tie:
//
//   - KeptBlock: the lane whose BLOCK survived audit-only mode wins its tie.
//   - The AUDIT tie rule (Gary, 2026-11-05; ADR-001 D4, #4779): when the
//     pick is a plain AUDIT (no audit-only downgrade) that names no rule,
//     the first verdict in row order that ties it exactly (AUDIT, no
//     downgrade) and names a rule is kept instead. An AUDIT rule exists to
//     attribute, and a receipt that names no rule cites no control. A lane
//     failure's AUDIT (LaneFailureRule) attributes nothing, so the record
//     never moves to one, and as the pick it names a rule, so it never
//     moves from one either: a lane failure ties exactly as on main. It is
//     evidence only: the verdicts tie, so Decision, OriginalDecision,
//     KeptBlock and Floored are what the pick alone gives
//     (TestCombine_AuditTieRuleChangesOnlyTheRecord). Every other tie keeps
//     the earlier lane, a rule-less one included: ALLOW, REQUIRE_APPROVAL,
//     BLOCK, an audit-only AUDIT[was BLOCK] or AUDIT[was
//     REQUIRE_APPROVAL] (its rank is the BLOCK's or the approval's, so the
//     audit-only receipt stays the one enforce mode records), and two AUDITs
//     that both name rules (the earlier lane's).
//
// An unranked verdict never wins over a ranked one; when nothing is ranked
// the first verdict is kept, as a single lane would be.
//
// So the winner's own decision is always the call's, except under the AUDIT
// floor (TestCombine_WinnerDecides).
func Combine(vs []Verdict) Combined {
	if len(vs) == 0 {
		return Combined{Winner: -1, Pick: -1}
	}
	best, bestRank := 0, Rank(vs[0])
	for i := 1; i < len(vs); i++ {
		if r := Rank(vs[i]); r > bestRank {
			best, bestRank = i, r
		}
	}
	c := Combined{Winner: best, Pick: best, Decision: vs[best].Decision, OriginalDecision: vs[best].OriginalDecision}

	// The audit-only tie rule (keptOnTie): a lane that kept its BLOCK ranks
	// 3, as the winner's downgraded BLOCK does, so it lost only on order. It
	// wins instead, with its own record (the first such lane in row order).
	if c.OriginalDecision == DecisionBlock {
		for i, v := range vs {
			if i != best && v.Decision == DecisionBlock && v.OriginalDecision == "" {
				c.Winner, c.Pick = i, i
				c.Decision, c.OriginalDecision, c.KeptBlock = DecisionBlock, "", true
				break
			}
		}
	}

	// The AUDIT tie rule: a rule-less plain AUDIT gives its record to the
	// first verdict that ties it exactly and names a rule a receipt can cite
	// (attributes). Only the record
	// moves: the candidate's Decision and OriginalDecision are the pick's,
	// so nothing set above changes, and the floor below cannot apply (the
	// pick ranks AUDIT). Verdicts before the pick rank below it, so the
	// candidate is always a later lane.
	if c.Decision == DecisionAudit && c.OriginalDecision == "" && !namesRule(vs[c.Winner]) {
		for i, v := range vs {
			if v.Decision == DecisionAudit && v.OriginalDecision == "" && attributes(v) {
				c.Winner = i
				break
			}
		}
	}

	// The AUDIT floor: a lane that could not read the call fully means no
	// ALLOW, from any lane, can stand.
	if bestRank < decisionRank(DecisionAudit) && anyUncertain(vs) {
		c.Decision, c.OriginalDecision, c.Floored = DecisionAudit, "", true
	}
	return c
}

// CarriedNotes are the notes of a row's other verdicts that the kept record
// carries after its own, in row order (ADR-001 D4, #4779):
//
//   - every other verdict's uncertainty notes. A lane that could not read
//     all of the call says so on the receipt whichever lane's record is
//     kept: it may be what put the AUDIT floor under the call, and it bounds
//     what the receipt can claim was read (the native-command bridge's cost
//     bounds are parse_error notes).
//   - when the AUDIT tie rule moved the record off the pick, every note of
//     the pick: its record was the receipt before that rule, and none of
//     its notes may drop off it.
//
// A note the kept verdict carries already, or one carried already, is not
// repeated; notes compare on Kind, Rule and Detail.
func CarriedNotes(vs []Verdict, c Combined) []Note {
	if c.Winner < 0 || c.Winner >= len(vs) {
		return nil
	}
	type key struct{ kind, rule, detail string }
	have := map[key]bool{}
	for _, n := range vs[c.Winner].Notes {
		have[key{n.Kind, n.Rule, n.Detail}] = true
	}
	var out []Note
	for i, v := range vs { // the kept verdict's own notes are all in have
		for _, n := range v.Notes {
			k := key{n.Kind, n.Rule, n.Detail}
			if (n.Uncertain || i == c.Pick) && !have[k] {
				have[k] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// LaneFailureRule is the rule id of the AUDIT a lane that could not decide
// takes outside managed fail_closed (ADR-001 D9: the hook's failSafeDecision,
// shield-server's laneFailure). It is a sentinel: it says the call was not
// fully evaluated, has no taxonomy and cites no control. The AUDIT tie rule
// never moves a record to it. On main a lane failure's AUDIT that tied MCP
// policy's lost on order, so MCP policy's evaluated record stayed the
// receipt with the failure named in lane_readings; moving the record to the
// failure would also lose the local audit line where the failure came
// before the audit log was opened (a fail-safe reading with no logger
// writes only to the SaaS queue), measured on
// TestLaneCombining_UnimplementedLaneIsAFailure.
const LaneFailureRule = "agentshield-eval-error"

// namesRule reports whether a verdict names any rule id; an empty id does
// not count. The pick is tested with it, so a lane failure's pick keeps its
// record.
func namesRule(v Verdict) bool {
	for _, r := range v.Rules {
		if r != "" {
			return true
		}
	}
	return false
}

// attributes reports whether a verdict names a rule a receipt can cite: an
// id other than "" and LaneFailureRule. A candidate is tested with it.
func attributes(v Verdict) bool {
	for _, r := range v.Rules {
		if r != "" && r != LaneFailureRule {
			return true
		}
	}
	return false
}

func anyUncertain(vs []Verdict) bool {
	for _, v := range vs {
		for _, n := range v.Notes {
			if n.Uncertain {
				return true
			}
		}
	}
	return false
}

// ReadingsDetail is the detail of the lane_readings note on a combined
// call's receipt: the tool the harness named, every lane of the row in row
// order with its decision and first rule, then the lane whose record was
// kept, e.g.
//
//	tool=Monitor; structured=AUDIT; posix=BLOCK(ts-block-rm-root); kept=posix
//
// The tool is there because a receipt kept from the POSIX lane is
// shell-shaped (a command, no tool name), so it would otherwise read as a
// Bash call. A downgraded decision shows what it was ("AUDIT[was BLOCK]"), a
// row lane with no verdict (nothing for it to read) shows "none", and the two
// rules beyond the plain pick are named: "block kept" (the kept lane won its
// tie through the keep-BLOCK rule) and "audit floor".
func ReadingsDetail(tool string, row []Lane, vs []Verdict, c Combined) string {
	parts := []string{"tool=" + tool}
	for _, l := range row {
		i := -1
		for j := range vs {
			if vs[j].Lane == l {
				i = j
				break
			}
		}
		if i < 0 {
			parts = append(parts, string(l)+"=none")
			continue
		}
		v := vs[i]
		s := string(l) + "=" + v.Decision
		if v.OriginalDecision != "" {
			s += "[was " + v.OriginalDecision + "]"
		}
		if len(v.Rules) > 0 {
			s += "(" + v.Rules[0] + ")"
		}
		parts = append(parts, s)
	}
	if c.Winner >= 0 && c.Winner < len(vs) {
		parts = append(parts, "kept="+string(vs[c.Winner].Lane))
	}
	// The AUDIT tie rule moved the record off the lane the decision rules
	// alone keep (Pick). Say so, naming that lane: the receipt is shaped by
	// the kept lane's writer, so without this a moved PowerShell record reads
	// as a shell call that came from nowhere (Gary, 2026-11-06).
	if c.Pick != c.Winner && c.Pick >= 0 && c.Pick < len(vs) {
		parts = append(parts, "audit tie moved from "+string(vs[c.Pick].Lane))
	}
	if c.KeptBlock {
		parts = append(parts, "block kept")
	}
	if c.Floored {
		parts = append(parts, "audit floor")
	}
	return strings.Join(parts, "; ")
}
