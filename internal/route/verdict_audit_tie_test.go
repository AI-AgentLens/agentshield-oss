package route

import (
	"math/rand"
	"slices"
	"testing"
)

// The AUDIT tie rule (Gary, 2026-11-05; ADR-001 D4, #4779): on a tie of
// plain AUDITs the record kept is a verdict that names a rule, not a
// rule-less earlier one. Evidence only: no decision changes.

// TestCombine_AuditTieRule is the rule, case by case.
func TestCombine_AuditTieRule(t *testing.T) {
	unsure := Note{Kind: "fake_parse_error", Uncertain: true}
	withNote := func(x Verdict, n Note) Verdict { x.Notes = []Note{n}; return x }
	cases := []struct {
		name               string
		vs                 []Verdict
		winner, pick       int
		decision, original string
		keptBlock, floored bool
	}{
		// The rule.
		{"rule-less AUDIT first, rule-bearing AUDIT second: the second",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", "ps-audit-env-exfil")}, 1, 0, "AUDIT", "", false, false},
		{"the first rule-bearing AUDIT in row order",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "AUDIT", "", "ts-y"), v(PowerShell, "AUDIT", "", "ps-z")}, 1, 0, "AUDIT", "", false, false},
		{"past a rule-less AUDIT to the rule-bearing one",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "AUDIT", ""), v(PowerShell, "AUDIT", "", "ps-z")}, 2, 0, "AUDIT", "", false, false},
		{"an empty rule id names no rule",
			[]Verdict{v(Structured, "AUDIT", "", ""), v(PowerShell, "AUDIT", "", "ps-z")}, 1, 0, "AUDIT", "", false, false},
		{"a list with one real id names a rule",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", "", "ps-z")}, 1, 0, "AUDIT", "", false, false},
		{"a lane failure's sentinel beside a real rule: the real rule attributes",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", LaneFailureRule, "ps-z")}, 1, 0, "AUDIT", "", false, false},
		// Lane failures tie as on main.
		{"a lane failure's AUDIT is never moved to",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", LaneFailureRule)}, 0, 0, "AUDIT", "", false, false},
		{"past a lane failure to a later real rule",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "AUDIT", "", LaneFailureRule), v(PowerShell, "AUDIT", "", "ps-z")}, 2, 0, "AUDIT", "", false, false},
		{"a lane failure as the pick keeps its record",
			[]Verdict{v(POSIX, "AUDIT", "", LaneFailureRule), v(PowerShell, "AUDIT", "", "ps-z")}, 0, 0, "AUDIT", "", false, false},
		{"the pick need not be the first verdict: an earlier ALLOW with a rule is no candidate",
			[]Verdict{v(Structured, "ALLOW", "", "mcp-allow"), v(POSIX, "AUDIT", ""), v(PowerShell, "AUDIT", "", "ps-z")}, 2, 1, "AUDIT", "", false, false},
		// What stays as it was.
		{"both name rules: the earlier lane",
			[]Verdict{v(Structured, "AUDIT", "", "mcp-x"), v(PowerShell, "AUDIT", "", "ps-y")}, 0, 0, "AUDIT", "", false, false},
		{"rule-bearing first, rule-less second: the first",
			[]Verdict{v(Structured, "AUDIT", "", "mcp-x"), v(PowerShell, "AUDIT", "")}, 0, 0, "AUDIT", "", false, false},
		{"no AUDIT names a rule: the earlier lane",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", "")}, 0, 0, "AUDIT", "", false, false},
		{"a later lane with an empty id only: the earlier lane",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", "", "")}, 0, 0, "AUDIT", "", false, false},
		{"ALLOW tie: the earlier lane",
			[]Verdict{v(Structured, "ALLOW", ""), v(POSIX, "ALLOW", "", "ts-allow-readonly")}, 0, 0, "ALLOW", "", false, false},
		{"REQUIRE_APPROVAL tie: the earlier lane",
			[]Verdict{v(Structured, "REQUIRE_APPROVAL", ""), v(POSIX, "REQUIRE_APPROVAL", "", "ts-ra")}, 0, 0, "REQUIRE_APPROVAL", "", false, false},
		{"BLOCK tie: the earlier lane",
			[]Verdict{v(Structured, "BLOCK", ""), v(PowerShell, "BLOCK", "", "ps-block")}, 0, 0, "BLOCK", "", false, false},
		{"a stricter rule-less AUDIT never gives way to a lower verdict's rule",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "ALLOW", "", "ts-allow-readonly")}, 0, 0, "AUDIT", "", false, false},
		// Audit-only mode: OriginalDecision is part of the tie.
		{"audit-only: a rule-less AUDIT[was BLOCK] outranks a plain AUDIT's rule",
			[]Verdict{v(Structured, "AUDIT", "BLOCK"), v(PowerShell, "AUDIT", "", "ps-y")}, 0, 0, "AUDIT", "BLOCK", false, false},
		{"audit-only: a rule-bearing AUDIT[was BLOCK] wins on rank, not by this rule",
			[]Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "BLOCK", "ps-y")}, 1, 1, "AUDIT", "BLOCK", false, false},
		{"audit-only: two AUDIT[was BLOCK] tie as BLOCKs do: the earlier lane",
			[]Verdict{v(Structured, "AUDIT", "BLOCK"), v(PowerShell, "AUDIT", "BLOCK", "ps-y")}, 0, 0, "AUDIT", "BLOCK", false, false},
		{"audit-only: two AUDIT[was REQUIRE_APPROVAL] tie as approvals do: the earlier lane",
			[]Verdict{v(Structured, "AUDIT", "REQUIRE_APPROVAL"), v(PowerShell, "AUDIT", "REQUIRE_APPROVAL", "ps-y")}, 0, 0, "AUDIT", "REQUIRE_APPROVAL", false, false},
		{"audit-only: a plain AUDIT tie still takes the rule",
			[]Verdict{v(Structured, "AUDIT", ""), v(POSIX, "AUDIT", "", "ts-y")}, 1, 0, "AUDIT", "", false, false},
		// KeptBlock and the floor are untouched.
		{"KeptBlock keeps the first kept BLOCK, rule-less or not",
			[]Verdict{v(Structured, "AUDIT", "BLOCK", "mcp-x"), v(POSIX, "BLOCK", ""), v(PowerShell, "BLOCK", "", "ps-z")}, 1, 1, "BLOCK", "", true, false},
		{"the floor over a rule-less ALLOW pick does not move the record to a rule-bearing ALLOW",
			[]Verdict{v(POSIX, "ALLOW", ""), withNote(v(PowerShell, "ALLOW", "", "ps-allow"), unsure)}, 0, 0, "AUDIT", "", false, true},
		{"an uncertain rule-less AUDIT gives its record to a tied rule, unfloored",
			[]Verdict{withNote(v(Structured, "AUDIT", ""), unsure), v(PowerShell, "AUDIT", "", "ps-y")}, 1, 0, "AUDIT", "", false, false},
	}
	for _, c := range cases {
		got := Combine(c.vs)
		if got.Winner != c.winner || got.Pick != c.pick || got.Decision != c.decision || got.OriginalDecision != c.original ||
			got.KeptBlock != c.keptBlock || got.Floored != c.floored {
			t.Errorf("%s: Combine = %+v, want winner %d pick %d decision %q original %q keptBlock %v floored %v",
				c.name, got, c.winner, c.pick, c.decision, c.original, c.keptBlock, c.floored)
		}
	}
}

// combineMain is Combine as main had it before the AUDIT tie rule
// (6d6ba507), kept verbatim as the oracle the rule is measured against.
func combineMain(vs []Verdict) Combined {
	if len(vs) == 0 {
		return Combined{Winner: -1}
	}
	best, bestRank := 0, Rank(vs[0])
	for i := 1; i < len(vs); i++ {
		if r := Rank(vs[i]); r > bestRank {
			best, bestRank = i, r
		}
	}
	c := Combined{Winner: best, Decision: vs[best].Decision, OriginalDecision: vs[best].OriginalDecision}
	if c.OriginalDecision == DecisionBlock {
		for i, v := range vs {
			if i != best && v.Decision == DecisionBlock && v.OriginalDecision == "" {
				c.Winner = i
				c.Decision, c.OriginalDecision, c.KeptBlock = DecisionBlock, "", true
				break
			}
		}
	}
	if bestRank < decisionRank(DecisionAudit) && anyUncertain(vs) {
		c.Decision, c.OriginalDecision, c.Floored = DecisionAudit, "", true
	}
	return c
}

// auditTieTarget is the verdict the rule must move the record to, given
// main's result, or -1: main kept a plain AUDIT naming no rule, and a later
// plain AUDIT names one other than the lane-failure sentinel. Written from
// the rule's statement, not from Combine's code.
func auditTieTarget(vs []Verdict, m Combined) int {
	w := vs[m.Winner]
	if m.Decision != DecisionAudit || m.OriginalDecision != "" || m.Floored || m.KeptBlock ||
		w.Decision != DecisionAudit || w.OriginalDecision != "" {
		return -1
	}
	for _, r := range w.Rules {
		if r != "" {
			return -1
		}
	}
	for i, x := range vs {
		if x.Decision != DecisionAudit || x.OriginalDecision != "" {
			continue
		}
		for _, r := range x.Rules {
			if r != "" && r != "agentshield-eval-error" {
				return i
			}
		}
	}
	return -1
}

// checkAgainstMain compares Combine with main's combiner on one verdict set:
// Decision, OriginalDecision, KeptBlock and Floored are identical, Pick is
// main's Winner, and Winner differs from main's exactly where the rule
// applies, and then is the rule's target. It returns whether the rule moved
// the record.
func checkAgainstMain(t *testing.T, vs []Verdict) bool {
	t.Helper()
	got, want := Combine(vs), combineMain(vs)
	if got.Decision != want.Decision || got.OriginalDecision != want.OriginalDecision ||
		got.KeptBlock != want.KeptBlock || got.Floored != want.Floored {
		t.Fatalf("Combine(%+v) = %+v; main decided %+v", vs, got, want)
	}
	if got.Pick != want.Winner {
		t.Fatalf("Combine(%+v): Pick %d, main's winner %d", vs, got.Pick, want.Winner)
	}
	target := auditTieTarget(vs, want)
	switch {
	case target < 0 && got.Winner != want.Winner:
		t.Fatalf("Combine(%+v): winner %d, main's %d, outside the AUDIT tie rule", vs, got.Winner, want.Winner)
	case target >= 0 && got.Winner != target:
		t.Fatalf("Combine(%+v): winner %d, the AUDIT tie rule names %d", vs, got.Winner, target)
	}
	return target >= 0
}

// verdictShapes are the verdicts the differential tests draw from: every
// decision shape (audit-only included, and unranked), each with no rule, an
// empty rule id, a rule, or the lane-failure sentinel, and with or without
// an uncertain note.
func verdictShapes() []Verdict {
	type d struct{ dec, orig string }
	// {"AUDIT", "AUDIT"} is an OriginalDecision no lane writes today: it
	// ranks as a plain AUDIT does, so it is the one shape that tells "the
	// same OriginalDecision" from "any OriginalDecision" (a mutant that
	// dropped the candidate's OriginalDecision check survived without it).
	decisions := []d{{"ALLOW", ""}, {"AUDIT", ""}, {"REQUIRE_APPROVAL", ""}, {"BLOCK", ""},
		{"AUDIT", "BLOCK"}, {"AUDIT", "REQUIRE_APPROVAL"}, {"AUDIT", "AUDIT"}, {"", ""}, {"BOGUS", ""}}
	rules := [][]string{nil, {""}, {"r"}, {"agentshield-eval-error"}}
	var out []Verdict
	for _, dd := range decisions {
		for _, rs := range rules {
			for _, unsure := range []bool{false, true} {
				x := Verdict{Decision: dd.dec, OriginalDecision: dd.orig, Rules: rs}
				if unsure {
					x.Notes = []Note{{Kind: "fake_parse_error", Uncertain: true}}
				}
				out = append(out, x)
			}
		}
	}
	return out
}

// TestCombine_AuditTieRuleChangesOnlyTheRecord is the differential property
// against main's combiner: exhaustive over every row of one to three
// verdicts drawn from verdictShapes (72 shapes: 72 + 72² + 72³ rows), then
// 200 000 random rows of four to six. Both sides of the property must be
// exercised: rows the rule moves, and rows it leaves.
func TestCombine_AuditTieRuleChangesOnlyTheRecord(t *testing.T) {
	shapes := verdictShapes()
	lanes := []Lane{Structured, POSIX, PowerShell, "l4", "l5", "l6"}
	row := func(idx ...int) []Verdict {
		vs := make([]Verdict, len(idx))
		for i, k := range idx {
			vs[i] = shapes[k]
			vs[i].Lane = lanes[i]
		}
		return vs
	}
	moved, rows := 0, 0
	count := func(m bool) {
		rows++
		if m {
			moved++
		}
	}
	n := len(shapes)
	for a := 0; a < n; a++ {
		count(checkAgainstMain(t, row(a)))
		for b := 0; b < n; b++ {
			count(checkAgainstMain(t, row(a, b)))
			for c := 0; c < n; c++ {
				count(checkAgainstMain(t, row(a, b, c)))
			}
		}
	}
	if want := n + n*n + n*n*n; rows != want {
		t.Fatalf("checked %d exhaustive rows, want %d", rows, want)
	}
	exhaustiveMoved := moved

	rng := rand.New(rand.NewSource(4779))
	for i := 0; i < 200000; i++ {
		k := 4 + rng.Intn(3)
		idx := make([]int, k)
		for j := range idx {
			idx[j] = rng.Intn(n)
		}
		count(checkAgainstMain(t, row(idx...)))
	}
	if exhaustiveMoved == 0 || moved == exhaustiveMoved || moved == rows {
		t.Fatalf("rule moved %d of %d rows (%d in the exhaustive part): the property is vacuous on one side", moved, rows, exhaustiveMoved)
	}
	t.Logf("%d rows: the AUDIT tie rule moved the record on %d (%d of the exhaustive %d), main's record kept on the rest",
		rows, moved, exhaustiveMoved, n+n*n+n*n*n)

	// The empty row is main's too.
	if got := Combine(nil); got.Winner != -1 || got.Pick != -1 {
		t.Errorf("Combine(nil) = %+v, want Winner and Pick -1", got)
	}
}

// TestCarriedNotes: the kept record carries every other verdict's
// uncertainty notes, and, when the AUDIT tie rule moved it, every note of
// the pick; nothing it carries already, and nothing twice.
func TestCarriedNotes(t *testing.T) {
	cwd := Note{Kind: "payload_cwd_unusable", Detail: "relative"}
	parse := Note{Kind: "parse_error", Detail: "bridge cut", Uncertain: true}
	dialect := Note{Kind: "dialect", Detail: "powershell"}
	posixNote := Note{Kind: "parse_fallback", Detail: "x"}
	with := func(x Verdict, ns ...Note) Verdict { x.Notes = ns; return x }

	cases := []struct {
		name string
		vs   []Verdict
		want []Note
	}{
		{"the moved-off pick's notes ride on the kept record, without repeats",
			[]Verdict{with(v(Structured, "AUDIT", ""), cwd, Note{Kind: "only_structured"}),
				with(v(PowerShell, "AUDIT", "", "ps-y"), dialect, cwd)},
			[]Note{{Kind: "only_structured"}}},
		{"another lane's uncertainty note rides on a BLOCK it lost to",
			[]Verdict{with(v(Structured, "BLOCK", "", "mcp-x"), cwd), with(v(PowerShell, "AUDIT", ""), dialect, parse, cwd)},
			[]Note{parse}},
		{"on a plain tie only the uncertainty notes ride",
			[]Verdict{with(v(Structured, "AUDIT", "", "mcp-x"), cwd), with(v(PowerShell, "AUDIT", "", "ps-y"), dialect, parse)},
			[]Note{parse}},
		{"a lower lane's certain notes do not",
			[]Verdict{with(v(Structured, "AUDIT", ""), cwd), with(v(POSIX, "ALLOW", "", "ts-allow-readonly"), posixNote)},
			nil},
		{"the kept record's own uncertainty note is not repeated",
			[]Verdict{with(v(Structured, "AUDIT", ""), parse), with(v(PowerShell, "AUDIT", "", "ps-y"), parse)},
			nil},
		{"two lanes' copies of one uncertainty note ride once, in row order",
			[]Verdict{with(v(Structured, "BLOCK", "", "mcp-x")), with(v(POSIX, "AUDIT", ""), parse, posixNote),
				with(v(PowerShell, "AUDIT", ""), Note{Kind: "dynamic_name", Uncertain: true}, parse)},
			[]Note{parse, {Kind: "dynamic_name", Uncertain: true}}},
		{"the pick's notes and a third lane's uncertainty notes, in row order",
			[]Verdict{with(v(Structured, "AUDIT", ""), cwd), with(v(POSIX, "AUDIT", "", "ts-y"), posixNote),
				with(v(PowerShell, "ALLOW", ""), parse, dialect)},
			[]Note{cwd, parse}},
	}
	for _, c := range cases {
		got := CarriedNotes(c.vs, Combine(c.vs))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: CarriedNotes = %+v, want %+v", c.name, got, c.want)
		}
	}
	if got := CarriedNotes(nil, Combine(nil)); got != nil {
		t.Errorf("no verdicts: %+v, want nil", got)
	}
}

// TestReadingsDetail_AuditTie: the note names the lane whose record was
// kept and, when the AUDIT tie rule moved it, the lane it moved from (Gary,
// 2026-11-06). A tie the rule does not move, and a decision that is not a
// tie, carry no such phrase.
func TestReadingsDetail_AuditTie(t *testing.T) {
	row := []Lane{Structured, PowerShell}
	cases := []struct {
		name string
		vs   []Verdict
		want string
	}{
		{"moved", []Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "", "ps-audit-env-exfil")},
			"tool=PowerShell; structured=AUDIT; powershell=AUDIT(ps-audit-env-exfil); kept=powershell; audit tie moved from structured"},
		{"both name a rule: not moved", []Verdict{v(Structured, "AUDIT", "", "mcp-audit-x"), v(PowerShell, "AUDIT", "", "ps-audit-env-exfil")},
			"tool=PowerShell; structured=AUDIT(mcp-audit-x); powershell=AUDIT(ps-audit-env-exfil); kept=structured"},
		{"neither names a rule: not moved", []Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "AUDIT", "")},
			"tool=PowerShell; structured=AUDIT; powershell=AUDIT; kept=structured"},
		{"not a tie", []Verdict{v(Structured, "AUDIT", ""), v(PowerShell, "BLOCK", "", "ps-block-x")},
			"tool=PowerShell; structured=AUDIT; powershell=BLOCK(ps-block-x); kept=powershell"},
	}
	for _, c := range cases {
		if got := ReadingsDetail("PowerShell", row, c.vs, Combine(c.vs)); got != c.want {
			t.Errorf("%s: ReadingsDetail = %q, want %q", c.name, got, c.want)
		}
	}
}
