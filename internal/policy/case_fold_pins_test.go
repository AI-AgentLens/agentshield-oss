package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// Pins for the three #4194 case-fold guarantees that survived the full suites
// as mutants (#4206, from the Opus pass on #4205). The safety argument of the
// fold is: the as-written evaluation is unchanged, and the folded one can only
// raise. Each test below names the mutant it exists to kill.
//
// Credential-path strings are assembled at runtime: the hook reads test
// sources as commands.

// M7: the as-written pass is handed the case-folded consumer table. That widens
// the BLOCK-to-AUDIT designated-consumer exemption on the one evaluation that
// must never be lowered.
//
// The shape: the protected-path hit is real (paths carries the canonical key),
// but the only protected-looking word in the command is a case-variant in
// ssh's -i slot. As written, that word is not a protected token, so no
// consumer slot is recognised and the hit BLOCKs. Read case-insensitively it is
// a designated consumer's slot and the hit would be recorded as AUDIT.
func TestCaseFold_AsWrittenPassNeverUsesFoldedConsumerTable_4206(t *testing.T) {
	engine, home := consumerEngine(t)
	dir := "." + "ssh"
	key := home + "/" + dir + "/id_ed25519"
	cmd := "ssh -i ~/.SSH/ID_ED25519 deploy@host.example"
	paths := []string{key}

	// Positive control: the same slot spelled canonically IS the designated
	// consumer (AUDIT, recorded), so the shape is capable of being exempted.
	canonical := "ssh -i ~/" + dir + "/id_ed25519 deploy@host.example"
	if r := engine.EvaluateCaseFold(canonical, paths, nil, "", CaseFoldOff); r.Decision != DecisionAudit ||
		!has(r.TriggeredRules, ProtectedPathConsumerRuleID) {
		t.Fatalf("control: canonical consumer use = %v rules=%v; want AUDIT with %s",
			r.Decision, r.TriggeredRules, ProtectedPathConsumerRuleID)
	}

	for name, mode := range map[string]CaseFoldMode{"off": CaseFoldOff, "stricter": CaseFoldStricter} {
		r := engine.EvaluateCaseFold(cmd, paths, nil, "", mode)
		if r.Decision != DecisionBlock {
			t.Errorf("%s: case-variant consumer slot beside a real protected hit decided %v rules=%v; want BLOCK (the exemption must not be reachable through a folded token on the as-written pass)",
				name, r.Decision, r.TriggeredRules)
		}
	}
}

// M10: cwd is not folded in the folded pass. A relative protected_paths
// pattern is matched against the path made relative to cwd; folding the path
// and the pattern but not cwd makes the path look like it sits outside cwd, so
// the folded reading never matches and the case variant stays unblocked.
func TestCaseFold_CwdIsFoldedInTheFoldedReading_4206(t *testing.T) {
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"secrets/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cwd := "/Work/Project"

	// Control: the canonical spelling is blocked, so the pattern and cwd wiring
	// are live in this test.
	canon := "cat /Work/Project/secrets/token"
	if r := engine.EvaluateCaseFold(canon, []string{"/Work/Project/secrets/token"}, nil, cwd, CaseFoldOff); r.Decision != DecisionBlock {
		t.Fatalf("control: canonical relative-pattern hit = %v rules=%v; want BLOCK", r.Decision, r.TriggeredRules)
	}

	variant := "cat /Work/Project/Secrets/token"
	paths := []string{"/Work/Project/Secrets/token"}
	if r := engine.EvaluateCaseFold(variant, paths, nil, cwd, CaseFoldOff); r.Decision == DecisionBlock {
		t.Fatalf("control: fold-off must not block the case variant (it is the pre-#4194 gap); got %v", r.Decision)
	}
	r := engine.EvaluateCaseFold(variant, paths, nil, cwd, CaseFoldStricter)
	if r.Decision != DecisionBlock || !has(r.TriggeredRules, "protected-path") {
		t.Errorf("case-variant path under a mixed-case cwd decided %v rules=%v; want BLOCK via protected-path (cwd must fold with the path)",
			r.Decision, r.TriggeredRules)
	}
}

// The tie rule of caseFoldResult: the folded result wins when strictly more
// restrictive, or at an equal decision when its record strictly extends the
// as-written one. Everything else keeps the as-written result. Mutants killed:
// "folded wins any tie", "superset check removed", "superset non-strict".
func TestCaseFoldResult_Selection_4206(t *testing.T) {
	note := analyzer.Note{Kind: "excused", Rule: "r1", Detail: "d"}
	mk := func(d Decision, rules []string, notes ...analyzer.Note) EvalResult {
		return EvalResult{Decision: d, TriggeredRules: rules, Notes: notes}
	}
	downgraded := func(orig, now Decision, rules []string) EvalResult {
		r := mk(now, rules)
		r.OriginalDecision = orig
		return r
	}

	cases := []struct {
		name     string
		asWr     EvalResult
		folded   EvalResult
		wantFold bool
	}{
		{"folded higher", mk(DecisionAudit, []string{"a"}), mk(DecisionBlock, []string{"b"}), true},
		{"folded higher, record unrelated", mk(DecisionAudit, nil), mk(DecisionRequireApproval, []string{"b"}), true},
		{"folded lower", mk(DecisionBlock, []string{"a"}), mk(DecisionAudit, []string{"a", "b"}), false},
		{"equal, strict superset", mk(DecisionAudit, []string{"a"}), mk(DecisionAudit, []string{"a", "b"}), true},
		{"equal, as-written empty, folded has a rule", mk(DecisionAudit, nil), mk(DecisionAudit, []string{"b"}), true},
		{"equal, identical rules", mk(DecisionAudit, []string{"a"}), mk(DecisionAudit, []string{"a"}), false},
		{"equal, both empty", mk(DecisionAudit, nil), mk(DecisionAudit, nil), false},
		{"equal, disjoint rules", mk(DecisionAudit, []string{"a"}), mk(DecisionAudit, []string{"b", "c"}), false},
		{"equal, folded drops a rule but adds two", mk(DecisionAudit, []string{"a", "x"}), mk(DecisionAudit, []string{"a", "b", "c"}), false},
		{"equal, superset rules but a note is dropped", mk(DecisionAudit, []string{"a"}, note), mk(DecisionAudit, []string{"a", "b"}), false},
		{"equal, superset rules and the note kept", mk(DecisionAudit, []string{"a"}, note), mk(DecisionAudit, []string{"a", "b"}, note), true},
		{"equal rank, different final decision", downgraded(DecisionBlock, DecisionAudit, []string{"a"}), mk(DecisionBlock, []string{"a", "b"}), false},
		{"as-written has an unranked decision", mk(Decision("?"), []string{"a"}), mk(DecisionBlock, []string{"a", "b"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.asWr.Explanation, tc.folded.Explanation = "as-written", "folded"
			got := caseFoldResult(tc.asWr, tc.folded)
			isFolded, isAsWr := got.Explanation == "folded", got.Explanation == "as-written"
			if tc.wantFold && !isFolded || !tc.wantFold && !isAsWr {
				t.Errorf("caseFoldResult returned %+v; want the %s result", got, map[bool]string{true: "folded", false: "as-written"}[tc.wantFold])
			}
		})
	}
}
