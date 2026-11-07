package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// The audit-only tie rule (keptOnTie, #4748 Opus pass 1). When two readings of
// a command both BLOCK before the mode downgrade, the layer returns the one it
// always returns; when that one was downgraded and the other's BLOCK was kept,
// it comes back as BLOCK with its own record, which is what enforce mode
// returns. Every other pair is returned unchanged.

func tieResult(rule string, dec, orig Decision) EvalResult {
	r := EvalResult{Decision: dec, OriginalDecision: orig, TriggeredRules: []string{rule}, Reasons: []string{rule + " reason"}, TaxonomyRefs: []string{rule + "/node"}}
	r.Explanation = buildExplanation(r)
	return r
}

var (
	tieDowngraded = func(rule string) EvalResult { return tieResult(rule, DecisionAudit, DecisionBlock) }
	tieKept       = func(rule string) EvalResult { return tieResult(rule, DecisionBlock, "") }
	tieEnforce    = tieKept // enforce mode: a BLOCK carries no OriginalDecision
	tiePlainAudit = func(rule string) EvalResult { return tieResult(rule, DecisionAudit, "") }
	tieDowngRA    = func(rule string) EvalResult { return tieResult(rule, DecisionAudit, DecisionRequireApproval) }
)

// tieWant is a layer's expected return: the reading whose record it carries
// and the decision fields it carries them with.
type tieWant struct {
	rule     string
	decision Decision
	orig     Decision
}

func checkTie(t *testing.T, got EvalResult, w tieWant) {
	t.Helper()
	if len(got.TriggeredRules) != 1 || got.TriggeredRules[0] != w.rule || got.Decision != w.decision || got.OriginalDecision != w.orig {
		t.Fatalf("got %s %v (original %q); want %s %v (original %q)", strings.Join(got.TriggeredRules, ","), got.Decision, got.OriginalDecision, w.rule, w.decision, w.orig)
	}
	if got.Reasons[0] != w.rule+" reason" || got.TaxonomyRefs[0] != w.rule+"/node" {
		t.Errorf("record mixed: reasons %v, taxonomy %v; want %s's own", got.Reasons, got.TaxonomyRefs, w.rule)
	}
	if !strings.HasPrefix(got.Explanation, "Decision: "+string(w.decision)+"\n") {
		t.Errorf("explanation %q does not state %v", got.Explanation, w.decision)
	}
}

func TestStricterResult_KeptOnTie_4748(t *testing.T) {
	for _, tc := range []struct {
		name    string
		off, on EvalResult
		want    tieWant
	}{
		{"tie: off downgraded, on kept -> off's record as BLOCK", tieDowngraded("off"), tieKept("on"), tieWant{"off", DecisionBlock, ""}},
		{"tie: neither kept -> off, still downgraded", tieDowngraded("off"), tieDowngraded("on"), tieWant{"off", DecisionAudit, DecisionBlock}},
		{"tie: off kept, on downgraded -> off as kept", tieKept("off"), tieDowngraded("on"), tieWant{"off", DecisionBlock, ""}},
		{"tie: both kept -> off", tieKept("off"), tieKept("on"), tieWant{"off", DecisionBlock, ""}},
		{"enforce tie -> off, unchanged", tieEnforce("off"), tieEnforce("on"), tieWant{"off", DecisionBlock, ""}},
		{"off downgraded, on plain AUDIT -> off, still downgraded", tieDowngraded("off"), tiePlainAudit("on"), tieWant{"off", DecisionAudit, DecisionBlock}},
		{"on strictly stricter (kept BLOCK over plain AUDIT) -> on", tiePlainAudit("off"), tieKept("on"), tieWant{"on", DecisionBlock, ""}},
		{"on strictly stricter (kept BLOCK over downgraded RA) -> on", tieDowngRA("off"), tieKept("on"), tieWant{"on", DecisionBlock, ""}},
		{"off outside the order, on BLOCK -> off, unchanged", tieResult("off", Decision("?"), ""), tieKept("on"), tieWant{"off", Decision("?"), ""}},
	} {
		t.Run(tc.name, func(t *testing.T) { checkTie(t, stricterResult(tc.off, tc.on), tc.want) })
	}
}

func TestCaseFoldResult_KeptOnTie_4748(t *testing.T) {
	// folded's record is a strict superset of asWritten's when it carries
	// asWritten's rule plus one more; caseFoldResult then returns folded.
	superset := func(r EvalResult) EvalResult {
		r.TriggeredRules = []string{"aw", "folded"}
		r.Reasons = []string{"folded reason", "folded reason"}
		r.TaxonomyRefs = []string{"folded/node"}
		return r
	}
	checkSuperset := func(t *testing.T, got EvalResult, dec, orig Decision) {
		t.Helper()
		if len(got.TriggeredRules) != 2 || got.TriggeredRules[1] != "folded" || got.Decision != dec || got.OriginalDecision != orig {
			t.Fatalf("got %v %v (original %q); want folded's record, %v (original %q)", got.TriggeredRules, got.Decision, got.OriginalDecision, dec, orig)
		}
		if !strings.HasPrefix(got.Explanation, "Decision: "+string(dec)+"\n") {
			t.Errorf("explanation %q does not state %v", got.Explanation, dec)
		}
	}
	t.Run("tie, as-written returned: downgraded, folded kept -> as-written as BLOCK", func(t *testing.T) {
		checkTie(t, caseFoldResult(tieDowngraded("aw"), tieKept("folded")), tieWant{"aw", DecisionBlock, ""})
	})
	t.Run("tie, as-written returned: neither kept -> still downgraded", func(t *testing.T) {
		checkTie(t, caseFoldResult(tieDowngraded("aw"), tieDowngraded("folded")), tieWant{"aw", DecisionAudit, DecisionBlock})
	})
	t.Run("tie, folded returned (superset): downgraded, as-written kept -> folded as BLOCK", func(t *testing.T) {
		checkSuperset(t, caseFoldResult(tieKept("aw"), superset(tieDowngraded("folded"))), DecisionBlock, "")
	})
	t.Run("tie, folded returned (superset): neither kept -> still downgraded", func(t *testing.T) {
		checkSuperset(t, caseFoldResult(tieDowngraded("aw"), superset(tieDowngraded("folded"))), DecisionAudit, DecisionBlock)
	})
	t.Run("enforce tie -> as-written, unchanged", func(t *testing.T) {
		checkTie(t, caseFoldResult(tieEnforce("aw"), tieEnforce("folded")), tieWant{"aw", DecisionBlock, ""})
	})
	// #4749: the third keptOnTie site. The folded record is a superset of
	// as-written's rules, but as-written carries a note folded lacks, so
	// as-written is returned; it was downgraded and folded's BLOCK was kept.
	t.Run("tie, as-written carries a note folded lacks: downgraded, folded kept -> as-written as BLOCK", func(t *testing.T) {
		aw := tieDowngraded("aw")
		aw.Notes = []analyzer.Note{{Kind: "excused", Rule: "aw", Detail: "only as-written"}}
		folded := superset(tieKept("folded"))
		folded.TriggeredRules = []string{"aw", "folded"}
		got := caseFoldResult(aw, folded)
		if len(got.TriggeredRules) != 1 || got.TriggeredRules[0] != "aw" || got.Decision != DecisionBlock || got.OriginalDecision != "" {
			t.Fatalf("got %v %v (original %q); want as-written's record as a kept BLOCK", got.TriggeredRules, got.Decision, got.OriginalDecision)
		}
		if len(got.Notes) != 1 || got.Notes[0].Detail != "only as-written" {
			t.Errorf("notes %v; want as-written's", got.Notes)
		}
	})
}

// Through a reading layer: the home-tilde reading alone resolves `~<login>/`,
// and an unrelated protected-path read makes both readings BLOCK before the
// downgrade. Only the expanded reading's keep sees the self-protection rule.
func TestEvaluateHomeTilde_KeptOnTie_4748(t *testing.T) {
	const home = "/zzhome/zzme"
	t.Setenv("HOME", home)
	restore := SetTildeAccountLookupForTest(func() (string, string) { return "zzme", home })
	t.Cleanup(restore)

	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, "~/.zzcred/**")
	pol.Rules = append(pol.Rules, Rule{ID: "zz-sp-block", Match: Match{CommandRegex: `touch\s+~/\.zzsp\b`}, Decision: DecisionBlock, Reason: "self-protection stand-in"})
	build := func(mode string) *Engine {
		e, err := NewEngineWithAnalyzers(pol, 2)
		if err != nil {
			t.Fatalf("NewEngineWithAnalyzers: %v", err)
		}
		e.SetMode(mode)
		e.SetSelfProtectionKeep(func(_ string, rules, _ []string) bool {
			for _, id := range rules {
				if id == "zz-sp-block" {
					return true
				}
			}
			return false
		})
		return e
	}
	eval := func(e *Engine, cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "/tmp")
		return e.EvaluateHomeTilde(cmd, n.Paths, n.Parsed, "/tmp", HomeTildeStricter)
	}
	enf, aud := build("enforce"), build("audit-only")
	for _, tc := range []struct {
		cmd  string
		kept bool
	}{
		{"touch ~zzme/.zzsp", true},                      // the action alone: the expanded reading decides
		{"cat ~/.zzcred/k; touch ~zzme/.zzsp", true},     // the tie
		{"cat ~/.zzcred/k; touch ~other/.zzsp", false},   // another login is not read
		{"cat ~/.zzcred/k; touch ~zzme/.zzplain", false}, // the expanded reading's BLOCK is not kept
		{"cat ~/.zzcred/k", false},                       // protected read alone
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			e := eval(enf, tc.cmd)
			if e.Decision != DecisionBlock {
				t.Fatalf("enforce decided %v %v; want BLOCK", e.Decision, e.TriggeredRules)
			}
			a := eval(aud, tc.cmd)
			if tc.kept {
				if a.Decision != DecisionBlock || a.OriginalDecision != "" {
					t.Errorf("audit-only decided %v (original %q) %v; want BLOCK, kept", a.Decision, a.OriginalDecision, a.TriggeredRules)
				}
			} else if a.Decision != DecisionAudit || a.OriginalDecision != DecisionBlock {
				t.Errorf("audit-only decided %v (original %q) %v; want AUDIT, original BLOCK", a.Decision, a.OriginalDecision, a.TriggeredRules)
			}
			// The record is enforce mode's.
			if strings.Join(a.TriggeredRules, ",") != strings.Join(e.TriggeredRules, ",") || strings.Join(a.Reasons, "|") != strings.Join(e.Reasons, "|") || strings.Join(a.TaxonomyRefs, ",") != strings.Join(e.TaxonomyRefs, ",") {
				t.Errorf("audit-only record %v %v %v; want enforce's %v %v %v", a.TriggeredRules, a.Reasons, a.TaxonomyRefs, e.TriggeredRules, e.Reasons, e.TaxonomyRefs)
			}
			if tc.kept && a.Explanation != e.Explanation {
				t.Errorf("audit-only explanation %q; want enforce's %q", a.Explanation, e.Explanation)
			}
		})
	}
}
