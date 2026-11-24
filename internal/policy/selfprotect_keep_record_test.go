package policy

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// The record of a BLOCK the audit-only keep kept (#5089). A BLOCK kept for a
// reason none of its rules states leads with SelfProtectRuleID and the keep's
// reason; the rules that fired follow, and the taxonomy is enforce mode's.
// A BLOCK a self-protection rule decided, a lowered BLOCK and every enforce
// mode BLOCK keep their record exactly.

const keepRecordWhy = "zq why"

func keepRecordPolicy() *Policy {
	return &Policy{
		Defaults: Defaults{Decision: DecisionAudit, ProtectedPaths: []string{"~/.zq-other/**"}},
		Rules: []Rule{
			{ID: "zq-plain-block", Taxonomy: "destructive-ops/disk-ops/filesystem-format", Match: Match{CommandRegex: `\bzqblock\b`}, Decision: DecisionBlock, Reason: "plain"},
			{ID: "zq-sp-block", Match: Match{CommandRegex: `\bzqsp\b`}, Decision: DecisionBlock, Reason: "sp"},
		},
	}
}

// keepRecordStub keeps a BLOCK zq-sp-block decided (a self-protection rule:
// no reason) and any BLOCK of a command naming zqtarget (a reading: a reason).
func keepRecordStub(calls *int) SelfProtectionKeep {
	return func(command string, rules, _ []string) (bool, string) {
		*calls++
		for _, id := range rules {
			if id == "zq-sp-block" {
				return true, ""
			}
		}
		if strings.Contains(command, "zqtarget") {
			return true, keepRecordWhy
		}
		return false, ""
	}
}

func keepRecordEngine(t *testing.T, mode string, calls *int) *Engine {
	t.Helper()
	e, err := NewEngine(keepRecordPolicy())
	if err != nil {
		t.Fatal(err)
	}
	e.SetMode(mode)
	e.SetSelfProtectionKeep(keepRecordStub(calls))
	return e
}

func TestKeptBlockRecord_5089(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	other := filepath.Join(home, ".zq-other", "a")
	var n int
	enf, aud := keepRecordEngine(t, "enforce", &n), keepRecordEngine(t, "audit-only", &n)
	for _, tc := range []struct {
		name    string
		command string
		paths   []string
		// lead is the reason the audit-only record leads with under
		// SelfProtectRuleID, or "" for enforce mode's record exactly.
		lead     string
		decision Decision
	}{
		{"kept by a reading: the keep's reason leads", "zqblock now; zqtarget", nil, keepRecordWhy, DecisionBlock},
		{"kept by a self-protection rule: the record is enforce mode's", "zqblock now; zqsp", nil, "", DecisionBlock},
		{"lowered: the record is enforce mode's", "zqblock now", nil, "", DecisionAudit},
		{"masked: the protected-path BLOCK names the rule the rest of the command kept", "cat x; zqsp", []string{other},
			SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule zq-sp-block", DecisionBlock},
		{"masked, lowered: the record is enforce mode's", "cat x; zqblock now", []string{other}, "", DecisionAudit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := enf.Evaluate(tc.command, tc.paths)
			if want.Decision != DecisionBlock || has(want.TriggeredRules, SelfProtectRuleID) {
				t.Fatalf("control: enforce decided %s %v; want BLOCK without %s", want.Decision, want.TriggeredRules, SelfProtectRuleID)
			}
			got := aud.Evaluate(tc.command, tc.paths)
			if got.Decision != tc.decision {
				t.Fatalf("audit-only decided %s (original %q) %v; want %s", got.Decision, got.OriginalDecision, got.TriggeredRules, tc.decision)
			}
			wantRules, wantReasons := want.TriggeredRules, want.Reasons
			if tc.lead != "" {
				wantRules = append([]string{SelfProtectRuleID}, wantRules...)
				wantReasons = append([]string{tc.lead}, wantReasons...)
			}
			if !reflect.DeepEqual(got.TriggeredRules, wantRules) || !reflect.DeepEqual(got.Reasons, wantReasons) {
				t.Errorf("record rules %v reasons %q; want rules %v reasons %q", got.TriggeredRules, got.Reasons, wantRules, wantReasons)
			}
			if !reflect.DeepEqual(got.TaxonomyRefs, want.TaxonomyRefs) {
				t.Errorf("taxonomy %v; want enforce mode's %v: %s contributes no node", got.TaxonomyRefs, want.TaxonomyRefs, SelfProtectRuleID)
			}
			if tc.lead != "" && !strings.Contains(got.Explanation, tc.lead) {
				t.Errorf("explanation %q does not carry the keep's reason", got.Explanation)
			}
		})
	}
}

// Enforce mode never asks the keep, so it can never lead a record.
func TestKeptBlockRecord_EnforceNeverAsks_5089(t *testing.T) {
	testhome.Set(t, t.TempDir())
	for _, mode := range []string{"", "enforce"} {
		var calls int
		r := keepRecordEngine(t, mode, &calls).Evaluate("zqblock now; zqtarget", nil)
		if r.Decision != DecisionBlock || !reflect.DeepEqual(r.TriggeredRules, []string{"zq-plain-block"}) || calls != 0 {
			t.Errorf("mode %q: %s %v, %d keep calls; want BLOCK [zq-plain-block], none", mode, r.Decision, r.TriggeredRules, calls)
		}
	}
}

func TestKeptForSelfProtection_5089(t *testing.T) {
	r := EvalResult{Decision: DecisionBlock, TriggeredRules: []string{"a"}, Reasons: []string{"ra"}, TaxonomyRefs: []string{"n/a"}}
	if got := keptForSelfProtection(r, ""); !reflect.DeepEqual(got, r) {
		t.Errorf("no reason: %+v; want r unchanged", got)
	}
	got := keptForSelfProtection(r, "why")
	if !reflect.DeepEqual(got.TriggeredRules, []string{SelfProtectRuleID, "a"}) || !reflect.DeepEqual(got.Reasons, []string{"why", "ra"}) || !reflect.DeepEqual(got.TaxonomyRefs, []string{"n/a"}) {
		t.Errorf("kept: %+v; want the reason first under %s, the rest as it was", got, SelfProtectRuleID)
	}
	if !reflect.DeepEqual(r.TriggeredRules, []string{"a"}) || !reflect.DeepEqual(r.Reasons, []string{"ra"}) {
		t.Errorf("the input's slices changed: %+v", r)
	}
	if again := keptForSelfProtection(got, "why 2"); !reflect.DeepEqual(again, got) {
		t.Errorf("a record that names %s already: %+v; want it unchanged", SelfProtectRuleID, again)
	}
}

// The masked keep's reason is why the rest of the evaluation stands: its
// own lead when the keep led it.
func TestMaskedKeptReason_5089(t *testing.T) {
	var n int
	e := keepRecordEngine(t, "audit-only", &n)
	m := keptForSelfProtection(EvalResult{Decision: DecisionBlock, TriggeredRules: []string{"zq-plain-block"}, Reasons: []string{"plain"}}, "m's why")
	if got := e.maskedKeptReason("zqblock; zqtarget", m); got != "m's why" {
		t.Errorf("got %q; want m's own reason", got)
	}
	m = EvalResult{Decision: DecisionBlock, TriggeredRules: []string{"zq-plain-block", "zq-sp-block"}}
	if got, want := e.maskedKeptReason("zqblock; zqsp", m), SelfProtectKeptReasonPrefix+"the command also matches the self-protection rule zq-sp-block"; got != want {
		t.Errorf("got %q; want %q (the self-protection rule only)", got, want)
	}
}

// The dialect lane's keep gives the same record (factsKeepsBlock).
func TestEvaluateFacts_KeptBlockRecord_5089(t *testing.T) {
	engine := factsEngine(t)
	engine.SetMode("audit-only")
	read := psFacts(`Get-Content ~\.ssh\` + sshKey)
	for _, tc := range []struct {
		why  string
		lead bool
	}{{"", false}, {keepRecordWhy, true}} {
		engine.SetSelfProtectionKeep(func(string, []string, []string) (bool, string) { return true, tc.why })
		got := engine.EvaluateFacts(read, "", FactsOptions{})
		want := []string{ProtectedPathRuleID}
		if tc.lead {
			want = append([]string{SelfProtectRuleID}, want...)
		}
		if got.Decision != DecisionBlock || !reflect.DeepEqual(got.TriggeredRules, want) || tc.lead && got.Reasons[0] != tc.why {
			t.Errorf("why %q: %s %v %q; want BLOCK %v", tc.why, got.Decision, got.TriggeredRules, got.Reasons, want)
		}
	}
}

// led is r with the keep's lead, as keptForSelfProtection writes it.
func led(r EvalResult) EvalResult { return keptForSelfProtection(r, keepRecordWhy) }

// keptOnTie raises the reading it returns because the other reading's BLOCK
// was kept; when that BLOCK was kept for the keep's reason, the raised record
// leads with it too (#5089: 71 managed mixed-case rows in the sweep named only
// ts-block-mkfs on main). A BLOCK kept by a self-protection rule gives the
// lead its provenance names (TestKeptOnTie_LeadComesFromProvenance_5091); one
// with no provenance, which no engine reading produces, gives none.
func TestKeptOnTie_CarriesTheLead_5089(t *testing.T) {
	got := stricterResult(tieDowngraded("off"), led(tieKept("on")))
	if got.Decision != DecisionBlock || got.OriginalDecision != "" ||
		!reflect.DeepEqual(got.TriggeredRules, []string{SelfProtectRuleID, "off"}) ||
		!reflect.DeepEqual(got.Reasons, []string{keepRecordWhy, "off reason"}) ||
		!reflect.DeepEqual(got.TaxonomyRefs, []string{"off/node"}) {
		t.Errorf("raised by a led reading: %s %v %q %v; want BLOCK, off's record led by the keep's reason", got.Decision, got.TriggeredRules, got.Reasons, got.TaxonomyRefs)
	}
	if !strings.Contains(got.Explanation, keepRecordWhy) {
		t.Errorf("explanation %q does not carry the lead", got.Explanation)
	}
	if got := stricterResult(tieDowngraded("off"), tieKept("on")); !reflect.DeepEqual(got.TriggeredRules, []string{"off"}) {
		t.Errorf("raised by a reading with no provenance: %v; want off's record as it was", got.TriggeredRules)
	}
	if got := stricterResult(tieDowngraded("off"), led(tieDowngraded("on"))); got.Decision != DecisionAudit || has(got.TriggeredRules, SelfProtectRuleID) {
		t.Errorf("neither kept: %s %v; want off still downgraded, no lead", got.Decision, got.TriggeredRules)
	}
}

// caseFoldResult compares the readings' records without the lead, so the
// lead never changes which record is returned: the folded reading that
// carries the self-protection rule still wins over a led as-written reading.
func TestCaseFoldResult_LeadDoesNotMoveTheRecord_5089(t *testing.T) {
	folded := tieKept("folded")
	folded.TriggeredRules = []string{"aw", "folded"}
	got := caseFoldResult(led(tieKept("aw")), folded)
	if !reflect.DeepEqual(got.TriggeredRules, []string{"aw", "folded"}) {
		t.Errorf("led as-written vs superset folded: %v; want folded's record, as without the lead", got.TriggeredRules)
	}
	got = caseFoldResult(tieDowngraded("aw"), func() EvalResult { r := tieKept("aw"); return led(r) }())
	if got.Decision != DecisionBlock || !reflect.DeepEqual(got.TriggeredRules, []string{SelfProtectRuleID, "aw"}) {
		t.Errorf("downgraded as-written vs led folded, same rules: %s %v; want as-written raised, led", got.Decision, got.TriggeredRules)
	}
	if !reflect.DeepEqual(withoutKeptLead(led(tieKept("a"))), []string{"a"}) || len(withoutKeptLead(EvalResult{})) != 0 {
		t.Errorf("withoutKeptLead")
	}
}
