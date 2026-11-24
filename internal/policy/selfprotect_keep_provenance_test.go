package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// The provenance of a BLOCK audit-only mode did not lower (keptFor, #5089
// fix round 1, #5091 pass 1). The reading layers' tie rule (keptOnTie) raises
// a lowered reading because the other reading's BLOCK stands; the raised
// record leads with why that one stands, whatever kept it: the keep's reason,
// the self-protection rule the other reading matched, or a managed lane's
// self-protection reading. The lead is found by provenance, never by rule
// id, so a rule that fired under SelfProtectRuleID is compared and recorded
// like any other.

// provenancePolicy: zp-sp-block is the stub keep's self-protection rule, read
// only where `~/.zpsp` is spelled in lower case after `~/`; zp-plain-block is
// an ordinary BLOCK; zp-aw-block matches the mixed-case spelling as written,
// so the case-fold reading loses it.
func provenancePolicy() *Policy {
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		Rule{ID: "zp-sp-block", Match: Match{CommandRegex: `touch\s+~/\.zpsp\b`}, Decision: DecisionBlock, Reason: "self-protection stand-in"},
		Rule{ID: "zp-plain-block", Taxonomy: "destructive-ops/disk-ops/filesystem-format", Match: Match{CommandRegex: `\bzpformat\b`}, Decision: DecisionBlock, Reason: "plain"},
		Rule{ID: "zp-aw-block", Match: Match{CommandRegex: `\.ZPsp\b`}, Decision: DecisionBlock, Reason: "as written"},
	)
	return pol
}

func provenanceEngine(t *testing.T, mode string) *Engine {
	t.Helper()
	e, err := NewEngineWithAnalyzers(provenancePolicy(), 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	e.SetMode(mode)
	e.SetSelfProtectionKeep(func(_ string, rules, _ []string) (bool, string) {
		for _, id := range rules {
			if id == "zp-sp-block" {
				return true, ""
			}
		}
		return false, ""
	})
	return e
}

// F1: the other reading's BLOCK was kept by a self-protection rule the
// raised reading cannot see. On 7c270ee1 both records named the ordinary rule
// alone: zp-plain-block, zp-aw-block.
func TestKeptOnTie_RuleKeptReadingLeadsTheRaisedRecord_5091(t *testing.T) {
	home := absPath("/zphome/zpme")
	testhome.Set(t, home)
	t.Cleanup(SetTildeAccountLookupForTest(func() (string, string) { return "zpme", home }))
	enf, aud := provenanceEngine(t, "enforce"), provenanceEngine(t, "audit-only")
	lead := SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule zp-sp-block"
	eval := func(e *Engine, cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, home)
		return e.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, home)
	}
	for _, tc := range []struct {
		name, cmd string
		rules     []string // enforce mode's record
	}{
		// The home-tilde reading alone reads `~zpme/` as `~/`.
		{"home tilde", "zpformat; touch ~zpme/.zpsp", []string{"zp-plain-block"}},
		// The case-fold reading alone reads `.ZPsp` as `.zpsp`, and loses
		// the as-written rule, so neither record is a superset.
		{"case fold", "touch ~/.ZPsp", []string{"zp-aw-block"}},
		// Both: the tilde reading's case-fold tie, then the tilde tie.
		{"home tilde and case fold", "zpformat; touch ~zpme/.ZPsp", []string{"zp-plain-block", "zp-aw-block"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := eval(enf, tc.cmd)
			if e.Decision != DecisionBlock || !reflect.DeepEqual(e.TriggeredRules, tc.rules) {
				t.Fatalf("control: enforce decided %s %v; want BLOCK %v", e.Decision, e.TriggeredRules, tc.rules)
			}
			a := eval(aud, tc.cmd)
			if a.Decision != DecisionBlock || a.OriginalDecision != "" {
				t.Fatalf("audit-only decided %s (original %q) %v; want BLOCK, kept", a.Decision, a.OriginalDecision, a.TriggeredRules)
			}
			wantRules := append([]string{SelfProtectRuleID}, e.TriggeredRules...)
			wantReasons := append([]string{lead}, e.Reasons...)
			if !reflect.DeepEqual(a.TriggeredRules, wantRules) || !reflect.DeepEqual(a.Reasons, wantReasons) {
				t.Errorf("audit-only record %v %q; want %v %q", a.TriggeredRules, a.Reasons, wantRules, wantReasons)
			}
			if !reflect.DeepEqual(a.TaxonomyRefs, e.TaxonomyRefs) {
				t.Errorf("audit-only taxonomy %v; want enforce mode's %v", a.TaxonomyRefs, e.TaxonomyRefs)
			}
			if !strings.Contains(a.Explanation, lead) {
				t.Errorf("explanation %q does not carry the lead", a.Explanation)
			}
		})
	}
}

// Codex pass 1, finding 1: a customer rule may use the id SelfProtectRuleID.
// When it fires only as written and another rule only once folded, main keeps
// the as-written record; comparing records with every SelfProtectRuleID
// removed picked the folded one and dropped the customer's rule, its reason
// and its taxonomy, in enforce mode too.
func TestCaseFoldResult_CustomerRuleUnderSelfProtectIDIsARule_5091(t *testing.T) {
	testhome.Set(t, t.TempDir())
	pol := DefaultPolicy()
	pol.Rules = append(pol.Rules,
		Rule{ID: SelfProtectRuleID, Taxonomy: "destructive-ops/disk-ops/filesystem-format", Match: Match{CommandRegex: `/tmp/ZQC/`}, Decision: DecisionBlock, Reason: "customer"},
		Rule{ID: "zq-folded", Match: Match{CommandRegex: `/tmp/zqc/`}, Decision: DecisionBlock, Reason: "folded"},
	)
	for _, mode := range []string{"enforce", "audit-only"} {
		e, err := NewEngineWithAnalyzers(pol, 2)
		if err != nil {
			t.Fatal(err)
		}
		e.SetMode(mode)
		got := e.EvaluateCaseFold("cat /tmp/ZQC/x", nil, nil, "", CaseFoldStricter)
		if !reflect.DeepEqual(got.TriggeredRules, []string{SelfProtectRuleID}) || !reflect.DeepEqual(got.Reasons, []string{"customer"}) {
			t.Errorf("%s: record %v %q; want the as-written record, the customer's rule", mode, got.TriggeredRules, got.Reasons)
		}
	}
}

// Codex pass 1, finding 3: a managed lane's own self-protection BLOCK
// (EvaluateFacts' sp-block-config-touch mirror) is not a keep's lead, but it
// is why a tied reading stands. `$PWD` names the managed configuration only
// in the lexical reading (#4830), so the as-written reading's protected-path
// BLOCK is lowered and raised for the lexical one. main recorded
// protected-path alone; 7c270ee1 copied the managed record's own message as
// if the keep had written it. The lead now says what the lexical reading
// read, in the keep's words.
func TestEvaluateFacts_ManagedSelfProtectReadingLeadsTheTiedRecord_5091(t *testing.T) {
	opt := FactsOptions{Managed: true, Home: "/Users/alice"}
	text := `Get-Content ~/.ssh/` + sshKey + `; Set-Content "$PWD\` + asDir + `\notes.txt" x`
	cwd := "/Users/alice"
	enf := communityEngine(t)
	want := enf.EvaluateFacts(factsWithHome(text, cmpHome(opt)), cwd, opt)
	if want.Decision != DecisionBlock || !reflect.DeepEqual(want.TriggeredRules, []string{ProtectedPathRuleID}) {
		t.Fatalf("control: enforce decided %s %v; want BLOCK [%s] (the as-written record on the tie)", want.Decision, want.TriggeredRules, ProtectedPathRuleID)
	}
	aud := communityEngine(t)
	aud.SetMode("audit-only")
	aud.SetSelfProtectionKeep(func(string, []string, []string) (bool, string) { return false, "" })
	f := factsWithHome(text, cmpHome(opt))
	if r := aud.evaluateFactsReading(f, cwd, opt, aud.factsHome(opt)); r.Decision != DecisionAudit || r.OriginalDecision != DecisionBlock {
		t.Fatalf("control: the as-written reading decided %s (original %q); want it lowered", r.Decision, r.OriginalDecision)
	}
	got := aud.EvaluateFacts(f, cwd, opt)
	wantRules := append([]string{SelfProtectRuleID}, want.TriggeredRules...)
	wantReasons := append([]string{managedFactsKeptReason}, want.Reasons...)
	if got.Decision != DecisionBlock || !reflect.DeepEqual(got.TriggeredRules, wantRules) || !reflect.DeepEqual(got.Reasons, wantReasons) {
		t.Errorf("audit-only %s %v %q; want BLOCK %v %q", got.Decision, got.TriggeredRules, got.Reasons, wantRules, wantReasons)
	}
	if !reflect.DeepEqual(got.TaxonomyRefs, want.TaxonomyRefs) {
		t.Errorf("taxonomy %v; want enforce mode's %v", got.TaxonomyRefs, want.TaxonomyRefs)
	}
	// The managed lane's own BLOCK carries the provenance in audit-only mode
	// only: enforce mode computes nothing for the record.
	direct := factsWithHome(`Set-Content `+psCfg+` x`, cmpHome(opt))
	for _, tc := range []struct {
		e    *Engine
		want string
	}{{aud, managedFactsKeptReason}, {enf, ""}} {
		g := tc.e.evaluateFactsReading(direct, cwd, opt, tc.e.factsHome(opt))
		if g.Decision != DecisionBlock || !reflect.DeepEqual(g.TriggeredRules, []string{SelfProtectRuleID}) || g.kept.why != tc.want {
			t.Errorf("mode %q: the managed lane's BLOCK %s %v, provenance %q; want BLOCK [%s], provenance %q", tc.e.mode, g.Decision, g.TriggeredRules, g.kept.why, SelfProtectRuleID, tc.want)
		}
	}
}

// The dialect lane's tie, F1's shape: the lexical reading alone reads the
// dot segment, and its BLOCK is kept by a self-protection rule the as-written
// reading cannot see. On 7c270ee1 the raised record named
// ps-block-format-volume alone.
func TestEvaluateFacts_RuleKeptReadingLeadsTheTiedRecord_5091(t *testing.T) {
	text := `Format-Volume -DriveLetter D -Force; Remove-Item ~\.\` + asDir + `\audit.jsonl`
	enf := communityEngine(t)
	want := enf.EvaluateFacts(psFacts(text), "", FactsOptions{})
	if want.Decision != DecisionBlock || !reflect.DeepEqual(want.TriggeredRules, []string{"ps-block-format-volume"}) {
		t.Fatalf("control: enforce decided %s %v; want BLOCK [ps-block-format-volume] (the as-written record on the tie)", want.Decision, want.TriggeredRules)
	}
	aud := communityEngine(t)
	aud.SetMode("audit-only")
	aud.SetSelfProtectionKeep(func(_ string, rules, _ []string) (bool, string) {
		for _, id := range rules {
			if id == "ps-block-agentshield-log-tamper" {
				return true, ""
			}
		}
		return false, ""
	})
	got := aud.EvaluateFacts(psFacts(text), "", FactsOptions{})
	wantRules := append([]string{SelfProtectRuleID}, want.TriggeredRules...)
	wantReasons := append([]string{SelfProtectKeptReasonPrefix + "the command also matches the self-protection rule ps-block-agentshield-log-tamper"}, want.Reasons...)
	if got.Decision != DecisionBlock || !reflect.DeepEqual(got.TriggeredRules, wantRules) || !reflect.DeepEqual(got.Reasons, wantReasons) {
		t.Errorf("audit-only %s (original %q) %v %q; want BLOCK %v %q", got.Decision, got.OriginalDecision, got.TriggeredRules, got.Reasons, wantRules, wantReasons)
	}
	if !reflect.DeepEqual(got.TaxonomyRefs, want.TaxonomyRefs) {
		t.Errorf("taxonomy %v; want enforce mode's %v", got.TaxonomyRefs, want.TaxonomyRefs)
	}
}

// keptOnTie takes the lead from the other reading's provenance, and only
// from it.
func TestKeptOnTie_LeadComesFromProvenance_5091(t *testing.T) {
	ruleKept := tieKept("on")
	ruleKept.kept.why = "on stands"
	got := stricterResult(tieDowngraded("off"), ruleKept)
	if got.Decision != DecisionBlock || !reflect.DeepEqual(got.TriggeredRules, []string{SelfProtectRuleID, "off"}) ||
		!reflect.DeepEqual(got.Reasons, []string{"on stands", "off reason"}) || got.kept != (keptFor{why: "on stands", led: true}) {
		t.Fatalf("raised by a rule-kept reading: %s %v %q %+v; want off's record led by on's reason", got.Decision, got.TriggeredRules, got.Reasons, got.kept)
	}
	// The raised reading stands for the same reason, for a layer above.
	if up := stricterResult(tieDowngraded("outer"), got); !reflect.DeepEqual(up.TriggeredRules, []string{SelfProtectRuleID, "outer"}) || up.Reasons[0] != "on stands" {
		t.Errorf("raised again by a raised reading: %v %q; want outer's record led by on's reason", up.TriggeredRules, up.Reasons)
	}
	// A record that names SelfProtectRuleID without provenance is a rule
	// that fired, not a lead: off is raised with its own record, as on main.
	byID := tieKept(SelfProtectRuleID)
	if got := stricterResult(tieDowngraded("off"), byID); !reflect.DeepEqual(got.TriggeredRules, []string{"off"}) || got.Decision != DecisionBlock {
		t.Errorf("raised by a record that only names the id: %s %v; want BLOCK [off]", got.Decision, got.TriggeredRules)
	}
}

// The provenance is in memory only: a result carrying it serializes exactly
// as one that does not (the audit event and shield-server's response are a
// cross-repo contract).
func TestKeptFor_NeverSerialized_5091(t *testing.T) {
	r := EvalResult{Decision: DecisionBlock, TriggeredRules: []string{"a"}, Reasons: []string{"ra"}}
	plain := keptForSelfProtection(r, "why")
	withProvenance := plain
	plain.kept = keptFor{}
	a, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(withProvenance)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || withProvenance.kept == (keptFor{}) {
		t.Errorf("serialized with provenance %s; without %s; want the same bytes", b, a)
	}
}

// ruleKeptReason names the rules the keep accepts on their own. A keep may
// accept only a combination (the SelfProtectionKeep contract allows it; the
// shipped keep tests each rule alone, so it never does): the reason then
// names no rule rather than an ordinary one.
func TestRuleKeptReason_NamesOnlySelfProtectionRules_5091(t *testing.T) {
	e, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	e.SetSelfProtectionKeep(func(_ string, rules, _ []string) (bool, string) {
		if len(rules) == 1 && rules[0] == "sp" {
			return true, ""
		}
		return len(rules) > 1, ""
	})
	if got, want := e.ruleKeptReason("x", []string{"plain", "sp"}), SelfProtectKeptReasonPrefix+"the command also matches the self-protection rule sp"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if got, want := e.ruleKeptReason("x", []string{"a", "b"}), SelfProtectKeptReasonPrefix+"the command also matches a self-protection rule"; got != want {
		t.Errorf("only the pair is kept: got %q; want %q", got, want)
	}
}

// withoutKeptLead sets aside only the lead the keep put there.
func TestWithoutKeptLead_ByProvenance_5091(t *testing.T) {
	r := EvalResult{Decision: DecisionBlock, TriggeredRules: []string{SelfProtectRuleID, "a"}, Reasons: []string{"customer", "ra"}}
	if got := withoutKeptLead(r); !reflect.DeepEqual(got, []string{SelfProtectRuleID, "a"}) {
		t.Errorf("a rule under the id: %v; want it kept", got)
	}
	l := keptForSelfProtection(EvalResult{Decision: DecisionBlock, TriggeredRules: []string{"a"}, Reasons: []string{"ra"}}, "why")
	if got := withoutKeptLead(l); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("the keep's lead: %v; want it set aside", got)
	}
	// A customer rule under the id keeps its record and takes the
	// provenance, so a tied reading is still raised with a lead.
	c := keptForSelfProtection(r, "why")
	if !reflect.DeepEqual(c.TriggeredRules, r.TriggeredRules) || !reflect.DeepEqual(c.Reasons, r.Reasons) || c.kept != (keptFor{why: "why"}) {
		t.Errorf("customer record %v %q %+v; want it unchanged, provenance why", c.TriggeredRules, c.Reasons, c.kept)
	}
}
