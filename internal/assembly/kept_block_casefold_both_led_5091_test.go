package assembly

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// A case-fold tie where BOTH readings are led (#5091 pass 2, follow-up 1):
// on a managed host, `rm -rf ~/.AgentShield; cat ~/.ssh/id_rsa` is kept in
// audit-only mode under the as-written reading and the folded one, and each
// carries its own lead. caseFoldResult must set aside both leads before it
// compares the readings, or the folded lead counts as an extra rule and the
// folded record wins: the receipt then gives ~/.agentshield/** as the reason
// and loses the ssh-private-key-read node enforce mode records. The PR strips
// both sides; this pins it (it kills pass 2's surviving mutant A2, which
// strips the as-written side only).
func TestShellEngine_CaseFoldTieBothLedKeepsEnforceRecord_5091(t *testing.T) {
	clearCIEnv(t)
	home := t.TempDir()
	testhome.Set(t, home)
	pol := keptReceiptPolicy(t)
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, policy.ManagedConfigProtectedPath)
	enf, err := ShellEngine(pol, 2, "enforce")
	if err != nil {
		t.Fatal(err)
	}
	aud, err := ShellEngine(pol, 2, "audit-only")
	if err != nil {
		t.Fatal(err)
	}
	const sshNode = "credential-exposure/private-key-access/ssh-private-key-read"
	del := "r" + "m -rf ~/.Agent" + "Shield"
	read := "cat ~/.ssh/" + "id_rsa"
	for _, cmd := range []string{del + "; " + read, read + "; " + del} {
		t.Run(cmd, func(t *testing.T) {
			e := keptReceiptEval(t, enf, cmd, home)
			if e.Decision != policy.DecisionBlock || !containsID(e.TaxonomyRefs, sshNode) {
				t.Fatalf("enforce: %s %v %v; want BLOCK citing %s", e.Decision, e.TriggeredRules, e.TaxonomyRefs, sshNode)
			}
			a := keptReceiptEval(t, aud, cmd, home)
			if a.Decision != policy.DecisionBlock || a.OriginalDecision != "" {
				t.Fatalf("audit-only: %s (original %q) %v; want a kept BLOCK", a.Decision, a.OriginalDecision, a.TriggeredRules)
			}
			if !containsID(a.TaxonomyRefs, sshNode) {
				t.Errorf("audit-only taxonomy %v lost %s; enforce mode records it", a.TaxonomyRefs, sshNode)
			}
			rules, reasons := a.TriggeredRules, a.Reasons
			if len(rules) > 0 && rules[0] == policy.SelfProtectRuleID {
				if len(reasons) == 0 || !strings.HasPrefix(reasons[0], policy.SelfProtectKeptReasonPrefix) {
					t.Fatalf("led by %s without the keep's reason: %q", policy.SelfProtectRuleID, reasons)
				}
				rules, reasons = rules[1:], reasons[1:]
			}
			if strings.Join(rules, ",") != strings.Join(e.TriggeredRules, ",") || strings.Join(reasons, "\n") != strings.Join(e.Reasons, "\n") {
				t.Errorf("audit-only record without the lead %v %q; want enforce mode's %v %q", rules, reasons, e.TriggeredRules, e.Reasons)
			}
		})
	}
	// The same rows through the fitness check, so the tie also names why the
	// BLOCK stands.
	checkKeptBlocksNameWhy(t, pol, enf, aud, []keptCase{{"both-led-1", del + "; " + read}, {"both-led-2", read + "; " + del}}, home)
}
