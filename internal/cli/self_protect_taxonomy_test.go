package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The nodes a managed host's shell self-protection BLOCK may attest. They are
// spelled out here rather than taken from the table, so these rows also run
// unchanged against a tree that does not have the table (main, or the pass-1
// head of #4603).
const (
	spNodeTampering  = "persistence-evasion/defense-evasion/security-tool-tampering"
	spNodeAuditTrail = "persistence-evasion/anti-forensics/ai-audit-trail-circumvention"
)

// spReceiptRow is one command a managed host blocks in the self-protection
// middleware, the sp-* rule that must block it, and the nodes its receipt
// must carry.
type spReceiptRow struct {
	name, rule, cmd string
	want            []string
}

// spReceiptRows are assembled at runtime: this repo dogfoods AgentShield, and
// the literal spellings are what the rules block.
func spReceiptRows(home string) []spReceiptRow {
	as := "agent" + "shield"
	dir := "~/." + as
	both := []string{spNodeAuditTrail, spNodeTampering} // sorted
	return []spReceiptRow{
		// One node per rule (Gary, 2026-10-30).
		{"bypass variable", "sp-block-bypass-env", "export " + strings.ToUpper(as) + "_BYPASS=1", []string{spNodeTampering}},
		{"setup disable", "sp-block-setup-disable", as + " setup claude-code --dis" + "able", []string{spNodeTampering}},
		{"policy overwrite", "sp-block-policy-write", "echo x > " + home + "/." + as + "/policy.yaml", []string{spNodeTampering}},
		{"agent hook delete", "sp-block-delete-hooks", "r" + "m ~/.claude/settings.json", []string{spNodeTampering}},
		{"binary replace", "sp-block-binary-replace", "cp /tmp/x /usr/local/bin/" + as, []string{spNodeTampering}},

		// sp-block-delete-config, split by target. A log is exactly what the
		// community rule ts-block-agentshield-log-delete protects (#4603 pass 1,
		// finding 1: these cited tampering).
		{"delete the audit log", "sp-block-delete-config", "r" + "m " + dir + "/audit.jsonl", []string{spNodeAuditTrail}},
		{"delete the logs directory", "sp-block-delete-config", "r" + "m -rf " + dir + "/logs/", []string{spNodeAuditTrail}},
		{"delete a session log, quoted ;", "sp-block-delete-config", "r" + "m -f " + dir + "/'session;1.jsonl'", []string{spNodeAuditTrail}},
		{"delete the audit log, $HOME quoted", "sp-block-delete-config", `r` + `m -f "$HOME/.` + as + `"/audit.jsonl`, []string{spNodeAuditTrail}},
		{"delete the logs, unset-parameter splice", "sp-block-delete-config", "r" + "m -rf " + dir + "/lo${zqx}gs", []string{spNodeAuditTrail}},
		{"delete the policy", "sp-block-delete-config", "r" + "m " + dir + "/policy.yaml", []string{spNodeTampering}},
		{"delete the packs", "sp-block-delete-config", "r" + "m -rf " + dir + "/packs", []string{spNodeTampering}},
		{"delete the policy and the log", "sp-block-delete-config", "r" + "m " + dir + "/policy.yaml " + dir + "/audit.jsonl", both},
		{"delete the whole directory", "sp-block-delete-config", "r" + "m -rf " + dir, both},
		// $HOME, not the scratch HOME's absolute path: the whole directory is
		// spelled the way the community rule spells it (~, $HOME, ${HOME},
		// /Users/*, /home/*, /root), and a test HOME lives under a temp dir.
		{"delete the whole directory, trailing slash", "sp-block-delete-config", "r" + "m -rf $HOME/." + as + "/", both},
		{"empty the whole directory", "sp-block-delete-config", "r" + "m -rf " + dir + "/*", both},

		// The rule's text pattern also blocks these, and neither deletes an
		// AgentShield path: no node rather than a guessed one.
		{"delete a sibling backup directory", "sp-block-delete-config", "r" + "m -rf " + dir + "-backup", nil},
		{"echo of a delete", "sp-block-delete-config", "echo 'r" + "m -rf " + dir + "'", nil},
	}
}

// TestSelfProtectBlockCarriesRuleNode drives each row through the real
// evaluation a hook runs, on a managed scratch HOME, and checks the node on
// the result and on the audit event (the event is what is logged and sent to
// the SaaS).
func TestSelfProtectBlockCarriesRuleNode(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	for _, c := range spReceiptRows(home) {
		t.Run(c.name, func(t *testing.T) {
			res, event := evaluateCommand(c.cmd, home, "claude-code-hook", "")
			assertSPBlock(t, res, c.rule)
			if !reflect.DeepEqual(res.TaxonomyRefs, c.want) {
				t.Errorf("result taxonomy %v, want %v", res.TaxonomyRefs, c.want)
			}
			if event == nil {
				t.Fatal("no audit event")
			}
			if !reflect.DeepEqual(event.TaxonomyRefs, c.want) {
				t.Errorf("audit event taxonomy %v, want %v", event.TaxonomyRefs, c.want)
			}
		})
	}
}

// TestSelfProtectConfigTouchCarriesNoNode pins a written gap (Gary,
// 2026-10-30). sp-block-config-touch blocks reads as well as interpreter
// writes, and security-tool-tampering is false for a read, so the rule attests
// no node until #4666 tells the two apart. The interpreter write is here on
// purpose: it is tampering, and it still attests nothing. Closing #4666 means
// changing this test deliberately.
func TestSelfProtectConfigTouchCarriesNoNode(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	as := "agent" + "shield"
	policyFile := "~/." + as + "/policy.yaml"
	for _, cmd := range []string{
		"less " + policyFile,
		"sed -n '1,40p' " + policyFile,
		"cat $(echo " + policyFile + ")",
		"grep -n mode ~/." + as + "/" + as + ".yaml | head -5",
		`python3 -c "open('` + home + "/." + as + `/policy.yaml','w')"`,
	} {
		t.Run(cmd, func(t *testing.T) {
			res, event := evaluateCommand(cmd, home, "claude-code-hook", "")
			assertSPBlock(t, res, "sp-block-config-touch")
			if len(res.TaxonomyRefs) != 0 {
				t.Errorf("result taxonomy %v, want none (#4666)", res.TaxonomyRefs)
			}
			if event == nil {
				t.Fatal("no audit event")
			}
			if len(event.TaxonomyRefs) != 0 {
				t.Errorf("audit event taxonomy %v, want none (#4666)", event.TaxonomyRefs)
			}
		})
	}
}

// The control: on an unmanaged host the middleware does not run, so neither
// the result nor the audit event can carry a node from it. A test that passed
// here too would not be measuring the self-protection path.
func TestSelfProtectTamperingNodeOnlyFromManagedPath(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	cmd := "export " + strings.ToUpper("agent"+"shield") + "_BYPASS=1"
	res, event := evaluateCommand(cmd, home, "claude-code-hook", "")
	if containsStr(res.TriggeredRules, "enterprise-self-protect") {
		t.Fatalf("unmanaged host ran self-protection: %v", res.TriggeredRules)
	}
	if len(res.TaxonomyRefs) != 0 {
		t.Errorf("unmanaged result attests %v without a self-protection BLOCK: %v", res.TaxonomyRefs, res.TriggeredRules)
	}
	if event == nil {
		t.Fatal("no audit event")
	}
	if len(event.TaxonomyRefs) != 0 {
		t.Errorf("unmanaged audit event attests %v without a self-protection BLOCK: %v", event.TaxonomyRefs, event.TriggeredRules)
	}
}

// assertSPBlock fails the test unless res is a self-protection BLOCK whose
// reason names rule. A row whose command is blocked by another rule would
// not be measuring the mapping it names.
func assertSPBlock(t *testing.T, res *policy.EvalResult, rule string) {
	t.Helper()
	if res.Decision != policy.DecisionBlock || !containsStr(res.TriggeredRules, "enterprise-self-protect") {
		t.Fatalf("decision %s rules %v; want an enterprise-self-protect BLOCK (the node must never move a decision)", res.Decision, res.TriggeredRules)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "(rule: "+rule+")") {
		t.Fatalf("reasons %v do not name %s; the row is not measuring it", res.Reasons, rule)
	}
}
