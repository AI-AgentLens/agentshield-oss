package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestSelfProtectEveryRuleIsMappedOrUnattributed is the ratchet behind the
// per-rule receipt (#4603). Every self-protection rule sits in exactly one
// place: the one-node table, the per-target rules (sp-block-delete-config,
// and sp-block-binary-replace since #4670), or the unattributed list with a
// written reason. A new sp-* rule fails here until someone decides its node.
// Taking the safe-looking default (no node, or tampering) without a decision
// is not an option.
func TestSelfProtectEveryRuleIsMappedOrUnattributed(t *testing.T) {
	mapped := map[string]bool{}
	for _, m := range selfProtectRuleTaxonomy {
		if mapped[m.RuleID] {
			t.Errorf("%s is mapped twice", m.RuleID)
		}
		mapped[m.RuleID] = true
	}
	ids := enterprise.SelfProtectRuleIDs()
	if len(ids) == 0 {
		t.Fatal("no self-protection rules: the ratchet would vouch for nothing")
	}
	live := map[string]bool{}
	for _, id := range ids {
		live[id] = true
		places := 0
		if mapped[id] {
			places++
		}
		if _, ok := selfProtectTargetRules[id]; ok {
			places++
		}
		if why, ok := selfProtectUnattributed[id]; ok {
			places++
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s is unattributed with no reason", id)
			}
		}
		if places != 1 {
			t.Errorf("%s is in %d of the three tables, want exactly 1: map it to a node in self_protect_taxonomy.go, or list it as unattributed with the reason", id, places)
		}
	}
	for id := range mapped {
		if !live[id] {
			t.Errorf("selfProtectRuleTaxonomy names %s, which is not a self-protection rule", id)
		}
	}
	for id := range selfProtectUnattributed {
		if !live[id] {
			t.Errorf("selfProtectUnattributed names %s, which is not a self-protection rule", id)
		}
	}
	for id := range selfProtectTargetRules {
		if !live[id] {
			t.Errorf("%s is not a self-protection rule any more; drop it from selfProtectTargetRules", id)
		}
	}
}

// An id the tables do not know attests nothing: the default is no node, never
// tampering. Unattributed rules get the same nil.
func TestSelfProtectUnmappedRuleCarriesNoNode(t *testing.T) {
	for _, id := range []string{"", "sp-block-not-a-rule", "sp-block-config-touch"} {
		if got := selfProtectTaxonomyRefs(id, "r"+"m -rf ~/.agent"+"shield"); got != nil {
			t.Errorf("%q: %v, want no node", id, got)
		}
	}
}

// TestAuditLogPathSetComesFromCommunityPack: the definition of a log target is
// the community rule's own pattern, read from the embedded pack, with no second
// copy (Gary, 2026-10-30). If the rule is renamed, moved or rewritten without
// a command_regex, this fails instead of every log delete going quiet.
func TestAuditLogPathSetComesFromCommunityPack(t *testing.T) {
	re := auditLogPathSet()
	if re == nil {
		t.Fatalf("%s not found in the embedded community packs, or it has no command_regex", auditLogDeleteRule)
	}
	rule := embeddedRule(t, auditLogDeleteRule)
	if re.String() != rule.Match.CommandRegex {
		t.Errorf("path set %q is not the rule's pattern %q", re.String(), rule.Match.CommandRegex)
	}
	as := "agent" + "shield"
	if !re.MatchString("r" + "m ~/." + as + "/audit.jsonl") {
		t.Error("positive control: the audit log is not a log target")
	}
	if re.MatchString("r" + "m ~/." + as + "/policy.yaml") {
		t.Error("negative control: the policy is a log target")
	}
}

// deletesNoAgentshieldPath lists the community log-delete TPs whose delete
// statement removes no AgentShield path, each with the reason. The community
// rule matches command text; the receipt names only what the matched delete
// removes (Gary, 2026-10-30, #4603 fix round 2), so these attest nothing.
var deletesNoAgentshieldPath = map[string]string{
	// An unquoted ; ends the statement even inside [ ]. bash runs
	// `rm -f /tmp/[` and then the command `]x` with the log as its argument;
	// zsh stops at "bad pattern: /tmp/[". Neither deletes the log. Checked
	// with echo in place of rm in bash 3.2.57 and zsh 5.9.
	"r" + "m -f /tmp/[;]x ~/.agent" + "shield/audit.jsonl": "the ; ends the rm statement before the log path",
}

// The exception list cannot go stale: each entry is still an inline TP of
// the community log rule and still reaches sp-block-delete-config.
func TestDeletesNoAgentshieldPathAreLiveTPs(t *testing.T) {
	rule := embeddedRule(t, auditLogDeleteRule)
	if rule.Tests == nil {
		t.Fatalf("%s has no inline tests", auditLogDeleteRule)
	}
	for cmd, why := range deletesNoAgentshieldPath {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%q has no reason", cmd)
		}
		if !containsStr(rule.Tests.TP, cmd) {
			t.Errorf("%q is not an inline TP of %s any more; drop it from the list", cmd, auditLogDeleteRule)
		}
		if id, ok := enterprise.MatchSelfProtectCommand(cmd); !ok || id != spDeleteConfigRule {
			t.Errorf("%q does not reach %s any more (%q, %v); drop it from the list", cmd, spDeleteConfigRule, id, ok)
		}
	}
}

// TestDeleteConfigNodesAgreeWithCommunityRules checks every inline TP of the
// two community rules that cite ai-audit-trail-circumvention, which is what
// an unmanaged host's receipt carries for these commands. When the managed
// rule sp-block-delete-config blocks one first, its receipt must carry:
//   - for a log-delete TP: the audit-trail node and not tampering, except a
//     TP in deletesNoAgentshieldPath, which carries no node;
//   - for a whole-directory TP: both nodes;
//   - for a whole-directory TN that the managed text rule still blocks
//     (a sibling directory, an echo): no node.
func TestDeleteConfigNodesAgreeWithCommunityRules(t *testing.T) {
	both := []string{spNodeAuditTrail, spNodeTampering}
	cases := []struct {
		rule string
		tn   bool
		want []string
	}{
		{auditLogDeleteRule, false, []string{spNodeAuditTrail}},
		{"ts-struct-block-agentshield-dir-delete", false, both},
		{"ts-struct-block-agentshield-dir-delete", true, nil},
	}
	for _, c := range cases {
		rule := embeddedRule(t, c.rule)
		if rule.Tests == nil {
			t.Fatalf("%s has no inline tests", c.rule)
		}
		cmds := rule.Tests.TP
		if c.tn {
			cmds = rule.Tests.TN
		}
		reached := 0
		for _, cmd := range cmds {
			if id, ok := enterprise.MatchSelfProtectCommand(cmd); !ok || id != spDeleteConfigRule {
				continue
			}
			reached++
			want := c.want
			if _, ok := deletesNoAgentshieldPath[cmd]; ok && c.rule == auditLogDeleteRule && !c.tn {
				want = nil
			}
			if got := selfProtectTaxonomyRefs(spDeleteConfigRule, cmd); !reflect.DeepEqual(got, want) {
				t.Errorf("%s tn=%v %q: %v, want %v", c.rule, c.tn, cmd, got, want)
			}
		}
		// A denominator, so a pack edit that stops these commands reaching the
		// managed rule cannot turn this test vacuous.
		t.Logf("%s tn=%v: %d of %d inline cases reach %s", c.rule, c.tn, reached, len(cmds), spDeleteConfigRule)
		if reached == 0 {
			t.Errorf("%s tn=%v: no inline case reaches %s; the parity check measured nothing", c.rule, c.tn, spDeleteConfigRule)
		}
	}
}

// TestAgentshieldDirSetComesFromCommunityPack: "the whole directory" is the
// community rule ts-struct-block-agentshield-dir-delete's own structural
// match, read from the embedded pack (Gary, 2026-10-30, pass-2 follow-up 3).
// If the rule is renamed, moved or stops being structural, this fails instead
// of every whole-directory delete going quiet.
func TestAgentshieldDirSetComesFromCommunityPack(t *testing.T) {
	set := agentshieldDirSet()
	if set == nil {
		t.Fatalf("%s not found in the embedded community packs, or it has no structural executable and args_any", agentshieldDirDeleteRule)
	}
	rule := embeddedRule(t, agentshieldDirDeleteRule)
	sm := rule.Match.Structural
	if sm == nil {
		t.Fatalf("%s is not structural", agentshieldDirDeleteRule)
	}
	if !reflect.DeepEqual(set.Executable, []string(sm.Executable)) || !reflect.DeepEqual(set.ArgsAny, sm.ArgsAny) ||
		!reflect.DeepEqual(set.ArgsNone, sm.ArgsNone) || !reflect.DeepEqual(set.FlagsAny, sm.FlagsAny) ||
		!reflect.DeepEqual(set.FlagsAll, sm.FlagsAll) || !reflect.DeepEqual(set.FlagsNone, sm.FlagsNone) {
		t.Errorf("directory set %+v is not the rule's match %+v", set, sm)
	}
	as := "agent" + "shield"
	both := []string{spNodeAuditTrail, spNodeTampering}
	for _, c := range []struct {
		cmd  string
		want []string
	}{
		{"r" + "m -rf ~/." + as, both},
		{"r" + "m -rf /home/bob/." + as + "/*", both},
		{"r" + "m -rf /root/." + as, both},
		{"r" + "m -rf /tmp/scratch-home/." + as, nil},
		{"r" + "m -rf /tmp/scratch-home/." + as + "/", nil},
		{"r" + "m -rf /opt/x/." + as + "/*", nil},
	} {
		if got := deleteConfigTaxonomyRefs(c.cmd); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestEchoedWords: an operand of the form $(echo …) is read as what the echo
// prints; anything else is not read.
func TestEchoedWords(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"$(echo x\necho ~/y\n)", []string{"x", "~/y"}},
		{`"$(echo ~/y)"`, []string{"~/y"}},
		{"$(echo -n ~/y)", []string{"~/y"}},
		{"$(cat ~/y)", nil},
		{"$(echo ~/y; cat ~/z)", nil},
		{"$(echo ~/y >/tmp/z)", nil},
		{"$(echo $(echo ~/y))", nil},
		{"$((1+2))", nil},
		{"<(echo ~/y)", nil},
		{"pre$(echo ~/y)", nil},
	} {
		if got := echoedWords(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

func TestShellWordsForTargets(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`rm -f ~/x/'a;b.jsonl'`, []string{"rm", "-f", "~/x/a;b.jsonl"}},
		{`rm -f "$HOME/x"/audit.jsonl`, []string{"rm", "-f", "$HOME/x/audit.jsonl"}},
		{`rm -rf $(echo x; echo ~/y)`, []string{"rm", "-rf", "$", "echo", "x", "echo", "~/y"}},
		{`rm a\;b>c 2>&1`, []string{"rm", "a;b", "c", "2", "1"}},
		{`echo 'a b' "c \" d"`, []string{"echo", "a b", `c " d`}},
		{"rm -rf \\\n ~/y", []string{"rm", "-rf", "~/y"}},
	} {
		if got := shellWordsForTargets(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

// embeddedRule is the community rule id as the binary embeds it.
func embeddedRule(t *testing.T, id string) policy.Rule {
	t.Helper()
	pol, _, err := policy.LoadEmbeddedShellPacks(&policy.Policy{})
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks: %v", err)
	}
	for _, r := range pol.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("%s is not in the embedded community packs", id)
	return policy.Rule{}
}
