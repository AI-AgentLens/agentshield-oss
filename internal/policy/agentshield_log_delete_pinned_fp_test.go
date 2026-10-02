package policy

import "testing"

// Pinned false positive: ts-block-agentshield-log-delete fires on an `rm` of
// an unrelated path when a LATER statement names a file "agentshield" and a
// later token contains "audit" (#4003). It stays on purpose (Gary,
// 2026-09-26, option A on #4028).
//
// # Why this test exists rather than a fix
//
// Two narrowings were each reviewed by Codex, and each failed open on real
// deletions of the audit log (confirmed on built binaries, BLOCK -> not BLOCK):
//   - [^;&|]* between the verb and the path (the first #4028 version): 16
//     shapes, e.g. a quoted "a|b" or 2>&1 before the target, $(…; …), <(…).
//   - the loose alternative confined to one path token (the rework): 3 shapes,
//     e.g. rm -f "$HOME/.agentshield"/audit.jsonl.
//
// A regex over raw text cannot tell a quote or quoted space inside one shell
// word from a word boundary, and that is exactly the difference between this
// false positive and a real delete. Every bypass shape is now an inline TP on
// the rule. This test pins the false positive, so lifting it has to be a
// deliberate decision, made with a statement-aware matcher, not a third regex.
func TestAgentShieldLogDeleteFP4003IsPinned(t *testing.T) {
	var rule *Rule
	rules := loadAllRules(t)
	for i := range rules {
		if rules[i].ID == "ts-block-agentshield-log-delete" {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("ts-block-agentshield-log-delete not found in the loaded packs")
	}
	engine, err := NewEngine(&Policy{Rules: []Rule{*rule}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	as := "agent" + "shield"
	cmd := "T=/tmp/d; rm -rf $T; cp x $T/" + as + "; bash scripts/replay-audit_test.sh --binary $T/" + as
	if !engine.matchRule(cmd, *rule) {
		t.Errorf("the #4003 false positive no longer fires. If that is deliberate, the replacement must keep\n"+
			"every inline TP of the rule; delete this pin and close the loop on #4003.\n  %s", cmd)
	}
}
