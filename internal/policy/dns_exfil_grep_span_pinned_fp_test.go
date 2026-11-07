package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// Pinned false positive: ne-block-dns-exfil-subquery fires when a lookup
// tool's name follows a | INSIDE a quoted grep -E alternation and a $( appears
// anywhere later in the command, even inside a quoted sed script (#4552). No
// lookup runs and nothing is substituted. The rule's anchor reads the quoted |
// as a pipe, and its .* runs across the real pipe to the quoted $(.
//
// # Why this test exists rather than a fix
//
// Stopping the span at a separator ([^|;&]* instead of .*) removes this false
// positive and opens a bypass: a quoted |, ; or & inside the lookup's own
// argument, before the substitution, still runs the query. #4028 measured
// exactly this narrowing on ts-block-agentshield-log-delete, where Codex found
// 16 fail-open shapes (a quoted "a|b" among them), and Gary chose to pin the
// false positive instead (#4003, TestAgentShieldLogDeleteFP4003IsPinned). The
// same reasoning holds here: a regex over raw text cannot tell a quoted
// separator from a real one.
//
// The shape is rare in real traffic. From 2026-10-21 to 2026-10-25 (7,439 hook
// events) it fired twice, both while this issue was being written up. The
// other real-traffic false positive of the pair, prose in a heredoc or
// commit message, is fixed by command_intent_downgrade on both rules.
//
// Lifting this pin needs a statement-aware matcher (the lookup tool as a
// segment's executable, a substitution in one of its own arguments), and the
// change must keep every inline TP of both rules.
func TestDNSExfilGrepSpanFP4552IsPinned(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	var rule *Rule
	rules := loadAllRules(t)
	for i := range rules {
		if rules[i].ID == "ne-block-dns-exfil-subquery" {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("ne-block-dns-exfil-subquery not found in the loaded packs")
	}
	engine, err := NewEngine(&Policy{Rules: []Rule{*rule}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	tool := "di" + "g"
	cmd := "grep -n -iE 'rule work|" + tool + " deeper' p.md | sed 's/week=$(date +%V)/week=44/'"
	if !engine.matchRule(cmd, *rule) {
		t.Errorf("the #4552 grep-span false positive no longer fires. If that is deliberate, the replacement must keep\n"+
			"every inline TP of ne-block-dns-exfil-subquery and -backtick; delete this pin and close #4552.\n  %s", cmd)
	}
}
