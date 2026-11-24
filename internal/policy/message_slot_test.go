package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// TestMessageSlotOnlyExcusesTheSlotStatement pins the half of #4988 that the
// shipped packs cannot: is_doc_text's regex also labels plain commands
// (`logger`, `docker run --label`, `npm version -m`, ...), and a commit on
// the line makes such a line one MessageSlotsSurviveImpureLine admits. Only
// the git/gh message statement may be excused there; a labelled plain
// command beside it keeps its BLOCK, as it does on main (the line is impure,
// so the strict gate withdraws the label). Both evaluation paths.
func TestMessageSlotOnlyExcusesTheSlotStatement(t *testing.T) {
	pol := &Policy{Defaults: Defaults{Decision: DecisionAudit}, Rules: []Rule{{
		ID:       "test-message-slot-doc-text",
		Taxonomy: "credential-exposure/password-db-access/system-shadow-read",
		Match: Match{
			CommandRegex:           `zqslotprobe`,
			CommandIntentDowngrade: []string{analyzer.LabelIsDocText},
		},
		Decision: DecisionBlock,
		Reason:   "test",
	}}}
	testPositionExcludeParity(t, pol, []struct {
		name    string
		command string
		want    Decision
	}{
		{"the message beside a build step", "git commit -q -m 'zqslotprobe'; make build", DecisionAudit},
		{"a gh body beside a test run", "gh issue comment 1 --body 'zqslotprobe'; go test ./...", DecisionAudit},
		{"logger beside a commit", "git commit -q -m wip; logger zqslotprobe", DecisionBlock},
		{"docker --label beside a commit", "git commit -q -m wip; docker run --label a=zqslotprobe alpine", DecisionBlock},
		{"npm version -m beside a commit", "git commit -q -m wip; npm version patch -m zqslotprobe", DecisionBlock},
		{"the match in both the slot and a plain command", "git commit -q -m 'zqslotprobe'; logger zqslotprobe", DecisionBlock},
		{"echo beside a build step stays strict", "echo 'zqslotprobe'; make build", DecisionBlock},
	})
}
