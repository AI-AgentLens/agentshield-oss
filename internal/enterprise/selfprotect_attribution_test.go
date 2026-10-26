package enterprise

import "testing"

// selfProtectAttribution maps every hardcoded self-protection rule to one
// command that must be attributed to THAT rule id. The existing per-rule tests
// assert only ctx.Blocked, so a rule that has gone dead (or is shadowed by an
// earlier rule, since matchesSelfProtectRule returns the first match) stays
// green while its receipt names a different id.
var selfProtectAttribution = map[string]string{
	"sp-block-bypass-env":     "export AGENTSHIELD_BYPASS=1",
	"sp-block-setup-disable":  "agentshield setup claude-code --disable",
	"sp-block-delete-config":  "rm -rf ~/.agentshield/",
	"sp-block-delete-hooks":   "rm ~/.claude/settings.json",
	"sp-block-policy-write":   "echo 'rules: []' > ~/.agentshield/policy.yaml",
	"sp-block-binary-replace": "cp /tmp/x /usr/local/bin/agentshield",
	"sp-block-config-touch":   "python3 -c \"open('/root/.agentshield/managed.json','w')\"",
}

// TestSelfProtect_EveryRuleHasAttributedTP is the mechanical invariant behind
// the managed-mode receipt: every selfProtectRules entry has a command that
// reports exactly its own id, and no rule can be added without a row here.
func TestSelfProtect_EveryRuleHasAttributedTP(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range selfProtectRules {
		seen[rule.ID] = true
		cmd, ok := selfProtectAttribution[rule.ID]
		if !ok {
			t.Errorf("%s has no attribution row: add one command that must report this id", rule.ID)
			continue
		}
		got, matched := matchesSelfProtectRule(cmd)
		if !matched || got != rule.ID {
			t.Errorf("%s: %q attributed to %q (matched=%v)", rule.ID, cmd, got, matched)
		}
	}
	for id := range selfProtectAttribution {
		if !seen[id] {
			t.Errorf("attribution row %q names no rule in selfProtectRules", id)
		}
	}
}
