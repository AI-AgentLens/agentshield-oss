package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The shell keep's reason for the record (#5089): "" when a self-protection
// rule decided the BLOCK (the record names it), else what the keep read. The
// decisions are TestShellSelfProtectionKeep's and
// TestShellSelfProtectionKeep_DecidingRule's, unchanged.
func TestShellSelfProtectionKeep_Reason_5089(t *testing.T) {
	h := t.TempDir()
	setTestHome(t, h)
	keep := ShellSelfProtectionKeep(&policy.Policy{Rules: []policy.Rule{{ID: "zq-block-agentshield-x", Decision: policy.DecisionBlock}}})
	as := "." + "agent" + "shield"
	gt := " " + ">" + " "
	names := func(rel, class string) string {
		return policy.SelfProtectKeptReasonPrefix + "the command names ~/" + rel + " (" + class + ") and is not a plain read"
	}
	for _, tc := range []struct {
		name    string
		command string
		rules   []string
		hits    []string
		keep    bool
		why     string
	}{
		{"a self-protection rule decided", "zq anything", []string{"zq-plain", "zq-block-agentshield-x"}, nil, true, ""},
		{"a guardian finding that disables AgentShield decided", "export " + "AGENT" + "SHIELD_" + "DIS" + "ABLE=1", []string{"guardian-dis" + "able_security"}, nil, true, ""},
		{"a protected-path hit on AgentShield's directory", "zq", []string{"protected-path"}, []string{filepath.Join(h, as, "audit.jsonl")},
			true, policy.SelfProtectKeptReasonPrefix + "a protected path it matched, ~/" + as + ", is AgentShield's own configuration"},
		{"the command names AgentShield's policy", "r" + "m ~/" + as + "/policy.yaml", []string{"zq-plain"}, nil, true, names(as, "AgentShield's own configuration")},
		{"the command names an agent hook file", "echo '{}'" + gt + "~/.claude/" + "settings.json", []string{"zq-plain"}, nil, true, names(".claude/settings.json", "an agent's hook file")},
		{"the command names an agent MCP configuration", "cp evil.json ~/.cursor/" + "mcp.json", []string{"zq-plain"}, nil, true, names(".cursor/mcp.json", "an agent's MCP configuration")},
		// Measured on main (#5089): the command-text reading counts a
		// compound that is not, as a whole, a plain read, so this read is
		// kept. The reason says what was read, "names", never "changes".
		{"a read inside a compound is named, not called a change", "zqblock; cat ~/" + as + "/policy.yaml", []string{"zq-plain"}, nil, true, names(as, "AgentShield's own configuration")},
		{"control: a plain read", "cat ~/.claude/" + "settings.json", []string{"zq-plain"}, nil, false, ""},
		{"control: nothing self-protected", "r" + "m -rf /", []string{"zq-plain"}, nil, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kept, why := keep(tc.command, tc.rules, tc.hits)
			if kept != tc.keep || why != tc.why {
				t.Errorf("keep(%q, %v, %v) = %v, %q; want %v, %q", tc.command, tc.rules, tc.hits, kept, why, tc.keep, tc.why)
			}
			if lw := strings.ToLower(why); strings.Contains(lw, "chang") || strings.Contains(lw, "writ") || strings.Contains(lw, "delet") {
				t.Errorf("reason %q claims a change; the keep's reading does not tell a read from a write", why)
			}
		})
	}
}

// Every self-protection target has a class for the reason, so a target added
// to the guard cannot reach a receipt as "a self-protection target".
func TestTargetClass_EveryTarget_5089(t *testing.T) {
	targets := selfProtectTargets()
	if len(targets) == 0 {
		t.Fatal("no self-protection targets")
	}
	for _, tg := range targets {
		if c := targetClass(tg.rel); c == "a self-protection target" {
			t.Errorf("target ~/%s has no class", tg.rel)
		}
	}
	if c := targetClass(".bash" + "rc"); c != "a self-protection target" {
		t.Errorf("a guarded file that is not a self-protection target got class %q", c)
	}
}
