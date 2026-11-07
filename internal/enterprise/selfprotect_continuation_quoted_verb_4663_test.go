package enterprise

import "testing"

// #4663: a backslash-newline continuation and a quoted command word took
// sp-block-binary-replace and sp-block-delete-hooks from BLOCK to AUDIT on a
// managed host, because no reading joined the continuation or unquoted the
// verb. Every TP row below fails on main. The readings only add matches, so
// the TNs pin that text the shell does not run as these commands stays clear.
func TestSelfProtect_ContinuationAndQuotedVerb_4663(t *testing.T) {
	tps := []struct{ cmd, rule string }{
		{"cp /tmp/x \\\n  /usr/local/bin/agentshield", "sp-block-binary-replace"},
		{"rm \\\n  ~/.claude/settings.json", "sp-block-delete-hooks"},
		{"'cp' /tmp/x /usr/local/bin/agentshield", "sp-block-binary-replace"},
		{"\"cp\" /tmp/x /opt/homebrew/bin/agentshield", "sp-block-binary-replace"},
		{"'mv' /tmp/x /opt/homebrew/bin/agentshield", "sp-block-binary-replace"},
		{"echo ok; 'cp' /tmp/x /usr/local/bin/agentshield", "sp-block-binary-replace"},
		{"true && 'cp' /tmp/x /usr/local/bin/agentshield", "sp-block-binary-replace"},
		{"'rm' ~/.claude/settings.json", "sp-block-delete-hooks"},
		// Opus pass 1 survivors M2 and M4: a continuation combined with a quote
		// splice in the path, and with a quoted verb.
		{"cp /tmp/x \\\n  /usr/local/bin/agentshi'e'ld", "sp-block-binary-replace"},
		{"'cp' /tmp/x \\\n  /usr/local/bin/agentshield", "sp-block-binary-replace"},
		// Codex pass on #4724: a quoted verb with a path spelling main already
		// reads (a quote splice, an unset-parameter splice). Each reading alone
		// missed, because none composed the verb fold with main's readings.
		{"'cp' /tmp/x /usr/local/bin/agentshi'e'ld", "sp-block-binary-replace"},
		{"'rm' ~/.claude/sett'ings'.json", "sp-block-delete-hooks"},
		{"'cp' /tmp/x /usr/local/bin/agentshi${zqx}eld", "sp-block-binary-replace"},
	}
	for _, tc := range tps {
		id, ok := matchesSelfProtectRule(tc.cmd)
		if !ok || id != tc.rule {
			t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want (%q, true)", tc.cmd, id, ok, tc.rule)
		}
	}

	// Controls: the plain spellings still match, and benign look-alikes do not.
	if id, ok := matchesSelfProtectRule("cp /tmp/x /usr/local/bin/agentshield"); !ok || id != "sp-block-binary-replace" {
		t.Errorf("control: plain cp = (%q, %v)", id, ok)
	}
	tns := []string{
		"cp /tmp/x \\\n  /tmp/y",
		"'cp' /tmp/x /tmp/y",
		"'cp' /tmp/x /tmp/y'z'",
		"rm \\\n  /tmp/scratch.txt",
		"echo 'cp /tmp/x \\\n/usr/local/bin/agentshield'",
	}
	for _, cmd := range tns {
		if id, ok := matchesSelfProtectRule(cmd); ok {
			t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no match", cmd, id)
		}
	}
}

// #4724 pass 2 follow-up 1: a command bash cannot parse that main matched only
// through its zsh reading or matchesSetupDisable keeps main's rule id. Before
// the #4663 readings moved after those, the quoted-verb fold claimed this
// command as sp-block-delete-config, which carries no taxonomy node, where main
// names sp-block-setup-disable (#4631's invariant).
func TestSelfProtect_4663ReadingsKeepMainsRuleIDOnZshOnlyText(t *testing.T) {
	cmd := "'rm' -rf ~/.agentshield; : ${(U)HOME}; agentshield setup claude-code --disa'b'le"
	if id, ok := matchesSelfProtectRule(cmd); !ok || id != "sp-block-setup-disable" {
		t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want (%q, true)", cmd, id, ok, "sp-block-setup-disable")
	}
}
