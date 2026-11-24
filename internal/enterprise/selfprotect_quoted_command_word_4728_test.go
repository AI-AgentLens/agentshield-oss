package enterprise

import "testing"

// A quoted command word that is not the first word of its statement (#4728):
// bash removes the quotes, so each of these runs cp onto the binary the hook
// calls. The unquoted control comes first; every row must decide as it does.
func TestSelfProtect_QuotedCommandWordAnywhere_4728(t *testing.T) {
	const bin = "/tmp/x /usr/local/bin/agentshield"
	controls := []string{
		"X=1 cp " + bin,
		"sudo cp " + bin,
		"env cp " + bin,
		"command cp " + bin,
		"nohup cp " + bin,
		"echo $(cp " + bin + ")",
	}
	for _, cmd := range controls {
		if id, ok := matchesSelfProtectRule(cmd); !ok || id != "sp-block-binary-replace" {
			t.Fatalf("control %q = (%q, %v), want sp-block-binary-replace", cmd, id, ok)
		}
	}
	tps := []string{
		"X=1 'cp' " + bin,
		"X=1 \"cp\" " + bin,
		"sudo 'cp' " + bin,
		"env 'cp' " + bin,
		"command 'cp' " + bin,
		"nohup 'cp' " + bin,
		"echo $('cp' " + bin + ")",
		"echo `'cp' " + bin + "`",
		"A=1 B=2 sudo 'mv' " + bin,
		"true && X=1 'cp' " + bin,
		"sudo 'cp' /tmp/x /usr/local/bin/agentshi'e'ld",
		"'sudo' 'cp' " + bin,
	}
	for _, cmd := range tps {
		if id, ok := matchesSelfProtectRule(cmd); !ok || id != "sp-block-binary-replace" {
			t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want sp-block-binary-replace", cmd, id, ok)
		}
	}
	// Another rule behind the same shapes.
	if id, ok := matchesSelfProtectRule("X=1 'rm' ~/.claude/settings.json"); !ok || id != "sp-block-delete-hooks" {
		t.Errorf("quoted rm after assignment = (%q, %v)", id, ok)
	}

	// A quoted word that is an argument, not the command, is not folded, and
	// benign targets stay unmatched.
	tns := []string{
		"X=1 'cp' /tmp/x /tmp/y",
		"sudo 'cp' /tmp/x /tmp/y",
		"echo $('cp' /tmp/x /tmp/y)",
		"echo 'cp' /tmp/x /tmp/y",
		"ls 'cp' /tmp/x",
	}
	for _, cmd := range tns {
		if id, ok := matchesSelfProtectRule(cmd); ok {
			t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no match", cmd, id)
		}
	}
}
