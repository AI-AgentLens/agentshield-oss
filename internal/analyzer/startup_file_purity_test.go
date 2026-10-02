package analyzer_test

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestDocTextDowngradeWithheldOnStartupFileWrite pins #4039: a BLOCK rule
// carrying the is_doc_text/in_heredoc downgrade must NOT drop to AUDIT when
// its own TP text is written into a shell/session startup file that a shell
// sources on its own. Before the shellparse.CommandLineIsPure fix, only
// `.git/hooks/` and `.husky/` voided the exemption — every other deferred-
// execution target (`.zshenv`, `.bashrc`, `/etc/profile.d/*`, `/etc/cron.d/`,
// ...) stayed "pure," so the write was treated as inert documentation even
// though the next shell invocation, login or cron tick runs it for real.
//
// Reproduces the issue's own measured shape (`ts-block-syslog-daemon-stop`,
// one of the 5 of 12 sampled rules that downgraded instead of BLOCKing).
func TestDocTextDowngradeWithheldOnStartupFileWrite(t *testing.T) {
	engine := newPipelineEngine(t)

	const payload = "systemctl stop rsyslog"
	cases := []struct {
		name string
		cmd  string
	}{
		{"append via echo into .zshenv", `echo "` + payload + `" >> ~/.zshenv`},
		{"append via echo into .bashrc through $HOME", `echo "` + payload + `" >> $HOME/.bashrc`},
		{"heredoc into .bash_profile", "cat >> ~/.bash_profile <<'EOF'\n" + payload + "\nEOF"},
		{"tee into .zprofile", `echo "` + payload + `" | tee -a ~/.zprofile`},
		{"append into /etc/profile.d", `echo "` + payload + `" >> /etc/profile.d/evil.sh`},
		{"append into /etc/cron.d", `echo "` + payload + `" >> /etc/cron.d/evil`},
	}
	for _, c := range cases {
		got := engine.Evaluate(c.cmd, nil)
		if got.Decision != policy.DecisionBlock {
			t.Errorf("%s: %q decided %s (rules=%v), want BLOCK — the is_doc_text/in_heredoc downgrade must be withheld on a write into an autorun startup file",
				c.name, c.cmd, got.Decision, got.TriggeredRules)
		}
	}

	// Control: the identical text written to an ordinary, non-autorun file
	// keeps its downgrade to AUDIT — this asserts the fix is scoped to the
	// enumerable autorun-path list, not a blanket revert of the is_doc_text
	// exemption for every write.
	control := `echo "` + payload + `" >> /tmp/notes.md`
	got := engine.Evaluate(control, nil)
	if got.Decision != policy.DecisionAudit {
		t.Errorf("control %q decided %s (rules=%v), want AUDIT — an ordinary file write must keep the doc-text downgrade",
			control, got.Decision, got.TriggeredRules)
	}
}
