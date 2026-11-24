package cli

import (
	"testing"
)

// TestManagedPlainRead_NewlineEndsTheRead_4840: on a managed host a bare
// read word, a newline and then a write of the managed config BLOCK through
// the Bash tool, as `cat; sed -i … <policy>` does. plainReadRe's `\s+`
// matched the newline, so both layers that exempt a plain read (the text
// rule sp-block-config-touch and the path layer protectManagedConfigDir)
// let the write through: AUDIT on main. The control: a plain read on one
// line still exits 0.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).
func TestManagedPlainRead_NewlineEndsTheRead_4840(t *testing.T) {
	cfg := "~/.agent" + "shield/policy.yaml"
	edit := "sed -i 's/BLOCK/AUDIT/' " + cfg
	rows := []struct {
		name string
		cmd  func(home string) string
		want int
	}{
		{"control: write alone", func(string) string { return edit }, 2},
		{"cat newline write", func(string) string { return "cat\n" + edit }, 2},
		{"wc newline write", func(string) string { return "wc\n" + edit }, 2},
		{"cat CRLF write", func(string) string { return "cat\r\n" + edit }, 2},
		{"ls newline truncate", func(home string) string {
			return "ls\ndd if=/dev/null of=" + home + "/.agent" + "shield/policy.yaml"
		}, 2},
		{"control: plain read", func(string) string { return "cat " + cfg }, 0},
		{"control: plain read after a blank line", func(string) string { return "\ncat " + cfg }, 0},
	}
	for _, r := range rows {
		for _, row := range []string{"claude-code Bash", "copilot native bash"} {
			t.Run(r.name+"/"+row, func(t *testing.T) {
				home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
				cmd := r.cmd(home)
				payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(cmd), nil)
				if row != "claude-code Bash" {
					payload = copilotNativePayload(t, "plainread", "bash", shellArgs(cmd))
				}
				code, _, stderr := runHookChild(t, home, payload)
				if code != r.want {
					t.Fatalf("%q exits %d, want %d. stderr:\n%s", cmd, code, r.want, stderr)
				}
				if r.want == 2 {
					if e := oneEvent(t, configDir); e.Decision != "BLOCK" {
						t.Errorf("event decision %q rules %v, want BLOCK", e.Decision, e.TriggeredRules)
					}
				}
			})
		}
	}
}
