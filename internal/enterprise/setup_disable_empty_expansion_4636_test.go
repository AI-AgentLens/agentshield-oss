package enterprise

import "testing"

// #4636: an unquoted empty expansion in command position is dropped by bash
// and zsh, so the next word runs. The argv walk read `$zqx` as the executable
// and never reached agentshield.
func TestSetupDisable_EmptyExpansionInCommandPosition_4636(t *testing.T) {
	const disable = "agentshield --mode enforce setup mcp --disable"
	for _, tc := range []struct {
		name, cmd string
		want      bool
	}{
		{"control", disable, true},
		{"dollar name", "$zqx " + disable, true},
		{"braced name", "${zqx} " + disable, true},
		{"two expansions", "$zqx ${zqy} " + disable, true},
		{"expansion before quoted agentshield", "$zqx 'agentshield' setup mcp --disable", true},
		{"expansion before path", "$zqx /usr/local/bin/agentshield setup mcp --disable", true},
		{"after separator", "true && $zqx " + disable, true},
		// Quoted: bash tries to run a command named "" and fails; nothing runs.
		{"quoted expansion", `"$zqx" ` + disable, false},
		// TNs: the peeled word must still be followed by agentshield + setup + --disable.
		{"expansion then status", "$zqx agentshield status", false},
		{"expansion then setup without disable", "$zqx agentshield setup mcp", false},
		{"expansion then other program", "$zqx echo agentshield setup --disable", false},
		{"expansion only", "$zqx", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, got := matchesSelfProtectRule(tc.cmd)
			if got != tc.want {
				t.Fatalf("matchesSelfProtectRule(%q) = (%q, %v), want matched=%v", tc.cmd, id, got, tc.want)
			}
			if got && id != "sp-block-setup-disable" {
				t.Fatalf("rule id = %q, want sp-block-setup-disable", id)
			}
		})
	}
}
