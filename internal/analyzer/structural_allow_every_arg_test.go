package analyzer

import "testing"

// #4595: an ALLOW rule's args_any must hold for EVERY positional operand.
// With "at least one", `rm -rf /tmp/x /etc/y` earned the /tmp cleanup ALLOW
// from its /tmp operand and the structural-override tag dropped the regex
// BLOCK on the /etc operand. BLOCK/AUDIT rules and negated rules keep the
// plain "at least one" reading.
func TestStructuralRule_AllowArgsAnyHoldsForEveryOperand(t *testing.T) {
	allowTmp := StructuralRule{
		Executable: []string{"rm"}, FlagsAll: []string{"r", "f"},
		ArgsAny: []string{"/tmp/**"}, ArgsNone: []string{"/tmp"},
		Decision: "ALLOW",
	}
	blockSys := StructuralRule{
		Executable: []string{"rm"}, FlagsAll: []string{"r", "f"},
		ArgsAny:  []string{"/etc/**"},
		Decision: "BLOCK",
	}
	negated := allowTmp
	negated.Negate = true

	for _, tc := range []struct {
		name    string
		command string
		rule    StructuralRule
		want    bool
	}{
		{"allow: single temp operand", "rm -rf /tmp/zz-build", allowTmp, true},
		{"allow: every operand under temp", "rm -rf /tmp/zz-a /tmp/zz-b", allowTmp, true},
		{"allow: a system operand beside a temp one", "rm -rf /tmp/zz-a /etc/zz-marker", allowTmp, false},
		{"allow: the system operand first", "rm -r -f /etc/zz-marker /tmp/zz-a", allowTmp, false},
		{"allow: a relative operand beside a temp one", "rm -rf /tmp/zz-a ./zz-build", allowTmp, false},
		{"allow: no operand", "rm -rf", allowTmp, false},
		{"allow: args_none still applies", "rm -rf /tmp", allowTmp, false},
		{"block: one matching operand is enough", "rm -rf /tmp/zz-a /etc/zz-marker", blockSys, true},
		{"negated allow keeps the plain reading", "rm -rf /tmp/zz-a /etc/zz-marker", negated, false},
		{"negated allow, no temp operand", "rm -rf /etc/zz-marker", negated, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchStructuralRule(parseCommand(t, tc.command), tc.rule); got != tc.want {
				t.Errorf("MatchStructuralRule(%q, %s) = %v, want %v", tc.command, tc.rule.Decision, got, tc.want)
			}
		})
	}
}
