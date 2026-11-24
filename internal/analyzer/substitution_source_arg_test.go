package analyzer

import (
	"slices"
	"testing"
)

// The scope walk reads a shell-source carrier's operand as a child-shell body,
// the way it reads `bash -c`'s (#4903). These pin the layer itself; the
// decision and the rule id are pinned end to end in
// internal/policy/source_arg_substitution_test.go.
func TestSubstitutionScope_SourceArgCarrierBodies(t *testing.T) {
	decode := "cat $(echo " + encodedSSHKeyB64 + " | base64 -d)"
	reached := []struct{ name, cmd string }{
		{"bash -c (control)", "bash -c '" + decode + "'"},
		{"env -S", "env -S '" + decode + "'"},
		{"man -P", "man -P '" + decode + "' ls"},
		{"osascript", `osascript -e 'do shell script "` + decode + `"'`},
		{"sudo man -P", "sudo man -P '" + decode + "' ls"},
		{"watch positional", "watch -n 1 '" + decode + "'"},
		{"prefix binding seen by the child", "B=" + encodedSSHKeyB64 + " man -P 'cat $(echo $B | base64 -d)' ls"},
		{"unresolvable operand elsewhere", "man -P '" + decode + "' \"$(date)\""},
	}
	for _, tc := range reached {
		t.Run(tc.name, func(t *testing.T) {
			if got := runSubstitution(t, tc.cmd); !slices.Contains(got, expectedSSHKey) {
				t.Errorf("materialized %v from %s, want %s among them", got, tc.cmd, expectedSSHKey)
			}
		})
	}

	notReached := []struct{ name, cmd string }{
		// A child shell does not see an unexported binding.
		{"unexported binding", "B=" + encodedSSHKeyB64 + "; man -P 'cat $(echo $B | base64 -d)' ls"},
		// -M is a manpath, not shell source.
		{"non-source flag", "man -M '" + decode + "' ls"},
		// The table, not a guess: grep's -e value is a pattern.
		{"not a carrier", "grep -e '" + decode + "' notes.txt"},
		{"relative ./man", "./man -P '" + decode + "' ls"},
		{"osascript dialog string", `osascript -e 'display dialog "` + decode + `"'`},
	}
	for _, tc := range notReached {
		t.Run("not/"+tc.name, func(t *testing.T) {
			if got := runSubstitution(t, tc.cmd); slices.Contains(got, expectedSSHKey) {
				t.Errorf("materialized %v from %s; the command opens no protected file", got, tc.cmd)
			}
		})
	}
}
