package analyzer

import (
	"slices"
	"testing"
)

// The scope walk reaches a `-c` carrier behind an exec wrapper, and a decode
// the outer shell folds inside a double-quoted carrier operand (#4925). The
// decision and the rule id are pinned end to end in
// internal/policy/carrier_substitution_4925_test.go.
func TestSubstitutionScope_WrappedAndDoubleQuotedCarriers4925(t *testing.T) {
	decode := "cat $(echo " + encodedSSHKeyB64 + " | base64 -d)"
	reached := []struct{ name, cmd string }{
		{"bash -c sq (control)", "bash -c '" + decode + "'"},
		{"sudo bash -c", "sudo bash -c '" + decode + "'"},
		{"env bash -c", "env bash -c '" + decode + "'"},
		{"sudo -u root sh -c", "sudo -u root sh -c '" + decode + "'"},
		{"sudo su -c", "sudo su -c '" + decode + "'"},
		{"bash -c dq", `bash -c "` + decode + `"`},
		{"sudo bash -c dq", `sudo bash -c "` + decode + `"`},
		{"eval dq", `eval "` + decode + `"`},
		// The decode is in eval's second argument, so its span must move by
		// the length of the first one and the joining space.
		{"eval dq, second argument", `eval "echo aaaaaaaaaaaaaaaaaaaaaaaa;" "` + decode + `"`},
		{"man -P dq", `man -P "` + decode + `" ls`},
		{"man --pager= dq", `man --pager="` + decode + `" ls`},
		{"watch -n 1 dq", `watch -n 1 "` + decode + `"`},
	}
	for _, tc := range reached {
		t.Run(tc.name, func(t *testing.T) {
			if got := runSubstitution(t, tc.cmd); !slices.Contains(got, expectedSSHKey) {
				t.Errorf("materialized %v from %s, want %s among them", got, tc.cmd, expectedSSHKey)
			}
		})
	}

	notReached := []struct{ name, cmd string }{
		{"sudo eval", "sudo eval '" + decode + "'"},
		{"sudo ./bash -c", "sudo ./bash -c '" + decode + "'"},
		{"sudo grep -c", "sudo grep -c '" + decode + "' notes.txt"},
		{"echo in dq body", `bash -c "echo $(echo ` + encodedSSHKeyB64 + ` | base64 -d)"`},
		{"man -M dq", `man -M "` + decode + `" ls`},
		// Only decode folds are marked; $HOME is the ssh rule's, as on main.
		{"HOME in dq body", `bash -c "cat $HOME/.ssh/id_rsa"`},
		// Accepted gap, pinned so closing it is deliberate: osascript's shell
		// source is a string inside AppleScript, so the body is not one of
		// argv's words and sourceArgDecoded maps no span onto it. Same on
		// main; the single-quoted twin is reached since #4903.
		{"gap: osascript dq", `osascript -e "do shell script \"` + decode + `\""`},
	}
	for _, tc := range notReached {
		t.Run("not/"+tc.name, func(t *testing.T) {
			if got := runSubstitution(t, tc.cmd); slices.Contains(got, expectedSSHKey) {
				t.Errorf("materialized %v from %s; want %s absent", got, tc.cmd, expectedSSHKey)
			}
		})
	}
}
