package enterprise

import (
	"strings"
	"testing"
)

// `setup claude-code --remove-managed` takes AgentShield's hook out of Claude
// Code's managed settings, so sp-block-setup-disable reads it exactly as it
// reads --disable: same decision and rule, in the regex reading and the argv
// reading alike (the #4649 additive exception, more spellings of one family).
// The echo row is matched by the regex reading alone, so it pins that half.
func TestSelfProtect_RemoveManagedReadsLikeDisable(t *testing.T) {
	templates := []string{
		"agentshield setup claude-code FLAG",
		"sudo agentshield setup claude-code FLAG",
		"env X=1 /opt/homebrew/bin/agentshield setup claude-code FLAG",
		"echo 'agentshield setup claude-code FLAG'",
		"bash -c 'agentshield setup claude-code FLAG'",
		"agentshield setup FLAG claude-code",
		"agentshield FLAG setup claude-code",
		"agentshield setup claude-code FLAG=true",
		"agentshield setup claude-code FLAG=false",
		"agentshield setup claude-code -- FLAG",
		"agentshield status FLAG",
		"grep -n -- FLAG README.md",
	}
	matched := 0
	for _, tmpl := range templates {
		disable := strings.ReplaceAll(tmpl, "FLAG", "--disable")
		remove := strings.ReplaceAll(tmpl, "FLAG", "--remove-managed")
		wantID, wantOK := matchesSelfProtectRule(disable)
		gotID, gotOK := matchesSelfProtectRule(remove)
		if gotOK != wantOK || gotID != wantID {
			t.Errorf("%q = (%q, %v); its --disable twin %q = (%q, %v)", remove, gotID, gotOK, disable, wantID, wantOK)
		}
		if wantOK {
			matched++
		}
	}
	// Both outcomes must be represented, or the parity proves nothing.
	if matched < 6 || matched == len(templates) {
		t.Fatalf("%d of %d --disable twins matched; the table needs matches and non-matches", matched, len(templates))
	}
}
