package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An unreadable policy.yaml (here the single word Claude Code's Write tool left
// behind) used to make scan and check print the command's usage and the error
// twice, and never say what to do (#4739). The decision path is untouched: the
// hook still decides AUDIT agentshield-eval-error.
func TestUnreadablePolicy_ScanAndCheckNameTheFileAndSilenceUsage_4739(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(bad, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	for _, args := range [][]string{
		{"scan", "--policy", bad},
		{"check", "--shell", "ls", "--policy", bad},
	} {
		t.Run(args[0], func(t *testing.T) {
			var out bytes.Buffer
			rootCmd.SetOut(&out)
			rootCmd.SetErr(&out)
			rootCmd.SetArgs(args)
			t.Cleanup(func() {
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				rootCmd.SetArgs(nil)
				policyPath, checkShell, checkPolicyPath = "", "", ""
				scanCmd.SilenceUsage, scanCmd.SilenceErrors = false, false
				checkCmd.SilenceUsage, checkCmd.SilenceErrors = false, false
			})
			err := rootCmd.Execute()
			if err == nil {
				t.Fatal("an unreadable policy must be an error")
			}
			msg := err.Error()
			for _, want := range []string{bad, "not a valid AgentShield policy", "agentshield-eval-error", "delete it"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error lacks %q:\n%s", want, msg)
				}
			}
			if strings.Contains(out.String(), "Usage:") {
				t.Errorf("a runtime error printed usage:\n%s", out.String())
			}
			if strings.Contains(out.String(), "not a valid AgentShield policy") {
				t.Errorf("error printed by cobra as well as main (twice):\n%s", out.String())
			}
		})
	}
}
