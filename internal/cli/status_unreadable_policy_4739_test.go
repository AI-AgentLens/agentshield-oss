package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// status used to show a tick for a policy.yaml the hook cannot read (#4739
// item 3). It now names the file and what the hook does instead.
func TestStatusShellPolicy_UnreadableFileIsReported_4739(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(bad, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { checkShellPolicyFile(bad) })
	for _, want := range []string{bad, "not a valid AgentShield policy", "agentshield-eval-error", "delete it"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "✅") {
		t.Errorf("an unreadable policy got a tick:\n%s", out)
	}
}

func TestStatusShellPolicy_ValidAndAbsentUnchanged_4739(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(good, []byte("version: \"0.1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := captureStdout(t, func() { checkShellPolicyFile(good) }); !strings.Contains(out, "✅ Shell policy: "+good) {
		t.Errorf("valid policy lost its tick:\n%s", out)
	}
	if out := captureStdout(t, func() { checkShellPolicyFile(filepath.Join(dir, "nope.yaml")) }); !strings.Contains(out, "built-in defaults") {
		t.Errorf("absent policy changed:\n%s", out)
	}
	if out := captureStdout(t, func() { checkShellPolicyFile("") }); !strings.Contains(out, "built-in defaults") {
		t.Errorf("empty path changed:\n%s", out)
	}
}
