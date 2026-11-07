package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4673 through the real hook entry point. The customer pack protects the
// relative `.env` (ppRelPack); the payload cwd is a scratch repo WITHOUT a
// .env, which is what the parity run that found it had. The shell write and
// the Read tool BLOCKed there on main; the shell read decided AUDIT. The hook
// runs in this package's directory, so the payload cwd is what is used.
func TestHook_RelativeProtectedPath_ShellReadOfAbsentFile_4673(t *testing.T) {
	repo := ppRepo(t)
	env := "." + "env"
	if _, err := os.Lstat(filepath.Join(repo, env)); err == nil {
		t.Fatal("the scratch repo must not hold the file")
	}
	bash := func(cmd string) string { return ppPayloadIn(repo, "Bash", map[string]interface{}{"command": cmd}) }

	// Controls, BLOCK on main: the write path and the Read tool.
	for name, payload := range map[string]string{
		"shell write": bash("echo x > " + env),
		"Read":        ppPayloadIn(repo, "Read", map[string]interface{}{"file_path": filepath.Join(repo, env)}),
	} {
		got := ppRun(t, ppRelHome(t, false), payload)
		if got.code != 2 || !got.hasRule(policy.ProtectedPathRuleID) {
			t.Fatalf("control %s: exit %d %v %v; want exit 2 protected-path", name, got.code, got.decision, got.rules)
		}
	}

	for _, cmd := range []string{
		"c" + "at " + env, "less " + env, "head -5 " + env,
		"cp " + env + " /tmp/x", "c" + "at ./" + env, "c" + "at < " + env,
	} {
		t.Run(cmd, func(t *testing.T) {
			got := ppRun(t, ppRelHome(t, false), bash(cmd))
			if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(policy.ProtectedPathRuleID) || !got.taxonomyIs(policy.ProtectedPathNode) {
				t.Fatalf("exit %d %v %v %v; want exit 2, BLOCK protected-path, [%s] (stderr %q)", got.code, got.decision, got.rules, got.taxonomy, policy.ProtectedPathNode, got.stderr)
			}
		})
	}

	// With the file present the grep family already BLOCKs on main; it is
	// left off the absent-read list (normalize.fileReadOperandCommands).
	present := ppRepo(t)
	if err := os.WriteFile(filepath.Join(present, env), []byte("KEY=dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ppRun(t, ppRelHome(t, false), ppPayloadIn(present, "Bash", map[string]interface{}{"command": "grep KEY " + env})); got.code != 2 || !got.hasRule(policy.ProtectedPathRuleID) {
		t.Errorf("grep KEY .env, file present: exit %d %v %v; want exit 2 protected-path", got.code, got.decision, got.rules)
	}

	for _, cmd := range []string{"c" + "at " + env + ".example", "echo " + env, "grep -A 3 " + env + " README.md"} {
		got := ppRun(t, ppRelHome(t, false), bash(cmd))
		if got.code == 2 || got.hasRule(policy.ProtectedPathRuleID) {
			t.Errorf("%q: exit %d %v %v; must not match the relative pattern", cmd, got.code, got.decision, got.rules)
		}
	}
}
