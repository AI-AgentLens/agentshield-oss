package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4676 through the real hook entry point. A customer pack protects an
// absolute <dir>/acme/**, and acme/notes.txt exists. On main `grep KEY
// <file>` BLOCKed protected-path while `grep -e KEY <file>` decided ALLOW
// (ts-allow-readonly) and `rg -e KEY <file>` AUDIT: when an option supplies
// the pattern, the path walk dropped the file operand.
func TestHook_CustomerProtectedPath_GrepPatternOption_4676(t *testing.T) {
	// A short directory under /tmp: a long random temp segment in the command
	// text reads as a high-entropy secret to guardian, a second reason to
	// block that would hide what this test measures.
	dir, err := os.MkdirTemp("/tmp", "pp4676-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		t.Fatal(err)
	}
	acme := filepath.Join(dir, "acme")
	if err := os.MkdirAll(acme, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(acme, "notes.txt")
	for _, p := range []string{f, filepath.Join(dir, "pats"), filepath.Join(dir, "README.md")} {
		if err := os.WriteFile(p, []byte("KEY=dummy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pack := "name: Acme Absolute\ndescription: An absolute customer path\nversion: 1.0.0\nauthor: Acme Security\n" +
		"defaults:\n  protected_paths:\n  - " + acme + "/**\nrules: []\n"
	home := func(t *testing.T) string {
		h := proxyHome(t, "mode: enforce\n")
		packs := filepath.Join(h, ".agentshield", "packs")
		if err := os.MkdirAll(packs, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(packs, "co-acme-abs.yaml"), []byte(pack), 0o600); err != nil {
			t.Fatal(err)
		}
		return h
	}
	bash := func(cmd string) string { return ppPayloadIn(dir, "Bash", map[string]interface{}{"command": cmd}) }

	// Control, BLOCK on main.
	if got := ppRun(t, home(t), bash("grep KEY "+f)); got.code != 2 || !got.hasRule(policy.ProtectedPathRuleID) {
		t.Fatalf("control grep KEY <file>: exit %d %v %v; want exit 2 protected-path (stderr %q)", got.code, got.decision, got.rules, got.stderr)
	}

	for _, cmd := range []string{
		"grep -e KEY " + f,
		"grep -e KEY -n " + f,
		"grep --regexp=KEY " + f,
		"grep -e A -e B " + f,
		"grep -f pats " + f,
		"rg -e KEY " + f,
		"grep -rn -e KEY " + acme,
	} {
		t.Run(cmd, func(t *testing.T) {
			got := ppRun(t, home(t), bash(cmd))
			if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(policy.ProtectedPathRuleID) || !got.taxonomyIs(policy.ProtectedPathNode) {
				t.Fatalf("exit %d %v %v %v; want exit 2, BLOCK protected-path, [%s] (stderr %q)", got.code, got.decision, got.rules, got.taxonomy, policy.ProtectedPathNode, got.stderr)
			}
		})
	}

	// The protected path as the -e value is pattern text; a needle with no
	// file operand reads nothing.
	for _, cmd := range []string{"grep -e " + f + " README.md", "grep -e KEY README.md", "echo x | grep -e KEY"} {
		got := ppRun(t, home(t), bash(cmd))
		if got.code == 2 || got.hasRule(policy.ProtectedPathRuleID) {
			t.Errorf("%q: exit %d %v %v; the protected path is not a file this command reads", cmd, got.code, got.decision, got.rules)
		}
	}
}
