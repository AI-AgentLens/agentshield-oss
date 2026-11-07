package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4689 through the real hook entry point. A customer pack protects an
// absolute <dir>/acme/**, and acme/notes.txt exists. On main `wc <file>`
// BLOCKed protected-path while `wc -m <file>` and `sort -m <file> <file>`
// decided ALLOW (ts-allow-readonly), and `less -m`, `pr -m` and
// `/usr/bin/grep -m 1 KEY <file>` AUDIT with no rule: the path walk's
// universal -m text flag read the file as message text, and a path-qualified
// grep had no grep spec.
func TestHook_CustomerProtectedPath_MFlagReaders_4689(t *testing.T) {
	// A short directory under /tmp: a long random temp segment in the command
	// text reads as a high-entropy secret to guardian (see #4676's test).
	dir, err := os.MkdirTemp("/tmp", "pp4689-")
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
	g := filepath.Join(acme, "other.txt")
	for _, p := range []string{f, g, filepath.Join(dir, "README.md")} {
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
	if got := ppRun(t, home(t), bash("wc "+f)); got.code != 2 || !got.hasRule(policy.ProtectedPathRuleID) {
		t.Fatalf("control wc <file>: exit %d %v %v; want exit 2 protected-path (stderr %q)", got.code, got.decision, got.rules, got.stderr)
	}

	for _, cmd := range []string{
		"wc -m " + f,
		"wc -lm " + f,
		"sort -m " + f + " " + g,
		"less -m " + f,
		"pr -m " + f + " " + g,
		"/usr/bin/grep -m 1 KEY " + f,
		"/usr/bin/grep -e KEY " + f,
	} {
		t.Run(cmd, func(t *testing.T) {
			got := ppRun(t, home(t), bash(cmd))
			if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(policy.ProtectedPathRuleID) || !got.taxonomyIs(policy.ProtectedPathNode) {
				t.Fatalf("exit %d %v %v %v; want exit 2, BLOCK protected-path, [%s] (stderr %q)", got.code, got.decision, got.rules, got.taxonomy, policy.ProtectedPathNode, got.stderr)
			}
		})
	}

	// A commit message is text, not a file; README.md is not protected.
	for _, cmd := range []string{
		`git commit -m "` + f + `"`,
		"wc -m README.md",
	} {
		got := ppRun(t, home(t), bash(cmd))
		if got.code == 2 || got.hasRule(policy.ProtectedPathRuleID) {
			t.Errorf("%q: exit %d %v %v; the protected path is not a file this command reads", cmd, got.code, got.decision, got.rules)
		}
	}
}
