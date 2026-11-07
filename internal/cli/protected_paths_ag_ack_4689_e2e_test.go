package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4689, the ag and ack rows, through the real hook entry point. A customer
// pack protects an absolute <dir>/acme/**. On main `ag KEY <file>` BLOCKed
// protected-path while `ag -m 1 KEY <file>` and `ack -m 1 KEY <file>` decided
// AUDIT with no rule: the walk's universal -m text flag read the file as
// message text.
func TestHook_CustomerProtectedPath_AgAckMFlag_4689(t *testing.T) {
	// A short directory under /tmp: a long random temp segment in the command
	// text reads as a high-entropy secret to guardian (see #4676's test).
	dir, err := os.MkdirTemp("/tmp", "pp4689a-")
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
	for _, p := range []string{f, filepath.Join(dir, "README.md")} {
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
	if got := ppRun(t, home(t), bash("ag KEY "+f)); got.code != 2 || !got.hasRule(policy.ProtectedPathRuleID) {
		t.Fatalf("control ag KEY <file>: exit %d %v %v; want exit 2 protected-path (stderr %q)", got.code, got.decision, got.rules, got.stderr)
	}

	for _, cmd := range []string{
		"ag -m 1 KEY " + f,
		"ack -m 1 KEY " + f,
		"ack --match KEY -m 1 " + f,
	} {
		t.Run(cmd, func(t *testing.T) {
			got := ppRun(t, home(t), bash(cmd))
			if got.code != 2 || got.decision != "BLOCK" || !got.hasRule(policy.ProtectedPathRuleID) || !got.taxonomyIs(policy.ProtectedPathNode) {
				t.Fatalf("exit %d %v %v %v; want exit 2, BLOCK protected-path, [%s] (stderr %q)", got.code, got.decision, got.rules, got.taxonomy, policy.ProtectedPathNode, got.stderr)
			}
		})
	}

	// The protected path as the pattern is a search for its string.
	for _, cmd := range []string{
		"ag -m 1 " + f + " README.md",
		"ack -m 1 " + f + " README.md",
	} {
		got := ppRun(t, home(t), bash(cmd))
		if got.code == 2 || got.hasRule(policy.ProtectedPathRuleID) {
			t.Errorf("%q: exit %d %v %v; the protected path is the pattern, not a file", cmd, got.code, got.decision, got.rules)
		}
	}
}
