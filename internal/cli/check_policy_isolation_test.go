package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// writePack writes a minimal shell pack and returns its path.
func writePack(t *testing.T, dir, name, ruleID, regex, decision string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: \"0.1\"\nrules:\n" +
		"- id: " + ruleID + "\n" +
		"  taxonomy: reconnaissance/host/test-only\n" +
		"  match:\n" +
		"    command_regex: " + regex + "\n" +
		"  decision: " + decision + "\n" +
		"  confidence: 0.99\n" +
		"  reason: isolation fixture\n" +
		"  tests:\n" +
		"    tp:\n" +
		"    - zzisolationprobe\n" +
		"    tn:\n" +
		"    - echo hi\n"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Issue #3030: `check --policy <file>` used to merge ~/.agentshield/packs on top
// of the named file, so a stale deployed copy of a rule silently supplied the
// verdict. A rule author would fix a regex, rebuild, run check against their
// file, and see the OLD behaviour with no indication why.
//
// The deployed pack here BLOCKs the probe token; the explicitly-named policy
// does not mention it. If deployed packs still shadow, the probe comes back
// BLOCK.
func TestCheckPolicyOverride_NotShadowedByDeployedPacks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgDir := filepath.Join(home, ".agentshield")
	writePack(t, filepath.Join(cfgDir, "packs"), "deployed.yaml",
		"zz-deployed-shadow", "zzisolationprobe", "BLOCK")

	// The policy the user explicitly names — deliberately says nothing about the probe.
	userPolicy := writePack(t, filepath.Join(home, "work"), "mine.yaml",
		"zz-user-rule", "zzsomethingelse", "BLOCK")

	got, err := evaluateShellCommand("zzisolationprobe", userPolicy)
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	for _, r := range got.TriggeredRules {
		if r == "zz-deployed-shadow" {
			t.Fatalf("deployed pack shadowed the explicit --policy file (#3030): triggered=%v", got.TriggeredRules)
		}
	}
}

// The converse must still hold: with NO --policy, deployed packs are part of the
// picture, because that mirrors what the runtime hook actually enforces. Fixing
// #3030 must not turn `check` into a tool that ignores installed premium packs.
func TestCheckWithoutPolicyOverride_StillLoadsDeployedPacks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfgDir := filepath.Join(home, ".agentshield")
	writePack(t, filepath.Join(cfgDir, "packs"), "deployed.yaml",
		"zz-deployed-active", "zzisolationprobe", "BLOCK")
	// A base policy must exist for the no-override path to resolve.
	writePack(t, cfgDir, "policy.yaml", "zz-base-rule", "zzsomethingelse", "BLOCK")

	got, err := evaluateShellCommand("zzisolationprobe", "")
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	var found bool
	for _, r := range got.TriggeredRules {
		if r == "zz-deployed-active" {
			found = true
		}
	}
	if !found {
		t.Fatalf("deployed pack was NOT loaded without --policy — check no longer mirrors the hook: triggered=%v", got.TriggeredRules)
	}
}
