package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// #5001: the tool-call surfaces read disable_rules from the shell policy file,
// the list the shell engine skips rules by, and from nowhere else.
func TestLoadDeclaredToolCallInputs_DisableRulesFromThePolicyFileOnly5001(t *testing.T) {
	dir := t.TempDir()
	packs := filepath.Join(dir, "packs")
	if err := os.MkdirAll(packs, 0o700); err != nil {
		t.Fatal(err)
	}
	// A pack has no disable_rules key, so this one adds nothing, here as on
	// the shell (Pack drops the key, mergePackInto never sees it).
	if err := os.WriteFile(filepath.Join(packs, "co-x.yaml"), []byte("name: x\ndisable_rules: [from-a-pack]\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyFile, []byte("version: \"0.1\"\ndisable_rules: [rule-a, rule-b]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, _, err := LoadDeclaredToolCallInputs(policyFile, packs)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"rule-a", "rule-b"}; !reflect.DeepEqual(got.DisableRules, want) {
		t.Errorf("DisableRules %v, want %v", got.DisableRules, want)
	}
	// The list is the shell engine's own: what Load, LoadEmbeddedShellPacks
	// and LoadPacks leave for the pipeline (the hook's shell path).
	shell, err := Load(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	shell, _, _ = LoadEmbeddedShellPacks(shell)
	if shell, _, err = LoadPacks(packs, shell); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.DisableRules, shell.DisableRules) || !reflect.DeepEqual(shell.ForToolCalls().DisableRules, shell.DisableRules) {
		t.Errorf("tool-call list %v, shell engine's %v (ForToolCalls %v)", got.DisableRules, shell.DisableRules, shell.ForToolCalls().DisableRules)
	}

	// Absent file: nothing listed. Unparsable file: an error and nothing
	// listed, so a broken policy switches no tool-call rule off.
	if got, _, err := LoadDeclaredToolCallInputs(filepath.Join(dir, "absent.yaml"), ""); err != nil || len(got.DisableRules) != 0 {
		t.Errorf("absent policy file: %v %v", got.DisableRules, err)
	}
	if err := os.WriteFile(policyFile, []byte("disable_rules: [rule-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := LoadDeclaredToolCallInputs(policyFile, packs); err == nil || len(got.DisableRules) != 0 {
		t.Errorf("unparsable policy file: %v %v; want an error and no list", got.DisableRules, err)
	}
}

// ForToolCalls copies: changing what it returned does not change the policy.
func TestForToolCalls_Copies5001(t *testing.T) {
	p := &Policy{DisableRules: []string{"a"}, Defaults: Defaults{ProtectedPaths: []string{"/p/**"}}}
	in := p.ForToolCalls()
	in.DisableRules[0], in.ProtectedPaths[0] = "x", "x"
	if p.DisableRules[0] != "a" || p.Defaults.ProtectedPaths[0] != "/p/**" {
		t.Errorf("ForToolCalls aliased the policy's slices: %v %v", p.DisableRules, p.Defaults.ProtectedPaths)
	}
}
