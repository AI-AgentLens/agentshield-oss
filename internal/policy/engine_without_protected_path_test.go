package policy

import (
	"slices"
	"testing"
)

// TestEngine_WithoutProtectedPath: the copy decides as the engine does except
// that the one pattern no longer protects anything; every other pattern
// still does, and the engine itself is unchanged. A pattern the list does not
// hold returns the engine itself. Paths are assembled at run time: the hook
// reads test sources it is asked to run as commands.
func TestEngine_WithoutProtectedPath(t *testing.T) {
	cfgFile := "~/.agent" + "shield/policy.yaml"
	key := "~/.s" + "sh/id_rsa"
	paths := []string{"~/.ssh/**", ManagedConfigProtectedPath, "~/.aws/**", ManagedConfigProtectedPath}
	e, err := NewEngine(&Policy{Version: "0.1", Defaults: Defaults{Decision: DecisionAudit, ProtectedPaths: slices.Clone(paths)}})
	if err != nil {
		t.Fatal(err)
	}

	c := e.WithoutProtectedPath(ManagedConfigProtectedPath)
	if c == e || c.Policy() == e.Policy() {
		t.Fatal("the copy shares the engine's policy value")
	}
	if want := []string{"~/.ssh/**", "~/.aws/**"}; !slices.Equal(c.Policy().Defaults.ProtectedPaths, want) {
		t.Errorf("copy's protected_paths %q, want %q (every entry of the pattern dropped)", c.Policy().Defaults.ProtectedPaths, want)
	}
	if !slices.Equal(e.Policy().Defaults.ProtectedPaths, paths) {
		t.Errorf("engine's protected_paths changed to %q", e.Policy().Defaults.ProtectedPaths)
	}

	r := e.Evaluate("cat "+cfgFile, []string{cfgFile})
	if r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
		t.Fatalf("control: the engine decides %s %v on the config file, want BLOCK by %s", r.Decision, r.TriggeredRules, ProtectedPathRuleID)
	}
	if r := c.Evaluate("cat "+cfgFile, []string{cfgFile}); r.Decision == DecisionBlock {
		t.Errorf("copy decides BLOCK %v on the config file, want the pattern gone", r.TriggeredRules)
	}
	for _, x := range []*Engine{e, c} {
		if r := x.Evaluate("cat "+key, []string{key}); r.Decision != DecisionBlock || !slices.Contains(r.TriggeredRules, ProtectedPathRuleID) {
			t.Errorf("the ssh key read decides %s %v, want BLOCK by %s on both engines", r.Decision, r.TriggeredRules, ProtectedPathRuleID)
		}
	}

	if c.WithoutProtectedPath(ManagedConfigProtectedPath) != c {
		t.Error("a pattern the list does not hold: want the engine itself")
	}
}
