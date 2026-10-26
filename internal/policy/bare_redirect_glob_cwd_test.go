package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4403 (#4381 class): with cwd inside the protected directory, a bare
// redirect target and a slash-less glob operand are aliases of the `./` and
// absolute spellings, which BLOCK. Each row asserts its control first. Paths
// are assembled at runtime: the hook reads test sources as commands.
func TestBareRedirectAndGlobInProtectedCwdBlocks_4403(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "."+"ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := "id_" + "rsa"
	if err := os.WriteFile(filepath.Join(dir, key), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"~/." + "ssh/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eval := func(cmd, cwd string) EvalResult {
		nc := normalize.NormalizeCommand(cmd, cwd)
		return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
	}
	for _, control := range []string{"cat < ./" + key, "cat ~/." + "ssh/id_*"} {
		if r := eval(control, dir); r.Decision != DecisionBlock {
			t.Fatalf("control %q: %v; want BLOCK", control, r.Decision)
		}
	}
	for _, cmd := range []string{
		"cat < " + key,
		"head -1 < " + key,
		"cat id_*",
		"cat id_r?a",
		"cat 'id_'*",
	} {
		if r := eval(cmd, dir); r.Decision != DecisionBlock {
			t.Errorf("%q cwd=protected: %v rules=%v; want BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	// A glob that matches nothing, descriptor redirects and output redirects to
	// an unprotected cwd stay as before.
	for _, cmd := range []string{"cat nomatch_*", "cat notes.txt 2>&1", "ls 2>/dev/null"} {
		if r := eval(cmd, dir); r.Decision == DecisionBlock {
			t.Errorf("%q cwd=protected: %v rules=%v; must not BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, key), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"cat < " + key, "cat id_*"} {
		if r := eval(cmd, other); r.Decision == DecisionBlock {
			t.Errorf("%q unprotected cwd: %v rules=%v; must not BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
}
