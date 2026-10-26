package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4381: a bare key name with cwd inside the protected directory is an alias
// of `<dir>/<key>`. Control: the ./ spelling and the ~-relative spelling
// BLOCK on main; the bare spelling decided ALLOW. Paths are assembled at
// runtime: the hook reads test sources as commands.
func TestBareOperandInProtectedCwdBlocks_4381(t *testing.T) {
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
	for _, cmd := range []string{"cat ./" + key, "cat " + key, "head -n 1 " + key, "cp " + key + " /tmp/x"} {
		if r := eval(cmd, dir); r.Decision != DecisionBlock {
			t.Errorf("%q cwd=protected: %v rules=%v; want BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	// Same bare name from an unprotected cwd stays as before.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, key), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := eval("cat "+key, other); r.Decision == DecisionBlock {
		t.Errorf("unprotected cwd: %v rules=%v; must not BLOCK", r.Decision, r.TriggeredRules)
	}
	// Ordinary words in the protected cwd do not become paths.
	if r := eval("ssh myhost", dir); r.Decision == DecisionBlock {
		t.Errorf("ssh myhost: %v rules=%v; must not BLOCK", r.Decision, r.TriggeredRules)
	}
}

// #4381 residual: a bare name that does not exist yet (create-write from
// inside the protected directory) is the same alias as `./name`, for commands
// that take a file operand. Words that are not files stay words.
func TestBareNewNameInProtectedCwdBlocks_4381(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "."+"ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
	key := "id_" + "rsa"
	// control: the ./ spelling of the same create-write BLOCKs on main
	if r := eval("touch ./"+key, dir); r.Decision != DecisionBlock {
		t.Fatalf("control touch ./%s: %v; want BLOCK", key, r.Decision)
	}
	for _, cmd := range []string{"touch " + key, "tee " + key, "cp /tmp/x " + key, "mv /tmp/x " + key} {
		if r := eval(cmd, dir); r.Decision != DecisionBlock {
			t.Errorf("%q: %v rules=%v; want BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	for _, cmd := range []string{"ssh myhost", "git status", "cat nosuchfile", "echo " + key} {
		if r := eval(cmd, dir); r.Decision == DecisionBlock {
			t.Errorf("%q: %v rules=%v; must not BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	// the same new name from an unprotected cwd is untouched
	if r := eval("touch "+key, t.TempDir()); r.Decision == DecisionBlock {
		t.Errorf("unprotected cwd: %v; must not BLOCK", r.Decision)
	}
}
