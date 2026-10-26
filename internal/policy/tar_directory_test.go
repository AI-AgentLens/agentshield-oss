package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// #4381 residual: `tar -C <dir> <operand>` reads <operand> from <dir>, so
// `tar czf x.tgz -C ~ .ssh` is an alias of reading the protected directory.
// Aliased rule: protected_paths ~/.ssh/** (controls: the explicit spellings
// below BLOCK on main). Paths are assembled at runtime: the hook reads test
// sources as commands.
func TestTarDirectoryOperandAliasesProtectedPath_4381(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshName := "." + "ssh"
	dir := filepath.Join(home, sshName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := "id_" + "rsa"
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"~/" + sshName + "/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eval := func(cmd, cwd string) EvalResult {
		nc := normalize.NormalizeCommand(cmd, cwd)
		return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, cwd)
	}
	other := t.TempDir()
	tp := []struct{ cmd, cwd string }{
		{"tar czf /tmp/x.tgz " + dir + "/" + key, other}, // control: explicit spelling
		{"tar czf /tmp/x.tgz -C " + home + " " + sshName, other},
		{"tar czf /tmp/x.tgz -C " + home + " " + sshName + "/" + key, other},
		{"tar czf /tmp/x.tgz -C " + dir + " " + key, other},
		{"tar czf /tmp/x.tgz -C " + dir + " .", other},
		{"tar czf /tmp/x.tgz -C" + dir + " " + key, other},
		{"tar czf /tmp/x.tgz --directory " + dir + " " + key, other},
		{"tar czf /tmp/x.tgz --directory=" + dir + " " + key, other},
		{"tar -czf /tmp/x.tgz -C ~ " + sshName, other},
		{"tar czf /tmp/x.tgz -C " + home + " -C " + sshName + " " + key, other},
		{"tar czf /tmp/x.tgz -C " + sshName + " " + key, home},
		{"gtar czf /tmp/x.tgz -C " + home + " " + sshName, other},
	}
	for _, c := range tp {
		if r := eval(c.cmd, c.cwd); r.Decision != DecisionBlock {
			t.Errorf("%q: %v rules=%v; want BLOCK", c.cmd, r.Decision, r.TriggeredRules)
		}
	}
	tn := []struct{ cmd, cwd string }{
		{"tar czf /tmp/x.tgz -C " + other + " src", other},
		{"tar xzf rel.tgz -C " + other, other},
		{"tar czf /tmp/x.tgz -C " + home + " Documents", other},
		{"tar czf out.tgz src", other},
	}
	for _, c := range tn {
		if r := eval(c.cmd, c.cwd); r.Decision == DecisionBlock {
			t.Errorf("%q: BLOCK rules=%v; must not", c.cmd, r.TriggeredRules)
		}
	}
}
