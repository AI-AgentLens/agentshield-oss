package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// #5023: `tar … -C ~ <dir>` lost its protected-path BLOCK on every Windows host.
// The `~` was replaced by the resolved home and then passed through expandPath,
// whose StripShellQuotes deletes every `\`. So C:\Users\x became the relative
// C:Usersx, joined under the cwd, and `.ssh` no longer resolved into the home.
//
// A Windows home always contains a backslash. On macOS and Linux a backslash is
// an ordinary filename character, so this test fakes that shape with a home
// directory whose name contains one. That lets non-Windows CI pin the Windows
// behaviour. The Windows job skips internal/policy (#5021, #5022).
//
// Controls: the explicit spellings BLOCK both before and after the fix. Paths
// are assembled at runtime because the hook reads test sources as commands.
func TestTarDirectoryTildeWithBackslashHome_5023(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "Users"+`\`+"x")
	sshName := "." + "ssh"
	dir := filepath.Join(home, sshName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	testhome.Set(t, home)
	key := "id_" + "rsa"
	pol := DefaultPolicy()
	pol.Defaults.ProtectedPaths = []string{"~/" + sshName + "/**"}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	other := t.TempDir()
	eval := func(cmd string) EvalResult {
		nc := normalize.NormalizeCommand(cmd, other)
		return engine.EvaluateWithParsedCwd(cmd, nc.Paths, nc.Parsed, other)
	}
	for _, cmd := range []string{
		"tar -czf /tmp/x.tgz -C ~ " + sshName,            // the #5023 row
		"tar czf /tmp/x.tgz -C ~ " + sshName + "/" + key, // same, deeper operand
		"tar czf /tmp/x.tgz --directory ~ " + sshName,    // long-flag spelling
		"tar czf /tmp/x.tgz -C ~/" + sshName + " " + key, // control
		"tar czf /tmp/x.tgz ~/" + sshName,                // control
		"cat ~/" + sshName + "/" + key,                   // control
	} {
		if r := eval(cmd); r.Decision != DecisionBlock {
			t.Errorf("%q: %v rules=%v; want BLOCK", cmd, r.Decision, r.TriggeredRules)
		}
	}
	for _, cmd := range []string{
		"tar czf /tmp/x.tgz -C ~ Documents",
		"tar czf out.tgz src",
	} {
		if r := eval(cmd); r.Decision == DecisionBlock {
			t.Errorf("%q: BLOCK rules=%v; must not", cmd, r.TriggeredRules)
		}
	}
}
