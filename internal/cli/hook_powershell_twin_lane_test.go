package cli

import (
	"os"
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// The cmdlet bridge's twin reading on a managed host (psLane.readTwin). The
// lane is read in-process, so each reading of a twin text is seen alone,
// without the lane's own reading, which BLOCKs every write to the config
// directory first and hides what the twin decides. Attack strings and paths
// are assembled at run time: the hook reads test sources as commands.

// managedTestCfg is a config whose host is managed, as protectManagedConfigDir
// and readTwin read it.
func managedTestCfg() *config.Config {
	return &config.Config{Managed: &config.ManagedConfig{Managed: true}}
}

// twinTestLane is the hook's PowerShell lane on a managed host's engine for a
// PowerShell call: the embedded packs, a policy whose default is AUDIT, and
// the config directory's pattern, which protectManagedConfigDir adds because
// no PowerShell text is a plain read. cmd is the call's text. cfg is the
// lane's config (nil: no config).
func twinTestLane(t *testing.T, cmd string, cfg *config.Config) *psLane {
	t.Helper()
	newFailSafeHome(t, true, "")
	pol := &policy.Policy{Version: "0.1", Defaults: policy.Defaults{Decision: policy.DecisionAudit}}
	if !protectManagedConfigDir(pol, managedTestCfg(), cmd) {
		t.Fatalf("control: protectManagedConfigDir did not protect the config directory for %q", cmd)
	}
	return testLaneOn(t, pol, cfg)
}

// bashToolEngineLane is the same lane on the engine the Bash tool builds for
// cmd on a managed host: the config directory's pattern only when cmd is not
// a plain read.
func bashToolEngineLane(t *testing.T, cmd string) *psLane {
	t.Helper()
	pol := &policy.Policy{Version: "0.1", Defaults: policy.Defaults{Decision: policy.DecisionAudit}}
	protectManagedConfigDir(pol, managedTestCfg(), cmd)
	return testLaneOn(t, pol, managedTestCfg())
}

func testLaneOn(t *testing.T, pol *policy.Policy, cfg *config.Config) *psLane {
	t.Helper()
	pol, _, err := policy.LoadEmbeddedShellPacks(pol)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := assembly.ShellEngine(pol, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")
	return &psLane{engine: engine, cfg: cfg, env: psreader.Env{Home: home}, opts: policy.FactsOptions{Managed: true, Home: home},
		cwd: home, source: "claude-code-hook", maxDepth: 2}
}

func sameReading(a, b policy.EvalResult) bool {
	return a.Decision == b.Decision && slices.Equal(a.TriggeredRules, b.TriggeredRules)
}

// TestPSLane_TwinOfAPlainReadReadsAsTheBashTool: on a managed host the twin
// of a known read (`Get-Content <policy>` is `cat ~/.agentshield/policy.yaml`)
// decides exactly what the Bash tool decides for that command, where the
// nested reading (readPOSIX, on the PowerShell call's engine) BLOCKs it by
// protected-path. A plain read of a credential file outside the directory
// still BLOCKs through the twin.
func TestPSLane_TwinOfAPlainReadReadsAsTheBashTool(t *testing.T) {
	policyRead := "cat ~/.agent" + "shield/policy.yaml"
	l := twinTestLane(t, "Get-Content ~\\.agent"+"shield\\policy.yaml", managedTestCfg())

	nested := l.readPOSIX(policyRead)
	if nested.Decision != policy.DecisionBlock || !slices.Contains(nested.TriggeredRules, policy.ProtectedPathRuleID) {
		t.Fatalf("control: the nested reading decides %s %v, want BLOCK by %s", nested.Decision, nested.TriggeredRules, policy.ProtectedPathRuleID)
	}
	bash := bashToolEngineLane(t, policyRead).readPOSIX(policyRead)
	if bash.Decision == policy.DecisionBlock {
		t.Fatalf("control: the Bash tool's engine BLOCKs %v the plain read", bash.TriggeredRules)
	}
	if twin := l.readTwin(policyRead); !sameReading(twin, bash) {
		t.Errorf("twin decides %s %v, want the Bash tool's %s %v", twin.Decision, twin.TriggeredRules, bash.Decision, bash.TriggeredRules)
	}

	keyRead := "cat " + sshKeyPath()
	if twin := l.readTwin(keyRead); twin.Decision != policy.DecisionBlock || !slices.Contains(twin.TriggeredRules, policy.ProtectedPathRuleID) {
		t.Errorf("twin of a key read decides %s %v, want BLOCK by %s", twin.Decision, twin.TriggeredRules, policy.ProtectedPathRuleID)
	}
}

// TestPSLane_TwinOfAWriteIsTheNestedReading: a twin text that is anything
// but one plain read is read exactly as before (readPOSIX), so every config
// write, delete, move and copy keeps the config directory's pattern, and so
// does a plain read beside a harmless second statement, as the Bash tool
// reads `cat <policy>; rm x`. The first row is one only the pattern BLOCKs
// in the twin: the middleware's text rules do not name notes.txt.
func TestPSLane_TwinOfAWriteIsTheNestedReading(t *testing.T) {
	d := "~/.agent" + "shield/"
	rm := "r" + "m "
	texts := []string{
		"echo x > " + d + "notes.txt",
		"echo x >> " + d + "notes.txt",
		"echo x > " + d + "policy.yaml",
		rm + d + "policy.yaml",
		"cp " + d + "policy.yaml C:/tmp/y",
		"cp C:/tmp/y " + d + "policy.yaml",
		"mv " + d + "policy.yaml C:/tmp/y",
		"mv C:/tmp/y " + d + "policy.yaml",
		"cat " + d + "policy.yaml\n" + rm + "./x",
	}
	l := twinTestLane(t, "Set-Content ~\\.agent"+"shield\\notes.txt 'x'", managedTestCfg())
	for _, text := range texts {
		nested, twin := l.readPOSIX(text), l.readTwin(text)
		if nested.Decision != policy.DecisionBlock {
			t.Errorf("control: the nested reading of %q decides %s %v, want BLOCK", text, nested.Decision, nested.TriggeredRules)
		}
		if !sameReading(twin, nested) {
			t.Errorf("twin of %q decides %s %v, want the nested reading's %s %v", text, twin.Decision, twin.TriggeredRules, nested.Decision, nested.TriggeredRules)
		}
	}
	// The pattern is what BLOCKs the first row: without it the twin would
	// decide below BLOCK, so the row above can see the exception misapplied.
	plain := *l
	plain.engine = l.engine.WithoutProtectedPath(policy.ManagedConfigProtectedPath)
	if r := plain.readPOSIX(texts[0]); r.Decision == policy.DecisionBlock {
		t.Errorf("control: %q BLOCKs %v without the pattern, so the first row cannot see the exception misapplied", texts[0], r.TriggeredRules)
	}
	// The Bash tool keeps the pattern for a plain read beside a second
	// statement, which is why the last row is read with it.
	if bash := bashToolEngineLane(t, texts[len(texts)-1]).readPOSIX(texts[len(texts)-1]); bash.Decision != policy.DecisionBlock {
		t.Errorf("control: the Bash tool decides %s %v on a plain read beside a second statement, want BLOCK", bash.Decision, bash.TriggeredRules)
	}
}

// TestPSLane_TwinOffAManagedHostIsTheNestedReading: where the config is not
// managed, the twin is the nested reading, even of a plain read and even when
// the engine protects the config directory (a policy that lists the pattern
// itself), as the Bash tool's engine then keeps it too.
func TestPSLane_TwinOffAManagedHostIsTheNestedReading(t *testing.T) {
	policyRead := "cat ~/.agent" + "shield/policy.yaml"
	for name, cfg := range map[string]*config.Config{"no config": nil, "not managed": {Managed: &config.ManagedConfig{}}, "no managed.json": {}} {
		t.Run(name, func(t *testing.T) {
			l := twinTestLane(t, "Get-Content x", cfg)
			nested, twin := l.readPOSIX(policyRead), l.readTwin(policyRead)
			if nested.Decision != policy.DecisionBlock {
				t.Fatalf("control: the nested reading decides %s %v, want BLOCK", nested.Decision, nested.TriggeredRules)
			}
			if !sameReading(twin, nested) {
				t.Errorf("twin decides %s %v, want the nested reading's %s %v", twin.Decision, twin.TriggeredRules, nested.Decision, nested.TriggeredRules)
			}
		})
	}
}
