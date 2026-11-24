package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// The audit-only keep-BLOCK raise on PowerShell rows (ADR-001 D4, the #4753
// Opus pass 1 finding). In audit-only mode a lane's ordinary BLOCK arrives as
// AUDIT[was BLOCK], while a self-protection BLOCK is never downgraded. When
// the two tie on the pre-downgrade rank, the call BLOCKs, and its receipt
// must name the rule that actually blocked, not the downgraded one of the
// lane that happened to come first.

// TestPowerShellLane_KeptBlockReceiptNamesTheBlockingRule: Copilot's native
// powershell row (POSIX, then PowerShell) on a managed host in audit-only
// mode. The POSIX lane reads an mkfs (ts-block-mkfs); the PowerShell lane
// reads a write to the policy file in its Windows spelling
// (enterprise-self-protect, kept). The call BLOCKs, and the receipt leads
// with enterprise-self-protect, the rule the BLOCK stands on, not the mkfs
// rule audit-only mode lowers everywhere else.
//
// Which lane's record is kept depends on the OS (#5089). Off Windows the
// POSIX lane's keep does not read the Windows spelling, so its BLOCK is
// lowered and the PowerShell lane's kept BLOCK wins the tie (block kept). On
// Windows it does (#5064), so both lanes keep their BLOCK, they tie, and row
// order keeps the POSIX lane's record. That record led with ts-block-mkfs on
// main, and since #5089 leads with the keep's reason, ts-block-mkfs after it.
func TestPowerShellLane_KeptBlockReceiptNamesTheBlockingRule(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte("mode: audit-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := "mkfs." + "ext4 /dev/sda1; Remove-Item " + policyFileWindowsSpelling()
	code, _, stderr := runHookChild(t, home, copilotNativePayload(t, "kb", "powershell", shellArgs(cmd)))
	if code != 2 {
		t.Fatalf("exit %d, want 2 (the self-protection BLOCK is kept in audit-only mode). stderr:\n%s", code, stderr)
	}
	e := oneEvent(t, configDir)
	n := laneReadingsNotes(e.Notes)
	if len(n) != 1 || !strings.Contains(n[0], "powershell=BLOCK(enterprise-self-protect)") {
		t.Fatalf("control: %s %q; want the PowerShell lane's kept BLOCK", analyzer.NoteLaneReadings, n)
	}
	if e.Decision != "BLOCK" || len(e.TriggeredRules) == 0 || e.TriggeredRules[0] != policy.SelfProtectRuleID {
		t.Errorf("event decision=%q rules=%v; want BLOCK led by %s, the rule the BLOCK stands on", e.Decision, e.TriggeredRules, policy.SelfProtectRuleID)
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(n[0], "posix=BLOCK("+policy.SelfProtectRuleID+")") || !strings.Contains(n[0], "kept=posix") {
			t.Errorf("%s %q; want the POSIX lane's kept BLOCK, led by %s, kept on row order", analyzer.NoteLaneReadings, n, policy.SelfProtectRuleID)
		}
		if len(e.Reasons) == 0 || !strings.HasPrefix(e.Reasons[0], policy.SelfProtectKeptReasonPrefix) || !containsStr(e.TriggeredRules, "ts-block-mkfs") {
			t.Errorf("event rules=%v reasons=%q; want the keep's reason first and ts-block-mkfs after it", e.TriggeredRules, e.Reasons)
		}
	} else {
		if !strings.Contains(n[0], "posix=AUDIT[was BLOCK](ts-block-mkfs)") || !strings.Contains(n[0], "kept=powershell") {
			t.Errorf("%s %q; want POSIX's downgraded BLOCK and the PowerShell lane's record kept", analyzer.NoteLaneReadings, n)
		}
		if containsStr(e.TriggeredRules, "ts-block-mkfs") {
			t.Errorf("event rules=%v; want the PowerShell lane's record, not the downgraded ts-block-mkfs", e.TriggeredRules)
		}
	}
	if !strings.Contains(stderr, policy.SelfProtectRuleID) {
		t.Errorf("stderr names %q; want the rule that blocked", stderr)
	}
}

// TestPSLane_NestedKeptBlockNamesTheBlockingRule: the same raise inside the
// lane. The text's own protected-path BLOCK is downgraded by audit-only mode;
// a nested `bash -c` that disables AgentShield is blocked by the managed
// middleware, which is never downgraded. The lane's result must carry the
// middleware's rule.
func TestPSLane_NestedKeptBlockNamesTheBlockingRule(t *testing.T) {
	newFailSafeHome(t, true, "")
	pol := &policy.Policy{Version: "0.1", Defaults: policy.Defaults{Decision: policy.DecisionAudit, ProtectedPaths: []string{"~/.ssh/**"}}}
	pol, _, err := policy.LoadEmbeddedShellPacks(pol)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := assembly.ShellEngine(pol, 2, "audit-only")
	if err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")
	l := &psLane{engine: engine, env: psreader.Env{Home: home}, opts: policy.FactsOptions{Home: home},
		cwd: home, source: "claude-code-hook", maxDepth: 2}

	own := l.read("Get-Content " + sshKeyPath())
	if own.Decision != policy.DecisionAudit || own.OriginalDecision != policy.DecisionBlock {
		t.Fatalf("control: the key read alone decides %s[was %s], want AUDIT[was BLOCK] in audit-only mode", own.Decision, own.OriginalDecision)
	}

	r := l.read("Get-Content " + sshKeyPath() + "; bash -c 'agentshield setup claude-code " + "--disable'")
	if r.Decision != policy.DecisionBlock || !containsStr(r.TriggeredRules, "enterprise-self-protect") || containsStr(r.TriggeredRules, policy.ProtectedPathRuleID) {
		t.Errorf("decision %s rules %v; want BLOCK naming enterprise-self-protect, not the downgraded %s", r.Decision, r.TriggeredRules, policy.ProtectedPathRuleID)
	}
}
