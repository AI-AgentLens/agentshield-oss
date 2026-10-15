package cli

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4333: a self-protect BLOCK returned before the audit logger opened and every
// caller discarded the event, so the tamper attempt was recorded nowhere.
func TestSelfProtectBlockIsRecordedInAuditChain_4333(t *testing.T) {
	_, configDir := newFailSafeHome(t, true, failSafePolicyGood)

	// Assembled at runtime: the hook reads test sources as commands.
	cmd := "export AGENTSHIELD_" + "BYPASS=1"
	result, _ := evaluateCommand(cmd, "/tmp", "claude-code-hook", "sess-4333")

	if result.Decision != policy.DecisionBlock || !containsStr(result.TriggeredRules, "enterprise-self-protect") {
		t.Fatalf("precondition: want self-protect BLOCK, got %v %v", result.Decision, result.TriggeredRules)
	}
	log := readFailSafeAuditLog(t, configDir)
	if n := strings.Count(log, "enterprise-self-protect"); n != 1 {
		t.Fatalf("audit.jsonl has %d self-protect lines, want exactly 1:\n%s", n, log)
	}
	if strings.Count(strings.TrimSpace(log), "\n") != 0 {
		t.Errorf("want exactly one line in the log:\n%s", log)
	}
	if v := logger.VerifyChain(configDir + "/audit.jsonl"); !v.Protected() {
		t.Errorf("chain not verified after self-protect record: %+v", v)
	}
}

// #4346: the SaaS leg of #4333. Deleting sendRemoteAudit from
// recordSelfProtectBlock left the local-chain test above green, so the receipt
// for a tamper attempt could stop reaching the evidence plane unnoticed.
func TestSelfProtectBlockReachesSaaS_4346(t *testing.T) {
	srv, bodies := captureAudit(t)
	newFailSafeHome(t, true, failSafePolicyGood)
	if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"}); err != nil {
		t.Fatalf("auth.Save: %v", err)
	}

	// Assembled at runtime: the hook reads test sources as commands.
	cmd := "export AGENTSHIELD_" + "BYPASS=1"
	result, _ := evaluateCommand(cmd, "/tmp", "claude-code-hook", "sess-4346")
	if result.Decision != policy.DecisionBlock || !containsStr(result.TriggeredRules, "enterprise-self-protect") {
		t.Fatalf("precondition: want self-protect BLOCK, got %v %v", result.Decision, result.TriggeredRules)
	}

	got := bodies()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 /api/audit body, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "enterprise-self-protect") {
		t.Errorf("SaaS payload does not name the self-protect rule:\n%s", got[0])
	}
}
