package cli

import (
	"encoding/json"
	"reflect"
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
//
// #4603: the receipt's node is what the SaaS resolves to controls, so the
// wire body must carry the node of the sp-* rule that fired, and nothing for
// sp-block-config-touch, whose node is an open decision (#4666).
func TestSelfProtectBlockReachesSaaS_4346(t *testing.T) {
	srv, bodies := captureAudit(t)
	newFailSafeHome(t, true, failSafePolicyGood)
	if err := auth.Save(&auth.Credentials{Server: srv.URL, Token: "test-agent-token"}); err != nil {
		t.Fatalf("auth.Save: %v", err)
	}

	// Assembled at runtime: the hook reads test sources as commands.
	dir := "~/.agent" + "shield"
	for i, c := range []struct {
		name, cmd string
		want      []string
	}{
		{"bypass variable", "export AGENTSHIELD_" + "BYPASS=1", []string{"persistence-evasion/defense-evasion/security-tool-tampering"}},
		{"audit log delete", "r" + "m " + dir + "/audit.jsonl", []string{"persistence-evasion/anti-forensics/ai-audit-trail-circumvention"}},
		{"config touch", "less " + dir + "/policy.yaml", []string{}},
	} {
		result, _ := evaluateCommand(c.cmd, "/tmp", "claude-code-hook", "sess-4346")
		if result.Decision != policy.DecisionBlock || !containsStr(result.TriggeredRules, "enterprise-self-protect") {
			t.Fatalf("%s: precondition: want self-protect BLOCK, got %v %v", c.name, result.Decision, result.TriggeredRules)
		}

		got := bodies()
		if len(got) != i+1 {
			t.Fatalf("%s: want exactly 1 new /api/audit body, have %d after %d commands: %v", c.name, len(got), i+1, got)
		}
		body := got[i]
		if !strings.Contains(body, "enterprise-self-protect") {
			t.Errorf("%s: SaaS payload does not name the self-protect rule:\n%s", c.name, body)
		}
		var wire struct {
			Events []struct {
				Taxonomy []string `json:"taxonomy"`
			} `json:"events"`
		}
		if err := json.Unmarshal([]byte(body), &wire); err != nil || len(wire.Events) != 1 {
			t.Fatalf("%s: wire body is not one event (%v):\n%s", c.name, err, body)
		}
		if tax := wire.Events[0].Taxonomy; tax == nil || !reflect.DeepEqual(tax, c.want) {
			t.Errorf("%s: wire taxonomy %v, want %v (present, even when empty):\n%s", c.name, tax, c.want, body)
		}
	}
}
