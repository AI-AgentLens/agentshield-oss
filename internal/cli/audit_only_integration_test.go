package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestAuditOnly_EndToEnd_PolicyYamlFlipsEngineMode is the load-bearing
// integration test for AgentShield issue #1952 — it walks the full chain
// the deep-dive caught was broken before PR #1984:
//
//  1. The SaaS pushes a policy.yaml with a top-level `enforcement_mode:`
//     field via /api/policy/yaml (aiagentlens rulepush.go:138).
//  2. AgentShield's enterprise sync writes it to ~/.agentshield/policy.yaml.
//  3. config.Load() reads the mode out of policy.yaml as resolution rung 3
//     (below CLI flag and ~/.agentshield/agentshield.yaml).
//  4. policy.Load() parses the same file into the Policy struct and
//     surfaces EnforcementMode.
//  5. The engine's SetMode(cfg.Mode) is called.
//  6. A command that matches a BLOCK rule is evaluated.
//  7. The engine downgrades BLOCK → AUDIT and records OriginalDecision.
//
// Before PR #1984: step 3 returned "" (Policy struct had no field, config
// didn't read policy.yaml). The whole flow degraded to enforce. This test
// would have caught the bug — keep it forever so future refactors that
// re-break any link in the chain fail loudly here.
func TestAuditOnly_EndToEnd_PolicyYamlFlipsEngineMode(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Simulate the policy.yaml the enterprise sync would write — a real
	// production payload would include many rules, but for the contract
	// test one BLOCK rule plus the enforcement_mode field is sufficient.
	policyYAML := `version: "0.1"
enforcement_mode: "audit-only"

defaults:
  decision: "AUDIT"
  log_redaction: true

rules:
  - id: e2e-block-telnet
    match:
      command_prefix:
        - "telnet "
    decision: "BLOCK"
    reason: "Plaintext telnet detected — supply-chain integrity rule."
`
	policyPath := filepath.Join(configDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile policy.yaml: %v", err)
	}

	// Step 1: config.Load must resolve Mode from policy.yaml's
	// enforcement_mode field (rung 3 of the resolution chain).
	cfg, err := config.Load("", "", "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Mode != config.ModeAuditOnly {
		t.Fatalf("config.Load Mode = %q; want %q "+
			"(the SaaS-pushed policy.yaml enforcement_mode is not being "+
			"read — this is the exact bug PR #1984 fixed; check that "+
			"config.go's loadPolicyEnforcementMode is on the path)",
			cfg.Mode, config.ModeAuditOnly)
	}

	// Step 2: policy.Load must surface EnforcementMode on the Policy struct
	// so callers that have the Policy without re-loading config can still
	// see the field.
	pol, err := policy.Load(policyPath)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	if pol.EnforcementMode != "audit-only" {
		t.Errorf("policy.Load EnforcementMode = %q; want %q "+
			"(Policy struct field was missing before PR #1984)",
			pol.EnforcementMode, "audit-only")
	}

	// Step 3: build the engine and apply the mode. This is the call site
	// hook.go uses at line 272 — `engine.SetMode(cfg.Mode)`.
	engine, err := policy.NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	engine.SetMode(cfg.Mode)

	// Step 4: evaluate a known-BLOCK command. Without audit-only mode the
	// engine returns Decision=BLOCK, OriginalDecision="". With audit-only
	// the engine downgrades and records OriginalDecision=BLOCK.
	cmd := "telnet legacy-router.lan 23"
	cmdArgs := strings.Fields(cmd)
	normalized := normalize.Normalize(cmdArgs, "")
	result := engine.EvaluateWithParsed(cmd, normalized.Paths, normalized.Parsed)

	if result.Decision != policy.DecisionAudit {
		t.Errorf("end-to-end decision = %v; want AUDIT (the BLOCK rule "+
			"should have been downgraded by audit-only mode). If this is "+
			"BLOCK, the engine isn't receiving the mode — check that "+
			"SetMode was wired into the actual evaluation path.",
			result.Decision)
	}
	if result.OriginalDecision != policy.DecisionBlock {
		t.Errorf("end-to-end OriginalDecision = %q; want BLOCK (the SaaS "+
			"dashboard reads this as the would-have-blocked signal — if "+
			"empty, downstream telemetry can't distinguish real blocks "+
			"from shadow-blocks)", result.OriginalDecision)
	}
	if !contains(result.TriggeredRules, "e2e-block-telnet") {
		t.Errorf("end-to-end TriggeredRules = %v; want to include "+
			"e2e-block-telnet (the rule must still fire — audit-only "+
			"hides the action, not the rule attribution)", result.TriggeredRules)
	}
}

// TestAuditOnly_EndToEnd_LocalConfigOverridesSaasPush is the precedence
// guarantee: a local ~/.agentshield/agentshield.yaml `mode: enforce` MUST
// override a SaaS-pushed `enforcement_mode: audit-only` in policy.yaml.
// Without this, an operator who needs to break-glass back to enforce can't
// do so until the SaaS toggle is flipped — which is the wrong direction of
// trust for a security tool.
func TestAuditOnly_EndToEnd_LocalConfigOverridesSaasPush(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// SaaS pushes audit-only
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"),
		[]byte(`version: "0.1"
enforcement_mode: "audit-only"

rules:
  - id: e2e-block-rm-root
    match:
      command_regex: "^rm\\s+-rf\\s+/"
    decision: "BLOCK"
    reason: "Destructive remove at filesystem root."
`), 0o600); err != nil {
		t.Fatalf("WriteFile policy.yaml: %v", err)
	}

	// Operator local override: enforce
	if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"),
		[]byte("mode: enforce\n"), 0o600); err != nil {
		t.Fatalf("WriteFile agentshield.yaml: %v", err)
	}

	cfg, err := config.Load("", "", "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Mode != config.ModeEnforce {
		t.Fatalf("local agentshield.yaml must win over SaaS-pushed policy.yaml: "+
			"got Mode=%q, want %q (precedence rung 2 > rung 3)",
			cfg.Mode, config.ModeEnforce)
	}

	pol, err := policy.Load(filepath.Join(configDir, "policy.yaml"))
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	engine, err := policy.NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	engine.SetMode(cfg.Mode)

	cmd := "rm -rf /tmp/abandoned"
	cmdArgs := strings.Fields(cmd)
	normalized := normalize.Normalize(cmdArgs, "")
	result := engine.EvaluateWithParsed(cmd, normalized.Paths, normalized.Parsed)

	if result.Decision != policy.DecisionBlock {
		t.Errorf("local enforce override failed: Decision = %v; want BLOCK "+
			"(if AUDIT, the operator's break-glass to enforce isn't working — "+
			"that's the wrong direction of trust for a security tool)",
			result.Decision)
	}
	if result.OriginalDecision != "" {
		t.Errorf("enforce mode must NOT carry OriginalDecision; got %q",
			result.OriginalDecision)
	}
}

// contains is a small helper kept local to this file to avoid coupling to
// other test files that may rename or remove their version.
func contains(slice []string, needle string) bool {
	for _, s := range slice {
		if s == needle {
			return true
		}
	}
	return false
}
