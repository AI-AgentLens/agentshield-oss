package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The error-to-decision boundary (#3619).
//
// evaluateCommand can fail before it reaches a verdict: config unreadable,
// audit log unwritable, policy unparseable, a pack dropped, the engine
// refusing to build (an unknown intent label, say). Each of those used to be
// handled at its own site — three became a BLOCK under managed fail_closed,
// two returned a plain error, and every harness handler turned an error into
// `return nil // fail open`. Reproduced on 2026-09-01: with managed.json
// {"managed":true,"fail_closed":true} and one typo'd command_intent_exclude
// label in policy.yaml, `rm -rf /` exited 0 with a warning and no audit event.
//
// failSafeDecision is the single place a failure becomes a decision, so there
// is exactly one answer to "what happens when evaluation cannot run" and every
// dialect inherits it:
//
//   - managed fail_closed → BLOCK, rule id enterprise-fail-closed, the error
//     in the reason and on the event;
//   - otherwise → the fail-safe default, AUDIT (the command runs), with a
//     flagged event carrying the error so the failure is visible in the audit
//     log and on the SaaS — never a silent allow.
//
// The event is written when a logger exists (it does not for config-load and
// audit-log-init failures) and always forwarded to the SaaS.

const (
	// failClosedRuleID is the sentinel rule id on a BLOCK produced by the
	// boundary under managed fail_closed.
	failClosedRuleID = "enterprise-fail-closed"
	// evalErrorRuleID is the sentinel rule id on the AUDIT produced by the
	// boundary outside managed fail_closed.
	evalErrorRuleID = "agentshield-eval-error"
)

// eventLogger is the slice of the audit logger the boundary needs.
type eventLogger interface {
	Log(event logger.AuditEvent) error
}

// evalFailure describes where evaluation stopped. cfg is nil when config
// itself failed to load; log is nil when no audit logger could be opened.
type evalFailure struct {
	stage string
	err   error
	cfg   *config.Config
	log   eventLogger
}

// failClosedEnabled reports whether managed fail-closed mode is on. It
// prefers the loaded config (one definition of "managed" — see
// internal/policy/remediation) and falls back to reading managed.json
// directly when config itself could not be loaded, so a config-load failure
// cannot switch the guarantee off.
func failClosedEnabled(cfg *config.Config) bool {
	if cfg != nil && cfg.Managed != nil {
		return cfg.Managed.FailClosed
	}
	if m := enterprise.LoadManagedConfig(); m != nil {
		return m.FailClosed
	}
	return false
}

// mcpRulesetDegraded describes why the MCP ruleset about to be evaluated is
// not the one configured, or "" when it is. Every source is a real failure:
// config unreadable, an MCP policy file that exists but does not parse, a
// packs directory that exists but cannot be read, a pack that failed to parse.
// An ABSENT policy file or packs directory is not degraded — the loaders
// return the embedded defaults for those without a warning.
func mcpRulesetDegraded(cfgErr error, loaded *loadedMCPPolicy) string {
	var parts []string
	if cfgErr != nil {
		parts = append(parts, "config load: "+cfgErr.Error())
	}
	if loaded != nil {
		parts = append(parts, loaded.Warnings...)
		for _, infos := range [][]mcp.MCPPackInfo{loaded.Embedded, loaded.Disk, loaded.LegacyDisk} {
			for _, fp := range mcp.FailedMCPPacks(infos) {
				parts = append(parts, fmt.Sprintf("pack %s failed to parse: %v", fp.Path, fp.LoadError))
			}
		}
	}
	return strings.Join(parts, "; ")
}

// hookInputFailure is the boundary for failures that happen before there is a
// command to evaluate: stdin unreadable, or not the JSON a harness sends. The
// dialect is unknown at that point, so a BLOCK is signalled the one way every
// harness understands — a message on stderr and exit code 2 — and an allow is
// a plain return with the warning. No audit logger exists yet either; the
// event still goes to the SaaS through sendRemoteAudit.
func hookInputFailure(stage string, err error) error {
	res, _ := failSafeDecision(evalFailure{stage: stage, err: err}, "<unparseable hook input>", "", "hook", "")
	if res.Decision == policy.DecisionBlock {
		fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED this command\n   Reason: %s\n", res.Explanation)
		os.Exit(2)
	}
	return nil
}

// failSafeDecision converts an evaluation failure into the decision every
// harness handler acts on. See the package comment above for the contract.
func failSafeDecision(f evalFailure, cmdStr, cwd, source, sessionID string) (*policy.EvalResult, *logger.AuditEvent) {
	failClosed := failClosedEnabled(f.cfg)

	var result policy.EvalResult
	if failClosed {
		reason := fmt.Sprintf("AgentShield: %s failed — blocking (fail_closed enabled): %v", f.stage, f.err)
		result = policy.EvalResult{
			Decision:       policy.DecisionBlock,
			TriggeredRules: []string{failClosedRuleID},
			Reasons:        []string{reason},
			Explanation:    reason,
		}
	} else {
		reason := fmt.Sprintf("AgentShield: %s failed — evaluated as AUDIT (fail-safe default, not enforced): %v", f.stage, f.err)
		result = policy.EvalResult{
			Decision:       policy.DecisionAudit,
			TriggeredRules: []string{evalErrorRuleID},
			Reasons:        []string{reason},
			Explanation:    reason,
		}
	}
	fmt.Fprintf(os.Stderr, "[AgentShield] warning: %s\n", result.Explanation)

	modeStr := ""
	if f.cfg != nil {
		modeStr = f.cfg.Mode
	}
	if failClosed {
		modeStr = "managed"
	}
	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Command:        cmdStr,
		Args:           strings.Fields(cmdStr),
		Cwd:            cwd,
		Decision:       string(result.Decision),
		Flagged:        true,
		TriggeredRules: result.TriggeredRules,
		Reasons:        result.Reasons,
		Mode:           modeStr,
		Source:         source,
		SessionID:      sessionID,
		Principal:      osPrincipal(),
		Error:          f.err.Error(),
	}
	if f.log != nil {
		if err := f.log.Log(event); err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield] warning: audit log failed: %v\n", err)
		}
	}
	sendRemoteAudit(&event)

	return &result, &event
}
