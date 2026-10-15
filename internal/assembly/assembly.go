// Package assembly is the composition root for Shield's decision engines.
// Every surface that decides live agent actions builds its engine here: the
// shell hook, the hook's tool path, both MCP proxies and shield-server. That
// gives a cross-cutting feature (an org overlay, data labels; #4315) one place
// to be installed, so it cannot silently skip a surface. Data labels skipping
// the hook's tool path (#4318) is what that costs today.
//
// The package sits above the core. internal/archtest keeps the core from
// importing it, and checks that enforcing surfaces construct engines only
// through here.
package assembly

import (
	"os"

	"github.com/AI-AgentLens/agentshield/internal/execenv"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// ShellEngine builds the shell decision engine for a merged policy.
//
// mode is the enforcement mode. "audit-only" downgrades BLOCK and
// REQUIRE_APPROVAL to AUDIT inside the engine, so every caller gets the same
// behaviour without repeating the downgrade (#1952).
//
// The execution context is detected from this process's environment (#3291),
// so context-scoped rules (match.context.ci) tighten posture when the
// evaluating process runs inside a CI/CD runner.
func ShellEngine(pol *policy.Policy, maxParseDepth int, mode string) (*policy.Engine, error) {
	engine, err := policy.NewEngineWithAnalyzers(pol, maxParseDepth)
	if err != nil {
		return nil, err
	}
	engine.SetMode(mode)
	engine.SetExecContext(execenv.Detect(os.Getenv))
	return engine, nil
}

// MCPEvaluator builds the MCP tool-call evaluator for a merged MCP policy.
// mode is as for ShellEngine; "" means enforce.
func MCPEvaluator(pol *mcp.MCPPolicy, mode string) *mcp.PolicyEvaluator {
	evaluator := mcp.NewPolicyEvaluator(pol)
	evaluator.SetMode(mode)
	return evaluator
}
