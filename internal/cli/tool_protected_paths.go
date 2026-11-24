package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// toolCallWorkDir is the directory a hook tool call's file-path arguments are
// resolved against (#4653): evalCwd, the payload cwd payloadEvalCwd accepted,
// or this process's directory when it accepted none, the same fallback
// evaluateCommand applies to a shell command.
func toolCallWorkDir(evalCwd string) string {
	if evalCwd != "" {
		return evalCwd
	}
	wd, _ := os.Getwd()
	return wd
}

// localDisables says what a tool-call surface does with a managed host's
// local disable_rules: what its shell side does (#5001). Each caller names
// one, so a new surface has to decide rather than inherit.
type localDisables int

const (
	// managedIgnoresLocalDisables: the hook's shell path drops the user
	// file's list on a managed host (dropLocalDisablesWhenManaged, #3620).
	// The hook's tool path mirrors it, and so do both MCP proxies: they have
	// no shell lane, and the hook is the shell side of the same host.
	managedIgnoresLocalDisables localDisables = iota
	// managedKeepsLocalDisables: `agentshield check` reads the list on a
	// managed host too (loadCheckPolicy has no managed check), so mcp-eval,
	// its tool-call twin, does as well. Mirrored, not fixed (#5001).
	managedKeepsLocalDisables
)

// toolCallShellPolicy returns what the shell policy enforced on this machine
// (cfg's policy file and its packs directory, the files the shell path loads)
// says about tool calls, for a tool-call surface to hand to
// assembly.MCPEvaluator: the protected_paths (#4645) and the disable_rules
// (#5001). The hook's tool path, mcp-eval and both MCP proxies use it, so all
// of them apply the same customer patterns and the same list; local says what
// a managed host's list counts for on the caller's surface.
//
// warnings name a layer that could not be read. The hook's tool path counts
// them as a degraded ruleset, as the shell path counts a pack that fails to
// parse: under managed fail_closed that blocks, elsewhere it is said out loud.
// cfg nil (config.Load failed) returns nothing, so no rule is switched off:
// the caller already reports that failure.
func toolCallShellPolicy(cfg *config.Config, local localDisables) (in policy.ToolCallInputs, warnings []string) {
	if cfg == nil {
		return policy.ToolCallInputs{}, nil
	}
	in, infos, err := policy.LoadDeclaredToolCallInputs(cfg.PolicyPath, filepath.Join(cfg.ConfigDir, "packs"))
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("shell policy protected_paths could not be fully read (%v); tool calls are checked against what loaded", err))
	}
	for _, fp := range policy.FailedPacks(infos) {
		warnings = append(warnings, fmt.Sprintf("pack %s failed to parse (%v); its protected_paths are not applied to tool calls", fp.Path, fp.LoadError))
	}
	if local == managedIgnoresLocalDisables {
		// The shell path's own predicate, on the same list, so the two
		// cannot disagree about what a managed host is.
		user := &policy.Policy{DisableRules: in.DisableRules}
		dropLocalDisablesWhenManaged(user, cfg)
		in.DisableRules = user.DisableRules
	}
	return in, warnings
}
