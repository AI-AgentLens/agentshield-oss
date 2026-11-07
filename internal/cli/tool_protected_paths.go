package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// shellProtectedPathsFor returns the protected_paths the shell hook enforces
// on this machine (cfg's policy file and its packs directory, the files the
// shell path loads), for a tool-call surface to hand to assembly.MCPEvaluator
// (#4645). The hook's tool path, mcp-eval and both MCP proxies use it, so all
// of them apply the same customer patterns.
//
// warnings name a layer that could not be read. The hook's tool path counts
// them as a degraded ruleset, as the shell path counts a pack that fails to
// parse: under managed fail_closed that blocks, elsewhere it is said out loud.
// cfg nil (config.Load failed) returns nothing: the caller already reports
// that failure.
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

func shellProtectedPathsFor(cfg *config.Config) (paths []string, warnings []string) {
	if cfg == nil {
		return nil, nil
	}
	paths, infos, err := policy.LoadDeclaredProtectedPaths(cfg.PolicyPath, filepath.Join(cfg.ConfigDir, "packs"))
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("shell policy protected_paths could not be fully read (%v); tool calls are checked against what loaded", err))
	}
	for _, fp := range policy.FailedPacks(infos) {
		warnings = append(warnings, fmt.Sprintf("pack %s failed to parse (%v); its protected_paths are not applied to tool calls", fp.Path, fp.LoadError))
	}
	return paths, warnings
}
