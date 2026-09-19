package cli

import (
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// dropLocalDisablesWhenManaged removes `disable_rules:` from a user policy on
// a managed host and returns what it removed (#3620).
//
// disable_rules is the user's opt-out from baseline rules (policy/types.go).
// `agentshield rule disable` already refuses to write it in managed mode with
// the message "local disables are ignored" — but the runtime honored a
// hand-written one (pipeline.go and engine.go both skip disabled ids), so the
// refusal was cosmetic: any tool that could write policy.yaml could switch
// rules off. Measured on 2026-09-01: with the four rules that fire on
// `rm -rf /` listed, three were disabled and one structural rule still
// blocked — accidental defense in depth, not design.
//
// Call it on the user policy before packs merge in, so a premium pack's own
// disable_rules (a deliberate tier split between community and premium) are
// left alone. Returns nil when the host is not managed or nothing was set.
// managedConfigProtectedPath is the glob added to protected_paths on a managed
// host for every command that is not a plain read (#3620, path layer).
const managedConfigProtectedPath = "~/.agentshield/**"

// protectManagedConfigDir adds the config directory to the policy's
// protected_paths on a managed host, unless cmd is a plain read-only statement
// (enterprise.IsPlainConfigRead — the same shape the text rule exempts, so the
// two layers agree). protected_paths is checked against both the normalizer's
// argv paths and the substitution analyzer's materialized paths, which is what
// lets a variable-indirected or interpreter-embedded write be caught when its
// text names the directory nowhere. Returns true when the glob was added.
func protectManagedConfigDir(pol *policy.Policy, cfg *config.Config, cmd string) bool {
	if pol == nil || cfg == nil || cfg.Managed == nil || !cfg.Managed.Managed {
		return false
	}
	if enterprise.IsPlainConfigRead(cmd) {
		return false
	}
	for _, p := range pol.Defaults.ProtectedPaths {
		if p == managedConfigProtectedPath {
			return true
		}
	}
	pol.Defaults.ProtectedPaths = append(pol.Defaults.ProtectedPaths, managedConfigProtectedPath)
	return true
}

func dropLocalDisablesWhenManaged(pol *policy.Policy, cfg *config.Config) []string {
	if pol == nil || cfg == nil || cfg.Managed == nil || !cfg.Managed.Managed {
		return nil
	}
	if len(pol.DisableRules) == 0 {
		return nil
	}
	dropped := pol.DisableRules
	pol.DisableRules = nil
	return dropped
}
