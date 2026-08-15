package policy

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads a user policy file and layers it on top of DefaultPolicy.
//
// Layering (rather than replacement) is what fixes #1641: before this change,
// the loader returned only the parsed user file when one existed, which meant
// that the moment `agentshield rule disable` wrote a minimal `disable_rules:`
// stanza, the hardcoded baseline rules (block-rm-root, block-pipe-to-shell,
// audit-package-installs, audit-file-edits, allow-safe-readonly), the default
// protected paths (~/.ssh/**, ~/.aws/**, ...), and the allow_domains list all
// silently disappeared from the merged policy. Embedded community packs still
// loaded on top so security wasn't compromised, but rule IDs drifted in a
// confusing way (block-rm-root → ts-block-rm-root).
//
// The merge semantics here intentionally favor safety:
//   - Defaults (decision, non_interactive): user value wins when set
//   - Defaults.LogRedaction: cannot be silently turned off (true OR'd with user)
//   - Defaults.ProtectedPaths: union (defense-in-depth — user can ADD but not REMOVE)
//   - Network.AllowDomains: union (same reason)
//   - Rules: appended after baseline (user rules run after, so user ALLOW/BLOCK
//     overrides baseline AUDIT via most-restrictive-wins; user BLOCK over baseline
//     ALLOW also wins)
//   - DataLabels: appended
//   - DisableRules: appended (user can opt out of any baseline rule by ID — the
//     intended way to "remove" a default)
//
// Users who want to remove a baseline default protected path or allow domain
// don't have a knob today; that's a deliberate floor. If a real customer asks
// for it, we add an explicit `override:` block then.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return nil, err
	}

	var user Policy
	if err := yaml.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return mergeUserOverDefaults(DefaultPolicy(), &user), nil
}

// mergeUserOverDefaults layers a user-authored policy on top of the hardcoded
// baseline. See Load for the merge semantics rationale.
func mergeUserOverDefaults(base, user *Policy) *Policy {
	merged := clonePolicy(base)

	if user.Version != "" {
		merged.Version = user.Version
	}

	if user.Defaults.Decision != "" {
		merged.Defaults.Decision = user.Defaults.Decision
	}
	if user.Defaults.NonInteractive != "" {
		merged.Defaults.NonInteractive = user.Defaults.NonInteractive
	}
	// LogRedaction is OR'd: once a baseline says "redact logs," a user file
	// cannot silently turn it off. If the user actively wants verbose logs they
	merged.Defaults.LogRedaction = merged.Defaults.LogRedaction || user.Defaults.LogRedaction

	merged.Defaults.ProtectedPaths = unionStrings(merged.Defaults.ProtectedPaths, user.Defaults.ProtectedPaths)
	merged.Network.AllowDomains = unionStrings(merged.Network.AllowDomains, user.Network.AllowDomains)

	merged.Rules = append(merged.Rules, user.Rules...)
	merged.DataLabels = append(merged.DataLabels, user.DataLabels...)
	merged.DisableRules = unionStrings(merged.DisableRules, user.DisableRules)

	// EnforcementMode: user value wins when set. Empty = "no opinion from
	// this layer," which lets config.Load fall through to its next
	// resolution rung (the local default). This is the SaaS-pushed value
	// from /api/policy/yaml. Issue #1952.
	if user.EnforcementMode != "" {
		merged.EnforcementMode = user.EnforcementMode
	}

	return merged
}

func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	out := a
	for _, s := range b {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

func DefaultPolicy() *Policy {
	return &Policy{
		Version: "0.1",
		Defaults: Defaults{
			Decision:       DecisionAudit,
			NonInteractive: DecisionBlock,
			LogRedaction:   true,
			ProtectedPaths: []string{
				"~/.ssh/**",
				"~/.aws/**",
				"~/.gnupg/**",
				"~/.config/gcloud/**",
				"~/.kube/**",
			},
		},
		Network: Network{
			AllowDomains: []string{
				"github.com",
				"api.github.com",
				"pypi.org",
				"files.pythonhosted.org",
				"registry.npmjs.org",
				"formulae.brew.sh",
			},
		},
		Rules: []Rule{
			{
				ID:       "block-rm-root",
				Match:    Match{CommandRegex: `^(rm|sudo rm)\s+-rf\s+/(\s|$)`},
				Decision: DecisionBlock,
				Reason:   "Destructive remove at filesystem root is not allowed.",
			},
			{
				ID:       "block-pipe-to-shell",
				Match:    Match{CommandRegex: `^(curl|wget).*(\||\s+\|)\s*(sh|bash|zsh)(\s|$)`},
				Decision: DecisionBlock,
				Reason:   "Blocking pipe-to-shell execution. Download and inspect scripts first.",
			},
			{
				ID: "audit-package-installs",
				Match: Match{CommandPrefix: []string{
					"npm install", "pnpm add", "yarn add",
					"pip install", "poetry add", "brew install",
				}},
				Decision: DecisionAudit,
				Reason:   "Package installs can introduce supply-chain risk. Flagged for audit.",
			},
			{
				ID:       "audit-file-edits",
				Match:    Match{CommandPrefix: []string{"sed ", "perl -pi", "python -c"}},
				Decision: DecisionAudit,
				Reason:   "In-place file edits flagged for audit review.",
			},
			{
				ID:       "allow-safe-readonly",
				Match:    Match{CommandPrefix: []string{"ls", "pwd", "whoami", "git status", "git diff", "cat README"}},
				Decision: DecisionAllow,
				Reason:   "Read-only / low-risk command.",
			},
		},
	}
}
