package policy

import (
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultPolicy(), nil
		}
		return nil, err
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	if policy.Defaults.Decision == "" {
		policy.Defaults.Decision = DecisionAudit
	}
	if policy.Defaults.NonInteractive == "" {
		policy.Defaults.NonInteractive = DecisionBlock
	}

	return &policy, nil
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
