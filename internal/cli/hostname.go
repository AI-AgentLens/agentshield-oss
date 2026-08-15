package cli

import "github.com/AI-AgentLens/agentshield/internal/enterprise"

// stableHostname returns a consistent machine name that doesn't change with networks.
func stableHostname() string {
	return enterprise.StableHostname()
}
