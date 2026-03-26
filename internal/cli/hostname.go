package cli

import "github.com/security-researcher-ca/agentshield/internal/enterprise"

// stableHostname returns a consistent machine name that doesn't change with networks.
func stableHostname() string {
	return enterprise.StableHostname()
}
