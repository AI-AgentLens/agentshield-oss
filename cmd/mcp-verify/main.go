// Command mcp-verify runs the MCP proxy self-test scenarios and outputs
// a Markdown report with accuracy metrics.
package main

import (
	"fmt"
	"os"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

func main() {
	// Determine packs directory. When run from repo root, packs/community/mcp/
	// is the default. Allow override via environment variable.
	packsDir := os.Getenv("MCP_PACKS_DIR")
	if packsDir == "" {
		packsDir = "packs/community/mcp"
	}

	// Layer premium packs on top when present (skipped in OSS-only checkouts),
	// mirroring how newTestMCPHandler loads them in unit tests.
	premiumDir := os.Getenv("MCP_PREMIUM_PACKS_DIR")
	if premiumDir == "" {
		premiumDir = "packs/premium/mcp"
	}

	results := mcp.RunMCPSelfTest(packsDir, premiumDir)

	fmt.Println(results.FormatMarkdown())

	if results.FP > 0 || results.FN > 0 {
		os.Exit(1)
	}
}
